# Findings processing engine: DynamoDB table, SQS dead-letter queue, findings-processor,
# custom Config rule evaluator and report-generator Lambdas (Python 3.13, arm64, zip package).
# Lambdas run outside a VPC: they only call AWS APIs and expose no endpoint (ADR 0010).

data "aws_partition" "current" {}

locals {
  p          = data.aws_partition.current.partition
  table_name = "${var.name_prefix}-findings"
  functions = {
    findings-processor = {
      handler     = "acscg.findings_processor.handler.lambda_handler"
      timeout     = 30
      concurrency = var.processor_concurrency
    }
    config-evaluator = {
      handler     = "acscg.compliance_evaluator.config_rule.handler"
      timeout     = 30
      concurrency = 2
    }
    report-generator = {
      handler     = "acscg.report_generator.handler.lambda_handler"
      timeout     = 120
      concurrency = 1
    }
    # Feeds Config's current results through the processor (evidence P4-13). Same permissions as the
    # processor plus read-only Config calls.
    findings-reconciler = {
      handler     = "acscg.findings_processor.reconcile.lambda_handler"
      timeout     = 300
      concurrency = 1
    }
  }
  environment = {
    ACSCG_ENV                 = var.environment
    ACSCG_ACCOUNT_ID          = var.account_id
    ACSCG_REGION              = var.region
    ACSCG_TABLE               = local.table_name
    ACSCG_EVIDENCE_BUCKET     = var.evidence_bucket_name
    ACSCG_TOPIC_ARN           = var.topic_arn
    ACSCG_KMS_KEY_ID          = var.kms_key_arn
    ACSCG_REMEDIATION_MODE    = var.remediation_mode
    ACSCG_REMEDIATION_ENABLED = tostring(var.remediation_enabled)
    ACSCG_ALLOW_SYNTHETIC     = tostring(var.allow_synthetic_events)
    ACSCG_GATEKEEPER_FUNCTION = var.gatekeeper_function_name
    ACSCG_POLICY_PARAMETER    = var.policy_parameter_name
  }
  evidence_arn = "arn:${local.p}:s3:::${var.evidence_bucket_name}"
}

# ------------------------------------------------------------------ state

resource "aws_dynamodb_table" "findings" {
  name                        = local.table_name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = var.deletion_protection

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  attribute {
    name = "execution_id"
    type = "S"
  }

  global_secondary_index {
    name            = "by-execution"
    projection_type = "ALL"
    key_schema {
      attribute_name = "execution_id"
      key_type       = "HASH"
    }
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.point_in_time_recovery
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-findings-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

# ------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "function" {
  for_each             = local.functions
  name                 = "${var.name_prefix}-${each.key}"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = var.permissions_boundary_arn
}

data "aws_iam_policy_document" "logs" {
  for_each = local.functions
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.function[each.key].arn}:*"]
  }
}

data "aws_iam_policy_document" "processor" {
  statement {
    sid       = "FindingsTable"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.findings.arn, "${aws_dynamodb_table.findings.arn}/index/*"]
  }
  statement {
    sid       = "EvidenceWrite"
    actions   = ["s3:PutObject"]
    resources = ["${local.evidence_arn}/evidence/*"]
  }
  statement {
    sid       = "ProjectKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:Encrypt"]
    resources = [var.kms_key_arn]
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [var.topic_arn]
  }
  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
  statement {
    sid       = "PolicyRead"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:${local.p}:ssm:${var.region}:${var.account_id}:parameter${var.policy_parameter_name}"]
  }
  statement {
    sid       = "AutomationStatusRead"
    actions   = ["ssm:GetAutomationExecution"]
    resources = ["arn:${local.p}:ssm:${var.region}:${var.account_id}:automation-execution/*"]
  }
  statement {
    sid       = "VerifyCompliance"
    actions   = ["config:GetComplianceDetailsByResource"]
    resources = ["*"] # the API does not support resource-level permissions
  }
  dynamic "statement" {
    for_each = var.gatekeeper_function_arn == "" ? [] : [var.gatekeeper_function_arn]
    content {
      sid       = "RequestRemediation"
      actions   = ["lambda:InvokeFunction"]
      resources = [statement.value]
    }
  }
}

data "aws_iam_policy_document" "evaluator" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
  statement {
    actions   = ["config:PutEvaluations"]
    resources = ["*"] # PutEvaluations does not support resource-level permissions
  }
  statement {
    sid       = "ListLogGroupsForPeriodicRetentionCheck"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["arn:${local.p}:logs:${var.region}:${var.account_id}:log-group:*"]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

data "aws_iam_policy_document" "report" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
  statement {
    actions   = ["dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.findings.arn, "${aws_dynamodb_table.findings.arn}/index/*"]
  }
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${local.evidence_arn}/reports/*", "${local.evidence_arn}/manifests/*"]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:Encrypt"]
    resources = [var.kms_key_arn]
  }
}

data "aws_iam_policy_document" "reconciler" {
  source_policy_documents = [data.aws_iam_policy_document.processor.json]
  statement {
    sid       = "ReadConfigResults"
    actions   = ["config:DescribeConfigRules", "config:GetComplianceDetailsByConfigRule"]
    resources = ["arn:${local.p}:config:${var.region}:${var.account_id}:config-rule/*"] # rule ARNs carry a random ID
  }
}

locals {
  role_policies = {
    findings-reconciler = data.aws_iam_policy_document.reconciler.json
    findings-processor  = data.aws_iam_policy_document.processor.json
    config-evaluator    = data.aws_iam_policy_document.evaluator.json
    report-generator    = data.aws_iam_policy_document.report.json
  }
}

resource "aws_iam_role_policy" "logs" {
  for_each = local.functions
  name     = "logs"
  role     = aws_iam_role.function[each.key].id
  policy   = data.aws_iam_policy_document.logs[each.key].json
}

resource "aws_iam_role_policy" "tracing" {
  for_each = local.functions
  name     = "tracing"
  role     = aws_iam_role.function[each.key].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], Resource = "*" }]
  })
}

resource "aws_iam_role_policy" "function" {
  for_each = local.functions
  name     = "permissions"
  role     = aws_iam_role.function[each.key].id
  policy   = local.role_policies[each.key]
}

# ------------------------------------------------------------------ functions

resource "aws_cloudwatch_log_group" "function" {
  for_each          = local.functions
  name              = "/aws/lambda/${var.name_prefix}-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_lambda_function" "this" {
  # checkov:skip=CKV_AWS_117:Lambdas call only AWS APIs and expose no endpoint; a VPC would add NAT cost (ADR 0010).
  # checkov:skip=CKV_AWS_272:Code signing is replaced by a reproducible package whose SHA-256 is verified in CI and pinned via source_code_hash.
  for_each                       = local.functions
  function_name                  = "${var.name_prefix}-${each.key}"
  role                           = aws_iam_role.function[each.key].arn
  runtime                        = "python3.13"
  architectures                  = ["arm64"]
  handler                        = each.value.handler
  filename                       = var.lambda_package_path
  source_code_hash               = filebase64sha256(var.lambda_package_path)
  timeout                        = each.value.timeout
  memory_size                    = 256
  reserved_concurrent_executions = each.value.concurrency
  kms_key_arn                    = var.kms_key_arn

  environment {
    variables = local.environment
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  logging_config {
    log_format = "Text" # the code writes structured JSON lines itself (common/log.py)
    log_group  = aws_cloudwatch_log_group.function[each.key].name
  }

  depends_on = [aws_iam_role_policy.logs, aws_iam_role_policy.function, aws_iam_role_policy.tracing]
}

resource "aws_lambda_function_event_invoke_config" "processor" {
  function_name                = aws_lambda_function.this["findings-processor"].function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600
  destination_config {
    on_failure {
      destination = aws_sqs_queue.dlq.arn
    }
  }
}

# ------------------------------------------------------------------ reconciliation

resource "aws_cloudwatch_event_rule" "reconcile" {
  name                = "${var.name_prefix}-reconcile"
  description         = "Reconcile findings with AWS Config's current results"
  schedule_expression = var.reconcile_schedule
}

resource "aws_cloudwatch_event_target" "reconcile" {
  rule = aws_cloudwatch_event_rule.reconcile.name
  arn  = aws_lambda_function.this["findings-reconciler"].arn
}

resource "aws_lambda_permission" "reconcile" {
  statement_id  = "AllowReconcileSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this["findings-reconciler"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reconcile.arn
}

# ------------------------------------------------------------------ daily report

resource "aws_cloudwatch_event_rule" "report" {
  name                = "${var.name_prefix}-daily-report"
  description         = "Daily compliance report"
  schedule_expression = var.report_schedule
  state               = var.report_schedule_enabled ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "report" {
  rule = aws_cloudwatch_event_rule.report.name
  arn  = aws_lambda_function.this["report-generator"].arn
}

resource "aws_lambda_permission" "report" {
  statement_id  = "AllowDailySchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this["report-generator"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.report.arn
}
