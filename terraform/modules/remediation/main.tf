# Remediation: gatekeeper Lambda, SSM Automation documents, per-runbook execution roles and the
# rendered platform policy (SSM SecureString). IAM independently limits every execution role to the
# allowlisted ARNs (defence in depth, docs/security-model.md §4). With an empty allowlist the
# execution roles can only read.

data "aws_partition" "current" {}

locals {
  p   = data.aws_partition.current.partition
  arn = "arn:${local.p}"

  runbooks = {
    sg   = { document = "acscg-RestrictSecurityGroupIngress", file = "restrict-security-group.yaml", action = "ec2:RevokeSecurityGroupIngress" }
    s3   = { document = "acscg-EnableBucketPublicAccessBlock", file = "enable-s3-protection.yaml", action = "s3:PutBucketPublicAccessBlock" }
    tags = { document = "acscg-EnforceRequiredTags", file = "enforce-required-tags.yaml", action = "tag:TagResources" }
    logs = { document = "acscg-SetLogRetention", file = "set-log-retention.yaml", action = "logs:PutRetentionPolicy" }
    ec2  = { document = "acscg-EnforceImdsV2", file = "enforce-imdsv2.yaml", action = "ec2:ModifyInstanceMetadataOptions" }
  }

  allowlist = try(var.policy_source.allowlist, [])
  allowed_arns = {
    for key, rb in local.runbooks : key => distinct([for e in local.allowlist : e.resource_arn if e.action == rb.action])
  }

  rendered_policy = merge(var.policy_source, {
    approval                   = merge(try(var.policy_source.approval, {}), { approvers = var.approvers })
    project_inventory          = sort(distinct(var.project_inventory))
    approved_change_principals = sort(distinct(concat(var.approved_change_principals, [for r in aws_iam_role.exec : r.arn])))
    project_role_arns          = sort(distinct(concat(var.project_role_arns, [for r in aws_iam_role.exec : r.arn], [aws_iam_role.gatekeeper.arn])))
  })
  rendered_policy_json = jsonencode(local.rendered_policy)

  definitions = [for rb in values(local.runbooks) : "${local.arn}:ssm:${var.region}:${var.account_id}:automation-definition/${rb.document}:*"]
}

# ------------------------------------------------------------------ platform policy parameter

resource "aws_ssm_parameter" "policy" {
  name        = var.policy_parameter_name
  description = "ACSCG platform policy (rendered by Terraform; read by the processor and gatekeeper)"
  type        = "SecureString"
  key_id      = var.kms_key_arn
  tier        = "Standard"
  value       = local.rendered_policy_json

  lifecycle {
    precondition {
      condition     = length(local.rendered_policy_json) <= 4096
      error_message = "Rendered policy exceeds the 4 KB Standard parameter limit."
    }
    precondition {
      condition     = var.policy_source.environment == var.environment
      error_message = "Policy source environment does not match the deployment environment."
    }
    precondition {
      condition     = !(var.environment == "prod" && var.policy_source.remediation_enabled)
      error_message = "Remediation cannot be enabled in prod."
    }
    precondition {
      condition     = alltrue([for e in local.allowlist : e.account == var.account_id && e.region == var.region])
      error_message = "Every allowlist entry must target this deployment's account and Region."
    }
  }
}

# ------------------------------------------------------------------ execution roles

locals {
  ssm_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ssm.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
        ArnLike      = { "aws:SourceArn" = "${local.arn}:ssm:${var.region}:${var.account_id}:automation-execution/*" }
      }
    }]
  })

  read_actions = {
    sg   = ["ec2:DescribeSecurityGroupRules"]
    s3   = ["s3:GetBucketPublicAccessBlock"]
    tags = ["tag:GetResources"]
    logs = ["logs:DescribeLogGroups"]
    ec2  = ["ec2:DescribeInstances"]
  }
  change_actions = {
    sg   = ["ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress"]
    s3   = ["s3:PutBucketPublicAccessBlock"]
    tags = ["tag:TagResources", "tag:UntagResources", "s3:PutBucketTagging", "s3:GetBucketTagging", "logs:TagResource", "logs:UntagResource", "ec2:CreateTags", "ec2:DeleteTags"]
    logs = ["logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy"]
    ec2  = ["ec2:ModifyInstanceMetadataOptions"]
  }

  # Rendered with jsonencode so tests can assert that changes are limited to allowlisted ARNs.
  exec_policies = {
    for key in keys(local.runbooks) : key => jsonencode({
      Version = "2012-10-17"
      Statement = concat(
        [
          {
            Sid      = "Reevaluate"
            Effect   = "Allow"
            Action   = "config:StartConfigRulesEvaluation"
            Resource = length(var.config_rule_arns) > 0 ? var.config_rule_arns : ["${local.arn}:config:${var.region}:${var.account_id}:config-rule/*"]
          },
          {
            Sid      = "ReadOnly"
            Effect   = "Allow"
            Action   = local.read_actions[key]
            Resource = "*" # Describe/Get APIs without resource-level support
          },
        ],
        length(local.allowed_arns[key]) == 0 ? [] : [{
          Sid       = "ScopedChangeOnAllowlistedResources"
          Effect    = "Allow"
          Action    = local.change_actions[key]
          Resource  = local.allowed_arns[key]
          Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
        }]
      )
    })
  }
}

resource "aws_iam_role" "exec" {
  for_each             = local.runbooks
  name                 = "${var.name_prefix}-rem-${each.key}-exec"
  assume_role_policy   = local.ssm_trust
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy" "exec" {
  for_each = local.runbooks
  name     = "runbook"
  role     = aws_iam_role.exec[each.key].id
  policy   = local.exec_policies[each.key]
}

# ------------------------------------------------------------------ SSM documents

resource "aws_ssm_document" "runbook" {
  for_each        = local.runbooks
  name            = each.value.document
  document_type   = "Automation"
  document_format = "JSON"
  content = jsonencode(merge(
    yamldecode(file("${var.runbooks_dir}/${each.value.file}")),
    {
      parameters = merge(
        yamldecode(file("${var.runbooks_dir}/${each.value.file}")).parameters,
        {
          AutomationAssumeRole = merge(
            yamldecode(file("${var.runbooks_dir}/${each.value.file}")).parameters.AutomationAssumeRole,
            { default = aws_iam_role.exec[each.key].arn }
          )
        }
      )
    }
  ))
}

# ------------------------------------------------------------------ gatekeeper

locals {
  lambda_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  })
}

resource "aws_iam_role" "gatekeeper" {
  name                 = "${var.name_prefix}-remediation-gatekeeper"
  assume_role_policy   = local.lambda_trust
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_cloudwatch_log_group" "gatekeeper" {
  name              = "/aws/lambda/${var.name_prefix}-remediation-gatekeeper"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

locals {
  gatekeeper_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.gatekeeper.arn}:*" },
      { Sid = "FindingsTable", Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"], Resource = [var.table_arn, "${var.table_arn}/index/*"] },
      { Sid = "EvidenceWrite", Effect = "Allow", Action = "s3:PutObject", Resource = "${local.arn}:s3:::${var.evidence_bucket_name}/evidence/*" },
      { Sid = "ProjectKey", Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt", "kms:Encrypt"], Resource = var.kms_key_arn },
      { Sid = "Notify", Effect = "Allow", Action = "sns:Publish", Resource = var.topic_arn },
      { Sid = "DeadLetter", Effect = "Allow", Action = "sqs:SendMessage", Resource = var.dlq_arn },
      { Sid = "PolicyRead", Effect = "Allow", Action = "ssm:GetParameter", Resource = aws_ssm_parameter.policy.arn },
      { Sid = "StartProjectRunbooksOnly", Effect = "Allow", Action = "ssm:StartAutomationExecution", Resource = concat(local.definitions, ["${local.arn}:ssm:${var.region}:${var.account_id}:automation-execution/*"]) },
      { Sid = "TagExecutions", Effect = "Allow", Action = "ssm:AddTagsToResource", Resource = "${local.arn}:ssm:${var.region}:${var.account_id}:automation-execution/*" },
      {
        Sid       = "PassOnlyRunbookRoles"
        Effect    = "Allow"
        Action    = "iam:PassRole"
        Resource  = [for r in aws_iam_role.exec : r.arn]
        Condition = { StringEquals = { "iam:PassedToService" = "ssm.amazonaws.com" } }
      },
      {
        Sid      = "LiveChecksReadOnly"
        Effect   = "Allow"
        Action   = ["ec2:DescribeSecurityGroupRules", "ec2:DescribeNetworkInterfaces", "ec2:DescribeInstances", "s3:GetBucketPublicAccessBlock", "tag:GetResources", "logs:DescribeLogGroups"]
        Resource = "*" # read-only APIs; several lack resource-level permissions
      },
      { Sid = "Tracing", Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], Resource = "*" },
      { Sid = "NeverApprove", Effect = "Deny", Action = "ssm:SendAutomationSignal", Resource = "*" },
    ]
  })
}

resource "aws_iam_role_policy" "gatekeeper" {
  name   = "gatekeeper"
  role   = aws_iam_role.gatekeeper.id
  policy = local.gatekeeper_policy
}

resource "aws_lambda_function" "gatekeeper" {
  # checkov:skip=CKV_AWS_117:Calls only AWS APIs and exposes no endpoint; a VPC would add NAT cost (ADR 0010).
  # checkov:skip=CKV_AWS_272:Reproducible package verified by SHA-256 in CI and pinned via source_code_hash.
  function_name                  = "${var.name_prefix}-remediation-gatekeeper"
  role                           = aws_iam_role.gatekeeper.arn
  runtime                        = "python3.13"
  architectures                  = ["arm64"]
  handler                        = "acscg.remediation_engine.handler.lambda_handler"
  filename                       = var.lambda_package_path
  source_code_hash               = filebase64sha256(var.lambda_package_path)
  timeout                        = 30
  memory_size                    = 256
  reserved_concurrent_executions = 2
  kms_key_arn                    = var.kms_key_arn

  environment {
    variables = {
      ACSCG_ENV                 = var.environment
      ACSCG_ACCOUNT_ID          = var.account_id
      ACSCG_REGION              = var.region
      ACSCG_TABLE               = var.table_name
      ACSCG_EVIDENCE_BUCKET     = var.evidence_bucket_name
      ACSCG_TOPIC_ARN           = var.topic_arn
      ACSCG_KMS_KEY_ID          = var.kms_key_arn
      ACSCG_REMEDIATION_MODE    = var.policy_source.remediation_mode
      ACSCG_REMEDIATION_ENABLED = tostring(var.policy_source.remediation_enabled)
      ACSCG_POLICY_PARAMETER    = var.policy_parameter_name
    }
  }

  dead_letter_config {
    target_arn = var.dlq_arn
  }

  tracing_config {
    mode = "Active"
  }

  logging_config {
    log_format = "Text" # the code writes structured JSON lines itself (common/log.py)
    log_group  = aws_cloudwatch_log_group.gatekeeper.name
  }

  depends_on = [aws_iam_role_policy.gatekeeper]
}

resource "aws_lambda_function_event_invoke_config" "gatekeeper" {
  function_name          = aws_lambda_function.gatekeeper.function_name
  maximum_retry_attempts = 0 # never start a runbook twice from a retry (ADR 0009)
}
