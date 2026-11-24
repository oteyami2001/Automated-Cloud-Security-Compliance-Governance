mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/acscg-dev-mock" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-2:111122223333:acscg-dev-findings-dlq", url = "https://sqs.us-east-2.amazonaws.com/111122223333/acscg-dev-findings-dlq" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-2:111122223333:log-group:/aws/lambda/acscg-dev-mock" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-2:111122223333:rule/acscg-dev-daily-report" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-2:111122223333:function:acscg-dev-mock" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  name_prefix           = "acscg-dev"
  environment           = "dev"
  account_id            = "111122223333"
  region                = "us-east-2"
  lambda_package_path   = "../../../tests/fixtures/lambda.zip"
  evidence_bucket_name  = "acscg-dev-evidence-111122223333-us-east-2"
  kms_key_arn           = "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555"
  topic_arn             = "arn:aws:sns:us-east-2:111122223333:acscg-dev-security-alerts"
  policy_parameter_name = "/acscg/dev/platform-policy"
}

run "engine_defaults" {
  command = apply

  assert {
    condition     = alltrue([for f in aws_lambda_function.this : f.runtime == "python3.13" && length(f.architectures) == 1 && contains(f.architectures, "arm64")])
    error_message = "Python 3.13 on arm64 (ADR 0010)"
  }
  assert {
    condition     = aws_lambda_function.this["findings-processor"].reserved_concurrent_executions == 5
    error_message = "processor concurrency is capped (T-06)"
  }
  assert {
    condition     = aws_lambda_function.this["findings-processor"].environment[0].variables.ACSCG_REMEDIATION_MODE == "report_only" && aws_lambda_function.this["findings-processor"].environment[0].variables.ACSCG_REMEDIATION_ENABLED == "false"
    error_message = "report-only by default"
  }
  assert {
    condition     = aws_lambda_function.this["findings-processor"].environment[0].variables.ACSCG_ALLOW_SYNTHETIC == "false"
    error_message = "synthetic events off by default"
  }
  assert {
    condition     = aws_dynamodb_table.findings.billing_mode == "PAY_PER_REQUEST" && one(aws_dynamodb_table.findings.ttl).enabled
    error_message = "on-demand table with TTL for idempotency keys"
  }
  assert {
    condition     = one(aws_dynamodb_table.findings.server_side_encryption).enabled
    error_message = "table encrypted with the project key"
  }
  assert {
    condition     = aws_sqs_queue.dlq.sqs_managed_sse_enabled
    error_message = "DLQ encrypted"
  }
  assert {
    condition     = aws_lambda_function_event_invoke_config.processor.maximum_retry_attempts == 2
    error_message = "bounded retries"
  }
  assert {
    condition     = alltrue([for g in aws_cloudwatch_log_group.function : g.retention_in_days == 30])
    error_message = "explicit log retention (SEC-014 applies to ourselves)"
  }
  assert {
    condition     = aws_lambda_function.this["findings-reconciler"].handler == "acscg.findings_processor.reconcile.lambda_handler" && aws_lambda_function.this["findings-reconciler"].reserved_concurrent_executions == 1
    error_message = "one reconciler at a time (P4-13)"
  }
  assert {
    condition     = aws_cloudwatch_event_rule.reconcile.schedule_expression == "rate(6 hours)"
    error_message = "Config results are reconciled every 6 hours"
  }
}

run "policy_parameter_name_validated" {
  command = plan
  variables {
    policy_parameter_name = "/other/policy"
  }
  expect_failures = [var.policy_parameter_name]
}

run "log_retention_validated" {
  command = plan
  variables {
    log_retention_days = 7
  }
  expect_failures = [var.log_retention_days]
}
