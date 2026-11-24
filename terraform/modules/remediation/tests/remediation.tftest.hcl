mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/acscg-dev-mock" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-2:111122223333:log-group:/aws/lambda/acscg-dev-remediation-gatekeeper" }
  }
  mock_resource "aws_ssm_parameter" {
    defaults = { arn = "arn:aws:ssm:us-east-2:111122223333:parameter/acscg/dev/platform-policy" }
  }
}

variables {
  name_prefix           = "acscg-dev"
  environment           = "dev"
  account_id            = "111122223333"
  region                = "us-east-2"
  lambda_package_path   = "../../../tests/fixtures/lambda.zip"
  runbooks_dir          = "../../../runbooks"
  policy_parameter_name = "/acscg/dev/platform-policy"
  table_name            = "acscg-dev-findings"
  table_arn             = "arn:aws:dynamodb:us-east-2:111122223333:table/acscg-dev-findings"
  evidence_bucket_name  = "acscg-dev-evidence-111122223333-us-east-2"
  kms_key_arn           = "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555"
  topic_arn             = "arn:aws:sns:us-east-2:111122223333:acscg-dev-security-alerts"
  dlq_arn               = "arn:aws:sqs:us-east-2:111122223333:acscg-dev-findings-dlq"
  approvers             = ["arn:aws:iam::111122223333:role/security-approver"]
  policy_source = {
    environment         = "dev"
    remediation_enabled = false
    remediation_mode    = "report_only"
    approval            = { timeout_minutes = 240 }
    limits              = { max_attempts_per_finding = 2 }
    allowlist           = []
    protected_resources = []
  }
}

run "report_only_roles_cannot_change_anything" {
  command = apply

  assert {
    condition = alltrue([
      for k, p in aws_iam_role_policy.exec : !contains([for s in jsondecode(p.policy).Statement : s.Sid], "ScopedChangeOnAllowlistedResources")
    ])
    error_message = "with an empty allowlist the execution roles must be read-only"
  }
  assert {
    condition     = length(aws_ssm_document.runbook) == 5
    error_message = "five runbooks expected"
  }
  assert {
    condition     = jsondecode(aws_ssm_document.runbook["sg"].content).parameters.AutomationAssumeRole["default"] == aws_iam_role.exec["sg"].arn
    error_message = "the runbook must default to its own execution role"
  }
  assert {
    condition     = aws_ssm_parameter.policy.type == "SecureString"
    error_message = "the rendered policy is stored encrypted"
  }
  assert {
    condition     = jsondecode(aws_ssm_parameter.policy.value).approval.approvers == ["arn:aws:iam::111122223333:role/security-approver"]
    error_message = "approvers must be rendered into the policy"
  }
  assert {
    condition     = aws_lambda_function_event_invoke_config.gatekeeper.maximum_retry_attempts == 0
    error_message = "the gatekeeper must never be retried (no duplicate runbook starts)"
  }
  assert {
    condition     = contains([for s in jsondecode(aws_iam_role_policy.gatekeeper.policy).Statement : s.Sid if s.Effect == "Deny" && s.Action == "ssm:SendAutomationSignal"], "NeverApprove")
    error_message = "the gatekeeper must be unable to approve"
  }
  assert {
    condition     = [for s in jsondecode(aws_iam_role_policy.gatekeeper.policy).Statement : s.Condition.StringEquals["iam:PassedToService"] if s.Sid == "PassOnlyRunbookRoles"][0] == "ssm.amazonaws.com"
    error_message = "PassRole must be limited to SSM"
  }
  assert {
    condition     = aws_lambda_function.gatekeeper.reserved_concurrent_executions == 2 && aws_lambda_function.gatekeeper.runtime == "python3.13"
    error_message = "gatekeeper runtime/concurrency"
  }
}

run "allowlisted_arns_scope_the_change" {
  command = apply
  variables {
    policy_source = {
      environment         = "dev"
      remediation_enabled = true
      remediation_mode    = "human_approval"
      approval            = { timeout_minutes = 240 }
      limits              = { max_attempts_per_finding = 2 }
      protected_resources = []
      allowlist = [{
        id           = "AL-001"
        control_id   = "SEC-005"
        action       = "ec2:RevokeSecurityGroupIngress"
        account      = "111122223333"
        region       = "us-east-2"
        resource_arn = "arn:aws:ec2:us-east-2:111122223333:security-group/sg-0123456789abcdef0"
        expires_at   = "2026-12-01T00:00:00Z"
        reason       = "scenario 9"
      }]
    }
  }

  assert {
    condition     = [for s in jsondecode(aws_iam_role_policy.exec["sg"].policy).Statement : s.Resource if s.Sid == "ScopedChangeOnAllowlistedResources"][0] == ["arn:aws:ec2:us-east-2:111122223333:security-group/sg-0123456789abcdef0"]
    error_message = "the SG execution role may change exactly the allowlisted group"
  }
  assert {
    condition     = !contains([for s in jsondecode(aws_iam_role_policy.exec["s3"].policy).Statement : s.Sid], "ScopedChangeOnAllowlistedResources")
    error_message = "other execution roles stay read-only"
  }
}

run "prod_cannot_enable_remediation" {
  command = plan
  variables {
    environment = "prod"
    policy_source = {
      environment         = "prod"
      remediation_enabled = true
      remediation_mode    = "auto_low_risk"
      approval            = { timeout_minutes = 240 }
      limits              = { max_attempts_per_finding = 2 }
      allowlist           = []
      protected_resources = []
    }
  }
  expect_failures = [aws_ssm_parameter.policy]
}

run "allowlist_for_other_account_rejected" {
  command = plan
  variables {
    policy_source = {
      environment         = "dev"
      remediation_enabled = true
      remediation_mode    = "human_approval"
      approval            = { timeout_minutes = 240 }
      limits              = { max_attempts_per_finding = 2 }
      protected_resources = []
      allowlist = [{
        id           = "AL-001"
        control_id   = "SEC-005"
        action       = "ec2:RevokeSecurityGroupIngress"
        account      = "444455556666"
        region       = "us-east-2"
        resource_arn = "arn:aws:ec2:us-east-2:444455556666:security-group/sg-0123456789abcdef0"
        expires_at   = "2026-12-01T00:00:00Z"
        reason       = "wrong account"
      }]
    }
  }
  expect_failures = [aws_ssm_parameter.policy]
}

run "approver_must_be_iam_principal" {
  command = plan
  variables {
    approvers = ["someone@example.com"]
  }
  expect_failures = [var.approvers]
}
