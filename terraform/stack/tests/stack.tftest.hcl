# Whole-stack tests with mocked providers. CI also runs this file once per environment with
# -var-file=../envs/<env>/terraform.tfvars so staging and prod are validated as references.

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/acscg-mock" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-2:111122223333:acscg-mock", url = "https://sqs.us-east-2.amazonaws.com/111122223333/acscg-mock" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-2:111122223333:acscg-mock" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-2:111122223333:log-group:/aws/lambda/acscg-mock" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-2:111122223333:rule/acscg-mock" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-2:111122223333:function:acscg-mock" }
  }
  mock_resource "aws_ssm_parameter" {
    defaults = { arn = "arn:aws:ssm:us-east-2:111122223333:parameter/acscg/mock" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:us-east-2:111122223333:table/acscg-mock" }
  }
  mock_resource "aws_config_config_rule" {
    defaults = { arn = "arn:aws:config:us-east-2:111122223333:config-rule/config-rule-mock" }
  }
  mock_resource "aws_security_group" {
    defaults = { arn = "arn:aws:ec2:us-east-2:111122223333:security-group/sg-0123456789abcdef0" }
  }
}

mock_provider "aws" {
  alias = "untagged"
  mock_resource "aws_security_group" {
    defaults = { arn = "arn:aws:ec2:us-east-2:111122223333:security-group/sg-0fedcba9876543210" }
  }
}

variables {
  environment            = "dev"
  aws_account_id         = "111122223333"
  lambda_package_path    = "../../tests/fixtures/lambda.zip"
  approvers              = ["arn:aws:iam::111122223333:role/security-approver"]
  allow_synthetic_events = true
  enable_test_fixtures   = true
}

run "dev_is_report_only_and_owns_nothing_account_wide" {
  command = apply

  assert {
    condition     = output.remediation_mode == "report_only" && !output.remediation_enabled
    error_message = "every environment starts in report-only mode (ADR 0006)"
  }
  assert {
    condition     = !output.ownership.config_recorder && !output.ownership.security_hub && !output.ownership.guardduty && !output.ownership.cloudtrail
    error_message = "the default stack must not own any account-level security service (ADR 0003)"
  }
  assert {
    condition     = !module.security_hub.findings_enabled && !module.guardduty.findings_enabled && module.guardduty.detector_id == null
    error_message = "optional services disabled"
  }
  assert {
    condition     = contains(output.event_rule_names, "acscg-dev-synthetic") && !contains(output.event_rule_names, "acscg-dev-guardduty")
    error_message = "synthetic events only in dev; GuardDuty rule only when enabled"
  }
  assert {
    condition     = length(output.runbook_documents) == 5
    error_message = "five runbooks"
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.fixture_open_ssh) == 0 && length(aws_security_group.fixture_untagged) == 0
    error_message = "fixture violations are off until a scenario explicitly enables them"
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.fixture[0].block_public_policy
    error_message = "fixture bucket fully protected by default"
  }
  assert {
    condition     = length(output.fixture_arns) == 3
    error_message = "remediable inventory = fixtures only"
  }
  assert {
    condition     = length(aws_accessanalyzer_analyzer.account) == 0
    error_message = "no analyzer unless discovery shows none exists"
  }
}

run "scenario_fixtures_can_be_enabled" {
  command = apply
  variables {
    fixture_open_ssh             = true
    fixture_missing_tags         = true
    fixture_bucket_bpa_gap       = true
    fixture_log_group_violations = true
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.fixture_open_ssh[0].from_port == 22 && aws_vpc_security_group_ingress_rule.fixture_open_ssh[0].cidr_ipv4 == "0.0.0.0/0"
    error_message = "scenario 2 fixture"
  }
  assert {
    condition     = !contains(keys(aws_security_group.fixture_untagged[0].tags), "Owner")
    error_message = "scenario 3 fixture must lack Owner"
  }
  assert {
    condition     = aws_cloudwatch_log_group.fixture[0].retention_in_days == 0 || aws_cloudwatch_log_group.fixture[0].retention_in_days == null
    error_message = "scenario 8 fixture has no retention"
  }
  assert {
    condition     = length(output.fixture_arns) == 4
    error_message = "the untagged fixture joins the inventory"
  }
}

run "prod_reference" {
  command = apply
  variables {
    environment            = "prod"
    allow_synthetic_events = false
    enable_test_fixtures   = false
    log_retention_days     = 365
    object_lock_days       = 365
    point_in_time_recovery = true
    deletion_protection    = true
  }
  assert {
    condition     = !contains(output.event_rule_names, "acscg-prod-synthetic") && length(output.fixture_arns) == 0
    error_message = "no synthetic events or fixtures in prod"
  }
  assert {
    condition     = module.compliance_engine.table_name == "acscg-prod-findings"
    error_message = "prod naming"
  }
}

run "unapproved_region_rejected" {
  command = plan
  variables {
    region = "us-east-1"
  }
  expect_failures = [var.region]
}
