# Environment invariants. Run once per environment with its tfvars:
#   terraform test -filter=tests/environments.tftest.hcl -var-file=../envs/<env>/terraform.tfvars
# Only values that are never committed (account, approvers) are set here.

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
  aws_account_id      = "111122223333"
  lambda_package_path = "../../tests/fixtures/lambda.zip"
  approvers           = ["arn:aws:iam::111122223333:role/security-approver"]
}

run "environment_invariants" {
  command = apply

  assert {
    condition     = output.remediation_mode == "report_only" && !output.remediation_enabled
    error_message = "committed configuration must be report-only (remediation windows are separate, reviewed changes)"
  }
  assert {
    condition     = !output.ownership.security_hub && !output.ownership.guardduty && !output.ownership.cloudtrail
    error_message = "Security Hub, GuardDuty and CloudTrail are never owned (SCP-denied or pre-existing; ADR 0003/0005)"
  }
  assert {
    condition     = !output.ownership.config_recorder || var.environment == "dev"
    error_message = "only dev may own a Config recorder (discovery D5: none existed in us-east-2)"
  }
  assert {
    condition     = contains(output.event_rule_names, "acscg-${var.environment}-synthetic") == (var.environment == "dev")
    error_message = "synthetic events exist only in dev"
  }
  assert {
    condition     = length(output.fixture_arns) == 0 || var.environment == "dev"
    error_message = "test fixtures exist only in dev"
  }
  assert {
    condition     = !output.remediation_deployed || var.environment != "prod"
    error_message = "the remediation module is never deployed in prod"
  }
  assert {
    condition     = var.environment != "prod" || (var.deletion_protection && var.point_in_time_recovery && var.log_retention_days >= 365)
    error_message = "prod reference requires deletion protection, PITR and 365-day logs"
  }
}
