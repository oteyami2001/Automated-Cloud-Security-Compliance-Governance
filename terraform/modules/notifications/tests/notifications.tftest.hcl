mock_provider "aws" {
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-2:111122223333:acscg-dev-security-alerts" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  name_prefix = "acscg-dev"
  account_id  = "111122223333"
  kms_key_arn = "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555"
}

run "encrypted_topic_without_subscription" {
  command = apply
  assert {
    condition     = aws_sns_topic.alerts.kms_master_key_id == "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555"
    error_message = "topic must use the project key"
  }
  assert {
    condition     = length(aws_sns_topic_subscription.email) == 0
    error_message = "no subscription without an e-mail"
  }
}

run "invalid_email_rejected" {
  command = plan
  variables {
    alert_email = "not-an-email"
  }
  expect_failures = [var.alert_email]
}
