mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/acscg-dev-mock" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  name_prefix = "acscg-dev"
  account_id  = "111122223333"
  region      = "us-east-2"
  kms_key_arn = "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555"
}

run "integrate_mode_never_touches_the_recorder" {
  command = apply

  assert {
    condition = (length(aws_config_configuration_recorder.this) + length(aws_config_delivery_channel.this) +
    length(aws_config_configuration_recorder_status.this) + length(aws_s3_bucket.delivery) + length(aws_iam_role.recorder)) == 0
    error_message = "integrate mode must not create or manage recorder resources (ADR 0003)"
  }
  assert {
    condition     = length(aws_config_config_rule.managed) == 18
    error_message = "all managed rules for SEC-001..014 expected"
  }
  assert {
    condition     = alltrue([for r in aws_config_config_rule.managed : startswith(r.name, "acscg-sec")])
    error_message = "rule names must carry the acscg-secNNN prefix used by the EventBridge filter"
  }
  assert {
    condition     = aws_config_config_rule.managed["sec009-console-mfa"].maximum_execution_frequency == "TwentyFour_Hours"
    error_message = "periodic rules evaluate every 24 h"
  }
  assert {
    condition     = jsondecode(aws_config_config_rule.managed["sec006-restricted-rdp"].input_parameters).blockedPort1 == "3389"
    error_message = "RDP rule must block 3389"
  }
}

run "create_mode_records_only_selected_types" {
  command = apply
  variables {
    ownership_mode = "create"
  }

  assert {
    condition     = one(aws_config_configuration_recorder.this[0].recording_group).all_supported == false
    error_message = "must not record all resource types (cost, ADR 0011)"
  }
  assert {
    condition     = length(one(aws_config_configuration_recorder.this[0].recording_group).resource_types) == 10
    error_message = "only the catalog's resource types are recorded"
  }
  assert {
    condition     = one(aws_config_configuration_recorder.this[0].recording_mode).recording_frequency == "CONTINUOUS"
    error_message = "continuous recording is cheaper here than daily (cost model)"
  }
}

run "controls_can_be_disabled" {
  command = apply
  variables {
    enabled_controls       = ["SEC-005"]
    enable_custom_rules    = true
    custom_rule_lambda_arn = "arn:aws:lambda:us-east-2:111122223333:function:acscg-dev-config-evaluator"
  }
  assert {
    condition     = keys(aws_config_config_rule.managed) == ["sec005-restricted-ssh"] && keys(aws_config_config_rule.custom) == ["sec005-admin-port-custom"]
    error_message = "only SEC-005 rules expected"
  }
}

run "periodic_rules_have_no_scope_and_retention_has_custom_check" {
  command = apply
  variables {
    enable_custom_rules    = true
    custom_rule_lambda_arn = "arn:aws:lambda:us-east-2:111122223333:function:acscg-dev-config-evaluator"
  }
  assert {
    condition     = aws_config_config_rule.managed["sec014-log-retention"].maximum_execution_frequency == "TwentyFour_Hours" && length(aws_config_config_rule.managed["sec014-log-retention"].scope) == 0
    error_message = "CW_LOGGROUP_RETENTION_PERIOD_CHECK is periodic (AWS Config developer guide)"
  }
  assert {
    condition     = tolist(one(aws_config_config_rule.custom["sec014-retention-set"].scope).compliance_resource_types) == tolist(["AWS::Logs::LogGroup"])
    error_message = "never-expire log groups need the custom retention check"
  }
  assert {
    condition     = !contains(one(aws_config_config_rule.managed["sec013-required-tags"].scope).compliance_resource_types, "AWS::Lambda::Function")
    error_message = "REQUIRED_TAGS does not support Lambda functions"
  }
}

run "invalid_mode_rejected" {
  command = plan
  variables {
    ownership_mode = "takeover"
  }
  expect_failures = [var.ownership_mode]
}
