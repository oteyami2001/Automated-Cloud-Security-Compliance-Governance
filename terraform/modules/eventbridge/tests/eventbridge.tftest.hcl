mock_provider "aws" {
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-2:111122223333:rule/acscg-dev-mock" }
  }
}

variables {
  name_prefix    = "acscg-dev"
  processor_arn  = "arn:aws:lambda:us-east-2:111122223333:function:acscg-dev-findings-processor"
  processor_name = "acscg-dev-findings-processor"
  dlq_arn        = "arn:aws:sqs:us-east-2:111122223333:acscg-dev-findings-dlq"
  dlq_url        = "https://sqs.us-east-2.amazonaws.com/111122223333/acscg-dev-findings-dlq"
}

run "base_rules_only_by_default" {
  command = apply
  assert {
    condition     = toset(keys(aws_cloudwatch_event_rule.this)) == toset(["config-compliance", "cloudtrail-changes", "access-analyzer", "ssm-status"])
    error_message = "optional sources and synthetic events are off by default"
  }
  assert {
    condition     = alltrue([for k, r in aws_cloudwatch_event_rule.this : alltrue([for s in jsondecode(r.event_pattern).source : startswith(s, "aws.")])])
    error_message = "base rules accept only AWS service sources, which cannot be forged with PutEvents (T-01)"
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.this["config-compliance"].event_pattern).detail.configRuleName[0].prefix == "acscg-"
    error_message = "only this project's Config rules are routed"
  }
  assert {
    condition     = alltrue([for t in aws_cloudwatch_event_target.processor : one(t.dead_letter_config).arn == "arn:aws:sqs:us-east-2:111122223333:acscg-dev-findings-dlq"])
    error_message = "every target needs the DLQ"
  }
}

run "optional_and_synthetic_rules" {
  command = apply
  variables {
    enable_security_hub    = true
    enable_guardduty       = true
    allow_synthetic_events = true
  }
  assert {
    condition     = length(aws_cloudwatch_event_rule.this) == 7
    error_message = "seven rules with all options on"
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.this["securityhub"].event_pattern).detail.findings.ProductFields["aws/securityhub/ProductName"][0]["anything-but"] == "Config"
    error_message = "Security Hub copies of Config findings are excluded (ADR 0004)"
  }
}
