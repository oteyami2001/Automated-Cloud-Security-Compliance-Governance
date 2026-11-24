mock_provider "aws" {}

variables {
  name_prefix = "acscg-dev"
  region      = "us-east-2"
  function_names = {
    findings-processor     = "acscg-dev-findings-processor"
    remediation-gatekeeper = "acscg-dev-remediation-gatekeeper"
  }
  processor_log_group = "/aws/lambda/acscg-dev-findings-processor"
  dlq_name            = "acscg-dev-findings-dlq"
  topic_arn           = "arn:aws:sns:us-east-2:111122223333:acscg-dev-security-alerts"
}

run "alarms_notify_operators" {
  command = apply
  assert {
    condition     = length(output.alarm_names) == 4
    error_message = "two function alarms, DLQ alarm, remediation-failure alarm"
  }
  assert {
    condition     = alltrue([for a in aws_cloudwatch_metric_alarm.function_errors : a.alarm_actions == toset(["arn:aws:sns:us-east-2:111122223333:acscg-dev-security-alerts"])])
    error_message = "alarms notify the security topic"
  }
  assert {
    condition     = length(jsondecode(aws_cloudwatch_dashboard.this.dashboard_body).widgets) == 4
    error_message = "dashboard widgets"
  }
}
