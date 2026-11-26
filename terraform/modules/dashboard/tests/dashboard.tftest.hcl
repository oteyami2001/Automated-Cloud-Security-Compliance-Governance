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
    condition     = length(jsondecode(aws_cloudwatch_dashboard.this.dashboard_body).widgets) == 6
    error_message = "dashboard widgets: header, health, dead letters, transitions, posture, severity"
  }
  assert {
    # CloudWatch: "metrics" must be an array of arrays of strings, with an optional renderer object last.
    condition = alltrue(flatten([
      for w in jsondecode(aws_cloudwatch_dashboard.this.dashboard_body).widgets : [
        for m in try(w.properties.metrics, []) : !can(tostring(m)) && length(m) >= 2
      ]
    ]))
    error_message = "every metric must be its own list (flatten() once merged them into one list of strings)"
  }
  assert {
    condition     = length(jsondecode(aws_cloudwatch_dashboard.this.dashboard_body).widgets[1].properties.metrics) == 4
    error_message = "two rows (invocations, errors) per function"
  }
  assert {
    condition = (jsondecode(aws_cloudwatch_dashboard.this.dashboard_body).widgets[4].properties.metrics[0] == ["ACSCG/acscg-dev", "ComplianceScore"] &&
    jsondecode(aws_cloudwatch_dashboard.this.dashboard_body).widgets[5].properties.metrics[1] == ["ACSCG/acscg-dev", "OpenFindingsBySeverity", "Severity", "high"])
    error_message = "posture widgets read the report generator's EMF namespace (Phase 7)"
  }
}
