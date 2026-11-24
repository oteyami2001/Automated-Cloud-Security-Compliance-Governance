output "dashboard_name" {
  value = aws_cloudwatch_dashboard.this.dashboard_name
}

output "alarm_names" {
  value = sort(concat(
    [for a in aws_cloudwatch_metric_alarm.function_errors : a.alarm_name],
    [aws_cloudwatch_metric_alarm.dlq.alarm_name, aws_cloudwatch_metric_alarm.remediation_failed.alarm_name],
  ))
}
