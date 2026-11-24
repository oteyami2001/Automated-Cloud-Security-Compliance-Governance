# Operational dashboard and alarms. Metrics are AWS-provided (Lambda, SQS) plus one log metric for
# failed remediations; posture numbers come from the report generator, not from this dashboard.

locals {
  functions = var.function_names
  # Each metric must stay a list of strings. flatten() would also flatten these rows into one list
  # of strings, which CloudWatch rejects (first dev apply, 2026-11-24); concat() joins only one level.
  lambda_metrics = concat([
    for name in values(local.functions) : [
      ["AWS/Lambda", "Invocations", "FunctionName", name],
      [".", "Errors", ".", name],
    ]
  ]...)
}

resource "aws_cloudwatch_log_metric_filter" "remediation_failed" {
  name           = "${var.name_prefix}-remediation-failed"
  log_group_name = var.processor_log_group
  pattern        = "{ $.state = \"REMEDIATION_FAILED\" || $.state = \"VERIFICATION_FAILED\" }"

  metric_transformation {
    name          = "RemediationFailures"
    namespace     = "ACSCG/${var.name_prefix}"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "function_errors" {
  for_each            = local.functions
  alarm_name          = "${each.value}-errors"
  alarm_description   = "Errors in ${each.value}"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${var.name_prefix}-findings-dlq-not-empty"
  alarm_description   = "Events failed processing and are in the dead-letter queue"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = var.dlq_name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "remediation_failed" {
  alarm_name          = "${var.name_prefix}-remediation-failed"
  alarm_description   = "A remediation failed or could not be verified"
  namespace           = "ACSCG/${var.name_prefix}"
  metric_name         = "RemediationFailures"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.topic_arn]
  depends_on          = [aws_cloudwatch_log_metric_filter.remediation_failed]
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = "${var.name_prefix}-security-posture"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          markdown = "## ACSCG ${var.name_prefix}\nOperational health. Compliance posture is in the daily report (reports/ in the evidence bucket). Framework-aligned, not certified."
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 12
        height = 6
        properties = {
          title   = "Lambda invocations and errors"
          region  = var.region
          stat    = "Sum"
          period  = 300
          metrics = local.lambda_metrics
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 2
        width  = 12
        height = 6
        properties = {
          title  = "Dead letters and failed remediations"
          region = var.region
          stat   = "Maximum"
          period = 300
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.dlq_name],
            ["ACSCG/${var.name_prefix}", "RemediationFailures", { stat = "Sum" }],
          ]
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 8
        width  = 24
        height = 6
        properties = {
          title  = "Finding state transitions (last 24 h)"
          region = var.region
          query  = "SOURCE '${var.processor_log_group}' | filter message = 'finding state' | stats count(*) as transitions by state, control_id | sort transitions desc"
          view   = "table"
        }
      },
    ]
  })
}
