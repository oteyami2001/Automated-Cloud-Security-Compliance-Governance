output "rule_names" {
  value = sort([for r in aws_cloudwatch_event_rule.this : r.name])
}

output "rule_arns" {
  value = { for k, r in aws_cloudwatch_event_rule.this : k => r.arn }
}

output "event_patterns" {
  value = { for k, r in aws_cloudwatch_event_rule.this : k => r.event_pattern }
}
