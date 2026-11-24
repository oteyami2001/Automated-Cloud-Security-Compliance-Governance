output "rule_names" {
  value = sort(concat([for r in aws_config_config_rule.managed : r.name], [for r in aws_config_config_rule.custom : r.name]))
}

output "rule_arns" {
  value = concat([for r in aws_config_config_rule.managed : r.arn], [for r in aws_config_config_rule.custom : r.arn])
}

output "recorder_created" {
  value = local.create
}
