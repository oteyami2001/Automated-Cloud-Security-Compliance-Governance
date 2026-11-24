output "table_name" {
  value = aws_dynamodb_table.findings.name
}

output "table_arn" {
  value = aws_dynamodb_table.findings.arn
}

output "dlq_arn" {
  value = aws_sqs_queue.dlq.arn
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}

output "dlq_name" {
  value = aws_sqs_queue.dlq.name
}

output "function_arns" {
  value = { for k, f in aws_lambda_function.this : k => f.arn }
}

output "function_names" {
  value = { for k, f in aws_lambda_function.this : k => f.function_name }
}

output "role_arns" {
  value = { for k, r in aws_iam_role.function : k => r.arn }
}

output "log_group_names" {
  value = { for k, g in aws_cloudwatch_log_group.function : k => g.name }
}
