output "gatekeeper_function_name" {
  value = aws_lambda_function.gatekeeper.function_name
}

output "gatekeeper_function_arn" {
  value = aws_lambda_function.gatekeeper.arn
}

output "gatekeeper_role_arn" {
  value = aws_iam_role.gatekeeper.arn
}

output "execution_role_arns" {
  value = { for k, r in aws_iam_role.exec : k => r.arn }
}

output "document_names" {
  value = sort([for d in aws_ssm_document.runbook : d.name])
}

output "allowed_arns" {
  description = "ARNs each execution role may change (empty = read-only)."
  value       = local.allowed_arns
}
