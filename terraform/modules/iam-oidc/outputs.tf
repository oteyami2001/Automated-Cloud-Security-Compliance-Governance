output "role_arns" {
  value = { for k, r in aws_iam_role.this : k => r.arn }
}

output "oidc_provider_arn" {
  value = local.provider_arn
}

output "trust_policies" {
  description = "Rendered trust policies (asserted by tests)."
  value       = local.trust
}
