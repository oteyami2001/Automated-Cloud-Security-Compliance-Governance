output "state_bucket" {
  value = aws_s3_bucket.state.bucket
}

output "state_kms_key_arn" {
  value = aws_kms_key.state.arn
}

output "workload_boundary_arn" {
  value = aws_iam_policy.workload_boundary.arn
}

output "ci_role_arns" {
  value = module.ci_roles.role_arns
}

output "ci_role_policies" {
  description = "Rendered CI role policies (asserted by tests, reviewed in the Phase 3 plan)."
  value       = { for k, r in local.ci_roles : k => r.policy_json }
}

output "budget_name" {
  value = module.budget.budget_name
}
