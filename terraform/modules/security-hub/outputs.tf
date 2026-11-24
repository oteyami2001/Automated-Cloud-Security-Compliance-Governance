output "findings_enabled" {
  description = "Whether the processor should receive Security Hub findings."
  value       = var.ownership_mode != "disabled"
}

output "managed_by_project" {
  value = var.ownership_mode == "create"
}
