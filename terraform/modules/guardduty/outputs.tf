output "findings_enabled" {
  value = var.ownership_mode != "disabled"
}

output "detector_id" {
  value = var.ownership_mode == "create" ? aws_guardduty_detector.this[0].id : (var.ownership_mode == "integrate" ? data.aws_guardduty_detector.existing[0].id : null)
}

output "managed_by_project" {
  value = var.ownership_mode == "create"
}
