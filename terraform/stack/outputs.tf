output "environment" {
  value = var.environment
}

output "remediation_mode" {
  value = local.policy_source.remediation_mode
}

output "remediation_enabled" {
  value = local.policy_source.remediation_enabled
}

output "function_names" {
  value = merge(module.compliance_engine.function_names, { remediation-gatekeeper = module.remediation.gatekeeper_function_name })
}

output "table_name" {
  value = module.compliance_engine.table_name
}

output "evidence_bucket" {
  value = module.evidence_store.bucket_name
}

output "config_rule_names" {
  value = module.security_config.rule_names
}

output "event_rule_names" {
  value = module.eventbridge.rule_names
}

output "runbook_documents" {
  value = module.remediation.document_names
}

output "dashboard_name" {
  value = module.dashboard.dashboard_name
}

output "ownership" {
  description = "What this stack owns versus integrates with (ADR 0003)."
  value = {
    config_recorder = module.security_config.recorder_created
    security_hub    = module.security_hub.managed_by_project
    guardduty       = module.guardduty.managed_by_project
    cloudtrail      = module.cloudtrail.managed_by_project
  }
}

output "fixture_arns" {
  value = local.fixture_arns
}
