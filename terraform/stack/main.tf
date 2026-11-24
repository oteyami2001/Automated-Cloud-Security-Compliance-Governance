# ACSCG workload stack (one root for every environment; per-environment values in ../envs/<env>).

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name_prefix   = "acscg-${var.environment}"
  arn           = "arn:${data.aws_partition.current.partition}"
  role_arn      = "${local.arn}:iam::${var.aws_account_id}:role"
  boundary_arn  = "${local.arn}:iam::${var.aws_account_id}:policy/acscg-workload-boundary"
  policy_param  = "/acscg/${var.environment}/platform-policy"
  apply_role    = "${local.role_arn}/acscg-github-${var.environment}-apply"
  cleanup_role  = "${local.role_arn}/acscg-github-${var.environment}-cleanup"
  gatekeeper    = "${local.name_prefix}-remediation-gatekeeper"
  gatekeeper_fn = "${local.arn}:lambda:${var.region}:${var.aws_account_id}:function:${local.gatekeeper}"

  policy_source = yamldecode(templatefile("${path.module}/../../policies/remediation/${var.environment}.yaml", {
    account_id = var.aws_account_id
    region     = var.region
  }))

  ci_roles = [for s in ["plan", "apply", "cleanup"] : "${local.role_arn}/acscg-github-${var.environment}-${s}"]
}

check "deployment_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
    error_message = "Credentials belong to a different account than aws_account_id."
  }
}

# ------------------------------------------------------------------ evidence, notifications

module "evidence_store" {
  source           = "../modules/evidence-store"
  name_prefix      = local.name_prefix
  account_id       = var.aws_account_id
  region           = var.region
  object_lock_days = var.object_lock_days
  writer_role_arns = concat(values(module.compliance_engine.role_arns), [module.remediation.gatekeeper_role_arn])
  cleanup_role_arn = local.cleanup_role
  admin_role_arns  = [local.apply_role]
}

module "notifications" {
  source      = "../modules/notifications"
  name_prefix = local.name_prefix
  account_id  = var.aws_account_id
  kms_key_arn = module.evidence_store.kms_key_arn
  alert_email = var.alert_email
}

# ------------------------------------------------------------------ processing and remediation

module "compliance_engine" {
  source                   = "../modules/compliance-engine"
  name_prefix              = local.name_prefix
  environment              = var.environment
  account_id               = var.aws_account_id
  region                   = var.region
  lambda_package_path      = var.lambda_package_path
  evidence_bucket_name     = "${local.name_prefix}-evidence-${var.aws_account_id}-${var.region}"
  kms_key_arn              = module.evidence_store.kms_key_arn
  topic_arn                = module.notifications.topic_arn
  policy_parameter_name    = local.policy_param
  gatekeeper_function_name = local.gatekeeper
  gatekeeper_function_arn  = local.gatekeeper_fn
  remediation_mode         = local.policy_source.remediation_mode
  remediation_enabled      = local.policy_source.remediation_enabled
  allow_synthetic_events   = var.allow_synthetic_events
  permissions_boundary_arn = local.boundary_arn
  log_retention_days       = var.log_retention_days
  point_in_time_recovery   = var.point_in_time_recovery
  deletion_protection      = var.deletion_protection
  report_schedule_enabled  = var.report_schedule_enabled
}

module "remediation" {
  source                     = "../modules/remediation"
  name_prefix                = local.name_prefix
  environment                = var.environment
  account_id                 = var.aws_account_id
  region                     = var.region
  lambda_package_path        = var.lambda_package_path
  runbooks_dir               = "${path.module}/../../runbooks"
  policy_source              = local.policy_source
  policy_parameter_name      = local.policy_param
  approvers                  = var.approvers
  project_inventory          = local.fixture_arns
  approved_change_principals = [local.apply_role, local.cleanup_role]
  project_role_arns          = concat(local.ci_roles, values(module.compliance_engine.role_arns))
  table_name                 = module.compliance_engine.table_name
  table_arn                  = module.compliance_engine.table_arn
  evidence_bucket_name       = "${local.name_prefix}-evidence-${var.aws_account_id}-${var.region}"
  kms_key_arn                = module.evidence_store.kms_key_arn
  topic_arn                  = module.notifications.topic_arn
  dlq_arn                    = module.compliance_engine.dlq_arn
  config_rule_arns           = module.security_config.rule_arns
  permissions_boundary_arn   = local.boundary_arn
  log_retention_days         = var.log_retention_days
}

# ------------------------------------------------------------------ detection sources

module "security_config" {
  source                        = "../modules/security-config"
  name_prefix                   = local.name_prefix
  account_id                    = var.aws_account_id
  region                        = var.region
  ownership_mode                = var.config_ownership_mode
  enable_custom_rules           = true
  custom_rule_lambda_arn        = module.compliance_engine.function_arns["config-evaluator"]
  kms_key_arn                   = module.evidence_store.kms_key_arn
  permissions_boundary_arn      = local.boundary_arn
  min_log_retention_days        = var.log_retention_days
  force_destroy_delivery_bucket = var.environment == "dev"
}

module "security_hub" {
  source         = "../modules/security-hub"
  ownership_mode = var.security_hub_mode
  region         = var.region
}

module "guardduty" {
  source         = "../modules/guardduty"
  ownership_mode = var.guardduty_mode
}

module "cloudtrail" {
  source              = "../modules/cloudtrail"
  mode                = var.cloudtrail_mode
  existing_trail_name = var.existing_trail_name
  name_prefix         = local.name_prefix
  account_id          = var.aws_account_id
  region              = var.region
}

resource "aws_accessanalyzer_analyzer" "account" {
  count         = var.create_access_analyzer ? 1 : 0
  analyzer_name = "${local.name_prefix}-external-access"
  type          = "ACCOUNT"
}

module "eventbridge" {
  source                 = "../modules/eventbridge"
  name_prefix            = local.name_prefix
  processor_arn          = module.compliance_engine.function_arns["findings-processor"]
  processor_name         = module.compliance_engine.function_names["findings-processor"]
  dlq_arn                = module.compliance_engine.dlq_arn
  dlq_url                = module.compliance_engine.dlq_url
  enable_security_hub    = module.security_hub.findings_enabled
  enable_guardduty       = module.guardduty.findings_enabled
  allow_synthetic_events = var.allow_synthetic_events
}

module "dashboard" {
  source = "../modules/dashboard"

  name_prefix = local.name_prefix
  region      = var.region
  function_names = merge(module.compliance_engine.function_names, {
    remediation-gatekeeper = module.remediation.gatekeeper_function_name
  })
  processor_log_group = module.compliance_engine.log_group_names["findings-processor"]
  dlq_name            = module.compliance_engine.dlq_name
  topic_arn           = module.notifications.topic_arn
}
