# Platform policy (SSM SecureString). Owned by the stack because the findings processor reads it
# (fail closed) whether or not the remediation module is deployed. The role ARNs are built from
# their fixed names so the parameter does not depend on the remediation module's resources.

locals {
  runbook_keys      = ["sg", "s3", "tags", "logs", "ec2"] # must equal the remediation module's runbooks (tested)
  exec_role_arns    = var.enable_remediation ? [for k in local.runbook_keys : "${local.role_arn}/${local.name_prefix}-rem-${k}-exec"] : []
  gatekeeper_role   = var.enable_remediation ? ["${local.role_arn}/${local.gatekeeper}"] : []
  allowlist         = try(local.policy_source.allowlist, [])
  compliance_roles  = [for k in ["findings-processor", "config-evaluator", "report-generator"] : "${local.role_arn}/${local.name_prefix}-${k}"]
  automation_admins = [local.apply_role, local.cleanup_role]

  rendered_policy = merge(local.policy_source, {
    approval                   = merge(try(local.policy_source.approval, {}), { approvers = var.approvers })
    project_inventory          = sort(distinct(local.fixture_arns))
    approved_change_principals = sort(distinct(concat(local.automation_admins, local.exec_role_arns)))
    project_role_arns          = sort(distinct(concat(local.ci_roles, local.compliance_roles, local.exec_role_arns, local.gatekeeper_role)))
  })
  rendered_policy_json = jsonencode(local.rendered_policy)
}

resource "aws_ssm_parameter" "policy" {
  name        = local.policy_param
  description = "ACSCG platform policy (rendered by Terraform; read by the processor and gatekeeper)"
  type        = "SecureString"
  key_id      = module.evidence_store.kms_key_arn
  tier        = "Standard"
  value       = local.rendered_policy_json

  lifecycle {
    precondition {
      condition     = length(local.rendered_policy_json) <= 4096
      error_message = "Rendered policy exceeds the 4 KB Standard parameter limit."
    }
    precondition {
      condition     = local.policy_source.environment == var.environment
      error_message = "Policy source environment does not match the deployment environment."
    }
    precondition {
      condition     = !(var.environment == "prod" && local.policy_source.remediation_enabled)
      error_message = "Remediation cannot be enabled in prod."
    }
    precondition {
      condition     = var.enable_remediation || !local.policy_source.remediation_enabled
      error_message = "remediation_enabled in the policy needs the remediation module (enable_remediation = true)."
    }
    precondition {
      condition     = alltrue([for e in local.allowlist : e.account == var.aws_account_id && e.region == var.region])
      error_message = "Every allowlist entry must target this deployment's account and Region."
    }
  }
}
