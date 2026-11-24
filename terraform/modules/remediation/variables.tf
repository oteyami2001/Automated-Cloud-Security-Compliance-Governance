variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "lambda_package_path" {
  type = string
}

variable "runbooks_dir" {
  description = "Directory holding the runbook YAML sources."
  type        = string
}

variable "policy_source" {
  description = "Decoded policies/remediation/<env>.yaml (rendered with account_id/region)."
  type        = any
}

variable "policy_parameter_name" {
  type = string
}

variable "approvers" {
  description = "IAM principal ARNs allowed to approve Mode 3 requests (TF_VAR, never committed)."
  type        = list(string)
  default     = []
  sensitive   = true
  validation {
    condition     = alltrue([for a in var.approvers : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/", a))])
    error_message = "approvers must be IAM role or user ARNs."
  }
}

variable "project_inventory" {
  description = "ARNs of resources created by this project (Terraform state), used for ownership checks."
  type        = list(string)
  default     = []
}

variable "approved_change_principals" {
  description = "Principals whose changes are authorised (Terraform apply role, runbook execution roles)."
  type        = list(string)
  default     = []
}

variable "project_role_arns" {
  description = "CI and automation roles: never allowed as approvers (separation of duties)."
  type        = list(string)
  default     = []
}

variable "table_name" {
  type = string
}

variable "table_arn" {
  type = string
}

variable "evidence_bucket_name" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "topic_arn" {
  type = string
}

variable "dlq_arn" {
  type = string
}

variable "config_rule_arns" {
  type    = list(string)
  default = []
}

variable "permissions_boundary_arn" {
  type    = string
  default = null
}

variable "log_retention_days" {
  type    = number
  default = 30
}
