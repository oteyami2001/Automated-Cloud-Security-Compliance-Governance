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

variable "policy_parameter_arn" {
  description = "ARN of the platform policy SecureString parameter (owned by the stack)."
  type        = string
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
