variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "ownership_mode" {
  description = "create: this project owns a recorder limited to recorded_resource_types. integrate: an existing recorder is used and never modified (rules only)."
  type        = string
  default     = "integrate"
  validation {
    condition     = contains(["create", "integrate"], var.ownership_mode)
    error_message = "ownership_mode must be create or integrate."
  }
}

variable "recorded_resource_types" {
  description = "Resource types recorded in create mode (only what the catalog evaluates; ADR 0011)."
  type        = list(string)
  default = [
    "AWS::S3::Bucket",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Volume",
    "AWS::EC2::Instance",
    "AWS::IAM::User",
    "AWS::IAM::Policy",
    "AWS::Logs::LogGroup",
    "AWS::CloudTrail::Trail",
    "AWS::DynamoDB::Table",
    "AWS::Lambda::Function",
  ]
  validation {
    condition     = length(var.recorded_resource_types) > 0 && length(var.recorded_resource_types) <= 20
    error_message = "Record between 1 and 20 resource types (cost guardrail)."
  }
}

variable "enabled_controls" {
  description = "Controls whose rules are created."
  type        = list(string)
  default     = ["SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007", "SEC-008", "SEC-009", "SEC-010", "SEC-011", "SEC-012", "SEC-013", "SEC-014"]
}

variable "min_log_retention_days" {
  type    = number
  default = 30
}

variable "enable_custom_rules" {
  description = "Create the custom Config rules (IPv6/port-range checks). Must be known at plan time."
  type        = bool
  default     = false
}

variable "custom_rule_lambda_arn" {
  description = "ARN of the custom-rule evaluator Lambda (required when enable_custom_rules = true)."
  type        = string
  default     = ""
}

variable "kms_key_arn" {
  type = string
}

variable "permissions_boundary_arn" {
  type    = string
  default = null
}

variable "force_destroy_delivery_bucket" {
  description = "Allow verified cleanup to empty the Config history bucket (dev only)."
  type        = bool
  default     = false
}
