variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "lambda_package_path" {
  description = "Path to the reproducible package built by scripts/build_lambda.py."
  type        = string
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

variable "policy_parameter_name" {
  description = "SSM parameter holding the rendered platform policy, e.g. /acscg/dev/platform-policy."
  type        = string
  validation {
    condition     = can(regex("^/acscg/(dev|staging|prod)/platform-policy$", var.policy_parameter_name))
    error_message = "policy_parameter_name must be /acscg/<env>/platform-policy."
  }
}

variable "gatekeeper_function_name" {
  type    = string
  default = ""
}

variable "gatekeeper_function_arn" {
  type    = string
  default = ""
}

variable "remediation_mode" {
  type    = string
  default = "report_only"
  validation {
    condition     = contains(["report_only", "auto_low_risk", "human_approval"], var.remediation_mode)
    error_message = "invalid remediation_mode."
  }
}

variable "remediation_enabled" {
  type    = bool
  default = false
}

variable "allow_synthetic_events" {
  type    = bool
  default = false
}

variable "permissions_boundary_arn" {
  type    = string
  default = null
}

variable "processor_concurrency" {
  description = "Reserved concurrency: caps cost and API pressure during event storms (T-06)."
  type        = number
  default     = 5
  validation {
    condition     = var.processor_concurrency >= 1 && var.processor_concurrency <= 20
    error_message = "processor_concurrency must be 1-20."
  }
}

variable "log_retention_days" {
  type    = number
  default = 30
  validation {
    condition     = contains([30, 90, 365], var.log_retention_days)
    error_message = "log_retention_days must be 30, 90 or 365."
  }
}

variable "point_in_time_recovery" {
  description = "PITR (USD 0.20 per GB-month of table size; the findings table is tiny, so it stays on)."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  type    = bool
  default = false
}

variable "reconcile_schedule" {
  description = "How often Config's current results are reconciled into the findings table."
  type        = string
  default     = "rate(6 hours)"
}

variable "report_schedule" {
  type    = string
  default = "cron(17 6 * * ? *)"
}

variable "report_schedule_enabled" {
  type    = bool
  default = true
}
