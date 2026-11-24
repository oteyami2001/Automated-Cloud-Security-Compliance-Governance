variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "aws_account_id" {
  description = "Target account (TF_VAR_aws_account_id from the GitHub environment; never committed)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be 12 digits."
  }
}

variable "region" {
  type    = string
  default = "us-east-2"
  validation {
    condition     = contains(["us-east-2"], var.region)
    error_message = "Only us-east-2 is approved (ADR 0002)."
  }
}

variable "owner" {
  type    = string
  default = "oteyami2001"
}

variable "lambda_package_path" {
  description = "Reproducible package from scripts/build_lambda.py."
  type        = string
  default     = "../../dist/acscg-lambda.zip"
}

variable "alert_email" {
  type      = string
  default   = ""
  sensitive = true
}

variable "approvers" {
  description = "IAM principals allowed to approve Mode 3 remediations (TF_VAR; never committed)."
  type        = list(string)
  default     = []
  sensitive   = true
  validation {
    condition     = alltrue([for a in var.approvers : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/", a))])
    error_message = "approvers must be IAM role or user ARNs."
  }
}

variable "enable_remediation" {
  description = "Deploy the remediation module (gatekeeper, SSM documents, execution roles). Phase 6; off until then."
  type        = bool
  default     = false
}

variable "config_ownership_mode" {
  description = "create | integrate (decided from discovery D5; ADR 0003)."
  type        = string
  default     = "integrate"
}

variable "security_hub_mode" {
  type    = string
  default = "disabled"
}

variable "guardduty_mode" {
  type    = string
  default = "disabled"
}

variable "cloudtrail_mode" {
  type    = string
  default = "integrate"
}

variable "existing_trail_name" {
  type    = string
  default = "idp-management-events"
}

variable "create_access_analyzer" {
  description = "Create an account-level external-access analyzer (free). Off: discovery D8 shows an SCP denies access-analyzer:* in the target account."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "object_lock_days" {
  type    = number
  default = 7
}

variable "point_in_time_recovery" {
  type    = bool
  default = true
}

variable "deletion_protection" {
  type    = bool
  default = false
}

variable "allow_synthetic_events" {
  type    = bool
  default = false
}

variable "report_schedule_enabled" {
  type    = bool
  default = true
}

# ------------------------------------------------------------------ test fixtures (scenarios)

variable "enable_test_fixtures" {
  description = "Create isolated, unattached test resources for the validation scenarios (dev only)."
  type        = bool
  default     = false
}

variable "fixture_open_ssh" {
  description = "Scenario 2: add 22/tcp from 0.0.0.0/0 to the UNATTACHED fixture group in a VPC WITHOUT an internet gateway."
  type        = bool
  default     = false
}

variable "fixture_bucket_bpa_gap" {
  description = "Scenario 4: disable one bucket-level BPA setting on the EMPTY fixture bucket. It stays private: ACLs are disabled and its only policy is a Deny (no account-level BPA exists, discovery D13)."
  type        = bool
  default     = false
}

variable "fixture_missing_tags" {
  description = "Scenario 3: an extra unattached fixture security group created without Owner/ManagedBy/DataClassification tags."
  type        = bool
  default     = false
}

variable "fixture_log_group_violations" {
  description = "Scenario 8: fixture log group without a retention period (never expire)."
  type        = bool
  default     = false
}
