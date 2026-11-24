variable "name_prefix" {
  description = "Resource name prefix, e.g. acscg-dev."
  type        = string
  validation {
    condition     = can(regex("^acscg-(dev|staging|prod)$", var.name_prefix))
    error_message = "name_prefix must be acscg-<dev|staging|prod>."
  }
}

variable "account_id" {
  description = "Target AWS account ID (never committed; passed as TF_VAR_aws_account_id)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be 12 digits."
  }
}

variable "region" {
  description = "AWS Region."
  type        = string
}

variable "object_lock_days" {
  description = "Default Object Lock retention (governance mode) for evidence objects."
  type        = number
  default     = 7
  validation {
    condition     = var.object_lock_days >= 1 && var.object_lock_days <= 3650
    error_message = "object_lock_days must be between 1 and 3650."
  }
}

variable "key_deletion_window_days" {
  description = "KMS key deletion window."
  type        = number
  default     = 30
  validation {
    condition     = var.key_deletion_window_days >= 7 && var.key_deletion_window_days <= 30
    error_message = "key_deletion_window_days must be 7-30."
  }
}

variable "writer_role_arns" {
  description = "Only these roles may write evidence objects (processor, gatekeeper, report generator)."
  type        = list(string)
  default     = []
}

variable "cleanup_role_arn" {
  description = "The only principal allowed to delete evidence or bypass governance retention (approved cleanup)."
  type        = string
  default     = ""
}

variable "admin_role_arns" {
  description = "Roles allowed to change the bucket's Object Lock configuration (Terraform apply role)."
  type        = list(string)
  default     = []
}
