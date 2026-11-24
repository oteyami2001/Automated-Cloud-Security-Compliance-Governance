variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "kms_key_arn" {
  description = "Customer managed key for the topic."
  type        = string
}

variable "alert_email" {
  description = "Operator e-mail (sensitive; supplied via TF_VAR). Empty = no subscription."
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition     = var.alert_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an e-mail address or empty."
  }
}
