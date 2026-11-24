variable "mode" {
  description = "integrate (default; existing trail, never managed) | create (requires explicit owner approval)."
  type        = string
  default     = "integrate"
  validation {
    condition     = contains(["integrate", "create"], var.mode)
    error_message = "mode must be integrate or create."
  }
}

variable "existing_trail_name" {
  description = "Name of the existing trail in integrate mode."
  type        = string
  default     = ""
}

variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "kms_key_arn" {
  type    = string
  default = null
}
