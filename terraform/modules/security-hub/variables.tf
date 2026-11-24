variable "ownership_mode" {
  description = "disabled (default) | integrate (hub already enabled; consume findings only) | create (approved window only)."
  type        = string
  default     = "disabled"
  validation {
    condition     = contains(["disabled", "integrate", "create"], var.ownership_mode)
    error_message = "ownership_mode must be disabled, integrate or create."
  }
}

variable "region" {
  type = string
}

variable "enable_fsbp" {
  description = "Subscribe to AWS Foundational Security Best Practices in create mode (higher check volume; cost model)."
  type        = bool
  default     = false
}
