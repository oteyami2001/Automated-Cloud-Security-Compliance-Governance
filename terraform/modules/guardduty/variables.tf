variable "ownership_mode" {
  description = "disabled (default) | integrate (existing detector; never managed) | create (approved window only)."
  type        = string
  default     = "disabled"
  validation {
    condition     = contains(["disabled", "integrate", "create"], var.ownership_mode)
    error_message = "ownership_mode must be disabled, integrate or create."
  }
}
