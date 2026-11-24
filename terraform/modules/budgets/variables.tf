variable "name" {
  type = string
}

variable "limit_usd" {
  description = "Monthly alert threshold in USD (not a spending cap)."
  type        = number
  default     = 25
  validation {
    condition     = var.limit_usd > 0 && var.limit_usd <= 100
    error_message = "limit_usd must be between 0 and 100 for this project."
  }
}

variable "tag_key" {
  type    = string
  default = "Project"
}

variable "tag_value" {
  type    = string
  default = "acscg"
}

variable "actual_thresholds" {
  type    = list(number)
  default = [50, 80]
}

variable "alert_email" {
  type      = string
  default   = ""
  sensitive = true
}
