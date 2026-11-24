variable "name_prefix" {
  type = string
}

variable "processor_arn" {
  type = string
}

variable "processor_name" {
  type = string
}

variable "dlq_arn" {
  type = string
}

variable "dlq_url" {
  type = string
}

variable "enable_access_analyzer" {
  description = "Route IAM Access Analyzer findings (off where an SCP denies access-analyzer:*)."
  type        = bool
  default     = false
}

variable "enable_security_hub" {
  type    = bool
  default = false
}

variable "enable_guardduty" {
  type    = bool
  default = false
}

variable "allow_synthetic_events" {
  type    = bool
  default = false
}
