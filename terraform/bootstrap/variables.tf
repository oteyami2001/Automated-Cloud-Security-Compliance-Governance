variable "aws_account_id" {
  description = "Target account (TF_VAR_aws_account_id; never committed). The provider refuses any other account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be 12 digits."
  }
}

variable "region" {
  description = "Deployment Region (pending owner confirmation, ADR 0002)."
  type        = string
  default     = "us-east-2"
  validation {
    condition     = contains(["us-east-2"], var.region)
    error_message = "Only us-east-2 is approved (us-east-1 is SCP-denied in the target account)."
  }
}

variable "owner" {
  type    = string
  default = "oteyami2001"
}

variable "github_owner" {
  type    = string
  default = "oteyami2001"
}

variable "github_owner_id" {
  description = "Numeric GitHub owner ID (immutable OIDC subject)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "github_owner_id must be numeric."
  }
}

variable "github_repo" {
  type    = string
  default = "Automated-Cloud-Security-Compliance-Governance"
}

variable "github_repo_id" {
  description = "Numeric GitHub repository ID (immutable OIDC subject; read from the GitHub API in Phase 3)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]+$", var.github_repo_id))
    error_message = "github_repo_id must be numeric."
  }
}

variable "create_oidc_provider" {
  description = "false (default): look up the existing shared provider and never manage it."
  type        = bool
  default     = false
}

variable "environments" {
  description = "Environments that get GitHub roles. Only dev is deployed in this project."
  type        = list(string)
  default     = ["dev"]
  validation {
    condition     = alltrue([for e in var.environments : contains(["dev", "staging", "prod"], e)])
    error_message = "environments must be dev, staging or prod."
  }
}

variable "alert_email" {
  type      = string
  default   = ""
  sensitive = true
}

variable "budget_limit_usd" {
  type    = number
  default = 25
}
