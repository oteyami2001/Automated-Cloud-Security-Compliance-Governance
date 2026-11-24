variable "name_prefix" {
  description = "Role name prefix, e.g. acscg."
  type        = string
}

variable "create_oidc_provider" {
  description = "Create the GitHub OIDC provider. Default false: the existing, shared provider is looked up and never managed."
  type        = bool
  default     = false
}

variable "subject_prefix" {
  description = "Immutable-ID subject prefix: repo:<owner>@<owner-id>/<repo>@<repo-id> (numeric IDs from the GitHub API)."
  type        = string
  validation {
    condition     = can(regex("^repo:[A-Za-z0-9-]+@[0-9]+/[A-Za-z0-9._-]+@[0-9]+$", var.subject_prefix))
    error_message = "subject_prefix must be repo:<owner>@<owner-id>/<repo>@<repo-id> with numeric IDs."
  }
}

variable "permissions_boundary_arn" {
  description = "Boundary attached to roles with attach_boundary = true."
  type        = string
  default     = null
}

variable "roles" {
  description = "Roles to create: key -> subject suffix (environment:<name> or ref:refs/heads/main), policy, optional job_workflow_ref."
  type = map(object({
    description         = string
    subject_suffix      = string
    policy_json         = string
    attach_boundary     = optional(bool, true)
    job_workflow_ref    = optional(string)
    managed_policy_arns = optional(list(string), [])
  }))

  validation {
    condition = alltrue([
      for r in values(var.roles) :
      can(regex("^(environment:[a-z0-9-]+|ref:refs/heads/main)$", r.subject_suffix))
    ])
    error_message = "subject_suffix must be environment:<name> or ref:refs/heads/main. pull_request and wildcard subjects are not allowed."
  }
}
