# GitHub Actions OIDC roles. The OIDC provider is looked up (shared, never managed) unless
# create_oidc_provider = true. Each role trusts exactly one immutable-ID subject (StringEquals).
# No role trusts pull_request subjects (Project 2 ADR 0003).

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

locals {
  provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

# Rendered with jsonencode (not a data source) so tests can assert the exact trust conditions.
locals {
  trust = {
    for k, r in var.roles : k => jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Action    = "sts:AssumeRoleWithWebIdentity"
        Principal = { Federated = local.provider_arn }
        Condition = {
          StringEquals = merge(
            {
              "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
              "token.actions.githubusercontent.com:sub" = "${var.subject_prefix}:${r.subject_suffix}"
            },
            r.job_workflow_ref == null ? {} : { "token.actions.githubusercontent.com:job_workflow_ref" = r.job_workflow_ref }
          )
        }
      }]
    })
  }
}

resource "aws_iam_role" "this" {
  for_each             = var.roles
  name                 = "${var.name_prefix}-github-${each.key}"
  description          = each.value.description
  assume_role_policy   = local.trust[each.key]
  max_session_duration = 3600
  permissions_boundary = each.value.attach_boundary ? var.permissions_boundary_arn : null
}

resource "aws_iam_role_policy" "this" {
  for_each = var.roles
  name     = "${var.name_prefix}-github-${each.key}"
  role     = aws_iam_role.this[each.key].id
  policy   = each.value.policy_json
}

resource "aws_iam_role_policy_attachment" "managed" {
  for_each   = { for pair in flatten([for k, r in var.roles : [for arn in r.managed_policy_arns : { key = "${k}|${arn}", role = k, arn = arn }]]) : pair.key => pair }
  role       = aws_iam_role.this[each.value.role].name
  policy_arn = each.value.arn
}
