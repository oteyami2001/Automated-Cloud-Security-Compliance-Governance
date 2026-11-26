mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555" }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/acscg-workload-boundary" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/acscg-mock" }
  }
}

variables {
  aws_account_id  = "111122223333"
  github_owner_id = "1234"
  github_repo_id  = "5678"
  alert_email     = "owner@example.com"
}

run "bootstrap_guardrails" {
  command = apply

  assert {
    condition     = aws_s3_bucket.state.bucket == "acscg-tfstate-111122223333-us-east-2"
    error_message = "state bucket name"
  }
  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "state must be KMS-encrypted"
  }
  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "state versioning"
  }
  assert {
    condition     = toset(keys(module.ci_roles.role_arns)) == toset(["dev-plan", "dev-apply", "dev-cleanup", "report"])
    error_message = "only dev roles plus the report role"
  }
  assert {
    condition     = jsondecode(module.ci_roles.trust_policies["dev-apply"]).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:oteyami2001@1234/Automated-Cloud-Security-Compliance-Governance@5678:environment:dev"
    error_message = "apply role trusts only the protected dev environment"
  }
  assert {
    condition     = [for s in jsondecode(output.ci_role_policies["dev-apply"]).Statement : s.Condition.StringEquals["iam:PermissionsBoundary"] if s.Sid == "CreateRolesOnlyWithBoundary"][0] == "arn:aws:iam::111122223333:policy/acscg-workload-boundary"
    error_message = "the apply role can only create roles with the workload boundary"
  }
  assert {
    condition     = !contains(flatten([for s in jsondecode(output.ci_role_policies["dev-apply"]).Statement : try(tolist(s.Action), [s.Action]) if s.Effect == "Allow"]), "s3:BypassGovernanceRetention")
    error_message = "only the cleanup role may bypass evidence retention"
  }
  assert {
    condition     = contains([for s in jsondecode(output.ci_role_policies["dev-cleanup"]).Statement : s.Sid], "EvidenceCleanup")
    error_message = "cleanup role needs evidence cleanup"
  }
  assert {
    condition = (contains([for s in jsondecode(output.ci_role_policies["dev-cleanup"]).Statement : s.Sid], "RemoveOwnConfigRecorder") &&
      !contains(flatten([for s in jsondecode(output.ci_role_policies["dev-apply"]).Statement : try(tolist(s.Action), [s.Action]) if s.Effect == "Allow"]), "config:DeleteConfigurationRecorder") &&
    [for s in jsondecode(output.ci_role_policies["dev-cleanup"]).Statement : s.Condition.StringEquals["aws:RequestedRegion"] if s.Sid == "RemoveOwnConfigRecorder"][0] == "us-east-2")
    error_message = "only the cleanup role may remove the project's recorder, and only in the approved Region (Phase 9)"
  }
  assert {
    condition     = alltrue([for k in ["dev-plan", "dev-apply", "dev-cleanup"] : contains([for s in jsondecode(output.ci_role_policies[k]).Statement : s.Sid if s.Effect == "Deny"], "NeverTouchOtherProjectsOrSharedIdentity")])
    error_message = "every CI role denies changes to other projects and the shared OIDC provider"
  }
  assert {
    condition     = contains([for s in jsondecode(aws_iam_policy.workload_boundary.policy).Statement : s.Sid if s.Effect == "Deny"], "NeverApproveOwnRemediation")
    error_message = "workload roles can never approve"
  }
  assert {
    condition     = length(module.ci_roles.oidc_provider_arn) > 0
    error_message = "OIDC provider looked up"
  }
  assert {
    condition     = alltrue([for k, p in output.ci_role_policies : length(p) <= 10240])
    error_message = "inline role policies must stay within the 10,240-character IAM limit"
  }
  assert {
    condition     = length(aws_iam_policy.workload_boundary.policy) <= 6144
    error_message = "managed policies are limited to 6,144 characters"
  }
  assert {
    condition = alltrue([for s in jsondecode(output.ci_role_policies["dev-plan"]).Statement :
    s.Resource == "arn:aws:s3:::acscg-tfstate-111122223333-us-east-2/*.tflock" if s.Effect == "Allow" && length(setintersection(try(tolist(s.Action), [s.Action]), ["s3:PutObject", "s3:DeleteObject"])) > 0])
    error_message = "the plan role may write only the state lock file"
  }
  assert {
    condition     = contains(flatten([for s in jsondecode(aws_iam_policy.workload_boundary.policy).Statement : s.Action if s.Sid == "ReadAndScopedRemediation"]), "s3:GetAccelerateConfiguration")
    error_message = "the Config recorder role needs the S3 configuration reads"
  }
  assert {
    condition     = [for st in jsondecode(output.ci_role_policies["dev-apply"]).Statement : st.Condition.StringEquals["aws:ResourceTag/Project"] if st.Sid == "FixtureSecurityGroupInProjectVpc"][0] == "acscg"
    error_message = "security groups may be created only inside project-tagged VPCs"
  }
  assert {
    condition     = [for st in jsondecode(output.ci_role_policies["dev-apply"]).Statement : st.Condition.StringEquals["aws:RequestTag/Project"] if st.Sid == "FixtureSecurityGroupRulesTagged"][0] == "acscg"
    error_message = "new security group rules must be tagged Project=acscg on creation"
  }
}

run "other_regions_rejected" {
  command = plan
  variables {
    region = "us-east-1"
  }
  expect_failures = [var.region]
}

run "prod_roles_only_when_requested" {
  command = apply
  variables {
    environments = ["dev", "prod"]
  }
  assert {
    condition     = contains(keys(module.ci_roles.role_arns), "prod-apply")
    error_message = "prod roles when requested"
  }
}
