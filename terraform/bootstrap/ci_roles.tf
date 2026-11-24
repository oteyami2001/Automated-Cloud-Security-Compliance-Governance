# GitHub Actions roles (OIDC, immutable-ID subjects). One plan/apply/cleanup set per environment
# plus a main-branch report role. Policies are scoped to acscg-* names; IAM role creation requires
# the workload boundary. Statements that need tightening after discovery are marked "Phase 3".

locals {
  subject_prefix = "repo:${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}"
  boundary_arn   = aws_iam_policy.workload_boundary.arn
  a              = var.aws_account_id
  r              = var.region

  state_access = [
    { Sid = "StateList", Effect = "Allow", Action = "s3:ListBucket", Resource = local.state_arn },
    { Sid = "StateObjects", Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = "${local.state_arn}/*" },
    { Sid = "StateKey", Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.state.arn },
  ]

  deny_guardrails = [
    {
      Sid      = "NeverTouchOtherProjectsOrSharedIdentity"
      Effect   = "Deny"
      Action   = ["iam:*"]
      Resource = concat(local.protected_role_patterns, ["${local.arn}:iam::${local.a}:oidc-provider/*"])
    },
    {
      Sid      = "NeverTouchOtherProjectBuckets"
      Effect   = "Deny"
      Action   = ["s3:Delete*", "s3:Put*"]
      Resource = ["${local.arn}:s3:::aiops-*", "${local.arn}:s3:::idp-*", "${local.arn}:s3:::aiops-*/*", "${local.arn}:s3:::idp-*/*"]
    },
    {
      Sid         = "NeverStopForeignTrails"
      Effect      = "Deny"
      Action      = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"]
      NotResource = "${local.arn}:cloudtrail:${local.r}:${local.a}:trail/acscg-*"
    },
    { Sid = "NoOrganizationChanges", Effect = "Deny", Action = ["organizations:*", "account:*"], Resource = "*" },
    { Sid = "NeverApprove", Effect = "Deny", Action = "ssm:SendAutomationSignal", Resource = "*" },
  ]

  project_write = [
    { Sid = "Lambda", Effect = "Allow", Action = "lambda:*", Resource = "${local.arn}:lambda:${local.r}:${local.a}:function:acscg-*" },
    { Sid = "LambdaRead", Effect = "Allow", Action = ["lambda:List*", "lambda:GetAccountSettings"], Resource = "*" },
    { Sid = "DynamoDB", Effect = "Allow", Action = "dynamodb:*", Resource = ["${local.arn}:dynamodb:${local.r}:${local.a}:table/acscg-*"] },
    { Sid = "Queues", Effect = "Allow", Action = "sqs:*", Resource = "${local.arn}:sqs:${local.r}:${local.a}:acscg-*" },
    { Sid = "Topics", Effect = "Allow", Action = "sns:*", Resource = "${local.arn}:sns:${local.r}:${local.a}:acscg-*" },
    { Sid = "Buckets", Effect = "Allow", Action = "s3:*", Resource = ["${local.arn}:s3:::acscg-*", "${local.arn}:s3:::acscg-*/*"] },
    { Sid = "Logs", Effect = "Allow", Action = "logs:*", Resource = ["${local.arn}:logs:${local.r}:${local.a}:log-group:/aws/lambda/acscg-*", "${local.arn}:logs:${local.r}:${local.a}:log-group:/aws/lambda/acscg-*:*", "${local.arn}:logs:${local.r}:${local.a}:log-group:/acscg/*"] },
    { Sid = "LogsRead", Effect = "Allow", Action = ["logs:Describe*", "logs:ListTagsForResource"], Resource = "*" },
    { Sid = "Events", Effect = "Allow", Action = "events:*", Resource = "${local.arn}:events:${local.r}:${local.a}:rule/acscg-*" },
    { Sid = "SsmProject", Effect = "Allow", Action = "ssm:*", Resource = ["${local.arn}:ssm:${local.r}:${local.a}:document/acscg-*", "${local.arn}:ssm:${local.r}:${local.a}:parameter/acscg/*"] },
    { Sid = "SsmRead", Effect = "Allow", Action = ["ssm:Describe*", "ssm:List*"], Resource = "*" },
    { Sid = "Alarms", Effect = "Allow", Action = ["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:TagResource", "cloudwatch:UntagResource", "cloudwatch:ListTagsForResource"], Resource = "${local.arn}:cloudwatch:${local.r}:${local.a}:alarm:acscg-*" },
    { Sid = "Dashboards", Effect = "Allow", Action = ["cloudwatch:PutDashboard", "cloudwatch:DeleteDashboards", "cloudwatch:GetDashboard"], Resource = "${local.arn}:cloudwatch::${local.a}:dashboard/acscg-*" },
    { Sid = "CloudWatchRead", Effect = "Allow", Action = ["cloudwatch:Describe*", "cloudwatch:List*", "logs:PutMetricFilter", "logs:DeleteMetricFilter"], Resource = "*" },
    # Phase 3: narrow once discovery shows whether a recorder exists (integrate mode needs rules only).
    { Sid = "ConfigRules", Effect = "Allow", Action = ["config:PutConfigRule", "config:DeleteConfigRule", "config:Describe*", "config:Get*", "config:List*", "config:TagResource", "config:UntagResource", "config:PutConfigurationRecorder", "config:PutDeliveryChannel", "config:StartConfigurationRecorder"], Resource = "*" },
    { Sid = "KmsCreateTagged", Effect = "Allow", Action = ["kms:CreateKey", "kms:TagResource"], Resource = "*", Condition = { StringEquals = { "aws:RequestTag/Project" = "acscg" } } },
    { Sid = "KmsProjectKeys", Effect = "Allow", Action = ["kms:*"], Resource = "*", Condition = { StringEquals = { "aws:ResourceTag/Project" = "acscg" } } },
    { Sid = "KmsAliases", Effect = "Allow", Action = ["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"], Resource = ["${local.arn}:kms:${local.r}:${local.a}:alias/acscg-*", "${local.arn}:kms:${local.r}:${local.a}:key/*"] },
    { Sid = "KmsRead", Effect = "Allow", Action = ["kms:List*", "kms:DescribeKey"], Resource = "*" },
    {
      Sid       = "CreateRolesOnlyWithBoundary"
      Effect    = "Allow"
      Action    = ["iam:CreateRole", "iam:PutRolePermissionsBoundary"]
      Resource  = "${local.arn}:iam::${local.a}:role/acscg-*"
      Condition = { StringEquals = { "iam:PermissionsBoundary" = local.boundary_arn } }
    },
    { Sid = "ManageProjectRoles", Effect = "Allow", Action = ["iam:GetRole", "iam:DeleteRole", "iam:TagRole", "iam:UntagRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole"], Resource = "${local.arn}:iam::${local.a}:role/acscg-*" },
    {
      Sid       = "AttachOnlyConfigServicePolicy"
      Effect    = "Allow"
      Action    = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
      Resource  = "${local.arn}:iam::${local.a}:role/acscg-*"
      Condition = { ArnEquals = { "iam:PolicyARN" = "${local.arn}:iam::aws:policy/service-role/AWS_ConfigRole" } }
    },
    {
      Sid       = "PassProjectRoles"
      Effect    = "Allow"
      Action    = "iam:PassRole"
      Resource  = "${local.arn}:iam::${local.a}:role/acscg-*"
      Condition = { StringEquals = { "iam:PassedToService" = ["lambda.amazonaws.com", "ssm.amazonaws.com", "config.amazonaws.com"] } }
    },
    { Sid = "IamRead", Effect = "Allow", Action = ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetOpenIDConnectProvider", "iam:ListOpenIDConnectProviders"], Resource = "*" },
    { Sid = "FixtureNetwork", Effect = "Allow", Action = ["ec2:CreateVpc", "ec2:CreateSecurityGroup", "ec2:CreateTags"], Resource = "*", Condition = { StringEquals = { "aws:RequestTag/Project" = "acscg" } } },
    { Sid = "FixtureNetworkManage", Effect = "Allow", Action = ["ec2:DeleteVpc", "ec2:DeleteSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress", "ec2:ModifySecurityGroupRules", "ec2:ModifyVpcAttribute", "ec2:DeleteTags"], Resource = "*", Condition = { StringEquals = { "aws:ResourceTag/Project" = "acscg" } } },
    { Sid = "Ec2Read", Effect = "Allow", Action = ["ec2:Describe*"], Resource = "*" },
    # Security Hub, GuardDuty and Access Analyzer are not granted: an SCP denies them in the target
    # account (discovery 2026-11-24). Add them here only for an account where they are allowed.
    { Sid = "Identity", Effect = "Allow", Action = "sts:GetCallerIdentity", Resource = "*" },
  ]

  plan_policy = {
    Version = "2012-10-17"
    Statement = concat(local.state_access, local.deny_guardrails, [
      { Sid = "DecryptProjectSecureStrings", Effect = "Allow", Action = "kms:Decrypt", Resource = "*", Condition = { StringEquals = { "aws:ResourceTag/Project" = "acscg" } } },
      { Sid = "ReadProjectParameters", Effect = "Allow", Action = ["ssm:GetParameter", "ssm:GetParameters"], Resource = "${local.arn}:ssm:${local.r}:${local.a}:parameter/acscg/*" },
    ])
  }

  apply_policy = { Version = "2012-10-17", Statement = concat(local.state_access, local.project_write, local.deny_guardrails) }

  cleanup_policy = {
    Version = "2012-10-17"
    Statement = concat(local.state_access, local.project_write, local.deny_guardrails, [
      { Sid = "EvidenceCleanup", Effect = "Allow", Action = ["s3:BypassGovernanceRetention", "s3:DeleteObjectVersion", "s3:ListBucketVersions"], Resource = ["${local.arn}:s3:::acscg-*-evidence-*", "${local.arn}:s3:::acscg-*-evidence-*/*"] },
    ])
  }

  report_policy = {
    Version = "2012-10-17"
    Statement = [
      { Sid = "InvokeReport", Effect = "Allow", Action = "lambda:InvokeFunction", Resource = "${local.arn}:lambda:${local.r}:${local.a}:function:acscg-*-report-generator" },
      { Sid = "ReadReports", Effect = "Allow", Action = "s3:GetObject", Resource = "${local.arn}:s3:::acscg-*-evidence-*/reports/*" },
      { Sid = "DecryptReports", Effect = "Allow", Action = "kms:Decrypt", Resource = "*", Condition = { StringEquals = { "aws:ResourceTag/Project" = "acscg" } } },
    ]
  }

  ci_roles = merge(
    { for e in var.environments : "${e}-plan" => {
      description         = "ACSCG ${e} terraform plan and drift detection (read-only)"
      subject_suffix      = "environment:${e}-plan"
      policy_json         = jsonencode(local.plan_policy)
      managed_policy_arns = ["${local.arn}:iam::aws:policy/ReadOnlyAccess"]
      attach_boundary     = false
    } },
    { for e in var.environments : "${e}-apply" => {
      description     = "ACSCG ${e} apply of the reviewed plan"
      subject_suffix  = "environment:${e}"
      policy_json     = jsonencode(local.apply_policy)
      attach_boundary = false
    } },
    { for e in var.environments : "${e}-cleanup" => {
      description     = "ACSCG ${e} approved, verified cleanup"
      subject_suffix  = "environment:${e}-cleanup"
      policy_json     = jsonencode(local.cleanup_policy)
      attach_boundary = false
    } },
    {
      report = {
        description      = "ACSCG compliance report (main branch, report workflow only)"
        subject_suffix   = "ref:refs/heads/main"
        policy_json      = jsonencode(local.report_policy)
        job_workflow_ref = "${var.github_owner}/${var.github_repo}/.github/workflows/compliance-report.yml@refs/heads/main"
        attach_boundary  = false
      }
    },
  )
}

module "ci_roles" {
  source               = "../modules/iam-oidc"
  name_prefix          = "acscg"
  create_oidc_provider = var.create_oidc_provider
  subject_prefix       = local.subject_prefix
  roles                = local.ci_roles
}

module "budget" {
  source      = "../modules/budgets"
  name        = "acscg"
  limit_usd   = var.budget_limit_usd
  alert_email = var.alert_email
}
