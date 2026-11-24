# Permissions boundary for every workload role the stack creates (Lambda, runbook execution,
# Config recorder). It allows only the services the platform uses and explicitly denies the
# changes the platform must never make (docs/security-model.md §2 and §6).

locals {
  project_resource_patterns = [
    "${local.arn}:s3:::acscg-*",
    "${local.arn}:s3:::acscg-*/*",
    "${local.arn}:dynamodb:${var.region}:${var.aws_account_id}:table/acscg-*",
    "${local.arn}:sqs:${var.region}:${var.aws_account_id}:acscg-*",
    "${local.arn}:sns:${var.region}:${var.aws_account_id}:acscg-*",
    "${local.arn}:logs:${var.region}:${var.aws_account_id}:log-group:*acscg*",
    "${local.arn}:ssm:${var.region}:${var.aws_account_id}:parameter/acscg/*",
    "${local.arn}:lambda:${var.region}:${var.aws_account_id}:function:acscg-*",
  ]
  boundary_name = "acscg-workload-boundary"
  protected_role_patterns = [
    "${local.arn}:iam::${var.aws_account_id}:role/aiops-*",
    "${local.arn}:iam::${var.aws_account_id}:role/idp-*",
  ]
}

resource "aws_iam_policy" "workload_boundary" {
  # checkov:skip=CKV_AWS_290:A boundary is a ceiling, not a grant; writes are limited to acscg-* data resources and each role policy scopes ARNs (tested).
  # checkov:skip=CKV_AWS_288:Object reads are limited to acscg-* buckets; the remaining '*' statement is metadata reads and scoped remediation actions.
  # checkov:skip=CKV_AWS_289:iam:PassRole is denied outside role/acscg-* and all IAM writes are explicitly denied in this boundary.
  # checkov:skip=CKV_AWS_355:Describe/List/tagging APIs lack resource-level permissions; role policies narrow every change action to allowlisted ARNs.
  name        = local.boundary_name
  description = "ACSCG workload permissions boundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ProjectDataOnly"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:GetBucket*", "s3:PutBucketPublicAccessBlock", "s3:PutBucketTagging", "s3:ListBucket", "dynamodb:*", "sqs:SendMessage", "sns:Publish", "logs:CreateLogStream", "logs:PutLogEvents", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:TagResource", "logs:UntagResource", "ssm:GetParameter", "lambda:InvokeFunction"]
        Resource = local.project_resource_patterns
      },
      {
        Sid      = "ProjectKeysOnly"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:ResourceTag/Project" = "acscg" }
        }
      },
      {
        Sid      = "ReadAndScopedRemediation"
        Effect   = "Allow"
        Action   = ["ssm:GetAutomationExecution", "ssm:StartAutomationExecution", "ssm:AddTagsToResource", "config:*", "ec2:Describe*", "ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress", "ec2:ModifyInstanceMetadataOptions", "ec2:CreateTags", "ec2:DeleteTags", "tag:*", "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*", "iam:Get*", "iam:List*", "iam:PassRole", "lambda:Get*", "lambda:List*", "logs:Describe*", "s3:GetAccountPublicAccessBlock", "s3:GetBucket*", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:ListAllMyBuckets", "dynamodb:Describe*", "dynamodb:ListTables", "xray:PutTraceSegments", "xray:PutTelemetryRecords", "sts:GetCallerIdentity"]
        Resource = "*" # the boundary is a ceiling: each role policy scopes these to exact ARNs (tested)
      },
      {
        Sid      = "NoIamWrites"
        Effect   = "Deny"
        Action   = ["iam:Create*", "iam:Delete*", "iam:Put*", "iam:Attach*", "iam:Detach*", "iam:Update*", "iam:Add*", "iam:Remove*", "iam:Set*", "iam:Tag*", "iam:Untag*"]
        Resource = "*"
      },
      {
        Sid         = "PassOnlyProjectRoles"
        Effect      = "Deny"
        Action      = "iam:PassRole"
        NotResource = "${local.arn}:iam::${var.aws_account_id}:role/acscg-*"
      },
      {
        Sid      = "NoOrganizationOrAccountChanges"
        Effect   = "Deny"
        Action   = ["organizations:*", "account:*"]
        Resource = "*"
      },
      {
        Sid      = "NeverDisableAuditServices"
        Effect   = "Deny"
        Action   = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors", "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder", "config:DeleteDeliveryChannel", "securityhub:Disable*", "guardduty:DeleteDetector", "guardduty:UpdateDetector"]
        Resource = "*"
      },
      {
        Sid      = "NeverTouchKeysLifecycle"
        Effect   = "Deny"
        Action   = ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy", "kms:CreateGrant"]
        Resource = "*"
      },
      {
        Sid      = "NeverTamperWithEvidence"
        Effect   = "Deny"
        Action   = ["s3:DeleteObject*", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration", "s3:PutBucketPolicy", "s3:DeleteBucket*"]
        Resource = ["${local.arn}:s3:::acscg-*-evidence-*", "${local.arn}:s3:::acscg-*-evidence-*/*"]
      },
      {
        Sid      = "NoAccountWideSettings"
        Effect   = "Deny"
        Action   = ["ec2:ModifyVpcAttribute", "ec2:*NetworkAcl*", "ec2:EnableEbsEncryptionByDefault", "ec2:DisableEbsEncryptionByDefault", "ec2:ModifyEbsDefaultKmsKeyId", "s3:PutAccountPublicAccessBlock"]
        Resource = "*"
      },
      {
        Sid      = "NeverApproveOwnRemediation"
        Effect   = "Deny"
        Action   = "ssm:SendAutomationSignal"
        Resource = "*"
      },
      {
        Sid      = "OtherProjectsUntouched"
        Effect   = "Deny"
        Action   = ["s3:Put*", "s3:Delete*"]
        Resource = ["${local.arn}:s3:::aiops-*", "${local.arn}:s3:::idp-*", "${local.arn}:s3:::aiops-*/*", "${local.arn}:s3:::idp-*/*"]
      },
      {
        Sid       = "StayInApprovedRegion"
        Effect    = "Deny"
        NotAction = ["iam:*", "sts:*", "organizations:*", "support:*", "budgets:*", "tag:*"]
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = [var.region] } }
      },
    ]
  })
}
