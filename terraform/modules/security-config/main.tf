# AWS Config: rules for SEC-001…014 and, only in "create" mode, a recorder limited to the catalog's
# resource types (ADR 0003, ADR 0011). In "integrate" mode the existing recorder is never touched:
# this module then creates rules only.

data "aws_partition" "current" {}

locals {
  create      = var.ownership_mode == "create"
  periodic    = "TwentyFour_Hours"
  bucket_name = "${var.name_prefix}-config-${var.account_id}-${var.region}"

  # Managed rules. Identifiers are pending verification against the AWS Config managed rules list (Phase 4 gate).
  managed_rules = {
    "sec001-bucket-public-access"   = { control = "SEC-001", identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED", types = ["AWS::S3::Bucket"], params = {} }
    "sec001-account-public-access"  = { control = "SEC-001", identifier = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC", types = [], params = {} }
    "sec002-bucket-sse"             = { control = "SEC-002", identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED", types = ["AWS::S3::Bucket"], params = {} }
    "sec003-bucket-versioning"      = { control = "SEC-003", identifier = "S3_BUCKET_VERSIONING_ENABLED", types = ["AWS::S3::Bucket"], params = {} }
    "sec004-ssl-requests-only"      = { control = "SEC-004", identifier = "S3_BUCKET_SSL_REQUESTS_ONLY", types = ["AWS::S3::Bucket"], params = {} }
    "sec005-restricted-ssh"         = { control = "SEC-005", identifier = "INCOMING_SSH_DISABLED", types = ["AWS::EC2::SecurityGroup"], params = {} }
    "sec006-restricted-rdp"         = { control = "SEC-006", identifier = "RESTRICTED_INCOMING_TRAFFIC", types = ["AWS::EC2::SecurityGroup"], params = { blockedPort1 = "3389" } }
    "sec007-encrypted-volumes"      = { control = "SEC-007", identifier = "ENCRYPTED_VOLUMES", types = ["AWS::EC2::Volume"], params = {} }
    "sec007-ebs-default-encryption" = { control = "SEC-007", identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT", types = [], params = {} }
    "sec008-imdsv2"                 = { control = "SEC-008", identifier = "EC2_IMDSV2_CHECK", types = ["AWS::EC2::Instance"], params = {} }
    "sec009-console-mfa"            = { control = "SEC-009", identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS", types = [], params = {} }
    "sec010-no-admin-policies"      = { control = "SEC-010", identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS", types = ["AWS::IAM::Policy"], params = {} }
    "sec011-access-keys-rotated"    = { control = "SEC-011", identifier = "ACCESS_KEYS_ROTATED", types = [], params = { maxAccessKeyAge = "90" } }
    "sec011-unused-credentials"     = { control = "SEC-011", identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK", types = [], params = { maxCredentialUsageAge = "45" } }
    "sec012-cloudtrail-enabled"     = { control = "SEC-012", identifier = "CLOUD_TRAIL_ENABLED", types = [], params = {} }
    "sec012-log-file-validation"    = { control = "SEC-012", identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED", types = [], params = {} }
    "sec013-required-tags" = {
      control    = "SEC-013"
      identifier = "REQUIRED_TAGS"
      types      = ["AWS::S3::Bucket", "AWS::EC2::SecurityGroup", "AWS::EC2::Volume", "AWS::EC2::Instance", "AWS::DynamoDB::Table"] # REQUIRED_TAGS does not support Lambda
      params     = { tag1Key = "Project", tag2Key = "Environment", tag3Key = "Owner", tag4Key = "ManagedBy", tag5Key = "DataClassification" }
    }
    # Periodic rule (no scope). It treats "Never expire" as COMPLIANT; the custom sec014-retention-set rule covers that.
    "sec014-log-retention" = { control = "SEC-014", identifier = "CW_LOGGROUP_RETENTION_PERIOD_CHECK", types = [], params = { MinRetentionTime = tostring(var.min_log_retention_days) } }
  }

  enabled_managed = { for k, r in local.managed_rules : k => r if contains(var.enabled_controls, r.control) }

  custom_rules = !var.enable_custom_rules ? {} : {
    "sec005-admin-port-custom" = { control = "SEC-005", types = ["AWS::EC2::SecurityGroup"], params = { check = "open_admin_port", controlId = "SEC-005" } }
    "sec006-admin-port-custom" = { control = "SEC-006", types = ["AWS::EC2::SecurityGroup"], params = { check = "open_admin_port", controlId = "SEC-006" } }
    # Periodic: Config records no log groups here (evidence P4-14); the evaluator lists them itself.
    "sec014-retention-set" = { control = "SEC-014", types = [], params = { check = "log_retention_set", minRetentionDays = tostring(var.min_log_retention_days) } }
  }
  enabled_custom = { for k, r in local.custom_rules : k => r if contains(var.enabled_controls, r.control) }
}

# ------------------------------------------------------------------ recorder (create mode only)

data "aws_iam_policy_document" "config_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "recorder" {
  count                = local.create ? 1 : 0
  name                 = "${var.name_prefix}-config-recorder"
  assume_role_policy   = data.aws_iam_policy_document.config_trust.json
  permissions_boundary = var.permissions_boundary_arn
}

resource "aws_iam_role_policy_attachment" "recorder" {
  count      = local.create ? 1 : 0
  role       = aws_iam_role.recorder[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "recorder_delivery" {
  count = local.create ? 1 : 0
  name  = "delivery"
  role  = aws_iam_role.recorder[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectAcl"]
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}/AWSLogs/${var.account_id}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = var.kms_key_arn
      },
    ]
  })
}

#trivy:ignore:AVD-AWS-0089 Config history bucket: access logging would need another bucket; delivery is by the Config service role only.
resource "aws_s3_bucket" "delivery" {
  # checkov:skip=CKV_AWS_18:Access logging would need a further bucket; only the Config service role writes here.
  # checkov:skip=CKV_AWS_144:Cross-Region replication is SCP-denied in the target account (ADR 0002).
  # checkov:skip=CKV2_AWS_62:Event notifications are not needed for Config history files.
  count         = local.create ? 1 : 0
  bucket        = local.bucket_name
  force_destroy = var.force_destroy_delivery_bucket
}

resource "aws_s3_bucket_public_access_block" "delivery" {
  count                   = local.create ? 1 : 0
  bucket                  = aws_s3_bucket.delivery[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "delivery" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.delivery[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "delivery" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.delivery[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "delivery" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.delivery[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "delivery" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.delivery[0].id
  rule {
    id     = "expire-history"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "delivery" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.delivery[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.delivery[0].arn, "${aws_s3_bucket.delivery[0].arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_config_configuration_recorder" "this" {
  # checkov:skip=CKV2_AWS_48:Recording only the catalog's resource types is a deliberate cost decision (ADR 0011).
  count    = local.create ? 1 : 0
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.recorder[0].arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = var.recorded_resource_types
    recording_strategy {
      use_only = "INCLUSION_BY_RESOURCE_TYPES"
    }
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = local.create ? 1 : 0
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.delivery[0].bucket
  s3_kms_key_arn = var.kms_key_arn
  depends_on     = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.delivery]
}

resource "aws_config_configuration_recorder_status" "this" {
  # checkov:skip=CKV2_AWS_45:Recording only the catalog's resource types is a deliberate cost decision (ADR 0011); create mode is used only if no recorder exists.
  count      = local.create ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

# ------------------------------------------------------------------ rules (both modes)

resource "aws_config_config_rule" "managed" {
  for_each = local.enabled_managed
  name     = "acscg-${each.key}"

  source {
    owner             = "AWS"
    source_identifier = each.value.identifier
  }

  input_parameters            = length(each.value.params) > 0 ? jsonencode(each.value.params) : null
  maximum_execution_frequency = length(each.value.types) == 0 ? local.periodic : null

  dynamic "scope" {
    for_each = length(each.value.types) > 0 ? [1] : []
    content {
      compliance_resource_types = each.value.types
    }
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

#trivy:ignore:AVD-AWS-0067 Config rule ARNs contain a random ID only known after creation; the permission is scoped with source_account as AWS documents for custom Config rules.
resource "aws_lambda_permission" "config" {
  count          = length(local.enabled_custom) > 0 ? 1 : 0
  statement_id   = "AllowConfigRules"
  action         = "lambda:InvokeFunction"
  function_name  = var.custom_rule_lambda_arn
  principal      = "config.amazonaws.com"
  source_account = var.account_id
}

resource "aws_config_config_rule" "custom" {
  for_each = local.enabled_custom
  name     = "acscg-${each.key}"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = var.custom_rule_lambda_arn
    source_detail {
      message_type                = length(each.value.types) > 0 ? "ConfigurationItemChangeNotification" : "ScheduledNotification"
      maximum_execution_frequency = length(each.value.types) > 0 ? null : "TwentyFour_Hours"
    }
  }

  input_parameters = jsonencode(each.value.params)

  dynamic "scope" {
    for_each = length(each.value.types) > 0 ? [each.value.types] : []
    content {
      compliance_resource_types = scope.value
    }
  }

  depends_on = [aws_lambda_permission.config, aws_config_configuration_recorder_status.this]
}
