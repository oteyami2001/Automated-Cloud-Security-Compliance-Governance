# Evidence store (ADR 0007): project CMK + S3 bucket with versioning, Object Lock (governance),
# SSE-KMS, TLS-only and KMS-only writes, deletes denied to everyone except the cleanup role.
# Evidence is tamper-evident (checksums + Object Lock governance), not tamper-proof.

data "aws_partition" "current" {}

locals {
  bucket_name   = "${var.name_prefix}-evidence-${var.account_id}-${var.region}"
  bucket_arn    = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}"
  root_arn      = "arn:${data.aws_partition.current.partition}:iam::${var.account_id}:root"
  log_group_arn = "arn:${data.aws_partition.current.partition}:logs:${var.region}:${var.account_id}:log-group:*${var.name_prefix}*"
  # Project log groups outside /aws/lambda live under /<project>/<env>/ (e.g. /acscg/dev/fixture).
  log_group_path_arn = "arn:${data.aws_partition.current.partition}:logs:${var.region}:${var.account_id}:log-group:/${replace(var.name_prefix, "-", "/")}/*"
}

data "aws_iam_policy_document" "key" {
  # checkov:skip=CKV_AWS_111:KMS key policies use Resource '*' to mean this key; the root statement is the AWS default administration statement.
  # checkov:skip=CKV_AWS_356:KMS key policies use Resource '*' to mean this key (not all resources).
  # checkov:skip=CKV_AWS_109:Key administration stays with the account root (IAM decides); service statements are scoped by source account and log-group ARN.
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  statement {
    sid       = "CloudWatchLogsForProjectLogGroups"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = [local.log_group_arn, local.log_group_path_arn]
    }
  }

  statement {
    sid       = "CloudWatchAlarmsToEncryptedTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name_prefix} evidence, findings, notifications and logs"
  enable_key_rotation     = true
  deletion_window_in_days = var.key_deletion_window_days
  policy                  = data.aws_iam_policy_document.key.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.this.key_id
}

#trivy:ignore:AVD-AWS-0089 Access logging of the evidence bucket would need another bucket; object-level API activity is attributable through CloudTrail and checksums detect modification.
resource "aws_s3_bucket" "evidence" {
  # checkov:skip=CKV_AWS_18:Server access logging needs a further log bucket; integrity is provided by Object Lock, versioning and SHA-256 manifests (ADR 0007).
  # checkov:skip=CKV_AWS_144:Cross-Region replication is not possible: the other US Region is denied by an SCP in the target account (ADR 0002).
  # checkov:skip=CKV2_AWS_62:Event notifications are not needed; evidence writers are the platform's own Lambdas.
  bucket              = local.bucket_name
  object_lock_enabled = true
  force_destroy       = false
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "retention"
    status = "Enabled"
    filter {}
    expiration {
      days = var.object_lock_days + 30
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

# Rendered with jsonencode so tests can assert every deny statement.
locals {
  any_principal = { AWS = "*" }
  bucket_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "DenyInsecureTransport"
          Effect    = "Deny"
          Principal = local.any_principal
          Action    = "s3:*"
          Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
          Condition = { Bool = { "aws:SecureTransport" = "false" } }
        },
        {
          Sid       = "DenyNonKmsEncryption"
          Effect    = "Deny"
          Principal = local.any_principal
          Action    = "s3:PutObject"
          Resource  = "${local.bucket_arn}/*"
          Condition = { StringNotEqualsIfExists = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
        },
        {
          Sid       = "DenyWritesWithoutProjectKey"
          Effect    = "Deny"
          Principal = local.any_principal
          Action    = "s3:PutObject"
          Resource  = "${local.bucket_arn}/*"
          Condition = { StringNotEqualsIfExists = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.this.arn } }
        },
        {
          Sid       = "DenyEvidenceDeletionExceptCleanup"
          Effect    = "Deny"
          Principal = local.any_principal
          Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold"]
          Resource  = "${local.bucket_arn}/*"
          Condition = { StringNotEquals = { "aws:PrincipalArn" = compact([var.cleanup_role_arn]) } }
        },
        {
          Sid       = "DenyLockTamperingExceptAdmins"
          Effect    = "Deny"
          Principal = local.any_principal
          Action    = ["s3:PutBucketObjectLockConfiguration", "s3:DeleteBucket"]
          Resource  = local.bucket_arn
          Condition = { StringNotEquals = { "aws:PrincipalArn" = compact(concat([var.cleanup_role_arn], var.admin_role_arns)) } }
        },
      ],
      length(var.writer_role_arns) == 0 ? [] : [{
        Sid       = "DenyWritesFromOtherPrincipals"
        Effect    = "Deny"
        Principal = local.any_principal
        Action    = "s3:PutObject"
        Resource  = "${local.bucket_arn}/*"
        Condition = { StringNotEquals = { "aws:PrincipalArn" = var.writer_role_arns } }
      }]
    )
  })
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  policy     = local.bucket_policy
  depends_on = [aws_s3_bucket_public_access_block.evidence]
}
