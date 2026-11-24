# Remote state: KMS-encrypted, versioned, TLS-only bucket with native S3 locking (use_lockfile).

data "aws_partition" "current" {}

locals {
  p            = data.aws_partition.current.partition
  arn          = "arn:${local.p}"
  state_bucket = "acscg-tfstate-${var.aws_account_id}-${var.region}"
  state_arn    = "${local.arn}:s3:::${local.state_bucket}"
}

resource "aws_kms_key" "state" {
  description             = "acscg Terraform state"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = "${local.arn}:iam::${var.aws_account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_kms_alias" "state" {
  name          = "alias/acscg-tfstate"
  target_key_id = aws_kms_key.state.key_id
}

#trivy:ignore:AVD-AWS-0089 State bucket access logging would need another bucket; CloudTrail records the API calls.
resource "aws_s3_bucket" "state" {
  # checkov:skip=CKV_AWS_18:Access logging would need a further bucket; CloudTrail records state access.
  # checkov:skip=CKV_AWS_144:Cross-Region replication is SCP-denied in the target account (ADR 0002); versioning protects history.
  # checkov:skip=CKV2_AWS_62:Event notifications are not needed for a state bucket.
  bucket = local.state_bucket

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "noncurrent"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  depends_on = [aws_s3_bucket_versioning.state]
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = [local.state_arn, "${local.state_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyStateWritesWithoutStateKey"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:PutObject"
        Resource  = "${local.state_arn}/*.tfstate"
        Condition = { StringNotEqualsIfExists = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.state.arn } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.state]
}
