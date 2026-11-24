# CloudTrail (ADR 0005). integrate (default): the existing trail is referenced by name and never
# managed; scripts/verify_bootstrap.sh checks it is logging. create: only after explicit approval
# (a second management-event trail is billed at USD 2.00 per 100,000 events).

data "aws_partition" "current" {}

locals {
  create      = var.mode == "create"
  trail_name  = local.create ? "${var.name_prefix}-management-events" : var.existing_trail_name
  bucket_name = "${var.name_prefix}-trail-${var.account_id}-${var.region}"
  trail_arn   = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${var.account_id}:trail/${local.trail_name}"
}

#trivy:ignore:AVD-AWS-0089 Access logging of the audit bucket would need another bucket; the trail records its API calls.
resource "aws_s3_bucket" "trail" {
  # checkov:skip=CKV_AWS_18:Access logging would need a further bucket; the trail records management calls on this bucket.
  # checkov:skip=CKV_AWS_144:Cross-Region replication is SCP-denied in the target account (ADR 0002).
  # checkov:skip=CKV2_AWS_62:Event notifications are not needed for an audit bucket.
  count  = local.create ? 1 : 0
  bucket = local.bucket_name
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count                   = local.create ? 1 : 0
  bucket                  = aws_s3_bucket.trail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  rule {
    # SSE-S3 unless a key whose policy grants CloudTrail is supplied (the project key does not).
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  rule {
    id     = "retention"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  count  = local.create ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail[0].arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "Write"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail[0].arn}/AWSLogs/${var.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control", "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.trail[0].arn, "${aws_s3_bucket.trail[0].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

resource "aws_cloudtrail" "this" {
  # checkov:skip=CKV_AWS_67:Multi-Region trails cannot deliver from the SCP-denied Region; single Region by design (ADR 0002).
  # checkov:skip=CKV2_AWS_10:CloudWatch Logs integration is not needed; EventBridge receives the events directly (ADR 0004).
  # checkov:skip=CKV_AWS_252:SNS notifications for log delivery are not needed.
  # checkov:skip=CKV_AWS_35:Create mode is a fallback that needs separate approval; a CloudTrail-enabled key policy is added then (SSE-S3 meanwhile).
  count                         = local.create ? 1 : 0
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  is_multi_region_trail         = false
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_key_arn
  depends_on                    = [aws_s3_bucket_policy.trail]
}
