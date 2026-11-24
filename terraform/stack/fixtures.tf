# Isolated test fixtures for the validation scenarios (docs/validation-scenarios.md). Off by
# default. Violations are separate flags, each off by default and reviewed in a plan before apply.
# Nothing here is reachable from the internet: the VPC has no internet gateway, the security group
# is attached to nothing, and the bucket is empty with ACLs disabled and a Deny-only bucket policy.
# (The account has no account-level S3 public access block, discovery D13, so it is not relied on.)

locals {
  fixtures = var.enable_test_fixtures ? 1 : 0
  fixture_arns = var.enable_test_fixtures ? concat([
    aws_security_group.fixture[0].arn,
    "${local.arn}:s3:::${local.name_prefix}-fixture-${var.aws_account_id}-${var.region}",
    "${local.arn}:logs:${var.region}:${var.aws_account_id}:log-group:/acscg/${var.environment}/fixture",
  ], aws_security_group.fixture_untagged[*].arn) : []
}

resource "aws_vpc" "fixture" {
  # checkov:skip=CKV2_AWS_11:Flow logs are not needed: the fixture VPC has no internet gateway, no subnets and no ENIs.
  count                = local.fixtures
  cidr_block           = "10.99.0.0/24"
  enable_dns_support   = false
  enable_dns_hostnames = false
  tags                 = { Name = "${local.name_prefix}-fixture" }
}

resource "aws_default_security_group" "fixture" {
  count  = local.fixtures
  vpc_id = aws_vpc.fixture[0].id
  # No rules: the default group of the fixture VPC denies everything (CIS 5.5 / 6.5).
}

resource "aws_security_group" "fixture" {
  # checkov:skip=CKV2_AWS_5:The fixture group is deliberately attached to nothing (validation scenarios 2 and 9-11; docs/validation-scenarios.md).
  count       = local.fixtures
  name        = "${local.name_prefix}-fixture-sg"
  description = "ACSCG test fixture: never attached to any network interface"
  vpc_id      = aws_vpc.fixture[0].id
  tags        = { Name = "${local.name_prefix}-fixture-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "fixture_open_ssh" {
  # checkov:skip=CKV_AWS_24:Deliberate, isolated violation for validation scenario 2 (unattached group, VPC without internet gateway, flag off by default).
  # checkov:skip=CKV_AWS_260:Same deliberate scenario fixture; see above.
  count             = var.enable_test_fixtures && var.fixture_open_ssh ? 1 : 0
  security_group_id = aws_security_group.fixture[0].id
  description       = "ACSCG scenario 2 fixture (deliberate violation)"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

#trivy:ignore:AVD-AWS-0089 Empty fixture bucket; access logging adds nothing.
resource "aws_s3_bucket" "fixture" {
  # checkov:skip=CKV_AWS_18:Empty test fixture; access logging adds nothing.
  # checkov:skip=CKV_AWS_144:Empty test fixture; replication is not applicable.
  # checkov:skip=CKV2_AWS_62:Empty test fixture; no notifications needed.
  # checkov:skip=CKV_AWS_21:Versioning is intentionally left to SEC-003 detection on this empty fixture.
  # checkov:skip=CKV2_AWS_61:Empty fixture; no lifecycle needed.
  # checkov:skip=CKV2_AWS_6:A public access block exists (aws_s3_bucket_public_access_block.fixture); Checkov cannot link count-based blocks.
  count         = local.fixtures
  bucket        = "${local.name_prefix}-fixture-${var.aws_account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "fixture" {
  # ACLs disabled: with no account-level public access block in this account (discovery D13), the
  # fixture's safety rests on no ACLs, an empty bucket and a Terraform-managed Deny-only policy.
  count  = local.fixtures
  bucket = aws_s3_bucket.fixture[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "fixture" {
  # checkov:skip=CKV_AWS_53:Scenario 4 can disable ONE setting on the empty fixture; ACLs are disabled and the only bucket policy is a Terraform-managed Deny.
  # checkov:skip=CKV_AWS_54:Scenario 4 fixture, see above.
  # checkov:skip=CKV_AWS_55:Scenario 4 fixture, see above.
  # checkov:skip=CKV_AWS_56:Scenario 4 fixture, see above.
  count                   = local.fixtures
  bucket                  = aws_s3_bucket.fixture[0].id
  block_public_acls       = true
  block_public_policy     = !var.fixture_bucket_bpa_gap
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "fixture" {
  count  = local.fixtures
  bucket = aws_s3_bucket.fixture[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.evidence_store.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "fixture" {
  count  = local.fixtures
  bucket = aws_s3_bucket.fixture[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.fixture[0].arn, "${aws_s3_bucket.fixture[0].arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.fixture]
}

resource "aws_cloudwatch_log_group" "fixture" {
  # checkov:skip=CKV_AWS_338:Retention below one year is the dev policy (30 days); scenario 8 may unset it deliberately.
  # checkov:skip=CKV_AWS_66:Scenario 8 fixture may deliberately have no retention (flag off by default).
  count             = local.fixtures
  name              = "/acscg/${var.environment}/fixture"
  retention_in_days = var.fixture_log_group_violations ? null : var.log_retention_days
  kms_key_id        = module.evidence_store.kms_key_arn
}

resource "aws_security_group" "fixture_untagged" {
  # checkov:skip=CKV2_AWS_5:The untagged fixture group is deliberately attached to nothing (validation scenario 3).
  count       = var.enable_test_fixtures && var.fixture_missing_tags ? 1 : 0
  provider    = aws.untagged
  name        = "${local.name_prefix}-fixture-untagged-sg"
  description = "ACSCG scenario 3 fixture: missing required tags, never attached"
  vpc_id      = aws_vpc.fixture[0].id
  tags = {
    Project     = "acscg"
    Environment = var.environment
    Name        = "${local.name_prefix}-fixture-untagged-sg"
  }
}
