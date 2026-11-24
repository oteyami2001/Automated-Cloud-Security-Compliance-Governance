mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555" }
  }
}

variables {
  name_prefix      = "acscg-dev"
  account_id       = "111122223333"
  region           = "us-east-2"
  writer_role_arns = ["arn:aws:iam::111122223333:role/acscg-dev-findings-processor"]
  cleanup_role_arn = "arn:aws:iam::111122223333:role/acscg-github-cleanup"
  admin_role_arns  = ["arn:aws:iam::111122223333:role/acscg-github-apply"]
}

run "evidence_bucket_controls" {
  command = apply

  assert {
    condition     = aws_s3_bucket.evidence.object_lock_enabled && !aws_s3_bucket.evidence.force_destroy
    error_message = "Object Lock must be enabled and force_destroy disabled"
  }
  assert {
    condition     = one(aws_s3_bucket_object_lock_configuration.evidence.rule).default_retention[0].mode == "GOVERNANCE"
    error_message = "governance mode keeps verified cleanup possible (ADR 0007)"
  }
  assert {
    condition     = aws_s3_bucket_versioning.evidence.versioning_configuration[0].status == "Enabled"
    error_message = "versioning must be enabled"
  }
  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.evidence.block_public_acls,
      aws_s3_bucket_public_access_block.evidence.block_public_policy,
      aws_s3_bucket_public_access_block.evidence.ignore_public_acls,
      aws_s3_bucket_public_access_block.evidence.restrict_public_buckets,
    ])
    error_message = "all public access must be blocked"
  }
  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.evidence.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
    error_message = "SSE-KMS required"
  }
  assert {
    condition     = aws_kms_key.this.enable_key_rotation
    error_message = "key rotation required"
  }
  assert {
    condition = toset([for s in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement : s.Sid]) == toset([
      "DenyInsecureTransport", "DenyNonKmsEncryption", "DenyWritesWithoutProjectKey",
      "DenyEvidenceDeletionExceptCleanup", "DenyLockTamperingExceptAdmins", "DenyWritesFromOtherPrincipals",
    ])
    error_message = "bucket policy must contain every deny statement"
  }
  assert {
    condition     = alltrue([for s in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement : s.Effect == "Deny"])
    error_message = "the bucket policy grants nothing; it only denies"
  }
  assert {
    condition     = [for s in jsondecode(aws_s3_bucket_policy.evidence.policy).Statement : s.Condition.StringNotEquals["aws:PrincipalArn"] if s.Sid == "DenyEvidenceDeletionExceptCleanup"][0] == ["arn:aws:iam::111122223333:role/acscg-github-cleanup"]
    error_message = "only the cleanup role may delete evidence"
  }
}

run "invalid_prefix_rejected" {
  command = plan
  variables {
    name_prefix = "other-dev"
  }
  expect_failures = [var.name_prefix]
}
