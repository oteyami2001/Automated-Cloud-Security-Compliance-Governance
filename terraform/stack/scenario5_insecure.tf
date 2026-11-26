# SCENARIO 5 DEMONSTRATION - DELIBERATELY INSECURE. Never merge, never apply.
# Expected: CI blocks this pull request (Checkov, Trivy, TFLint), and the PR is closed unmerged.

resource "aws_security_group_rule" "scenario5_ssh_from_anywhere" {
  type              = "ingress"
  description       = "scenario 5: SSH from the internet"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.fixture[0].id
}

resource "aws_s3_bucket" "scenario5_unencrypted" {
  bucket = "${local.name_prefix}-scenario5-${var.aws_account_id}-${var.region}"
}
