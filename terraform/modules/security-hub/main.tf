# Security Hub CSPM (optional, ADR 0004). disabled: nothing. integrate: nothing is managed; the
# EventBridge rule is enabled for an already-enabled hub. create: hub enabled WITHOUT default
# standards and without auto-enabling new controls; FSBP only if explicitly requested for a window.

data "aws_partition" "current" {}

resource "aws_securityhub_account" "this" {
  count                     = var.ownership_mode == "create" ? 1 : 0
  enable_default_standards  = false
  auto_enable_controls      = false
  control_finding_generator = "SECURITY_CONTROL"
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.ownership_mode == "create" && var.enable_fsbp ? 1 : 0
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}
