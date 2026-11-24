# GuardDuty (optional, ADR 0004). create: a detector with every optional protection plan disabled
# (foundational CloudTrail/VPC/DNS analysis only). integrate: the existing detector is looked up,
# never managed. Findings are always report-only.

locals {
  optional_features = toset([
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
    "RUNTIME_MONITORING",
  ])
}

data "aws_guardduty_detector" "existing" {
  count = var.ownership_mode == "integrate" ? 1 : 0
}

resource "aws_guardduty_detector" "this" {
  # checkov:skip=CKV2_AWS_3:Single-account, single-Region project without Organizations delegated administration (ADR 0002).
  count                        = var.ownership_mode == "create" ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "disabled" {
  for_each    = var.ownership_mode == "create" ? local.optional_features : toset([])
  detector_id = aws_guardduty_detector.this[0].id
  name        = each.value
  status      = "DISABLED"
}
