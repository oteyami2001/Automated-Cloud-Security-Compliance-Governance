# dev environment. Non-sensitive values only: aws_account_id, alert_email and approvers come from
# GitHub environment secrets/variables as TF_VAR_* (never committed).
environment            = "dev"
region                 = "us-east-2"
config_ownership_mode  = "create"    # discovery 2026-11-24 (D5): no recorder in us-east-2, so this project owns one, limited to catalog types
security_hub_mode      = "disabled"  # SCP explicitly denies securityhub:* in this account (discovery D6); never bypassed
guardduty_mode         = "disabled"  # SCP explicitly denies guardduty:* in this account (discovery D7); never bypassed
cloudtrail_mode        = "integrate" # D4: idp-management-events is logging, log file validation on (ADR 0005)
existing_trail_name    = "idp-management-events"
log_retention_days     = 30
object_lock_days       = 7
point_in_time_recovery = true
deletion_protection    = false
allow_synthetic_events = true
enable_test_fixtures   = false # Phase 4 deploys monitoring only; fixtures come with the scenario PRs (Phase 5+)
enable_remediation     = false # Phase 6
