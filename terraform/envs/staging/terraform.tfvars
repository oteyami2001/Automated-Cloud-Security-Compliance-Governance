# staging environment. Non-sensitive values only: aws_account_id, alert_email and approvers come from
# GitHub environment secrets/variables as TF_VAR_* (never committed).
environment            = "staging"
region                 = "us-east-2"
config_ownership_mode  = "integrate" # confirm from discovery D5 (ADR 0003)
security_hub_mode      = "disabled"  # optional, approved window only (ADR 0004)
guardduty_mode         = "disabled"  # optional, approved window only (ADR 0004)
cloudtrail_mode        = "integrate" # reuse the existing trail (ADR 0005)
existing_trail_name    = "idp-management-events"
log_retention_days     = 90
object_lock_days       = 30
point_in_time_recovery = true
deletion_protection    = false
allow_synthetic_events = false
enable_test_fixtures   = false
