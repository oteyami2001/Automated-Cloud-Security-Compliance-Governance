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
enable_test_fixtures   = true # Phase 5: isolated fixtures (VPC without IGW or subnets, unattached SGs, empty private bucket)
# Phase 6 step B: violations re-created INSIDE the remediation window, so they open as new findings
# (docs/remediation-runbook.md §2). Expected: log group and bucket fixed automatically (Mode 2), SSH
# rule waits for the owner's approval (Mode 3), untagged SG rejected (not allowlisted, scenario 7a).
fixture_open_ssh             = false # scenario 9/11: 22/tcp from 0.0.0.0/0 on the UNATTACHED fixture SG (off: step B retry, part 1)
fixture_missing_tags         = true  # scenario 7a: unattached SG without Owner/ManagedBy/DataClassification, NOT allowlisted
fixture_bucket_bpa_gap       = false # scenario 8: BlockPublicPolicy off on the EMPTY bucket (off: step B retry, part 1)
fixture_log_group_violations = false # scenario 8: fixture log group without retention (off: step B retry, part 1)
enable_remediation           = true  # Phase 6 window (policies/remediation/dev.yaml)
