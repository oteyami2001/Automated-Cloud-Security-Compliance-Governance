mock_provider "aws" {}

run "disabled_by_default" {
  command = apply
  assert {
    condition     = length(aws_guardduty_detector.this) == 0 && !output.findings_enabled
    error_message = "GuardDuty must be disabled by default"
  }
}

run "integrate_looks_up_never_manages" {
  command = apply
  variables {
    ownership_mode = "integrate"
  }
  assert {
    condition     = length(aws_guardduty_detector.this) == 0 && length(aws_guardduty_detector_feature.disabled) == 0 && output.findings_enabled
    error_message = "an existing detector must never be managed"
  }
}

run "create_disables_all_optional_protection_plans" {
  command = apply
  variables {
    ownership_mode = "create"
  }
  assert {
    condition     = length(aws_guardduty_detector_feature.disabled) == 6 && alltrue([for f in aws_guardduty_detector_feature.disabled : f.status == "DISABLED"])
    error_message = "every optional protection plan must be disabled (cost model)"
  }
}
