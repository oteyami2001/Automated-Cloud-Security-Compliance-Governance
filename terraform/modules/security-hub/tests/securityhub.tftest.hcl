mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
}

variables {
  region = "us-east-2"
}

run "disabled_by_default" {
  command = apply
  assert {
    condition     = length(aws_securityhub_account.this) == 0 && !output.findings_enabled
    error_message = "Security Hub must be disabled by default"
  }
}

run "integrate_manages_nothing" {
  command = apply
  variables {
    ownership_mode = "integrate"
  }
  assert {
    condition     = length(aws_securityhub_account.this) == 0 && output.findings_enabled && !output.managed_by_project
    error_message = "integrate mode consumes findings without managing the hub"
  }
}

run "create_without_default_standards" {
  command = apply
  variables {
    ownership_mode = "create"
  }
  assert {
    condition     = !aws_securityhub_account.this[0].enable_default_standards && !aws_securityhub_account.this[0].auto_enable_controls
    error_message = "no default standards and no auto-enabled controls (cost)"
  }
  assert {
    condition     = length(aws_securityhub_standards_subscription.fsbp) == 0
    error_message = "FSBP only when explicitly requested"
  }
}
