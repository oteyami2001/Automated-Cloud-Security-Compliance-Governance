mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
}

variables {
  name_prefix         = "acscg-dev"
  account_id          = "111122223333"
  region              = "us-east-2"
  existing_trail_name = "idp-management-events"
}

run "integrate_reuses_existing_trail" {
  command = apply
  assert {
    condition     = length(aws_cloudtrail.this) == 0 && length(aws_s3_bucket.trail) == 0
    error_message = "no second trail by default (ADR 0005)"
  }
  assert {
    condition     = output.trail_name == "idp-management-events" && !output.managed_by_project
    error_message = "existing trail referenced, not managed"
  }
}

run "create_mode_is_validated_and_single_region" {
  command = apply
  variables {
    mode = "create"
  }
  assert {
    condition     = aws_cloudtrail.this[0].enable_log_file_validation && !aws_cloudtrail.this[0].is_multi_region_trail
    error_message = "log file validation on; single Region by design"
  }
}
