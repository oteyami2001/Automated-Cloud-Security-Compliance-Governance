# Mocked provider: nothing reaches AWS.
mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
  }
}

variables {
  name_prefix              = "acscg"
  subject_prefix           = "repo:octo-org@1234/acscg@5678"
  permissions_boundary_arn = "arn:aws:iam::111122223333:policy/acscg-ci-boundary"
  roles = {
    plan = {
      description    = "plan"
      subject_suffix = "environment:dev-plan"
      policy_json    = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
    report = {
      description      = "report"
      subject_suffix   = "ref:refs/heads/main"
      policy_json      = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
      job_workflow_ref = "octo-org/acscg/.github/workflows/compliance-report.yml@refs/heads/main"
      attach_boundary  = false
    }
  }
}

run "exact_subject_and_audience" {
  command = apply

  assert {
    condition     = jsondecode(output.trust_policies["plan"]).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:octo-org@1234/acscg@5678:environment:dev-plan"
    error_message = "plan role must trust exactly the dev-plan environment subject"
  }
  assert {
    condition     = jsondecode(output.trust_policies["plan"]).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "audience must be sts.amazonaws.com"
  }
  assert {
    condition     = !can(jsondecode(output.trust_policies["plan"]).Statement[0].Condition.StringLike)
    error_message = "trust must not use StringLike (wildcards)"
  }
  assert {
    condition     = jsondecode(output.trust_policies["report"]).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:job_workflow_ref"] == "octo-org/acscg/.github/workflows/compliance-report.yml@refs/heads/main"
    error_message = "report role must be bound to the report workflow"
  }
  assert {
    condition     = aws_iam_role.this["plan"].permissions_boundary == "arn:aws:iam::111122223333:policy/acscg-ci-boundary" && aws_iam_role.this["report"].permissions_boundary == null
    error_message = "boundary attachment must follow attach_boundary"
  }
  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 0
    error_message = "the shared OIDC provider must be looked up, never created, by default"
  }
}

run "pull_request_subjects_rejected" {
  command = plan
  variables {
    roles = {
      pr = {
        description    = "bad"
        subject_suffix = "pull_request"
        policy_json    = "{}"
      }
    }
  }
  expect_failures = [var.roles]
}

run "mutable_subject_prefix_rejected" {
  command = plan
  variables {
    subject_prefix = "repo:octo-org/acscg"
  }
  expect_failures = [var.subject_prefix]
}
