mock_provider "aws" {}

variables {
  name        = "acscg"
  alert_email = "owner@example.com"
}

run "tag_filtered_budget_with_alerts" {
  command = apply
  assert {
    condition     = length(one(aws_budgets_budget.project.cost_filter).values) == 1 && contains(one(aws_budgets_budget.project.cost_filter).values, "user:Project$acscg")
    error_message = "budget must be filtered on the Project cost-allocation tag"
  }
  assert {
    condition     = aws_budgets_budget.project.limit_amount == "25.00"
    error_message = "USD 25 default"
  }
  assert {
    condition     = length(aws_budgets_budget.project.notification) == 3
    error_message = "50 % and 80 % actual, 100 % forecast"
  }
}

run "limit_bounded" {
  command = plan
  variables {
    limit_usd = 1000
  }
  expect_failures = [var.limit_usd]
}
