# Bootstrap inputs (non-sensitive). The account ID and alert e-mail are supplied as
# TF_VAR_aws_account_id / TF_VAR_alert_email in CloudShell and are never committed.
region = "us-east-2" # confirmed by the owner 2026-11-24 (ADR 0002)

# Numeric GitHub IDs for immutable OIDC subjects (public values, read from the GitHub API 2026-11-24):
# repo:oteyami2001@157901928/Automated-Cloud-Security-Compliance-Governance@1465572625
github_owner    = "oteyami2001"
github_owner_id = "157901928"
github_repo     = "Automated-Cloud-Security-Compliance-Governance"
github_repo_id  = "1465572625"

create_oidc_provider = false   # D9: the shared provider exists; looked up, never managed
environments         = ["dev"] # staging and prod stay reference configurations
budget_limit_usd     = 25
