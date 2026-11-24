# Terraform

📝 Planned. Module design: `docs/architecture.md` §9. Modules and `terraform test` suites (mock
providers) are built in Phase 2; the bootstrap is applied in Phase 3 only after approval.

```
bootstrap/   state bucket, KMS, OIDC roles, permissions boundary, budget
modules/     iam-oidc, security-config, security-hub, guardduty, cloudtrail, eventbridge,
             compliance-engine, remediation, evidence-store, notifications, dashboard, budgets
envs/        dev (deployed), staging and prod (validated reference configurations only)
```
