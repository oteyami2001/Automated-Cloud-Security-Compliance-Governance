# Terraform

🧱 Implemented, ✅ tested with mocked providers (Phase 2). Nothing applied yet (bootstrap: Phase 3).
Design: `docs/architecture.md` §9, ADR 0012.

```
bootstrap/   state bucket + KMS, GitHub OIDC roles, workload permissions boundary, budget
modules/     iam-oidc, security-config, security-hub, guardduty, cloudtrail, eventbridge,
             compliance-engine, remediation, evidence-store, notifications, dashboard, budgets
stack/       the single root for every environment (+ isolated scenario fixtures, off by default)
envs/<env>/  terraform.tfvars and backend.hcl.example
```

Run everything offline with `make terraform`.
