# Architecture Decision Records

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-decisions-and-status-vocabulary.md) | Record architecture decisions and a four-level status vocabulary | Accepted |
| [0002](0002-account-and-region.md) | Target account and Region | Proposed (pending owner confirmation, blocker B1) |
| [0003](0003-integrate-not-own-account-security-services.md) | Integrate with, never take ownership of, account-level security services | Accepted |
| [0004](0004-config-primary-optional-securityhub-guardduty.md) | AWS Config is the primary detection engine. Security Hub CSPM and GuardDuty are optional | Accepted |
| [0005](0005-reuse-existing-cloudtrail.md) | Reuse the existing CloudTrail trail and do not create a second one | Proposed (pending discovery D4) |
| [0006](0006-remediation-modes-and-authorization.md) | Report-only default, three remediation modes, allowlist-based authorization, SSM approval | Accepted |
| [0007](0007-evidence-store.md) | Evidence store: SSE-KMS, versioning, Object Lock in governance mode, checksums | Accepted |
| [0008](0008-plan-integrity.md) | Apply only the exact reviewed plan (digest-bound, fail closed) | Accepted |
| [0009](0009-idempotency-and-deduplication.md) | Idempotency with DynamoDB conditional writes and a canonical finding key | Accepted |
| [0010](0010-serverless-python-313.md) | Serverless runtime: Python 3.13 Lambda (arm64), zip packages, no persistent compute | Accepted |
| [0011](0011-cost-guardrails.md) | Cost guardrails: scoped recording, disabled optional services, tag budget, short windows | Accepted |
| [0012](0012-single-stack-root-per-environment-tfvars.md) | One stack root with per-environment variable files | Accepted |
| [0013](0013-runtime-dependencies-and-policy-delivery.md) | Standard-library runtime and a Terraform-rendered policy parameter | Accepted |
