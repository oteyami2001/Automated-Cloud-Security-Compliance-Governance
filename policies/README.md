# Policies

| Path | Contents | Validated by |
|---|---|---|
| `remediation/<env>.yaml` | Remediation mode, enable flag, approval timeout, attempt limit, exact-ARN allowlist, protected resources (all report-only and empty as committed) | `schemas/remediation-policy.schema.json`, `remediation_engine.policy.parse_policy`, Terraform preconditions |
| `exceptions/<env>.yaml` | Time-boxed control exceptions (≤ 90 days, approver, ticket) | `schemas/exceptions.schema.json` |
| `exceptions/scanner-exceptions.yaml` | Register of every inline scanner suppression | `scripts/check_suppressions.py` (CI) |
| `iam/` | Reserved for standalone IAM policy documents (current policies are rendered in Terraform and asserted by `terraform test`) | — |

Authorization rules: `docs/security-model.md`.
