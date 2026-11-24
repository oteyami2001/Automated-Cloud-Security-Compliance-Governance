# Policies

| Directory | Contents | Status |
|---|---|---|
| `remediation/` | Remediation policy: mode, enable flag, approvers, exact-ARN allowlist, protected resources | 📝 draft example only (Phase 2 schema, Phase 6 live) |
| `exceptions/` | Time-boxed control exceptions (≤ 90 days, approver, ticket) and the scanner-suppression register | 📝 Phase 2 |
| `iam/` | IAM policy documents and policy tests (boundary, execution roles) | 📝 Phase 2/3 |

See `docs/security-model.md` for the authorization rules these files feed.
