# SSM Automation runbooks

📝 Planned (Phase 2 offline validation, Phase 6 deployment). Every document follows the safety
pattern in `docs/security-model.md` §4: precondition assert → capture before-state → (approve) →
single scoped change → re-evaluate → verify → rollback on failure.

| Document | Control | Mode |
|---|---|---|
| `restrict-security-group.yaml` | SEC-005, SEC-006 | 3 (approval) |
| `enable-s3-protection.yaml` | SEC-001 | 2 |
| `enforce-required-tags.yaml` | SEC-013 | 2 |
| `set-log-retention.yaml` | SEC-014 | 2 (3 if older data exists) |
| `enforce-imdsv2.yaml` | SEC-008 | 3 |
