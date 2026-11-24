# SSM Automation runbooks

🧱 Implemented and ✅ validated offline (Phase 2: `tests/unit/test_runbooks.py` checks structure and executes the
embedded scripts against fakes). Deployed by `terraform/modules/remediation` in Phase 6. Every document follows the safety
pattern in `docs/security-model.md` §4: precondition assert → capture before-state → (approve) →
single scoped change → re-evaluate → verify → rollback on failure.

| Document | Control | Mode |
|---|---|---|
| `restrict-security-group.yaml` | SEC-005, SEC-006 | 3 (approval) |
| `enable-s3-protection.yaml` | SEC-001 | 2 |
| `enforce-required-tags.yaml` | SEC-013 | 2 |
| `set-log-retention.yaml` | SEC-014 | 2 (3 if older data exists) |
| `enforce-imdsv2.yaml` | SEC-008 | 3 |
