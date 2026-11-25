# Implementation roadmap

Each phase ends with a report, and the next phase starts only after the owner's explicit approval.
AWS-changing steps (marked ☁️) additionally need approval of the specific plan.

| Phase | Goal | Main deliverables | Exit criteria | AWS changes |
|---|---|---|---|---|
| **0** Discovery | Know the repository and account | `docs/phase-0-assessment.md`, `scripts/discover_aws.sh` | Repository assessed ✅. **Account/Region confirmed by owner, discovery report summarised** ⏳ | None (read-only) |
| **1** Design | Architecture, controls, mappings, threats, costs, ADRs | This documentation set, `controls/*`, diagrams, catalog validator + tests | Catalog valid, tests green, docs in sync. **Owner approval** | None |
| **2** Offline automation ✅ (2026-11-24) | All logic proven without AWS | `src/` packages (event schemas, normaliser, severity, ownership, idempotency, lifecycle, gatekeeper decision, evidence builder, report builder), `policies/` (allowlist schema, exceptions), Terraform modules with `terraform test` (mock providers), plan guard, CI workflow `ci.yml` | ≥ 90 % line coverage on `src/`. Scenarios 1–4, 6, 7, 13 green offline. Terraform `validate` + tests green for dev/staging/prod | None |
| **3** Secure bootstrap ☁️ (2026-11-24) | Foundation in AWS | `terraform/bootstrap`: state bucket (SSE-KMS, versioning, native locking), OIDC roles, boundary, budget. Cost-allocation tag activation. `verify_bootstrap.sh` | Bootstrap verified (all checks pass, timestamped). OIDC roles trust exactly one subject each | ☁️ small IAM/S3/KMS/Budgets plan |
| **4** Security monitoring ☁️ (deployed and verified 2026-11-24; gaps P4-13/P4-14 carried into Phase 5) | Detection running | Config (create/integrate per D5), rules for SEC-001…014, Access Analyzer, EventBridge rules, CloudTrail integration (no new trail). Security Hub CSPM / GuardDuty modules present but `disabled` | Rules evaluate. Scenario 1 ☁️. Security Hub/Config identifiers verified against AWS docs | ☁️ via reviewed plan/apply |
| **5** Findings engine ☁️ (2026-11-24/25; scenarios 2, 3, 4, 6, 12, 13 verified in AWS) | Findings flow end to end | findings-processor Lambda, DynamoDB, DLQ, SNS, alarms | Scenarios 2, 3, 4, 6, 12, 13 ☁️ | ☁️ |
| **6** Remediation | Controlled change | Gatekeeper, SSM documents, execution roles, allowlist, Mode 2/3 | Scenarios 7–11 ☁️ in an approved window. Remediation off again afterwards | ☁️ |
| **7** Reporting | Posture visibility | report-generator, `compliance-report.yml`, dashboard, metrics | Scenario 14 ☁️. Metrics match DynamoDB counts | ☁️ |
| **8** DevSecOps and governance | Enforced pipeline | All workflows, rulesets/environments configured **and verified**, exceptions register, drift detection, cleanup workflow | Scenario 5 (GitHub) and 15. `verify_github_settings.sh` passes | ☁️ (drift drill) |
| **9** Live validation and cleanup | Full lifecycle proof | All 17 scenarios with evidence. Optional services window (16). Cost review. Verified cleanup (17) | Evidence table complete. Cleanup verified. Pre-existing services unchanged | ☁️ incl. destroy |
| **10** Portfolio | Recruiter-ready | README, technical report, evidence links, demo script, interview notes | Owner review | None |

## Phase 2 task list (completed: see `docs/portfolio-evidence.md` P2-1…P2-11)

1. `src/common`: `Finding` model (dataclasses), severity enum, structured JSON logger with masking, settings loader (env vars, fail closed).
2. `src/findings_processor`: JSON Schemas for Config compliance change, CloudTrail API call, Access Analyzer, Security Hub ASFF (subset), GuardDuty, SSM status, synthetic. Normalisers. Severity classifier. Ownership resolver. Idempotency and lifecycle store interface with an in-memory fake and a DynamoDB adapter (moto or Stubber tests).
3. `src/remediation_engine`: pure gatekeeper decision (all deny reasons enumerated), allowlist schema and loader, approval-state handling, rollback descriptors.
4. `src/compliance_evaluator`: custom evaluators (SG IPv6 and port-range logic for SEC-005/006, tag-value validation for SEC-013, unauthorised-change attribution for SEC-015).
5. `src/evidence_collector`: evidence document builder (all §12 fields) + canonical JSON + SHA-256. `src/report_generator`: JSON + Markdown report with redaction.
6. `runbooks/`: SSM Automation YAML for SG rule revoke, bucket BPA, tags, log retention. Static validation (schema + "single mutating step" test).
7. `policies/`: allowlist and exception schemas, protected-resource list format, scanner-exception register.
8. Terraform modules (all 12) + `envs/{dev,staging,prod}` with mocked-provider tests, incl. "integrate mode creates nothing" and boundary assertions. Plan guard + digest script (from Project 2) with tests.
9. `ci.yml` (no AWS access) running everything above. Actions pinned to SHAs verified against release tags.
10. Offline evidence: test reports, coverage, Checkov/Trivy outputs recorded in `docs/portfolio-evidence.md`.

## Phase 3 proposed task list (needs discovery results and approval)

1. Owner runs `scripts/discover_aws.sh` in CloudShell. Confirm account/Region (ADR 0002). Decide
   `config_ownership_mode`, `create_access_analyzer`, `existing_trail_name` and the protected
   resource list from D4–D13.
2. Verify Security Hub control IDs and Config managed-rule identifiers against AWS docs (gate from
   Phase 1). Update the catalog and `security-config` module if any differ.
3. Read the repository's numeric owner/repo IDs from the GitHub API and enable immutable OIDC
   subject claims. Create GitHub environments `dev-plan`, `dev`, `dev-cleanup` with required reviewers.
4. In CloudShell: checksum-verified Terraform, `terraform -chdir=terraform/bootstrap init` (generates
   the provider lock file), plan, **owner review**, apply, state migration, then `scripts/verify_bootstrap.sh`.
5. Activate the `Project` cost-allocation tag. Record evidence with timestamps.
