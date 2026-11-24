# Portfolio evidence

Legend (ADR 0001): 📝 planned · 🧱 implemented · ✅ tested offline · ☁️ verified in AWS · ⏳ waiting on owner.
Only observed results are recorded, each with a GitHub run ID, AWS evidence key or command output,
and a UTC timestamp. Account IDs, IPs and e-mail addresses are never recorded here.

## Phase 0: discovery

| ID | Item | Evidence | Status |
|---|---|---|---|
| P0-1 | Repository inspected | GitHub API `list_branches` → `[]`. Local clone: "No commits yet" (2026-11-24) | ✅ |
| P0-2 | AWS access from the build environment | `sts:GetCallerIdentity` → `InvalidClientTokenId` (2026-11-24). No AWS call succeeded | ✅ (blocked, recorded) |
| P0-3 | Discovery script read-only + redaction | `tests/unit/test_discovery_script.py` (static verb check + stubbed-CLI redaction test) | ✅ |
| P0-4 | Live discovery in CloudShell | owner run of `scripts/discover_aws.sh us-east-2 us-east-1` | ⏳ |
| P0-5 | Account and Region confirmed | owner confirmation | ⏳ |

## Phase 1: design

| ID | Item | Evidence | Status |
|---|---|---|---|
| P1-1 | Control catalog (15 controls) validates against schema and framework files | `python3 scripts/validate_catalog.py` → valid; `pytest` (see commit) | ✅ |
| P1-2 | Catalog safety invariants (report-only default, audit services never remediated, no "verified-in-aws" claims) | `tests/unit/test_control_catalog.py` mutation-style tests | ✅ |
| P1-3 | NIST IDs/titles verified against primary source | NIST OSCAL catalog Release 5.2.0 | ✅ |
| P1-4 | CIS/PCI/SOC 2 references | Secondary source only; primary pending | ⏳ |
| P1-5 | Diagrams render (Mermaid) | `mmdc` render of all 4 diagrams in the build environment (2026-11-24) | ✅ |
| P1-6 | Docs generated sections in sync | `scripts/sync_diagrams.py --check`, `scripts/render_control_tables.py --check` | ✅ |
| P1-7 | Unit prices for the cost model | AWS Price List API, publication dates in `docs/cost-model.md` | ✅ |

## Phase 2: offline security automation (2026-11-24)

All results below were produced in the build environment without AWS credentials. CI
(`.github/workflows/ci.yml`) repeats them on every pull request. Its run IDs are recorded when
the first run completes on GitHub.

| ID | Item | Evidence | Status |
|---|---|---|---|
| P2-1 | Python tests | `pytest`: **213 passed**, line coverage **98.18 %** (gate 90 %), Python 3.13.18 | ✅ |
| P2-2 | Lint / SAST | Ruff 0.17.4 (`E,F,W,I,B,BLE,UP,S,N,SIM,PL,RUF`): clean. Bandit 1.9.4: 0 issues (1 registered `nosec`) | ✅ |
| P2-3 | Terraform | Terraform 1.17.2 + AWS provider 6.73.0 (checksum-verified): `fmt`, `validate` and `terraform test` with mocked providers for 12 modules, bootstrap and stack, **42 runs passed, 0 failed**, including environment invariants for dev, staging and prod | ✅ |
| P2-4 | TFLint | v0.55.1 with `terraform` (recommended) + `aws` 0.49.0 rulesets: 0 issues (2 unused data sources found and removed) | ✅ |
| P2-5 | Checkov | 3.4.3: Terraform **339 passed, 0 failed**, 51 skips. GitHub Actions 144 passed, 0 failed. Findings fixed rather than skipped: boundary narrowed to `acscg-*` data resources, PITR enabled, X-Ray tracing enabled | ✅ |
| P2-6 | Trivy | 0.76.1 (checksum-verified) `fs` misconfig + secret + vuln: **0 findings** | ✅ |
| P2-7 | Workflow security | zizmor 1.32.0 (pedantic persona): 0 findings. actionlint 1.7.12: 0. All 7 action SHAs verified against their release tags with `git ls-remote` | ✅ |
| P2-8 | Suppression register | `scripts/check_suppressions.py`: 63 inline suppressions (60 register entries), each justified and registered with owner and review date (`policies/exceptions/scanner-exceptions.yaml`) | ✅ |
| P2-9 | Reproducible Lambda package | `scripts/build_lambda.py` twice → identical SHA-256. Test asserts determinism and contents | ✅ |
| P2-10 | Hash-locked dependencies | `requirements-dev.lock` installs with `--require-hashes`. Pins are the newest releases ≥ 14 days old | ✅ |
| P2-11 | Mermaid diagrams | Re-rendered after the lifecycle changes (unchanged structure) | ✅ |

### Defects found and fixed during Phase 2 (by tests or scanners)

| Defect | Found by | Fix |
|---|---|---|
| A new violation in report-only mode moved OPEN → REPORTED in one save and sent **no** notification | `test_scenario_2…` | Notify when any transition in a save is notifiable |
| Config custom-rule `count` depended on a Lambda ARN unknown at plan time (a real first plan would fail) | stack `terraform test` | Explicit `enable_custom_rules` flag |
| Budget tag filter rendered a literal `${…}` (would never match) | budgets test | `format("user:%s$%s", …)` |
| Policy parameter is a SecureString, but the provider read it without decryption | review while wiring Terraform | `WithDecryption=True` + test |
| Lambda JSON log format would have wrapped the code's own JSON lines and broken the metric filter | review | `Text` log format (ADR 0013) |
| `assert` used for fail-closed checks in production code (removed under `python -O`) | Ruff S101 review | Explicit `RuntimeError` |
| Scenario 3 fixture could not lack tags (provider `default_tags`) | design review | Separate un-tagged provider alias for one fixture SG |

### Tooling notes (build environment only)

- `registry.terraform.io` was blocked by the build environment's network policy. The AWS provider
  was installed from the official HashiCorp release site (`releases.hashicorp.com`) after
  verifying its published SHA-256, and served through a local `filesystem_mirror`. CI on GitHub
  uses the registry normally.
- `tflint --init` needs the GitHub API (blocked here). The ruleset was installed from its GitHub
  release after checksum verification. CI uses `tflint --init` with the workflow token.

## Validation scenarios (Phase 9 target)

See `docs/validation-scenarios.md`. Rows are filled in only as each scenario runs.

| # | Scenario | Offline (Phase 2 test) | AWS | Run ID / evidence | Timestamp (UTC) |
|---|---|---|---|---|---|
| 1 | Compliant resource passes | ✅ `test_scenario_1_compliant_resource_passes` | 📝 | — | — |
| 2 | Noncompliant SG detected | ✅ `test_scenario_2_noncompliant_security_group_detected` | 📝 | — | — |
| 3 | Missing tags detected | ✅ `test_scenario_3_missing_tags_detected`, custom rule `test_config_rule_variants`, fixture `scenario_fixtures_can_be_enabled` | 📝 | — | — |
| 4 | S3 protection violation | ✅ `test_scenario_4_s3_protection_violation_detected` | 📝 | — | — |
| 5 | Insecure Terraform blocked by CI | 🧱 Checkov/Trivy/plan guard in `ci.yml` (`test_guard_rejects`). Live PR demo is Phase 8 | 📝 | — | — |
| 6 | Duplicates → no duplicate remediation | ✅ `test_scenario_6_duplicate_events_do_not_duplicate_work` | 📝 | — | — |
| 7 | Unauthorized remediation rejected | ✅ `test_each_condition_denies` (14 cases), `test_tag_alone_never_authorizes`, `test_wrong_region_allowlist_entry_denies`, `test_service_denial_is_recorded_and_unlocks` | 📝 | — | — |
| 8 | Permitted low-risk remediation | ✅ `test_low_risk_control_is_automatic_only_in_auto_mode`, runbook scripts `test_log_retention_scripts…`, `test_tag_scripts_never_overwrite` | 📝 | — | — |
| 9 | High-risk needs approval | ✅ `test_service_starts_approval_runbook_with_live_parameters`, `test_end_to_end_detection_to_request` | 📝 | — | — |
| 10 | Rejected approval prevents execution | ✅ `test_scenario_10_rejected_approval_prevents_execution` | 📝 | — | — |
| 11 | Post-remediation compliance verified | ✅ `test_scenarios_9_and_11…`, `test_sg_verify_detects_collateral_changes` | 📝 | — | — |
| 12 | Notifications delivered | 🧱 message content and de-duplication tested. Delivery needs AWS | 📝 | — | — |
| 13 | Audit evidence generated | ✅ `test_scenario_13_every_evidence_object_is_complete_and_verifiable`, `test_evidence_checksum_detects_tampering` | 📝 | — | — |
| 14 | Compliance report generated | ✅ `test_scenario_14_report_from_real_findings`, `test_report_handler_writes_three_objects` | 📝 | — | — |
| 15 | Drift / unauthorized change | ✅ `test_scenario_15_unauthorized_change_then_restored_by_pipeline`. Drift workflow is Phase 8 | 📝 | — | — |
| 16 | Optional threat findings | ✅ `test_guardduty_sample_findings_scenario_16`, `test_security_hub_findings` | 📝 | — | — |
| 17 | Verified cleanup | 🧱 plan guard destroy mode (`test_destroy_mode_only_deletes`). Cleanup run is Phase 9 | 📝 | — | — |
