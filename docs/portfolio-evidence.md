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
| P0-4 | Live discovery in CloudShell | Owner run 2026-11-24T06:21:46Z, 845-line report (kept private). Summary in `docs/phase-0-assessment.md` §2.4 | ☁️ |
| P0-5 | Account and Region confirmed | owner confirmation | ⏳ |
| P0-6 | Discovery redaction gap (other accounts' IDs, unique IDs, UUIDs, authorization IDs) | Found in the owner's run. Fixed in `scripts/discover_aws.sh` and covered by `test_output_is_redacted_by_default` | ✅ |

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
(`.github/workflows/ci.yml`) repeats them on every pull request (first run: P2-12).

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
| P2-12 | **CI on GitHub** | `ci` run [45337736595](https://github.com/oteyami2001/Automated-Cloud-Security-Compliance-Governance/actions/runs/45337736595) on commit `5b4adb0` (PR #1), 2026-11-24 06:04:31–06:06:35 UTC: python, terraform, tflint, checkov, trivy and workflow-security all **success** | ✅ |

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

## Phase 3: secure bootstrap (approved 2026-11-24)

| ID | Item | Evidence | Status |
|---|---|---|---|
| P3-1 | Owner and repository IDs for immutable OIDC subjects | GitHub search API: owner 157901928, repository 1465572625 (2026-11-24) | ✅ |
| P3-2 | Provider lock files for bootstrap and stack | AWS provider 6.73.0, 5 platforms, zips checksum-verified against HashiCorp SHA256SUMS | ✅ |
| P3-3 | Bootstrap tooling | `install_terraform.sh` (checksum), `bootstrap.sh` (account check, digest-bound apply of the saved plan), `verify_bootstrap.sh` (read-only). `tests/unit/test_phase3_scripts.py` | ✅ |
| P3-4 | GitHub settings applied and verified | `configure_github.sh` then `verify_github_settings.sh` at **2026-11-24T12:51:56Z: `RESULT: all checks passed`**. Default branch `main`, secret scanning + push protection, Dependabot, read-only token, ruleset (PR + `ci-ok`, no force push/deletion), environments `dev-plan`/`dev`/`dev-cleanup` (main only; reviewer on dev and dev-cleanup), `use_immutable_subject: true` with prefix `repo:oteyami2001@157901928/Automated-Cloud-Security-Compliance-Governance@1465572625` | ☁️ |
| P3-5 | Bootstrap plan reviewed (summary + digest) | `Plan: 20 to add, 0 to change, 0 to destroy.` 9 state resources, boundary, 4 CI roles + 4 inline policies + ReadOnlyAccess on dev-plan, budget. Nothing changed or destroyed. Digest `40a4f9f0…0c536f`, reviewed and approved 2026-11-24 | ☁️ |
| P3-6 | Bootstrap applied, state migrated | `Plan digest matches the reviewed plan.` → `Apply complete! Resources: 20 added, 0 changed, 0 destroyed.` State migrated to the bucket (object SSE `aws:kms`). Local state files removed (2026-11-24, before 13:18 UTC) | ☁️ |
| P3-7 | `verify_bootstrap.sh`: all checks passed | **2026-11-24T13:18:39Z: 17/17 PASS, `RESULT: all checks passed`**: state bucket (versioning, SSE-KMS, public access blocked, TLS-only), key rotation, boundary, each CI role trusts exactly one immutable subject, plan role read-only, budget filter, shared OIDC provider + `aiops`/`idp` roles + existing trail untouched | ☁️ |
| P3-8 | Cost-allocation tag `Project` | `not found` at 13:18 UTC: new tags can take up to 24 h to appear, and in an Organization activation is usually done from the management account. Until active, the account-wide `aiops-account-monthly` budget (USD 30) is the backstop | ⏳ |
| P3-9 | Issue found during the run | CloudShell's 1 GB home cannot hold the ~700 MB AWS provider (`no space left on device`). Fixed: `bootstrap.sh` keeps `.terraform` in `/tmp` via `TF_DATA_DIR` | ✅ |

## Phase 4: security monitoring (approved 2026-11-24)

| ID | Item | Evidence | Status |
|---|---|---|---|
| P4-1 | Config managed rule identifiers verified | 18/18 identifiers exist in the AWS Config developer guide (archived `awsdocs/aws-config-developer-guide`, commit 80500dbb). Corrections: `CW_LOGGROUP_RETENTION_PERIOD_CHECK` is periodic (scope removed) and treats "Never expire" as COMPLIANT (new custom check `log_retention_set`, rule `acscg-sec014-retention-set`); `REQUIRED_TAGS` does not support Lambda functions (removed from SEC-013). `docs/compliance-mapping.md` §6 | ✅ |
| P4-2 | Security Hub control IDs | Secondary sources only (AWS docs archive empty): 21/24 found in Prowler FSBP and Steampipe; EC2.53, EC2.54, CloudWatch.16 pending. Security Hub is SCP-denied, so mapping only | ⚠️ |
| P4-3 | Phase scope | Remediation module (Phase 6) and scenario fixtures off in dev (`enable_remediation = false`, `enable_test_fixtures = false`). Platform policy parameter moved to the stack (report-only). Tested: `stack.tftest.hcl`, `environments.tftest.hcl` (prod never deploys remediation) | ✅ |
| P4-4 | Bootstrap least privilege | Plan role may write only `*.tflock` in the state bucket. Boundary allows the read-only S3/Logs/DynamoDB calls the Config recorder needs. Bootstrap plan `0 to add, 2 to change, 0 to destroy`, digest `db07fb8a…95474a` reviewed and applied by the owner (2026-11-24). Re-plan: `No changes`. Live boundary contains `s3:GetAccelerateConfiguration`. `verify_bootstrap.sh` 17/17 PASS at 14:21:41Z | ☁️ |
| P4-5 | Plan/apply workflows | `terraform-plan.yml`, `terraform-apply.yml` (OIDC, environment-gated, digest-bound). actionlint, zizmor (0 findings), Checkov (1 registered suppression), `test_phase4_workflows.py` | ✅ |
| P4-6 | Offline checks for this change set | `make check`: 235 tests, coverage ≥ 90 %; `make terraform`: all module, bootstrap, stack and per-environment tests pass; TFLint 0 issues; Checkov 0 failed; Trivy 0 misconfigurations/secrets (2026-11-24) | ✅ |
| P4-7 | Stack plan reviewed | Run 45413564497 (14:24Z): `Plan: 93 to add, 0 to change, 0 to destroy`, digest `077372ca…30ae2`. No remediation, fixtures, Security Hub, GuardDuty, Access Analyzer or trail; Config recorder created (D5) | ☁️ |
| P4-8 | First apply attempts | Runs 45415081722 and 45418146520: OIDC login refused, `Request ARN is invalid` (the `dev` environment secret `AWS_ACCOUNT_ID` was missing, then not 12 plain digits). Nothing planned or changed. Fix: workflows now check the secrets before login | ✅ |
| P4-9 | Apply | Run 45420207376 (15:03–15:04Z): `Plan digest matches the reviewed plan.`, then 92 of 93 resources created; failed on `module.dashboard.aws_cloudwatch_dashboard.this` (error detail cut by the log filter; fixed in `tf_ci.sh`). Plan run 45421467579 (15:06Z): `Plan: 1 to add` (only the dashboard). SNS subscription confirmed by the owner | ☁️ partial |
| P4-10 | Deployment verification | Pending: recorder status, rule evaluations, processor events, findings in DynamoDB | ⏳ |
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
