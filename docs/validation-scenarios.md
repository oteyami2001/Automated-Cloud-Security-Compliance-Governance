# Validation scenarios

**Status: 📝 planned.** Each scenario is first proven offline (✅, Phase 2/5/6 unit and integration
tests with mocked AWS), then in AWS (☁️, Phase 9) on isolated, project-owned test resources.
Synthetic events are used where a real violation would be unsafe or need forbidden infrastructure.
Results are recorded in `docs/portfolio-evidence.md` with GitHub run IDs, AWS evidence keys and UTC
timestamps. Nothing is recorded that was not observed.

Test fixtures (created by a separate, approved `terraform/envs/dev` test fixture with
`enable_test_fixtures = true`, never internet-reachable):

| Fixture | Purpose | Exposure |
|---|---|---|
| `acscg-dev-fixture-sg` in a fixture VPC with **no internet gateway** and no ENIs attached | SEC-005/006 violations | None: the group is not attached to anything, and the VPC has no route to the internet |
| `acscg-dev-fixture-bucket` (empty) | SEC-001/013 | Account-level Block Public Access stays on, so a bucket-level BPA gap is detectable but **cannot** make the bucket public |
| `acscg-dev-fixture-logs` log group (empty) | SEC-014 | None |

| # | Scenario | Method | Controls | Expected result / evidence | Offline | AWS |
|---|---|---|---|---|---|---|
| 1 | Compliant resource passes | Fixture bucket with all settings correct | SEC-001–004 | Config `COMPLIANT`. No finding opened. Report counts it as passed | P2 | P9 |
| 2 | Noncompliant security group detected | Add ingress 22 from 0.0.0.0/0 to the unattached fixture SG (Terraform flag, approved apply) | SEC-005 | `NON_COMPLIANT` → finding OPEN, severity high, SNS message, evidence object | P2 | P9 |
| 3 | Missing required tags detected | Fixture log group created without `Owner` | SEC-013 | `NON_COMPLIANT` with the missing keys listed | P2 | P9 |
| 4 | S3 protection violation detected safely | Disable one bucket-level BPA setting on the empty fixture bucket. The account-level block remains, so nothing becomes public | SEC-001 | Finding OPEN. Live check proves the bucket is still not public (account block). Nothing exposed | P2 | P9 |
| 5 | Insecure Terraform change blocked by CI | PR adding an SG rule 0.0.0.0/0:22 and an unencrypted bucket | SEC-005, SEC-002 | `ci` run fails on Checkov/Trivy + plan-guard/policy test. Run ID recorded. PR closed unmerged | P8 | P8 (GitHub) |
| 6 | Duplicate events → no duplicate remediation | Replay the same Config event 3× (synthetic copy for offline; EventBridge archive replay in AWS if enabled) | SEC-005 | 1 finding, 1 notification, ≤1 remediation request, 2 `duplicate_event` log lines | P2 | P9 |
| 7 | Unauthorized remediation rejected | (a) resource tagged `Project=acscg` but not allowlisted, (b) allowlisted ARN in the wrong Region (synthetic), (c) `remediation_enabled=false` | SEC-005, SEC-001 | `REJECTED_POLICY` with the reason. **No** AWS write API call (CloudTrail search empty) | P2/P6 | P9 |
| 8 | Permitted low-risk remediation succeeds | Mode 2 window on the fixture log group (never-expire → 30 days) or the fixture bucket BPA | SEC-014 / SEC-001 | SSM execution Success. Before/after captured. `VERIFIED_RESOLVED` | P6 | P9 |
| 9 | High-risk remediation requires approval | Mode 3 on the scenario 2 SG rule | SEC-005 | Execution waits in `aws:approve`. SNS approval notice. Nothing changes before approval | P6 | P9 |
| 10 | Rejected approval prevents execution | Approver sends `Reject` | SEC-005 | Execution `Failed`/`Cancelled`. Rule still present. `REMEDIATION_REJECTED` | P6 | P9 |
| 11 | Post-remediation compliance verified | After scenario 9 approval | SEC-005 | Only the offending rule removed, other rules identical. Config `COMPLIANT`. `VERIFIED_RESOLVED` with verification timestamp | P6 | P9 |
| 12 | Notifications delivered | SNS e-mail subscription confirmed | all | SNS `NumberOfNotificationsDelivered` metric + received message (headers redacted) | P5 | P9 |
| 13 | Audit evidence generated | Any completed lifecycle | all | Evidence JSON has every prompt §12 field. Recomputed SHA-256 matches the stored checksum. Object Lock retention set | P2 | P9 |
| 14 | Compliance report generated | `compliance-report` workflow | all | JSON + Markdown report. Metrics computed from real findings. No account ID/IP/e-mail in output (scanner check) | P7 | P9 |
| 15 | Configuration drift detected | Console change to a project resource (e.g. fixture SG description, or an alarm threshold) | SEC-015 | SEC-015 finding (principal ≠ apply role). `drift-detection` run exits with drift and the address. Restored via reviewed plan/apply | P8 | P9 |
| 16 | Optional threat findings processed | In an approved window: `guardduty create-sample-findings` (and/or a Security Hub sample ASFF via `BatchImportFindings` from the project's own product ARN) | optional | Findings normalised, severity mapped, **never remediated**, marked `sample=true` | P5 | P9 (only if the window is approved) |
| 17 | Cleanup removes billable project resources only | `cleanup` workflow with digest + `destroy-dev` + approval | all | State empty. No `acscg-*` Lambda/DynamoDB/SQS/SNS/KMS (pending deletion)/rules/dashboards. **Pre-existing** trail, recorder, Security Hub, GuardDuty and OIDC provider unchanged (before/after diff from `discover_aws.sh`) | P8 | P9 |

### Not demonstrated live (and why)

| Item | Reason | Alternative |
|---|---|---|
| SEC-007/008 on a real EC2 volume/instance | No EC2 without explicit approval (prompt §15) | Synthetic Config events + runbook unit tests. Optional approved t4g.nano for ≤ 1 h |
| SEC-009/011 on real IAM users | Creating IAM users with keys is unsafe and contradicts the OIDC-only design | Synthetic Config events. Report against existing users is read-only |
| SEC-012 by stopping the shared trail | Must not modify an existing audit service | Synthetic `StopLogging` CloudTrail event on the `acscg.synthetic` source |
