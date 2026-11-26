# Technical report: Automated Cloud Security, Compliance & Governance (ACSCG)

**Scope:** one AWS account (dev), us-east-2, November 2026. Every number below comes from a recorded
run; the run IDs and timestamps are in [portfolio-evidence.md](portfolio-evidence.md). This is a
framework-aligned portfolio project, not a certification.

## 1. Problem

Cloud misconfigurations (public buckets, SSH open to the internet, missing encryption or log
retention) are found too late, fixed by hand, and leave no audit trail. Automatic fixing is the
obvious answer and also the risky one: a remediation engine with broad write access is a confused
deputy waiting to happen.

The goal was a platform that **detects → analyses → approves → remediates → verifies → audits**, and
that is safe by default: it reports everything, changes only what is explicitly authorised, and can
prove what it did.

## 2. Design

| Layer | Implementation |
|---|---|
| Controls | 15 controls (SEC-001…015) in a machine-readable catalog, mapped to NIST SP 800-53 Rev. 5, CIS AWS Foundations v5/v6, PCI DSS v4.0.1 and SOC 2; tables in the docs are generated from it |
| Detection | AWS Config recorder (selected resource types only) with 18 managed + 4 custom Lambda rules; CloudTrail events via EventBridge for unauthorised changes (SEC-015); a 6-hourly reconciler for missed events |
| Processing | Lambda findings processor: validate → normalise → severity → ownership → idempotent de-duplication → lifecycle state machine (14 states); DynamoDB; SQS dead-letter queue; SNS alerts |
| Remediation | Gatekeeper Lambda + SSM Automation runbooks (assert → approve → change → verify → rollback). Report-only by default; Mode 2 (automatic) and Mode 3 (human approval through `aws:approve`) need an enable flag, an exact-ARN allowlist that expires, and a live re-check |
| Evidence | Per transition: JSON with SHA-256, KMS-encrypted S3 with versioning and Object Lock (governance) |
| Reporting | Daily report (JSON, private and public Markdown) and CloudWatch EMF posture metrics; read-only workflow proves report = metrics = DynamoDB recount and scans the public report for identifiers |
| Delivery | Terraform (12 modules), GitHub Actions with OIDC (no stored keys): plan prints a digest, apply re-plans and applies only if the digest matches, after the owner approves the environment |
| Governance | Ruleset on `main` (PR + `ci-ok`), weekly drift detection, daily verification, guarded cleanup |

Key decisions are ADRs 0001–0013 (`docs/adr/`). The most important: integrate with existing
account services instead of owning them (0003), Config as the primary path (0004), report-only by
default with tags never authorising (0006), digest-bound apply (0008), serverless only (0010).

## 3. What happened in AWS

1. **Bootstrap (Phase 3):** state bucket, OIDC roles per environment (plan read-only, apply, cleanup),
   permissions boundary for every workload role, budget. Applied from CloudShell with the same
   digest gate.
2. **Monitoring and findings (Phases 4–5):** the recorder and rules evaluated real resources; test
   fixtures (an unattached security group in a VPC without internet gateway, an empty private
   bucket, an empty log group) produced the violations for scenarios 2–4.
3. **Remediation window (Phase 6):** opened for the fixtures only, with entries expiring within
   7 days. Proven: an unlisted resource was refused; a bucket and a log group were fixed
   automatically and verified; an SSH revoke waited for the owner, was approved and verified; a
   second one was rejected and nothing changed. The window was then closed and the module removed.
4. **Reporting (Phase 7):** report, metrics and a DynamoDB recount gave the same numbers.
5. **Governance (Phase 8):** an insecure Terraform PR was blocked by CI; a console change was
   reported 10 s later as an unapproved change and caught by drift detection; GitHub settings were
   read back from the API.
6. **Cleanup (Phase 9):** a reviewed destroy digest, the evidence bucket emptied inside the approved
   run, 113 resources destroyed, and a before/after discovery diff showing nothing else changed.

## 4. Defects found in AWS and how they were fixed

Every defect below was found by running against real AWS, fixed with a regression test, and
recorded. **None caused an unintended change:** each one made the platform refuse or stop.

| Found | Defect | Fix |
|---|---|---|
| P5-10 | One finding per control and resource, but the last rule to report decided its compliance | Per-rule results, worst wins |
| P6-5 | SSM `ClientToken` must be a 36-character UUID; the gatekeeper sent 32 hex characters | Deterministic UUID; the test fake now validates every call against the botocore model |
| P6-6 | IAM: `StartAutomationExecution` is authorised on the document ARN; a repeated start failure crashed while holding the per-finding lock | Document ARNs granted; lock always released; no self-transition |
| P6-7 | Verification read Config's pre-remediation result | Ignore results recorded before the request |
| P6-8/9 | `PutRetentionPolicy` needs an integer; SSM rejects non-String parameters inside a longer string | `Integer` parameter; tests check every runbook API input against the botocore model |
| P6-9 | Attempt limit counted every attempt the finding ever had | Count per violation episode |
| P7-3 | Verification counted Lambda errors for a fixed list of functions | All project functions with metrics |
| P9-1 | Cleanup could not have worked: Object Lock bucket not emptied, recorder not removable by the cleanup role | Empty inside the approved destroy after the digest check; Region-limited recorder permissions for the cleanup role only |

## 5. Security properties

- **No stored credentials:** GitHub OIDC with immutable repository and owner IDs in the subject;
  the plan role is read-only; apply and cleanup need the owner's environment approval.
- **Apply only what was reviewed:** the digest covers the mode, addresses, actions and planned
  values; any difference stops the run before a change. A plan guard rejects deletes of protected
  resources and roles without the permissions boundary.
- **Least privilege at runtime:** every workload role has a boundary that denies IAM writes, audit
  service shutdown, key deletion, evidence tampering and self-approval.
- **Remediation cannot be steered:** exact-ARN allowlist with expiry, live re-check, attempt limit,
  per-finding lock, `aws:approve` with IAM-authenticated approvers; the gatekeeper is explicitly
  denied `ssm:SendAutomationSignal`.
- **Public repository hygiene:** account IDs, e-mail addresses, resource IDs and authorisation
  messages are redacted from CI logs; the public report is leak-scanned before it is shown.

## 6. Cost

Estimated in Phase 1 from the AWS Price List; measured in Phase 9 with Cost Explorer: **USD 1.12 of
usage for the whole account** over the project's days, fully covered by credits. The account is an
Organization member, so the `Project` cost-allocation tag can only be activated from the management
account and per-project figures could not be isolated.

## 7. Lessons

1. **Offline tests need the real API contracts.** Fakes that accepted anything hid four defects;
   validating calls against the botocore model would have caught them before AWS.
2. **Eventual consistency is a design input.** Verification has to wait for an evaluation recorded
   after the change, not read the latest one.
3. **Cleanup is a feature.** It needed its own permissions, its own ordering and its own tests.
4. **Fail closed pays off.** Every defect surfaced as a refusal or a stopped run, never as damage.

## 8. Limits

- Single account and Region; staging and prod configurations exist but were not deployed.
- Security Hub and GuardDuty integrations are tested offline only (SCP-denied in this account).
- Single maintainer: required approvals are 0 because GitHub does not let an author approve their
  own PR; the environment approvals are the human gate.
