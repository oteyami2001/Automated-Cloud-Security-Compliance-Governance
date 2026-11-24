# Threat model

**Status: 📝 planned (Phase 1).** Method: STRIDE per trust boundary (`diagrams/trust-boundaries.mmd`),
scored likelihood × impact (L/M/H). Mitigation status uses ADR 0001 (📝 / 🧱 / ✅ / ☁️).

## 1. Assets

| Asset | Why it matters |
|---|---|
| A1 Remediation capability (gatekeeper, execution roles) | Can change real resources: the most dangerous capability in the system |
| A2 Audit evidence and reports | Must be trustworthy for audits. Integrity matters more than confidentiality |
| A3 Findings database | Drives notifications, remediation and reports |
| A4 CI/CD identities (OIDC roles) | Can create and destroy the platform |
| A5 Pre-existing security services and other projects' resources | Must not be modified or disabled |
| A6 Account identifiers, approver identities, resource names | Reconnaissance value in a public repository |
| A7 Cost | Security services bill account-wide |

## 2. Threats

| ID | Boundary | STRIDE | Threat | L | I | Mitigations | Status |
|---|---|---|---|---|---|---|---|
| T-01 | TB2→TB3a | Spoofing | Forged "Config" or "GuardDuty" event injected to trigger remediation | L | H | `aws.*` sources cannot be put by customers. Rules match `source` exactly. Synthetic source handled separately and never remediated. Gatekeeper re-reads live state | 📝 |
| T-02 | TB3a→TB3b | Elevation | Confused deputy: a finding for an unrelated resource drives remediation | M | H | Exact-ARN allowlist + ownership inventory + protected list + IAM scoping of execution roles to allowlisted ARNs | 📝 |
| T-03 | TB3b | Spoofing | Attacker tags a foreign resource `Project=acscg` to get it "fixed" (or broken) | M | M | Tags never authorise (ADR 0006). The allowlist is in Terraform, behind PR review and apply approval | 📝 |
| T-04 | TB4 | Spoofing | Approval forged via a forwarded e-mail link or a replayed token | L | H | No links or tokens. Approval = authenticated `SendAutomationSignal` by a listed principal | 📝 |
| T-05 | TB4 | Elevation | Automation approves its own request | L | H | Deny `ssm:SendAutomationSignal` to all project roles. Approver list validated by test | 📝 |
| T-06 | TB3b | Tampering | Remediation loop or event storm repeatedly modifies a resource | M | M | Idempotency keys, one lock per finding, ≤ 2 attempts, reserved concurrency 5, alarm on remediation count | 📝 |
| T-07 | TB3b | Tampering | Remediation removes more than intended (whole SG, all rules, bucket policy) | L | H | Action by rule ID only. Before/after diff verification. Rollback step. Runbook unit tests | 📝 |
| T-08 | TB6 | Tampering / Repudiation | Evidence altered or deleted to hide an incident | L | H | Object Lock (governance), versioning, delete deny in the bucket policy, SHA-256 per object + daily hashed manifest, CloudTrail records bucket API calls. **Residual:** governance bypass by a privileged admin, so evidence is "tamper-evident" | 📝 |
| T-09 | TB1 | Elevation | Malicious PR obtains AWS credentials | M | H | No OIDC trust for `pull_request`. Environment-bound subjects with immutable IDs. Required reviewers. Fork workflows get no secrets | 📝 |
| T-10 | TB1 | Tampering | Reviewed plan differs from the applied plan (TOCTOU) | M | H | Digest-bound apply (ADR 0008), mode-bound digest, fail closed | 📝 |
| T-11 | TB1 | Tampering | Supply-chain compromise of a GitHub Action or Python dependency | M | H | Actions pinned to commit SHAs, Dependabot, zizmor/actionlint, pinned dependencies (hashes in Phase 8), minimal `permissions:` | 📝 |
| T-12 | TB7 | Information disclosure | Account ID, IPs, e-mails or ARNs leak via CI logs, reports or commits | H | M | Masking, redaction in report generator, gitleaks/Trivy secret scan, discovery output git-ignored, tests on redaction | 📝 |
| T-13 | TB5 | Tampering / DoS | Terraform takes ownership of, or destroys, a pre-existing service (Config recorder, trail) | M | H | `integrate` mode = data sources only. Plan guard rejects changes to protected addresses/types. Cleanup verification of pre-existing services | 📝 |
| T-14 | TB5 | Tampering | Another project's broad apply role (AIOps) modifies ACSCG resources | L | M | Out of scope to fix (recorded in Project 2). SEC-015 detects unauthorised changes. Drift detection | 📝 |
| T-15 | TB3a | DoS | Malformed or huge events crash the processor, so findings are lost | M | M | Schema validation, size limit, DLQ, alarm on DLQ depth > 0 | 📝 |
| T-16 | TB3a | Repudiation | Who changed what cannot be established | L | M | CloudTrail (existing trail), structured logs with correlation IDs, lifecycle history items | 📝 |
| T-17 | TB3a/3b | Elevation | `iam:PassRole` abuse: gatekeeper passes a powerful role to SSM | L | H | PassRole limited to 4 named execution roles with `iam:PassedToService = ssm.amazonaws.com` | 📝 |
| T-18 | A7 | DoS (financial) | Enabling Security Hub/GuardDuty or recording all resource types runs up cost | M | M | Off by default, explicit flags, approved windows, recorded resource types only, budget alerts, cost review per phase | 📝 |
| T-19 | TB3a | Information disclosure | Notifications leak sensitive configuration to e-mail | M | L | Minimal message content. KMS topic. Subscription confirmation required | 📝 |
| T-20 | TB5 | Elevation | SCP or account changes make the platform fail open (e.g. checks skipped on AccessDenied) | L | H | Fail closed: any error in the gatekeeper → deny. Evaluator errors → finding `ERROR`, not `COMPLIANT` | 📝 |
| T-21 | TB3a | Tampering | Exception records used to silence real findings indefinitely | M | M | Exceptions expire (≤ 90 days), require approver and ticket, and appear in every report | 📝 |

## 3. Abuse cases that become tests

| Test (phase) | Expectation |
|---|---|
| Synthetic event with `remediation_eligible` forced on (P2) | Gatekeeper rejects: source is synthetic |
| Allowlist entry for a different Region (P2/P6) | `REJECTED_POLICY`, no AWS write call issued |
| Tag-only "authorisation" (P2/P9, scenario 7) | Rejected |
| Duplicate event ×3 (P2/P9, scenario 6) | One finding, one notification, one remediation |
| Approver = gatekeeper role (P2) | Configuration test fails |
| Plan touching `aws_config_configuration_recorder` in integrate mode (P2) | Plan guard fails CI |
| Gatekeeper raises any exception (P2) | Decision = deny |

## 4. Residual risks accepted for a portfolio dev environment

- Governance-mode Object Lock (L4). Compliance mode would block verified cleanup.
- Single-Region detection (L1).
- Shared account blast radius (T-14).
- Approver is the same person as the repository owner (one-person project). Separation of duties is
  implemented technically (different principals) but not organisationally.
