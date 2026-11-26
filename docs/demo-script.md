# Demo script (5 minutes)

The stack is destroyed after validation, so the demo uses the repository, the recorded runs and the
screenshots. To demo live, rebuild first ([rebuild.md](rebuild.md), about 15 minutes plus ~30
minutes for Config's first evaluation).

## 0:00 – The problem (30 s)

"Misconfigurations like public buckets or SSH open to the internet are found late and fixed by hand.
Automatic fixing helps, but a bot with broad write access is a risk of its own. This platform detects,
fixes only what is explicitly allowed, and proves what it did."

## 0:30 – Architecture (1 min)

README → architecture diagram. Walk the lifecycle: **Config and CloudTrail → EventBridge → findings
processor → gatekeeper → SSM runbook → Config verifies → evidence in S3 with SHA-256 and Object Lock.**
Point out: report-only by default, exact-ARN allowlist with expiry, human approval for high risk.

## 1:30 – Results (1 min)

README → "Results at a glance" and the posture screenshot: 86.5 %, 74 resources, 10 open, 2 verified
remediations. Then the compliance-report screenshot: "the stored report, the CloudWatch metrics and
a fresh DynamoDB count are equal, and the public report passed a leak scan."

## 2:30 – Remediation, safely (1 min)

portfolio-evidence → P6-8 and P6-10: the bucket fixed automatically and verified; the SSH revoke
waited for my approval (approver identity and comment recorded); a second one I rejected changed
nothing. "And when things went wrong in AWS, every defect made the platform stop, never change
something it should not."

## 3:30 – Governance (1 min)

- Draft PR #34: insecure Terraform blocked by Checkov, Trivy and `terraform test`.
- Issue #35: a console change reported as an unapproved change 10 seconds later, drift detected,
  restored through a reviewed apply.
- Actions → terraform-apply: every AWS change is a digest-bound, owner-approved run with OIDC.

## 4:30 – Cost and cleanup (30 s)

USD 1.12 of usage for the whole account, covered by credits. 113 resources destroyed after a reviewed
destroy digest, and a before/after diff showing nothing else in the account changed.
