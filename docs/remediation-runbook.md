# Remediation runbook (operator procedures)

**Status:** runbooks, gatekeeper and policy are 🧱 implemented and ✅ tested offline (Phase 2). The
commands below do nothing until the remediation module is deployed (Phase 6) and a window is opened.

## 1. Default state

Every environment runs in **report-only** mode (`remediation_mode = "report_only"`,
`remediation_enabled = false`). Findings are recorded and notified. Nothing is changed.

## 2. Opening a remediation window (dev only)

1. PR changing `policies/remediation/dev.yaml`: `remediation_enabled: true`,
   `remediation_mode: human_approval` (or `auto_low_risk`), and allowlist entries (exact ARNs with
   `${account_id}`, control, action, `expires_at` ≤ 7 days ahead, and tag values in `parameters` for SEC-013).
   The JSON Schema, `parse_policy` and Terraform preconditions validate it.
2. Review → merge → `terraform-plan` → review the digest → `terraform-apply` with approval.
3. Record the window start in `docs/portfolio-evidence.md`.
4. Close the window the same way (flags back to report-only, allowlist emptied).

## 3. Approving or rejecting a Mode 3 request

The SNS e-mail names the finding, control, resource and proposed action. It contains **no** link
that approves anything.

```bash
aws ssm get-automation-execution --automation-execution-id <execution-id> --query "AutomationExecution.{Doc:DocumentName,Status:AutomationExecutionStatus,Params:Parameters}"
```

```bash
aws ssm send-automation-signal --automation-execution-id <execution-id> --signal-type Approve --payload "Comment=<ticket and reason>"
```

```bash
aws ssm send-automation-signal --automation-execution-id <execution-id> --signal-type Reject --payload "Comment=<reason>"
```

Approve only when: the resource is the allowlisted test resource, the proposed change is exactly the
rule/setting in the finding, and nothing depends on it. Timeout is 4 hours. No answer means no change.

## 4. Rollback

| Runbook | Rollback |
|---|---|
| `acscg-RestrictSecurityGroupIngress` | Automatic on failed verification. Manual: re-authorise the captured rule from the evidence record (`before.rule`) |
| `acscg-EnableBucketPublicAccessBlock` | Restore the captured `PublicAccessBlockConfiguration` |
| `acscg-EnforceRequiredTags` | Remove exactly the keys listed in `evidence.added_tag_keys` |
| `acscg-SetLogRetention` | `DeleteRetentionPolicy`. Already expired data cannot be restored, which is why the runbook refuses when older data exists |

## 5. Escalation

SEC-012 (CloudTrail) and any `VERIFICATION_FAILED` or `REMEDIATION_FAILED` state page the operator.
The platform never modifies the trail or retries more than twice.

## 6. Exceptions

Add to `policies/exceptions/exceptions.<env>.yaml` via PR: control, exact resource ARN, reason,
ticket, approver, expiry (≤ 90 days, or the control's stricter maximum). Expired exceptions re-open
the finding automatically and are listed in every report.
