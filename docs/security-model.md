# Security model: IAM and remediation authorization

**Status: 📝 planned (Phase 1 design).** Policies are written as intent here. They become
Terraform and policy tests in Phases 2–3 and are verified in AWS in Phase 3+.

## 1. Identities

| Role (prefix `acscg-`) | Assumed by | Trust condition | Purpose | Can write to |
|---|---|---|---|---|
| `github-plan` | GitHub Actions | OIDC `aud = sts.amazonaws.com`, `sub = repo:oteyami2001@<owner-id>/<repo>@<repo-id>:environment:dev-plan` (StringEquals, immutable IDs) | `terraform plan`, drift detection | State lock object only |
| `github-apply` | GitHub Actions | `…:environment:dev` (required reviewers) | Apply the reviewed plan | Project resources (tag/name-scoped), state |
| `github-report` | GitHub Actions | `…:ref:refs/heads/main` + workflow `compliance-report.yml` (`job_workflow_ref`) | Invoke the report generator, read reports | Nothing (invoke only) |
| `github-cleanup` | GitHub Actions | `…:environment:dev-cleanup` (required reviewers) | Approved destroy of project resources | Project resources; `s3:BypassGovernanceRetention` on the evidence bucket only |
| `findings-processor` | Lambda | `lambda.amazonaws.com`, `aws:SourceAccount` | Process events | Own table, `evidence/` prefix, SNS topic, SQS DLQ, own logs |
| `remediation-gatekeeper` | Lambda | `lambda.amazonaws.com` | Decide and start runbooks | Own table items (`REM#`, `LOCK#`), `ssm:StartAutomationExecution` on the 4 `acscg-*` documents, `iam:PassRole` on the 4 execution roles only |
| `rem-sg-exec` | SSM Automation | `ssm.amazonaws.com`, `aws:SourceAccount`, `aws:SourceArn` = acscg documents | Revoke one SG ingress rule | `ec2:RevokeSecurityGroupIngress` on **allowlisted SG ARNs** only |
| `rem-s3-exec` | SSM Automation | as above | Bucket-level public access block | `s3:PutBucketPublicAccessBlock` on allowlisted bucket ARNs only |
| `rem-tags-exec` | SSM Automation | as above | Add missing tags | `tag:TagResources` + service tag action, allowlisted ARNs, `aws:TagKeys` limited to required keys |
| `rem-logs-exec` | SSM Automation | as above | Set log retention | `logs:PutRetentionPolicy` on allowlisted log group ARNs |
| `report-generator` | Lambda | `lambda.amazonaws.com` | Build reports | `reports/`, `manifests/` prefixes |
| Approver(s) | Humans (IAM Identity Center or IAM, MFA) | Their own sign-in | Approve or reject Mode 3 requests | `ssm:SendAutomationSignal` on `acscg-*` executions only |

No IAM users or access keys are created. The OIDC provider is looked up, not managed.

## 2. Permissions boundary `acscg-workload-boundary`

Attached to every role the project creates (the apply role may create roles only with
`iam:PermissionsBoundary = acscg-workload-boundary`). It allows the union of the project's needs
and **explicitly denies**:

| Denied | Why |
|---|---|
| `iam:*` except `iam:PassRole` on `acscg-*` execution roles (workload roles), and IAM writes on `aiops-*`, `idp-*` and the OIDC provider (all roles) | Never modify IAM administrator permissions or other projects |
| `organizations:*`, `account:*` | Never touch organization policies or account settings |
| `cloudtrail:StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` | Existing audit service |
| `config:StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel`, `PutConfigurationRecorder` (unless `config_ownership_mode = create`, apply role only) | Existing audit service |
| `securityhub:Disable*`, `securityhub:DeleteMembers`, `guardduty:DeleteDetector`, `guardduty:UpdateDetector` (unless ownership `create`) | Existing security services |
| `kms:ScheduleKeyDeletion`, `kms:DisableKey`, `kms:PutKeyPolicy` (workload roles) | Encryption keys |
| `s3:DeleteObject*`, `s3:PutBucketObjectLockConfiguration`, `s3:BypassGovernanceRetention`, `s3:PutLifecycleConfiguration` on the evidence bucket (all except the cleanup role, and Terraform for lifecycle) | Audit evidence |
| `ec2:ModifyVpcAttribute`, `ec2:*NetworkAcl*`, `ec2:EnableEbsEncryptionByDefault`, `ec2:DisableEbsEncryptionByDefault`, `s3:PutAccountPublicAccessBlock` | Account-wide network and storage settings |
| Any action outside the approved Region (`aws:RequestedRegion`), except global services | Region scope |

## 3. Remediation modes

| Mode | Name | When it runs | Default |
|---|---|---|---|
| 1 | Report only | Always available. Detect, record, notify | **Yes, all environments** |
| 2 | Automatic, low risk | `remediation_mode = auto_low_risk` **and** `remediation_enabled = true` **and** catalog eligibility `auto_low_risk` **and** allowlist match | No |
| 3 | Human-approved | `remediation_mode = human_approval` (or `auto_low_risk`, which includes Mode 3) **and** enabled **and** eligibility ∈ {`auto_low_risk`, `human_approval`} **and** allowlist match **and** approver decision | No |

Catalog eligibility per control (`controls/control-catalog.yaml`):

| Eligibility | Controls |
|---|---|
| `auto_low_risk` | SEC-001 (bucket-level BPA), SEC-013 (add missing tags), SEC-014 (set retention on never-expire groups) |
| `human_approval` | SEC-005, SEC-006 (revoke one SG rule), SEC-008 (IMDSv2) |
| `report_only` | SEC-002, 003, 004, 007, 009, 010, 011, 015 |
| `escalate` | SEC-012 (CloudTrail) |

## 4. Authorization decision (gatekeeper)

The gatekeeper is a pure decision function plus a thin AWS adapter. The decision is logged with
every input and stored as evidence. Inputs come from the DynamoDB finding, the Terraform-rendered
policy (`policies/remediation/`), and **live AWS reads**. The event payload is never trusted.

```
deny unless all:
  env.remediation_enabled == true
  env.remediation_mode in allowed_modes(control.eligibility)
  entry := allowlist.match(account, region, resource_arn, control_id, action)  # exact ARN, no wildcards
  entry.expires_at > now
  resource.ownership == "project-owned"        # allowlist AND Terraform state inventory
  resource_arn not in protected_resources      # pre-existing violations from discovery (D13)
  live_state(resource) still violates control  # re-read, not the event
  action in control.remediation.action_set     # e.g. revoke rule by ID, never "delete group"
  no active LOCK#finding and attempts < 3
then:
  Mode 2 → start runbook without approval step
  Mode 3 → start runbook whose first step is aws:approve (approvers = policy.approvers, MinRequiredApprovals = 1)
```

**Tags are never sufficient.** A resource tagged `Project=acscg` that is not on the allowlist is
rejected (scenario 7). A resource on the allowlist whose live account or Region differs is rejected.

### Approval (Mode 3)

- Approval uses the SSM Automation `aws:approve` action. The approver must be an IAM principal on
  the `Approvers` list and must call `ssm:SendAutomationSignal` while authenticated. SNS e-mails
  carry no approve link and no token: a forwarded e-mail cannot approve anything.
- Separation of duties: the CI roles, the gatekeeper and the execution roles are denied
  `ssm:SendAutomationSignal`. The approver list excludes them by construction (validated by a test).
- Timeout 4 h → the execution fails, and the finding records `APPROVAL_EXPIRED`. Rejection →
  `REMEDIATION_REJECTED`. Neither changes the resource (scenario 10).
- Evidence stores the approver ARN (redacted to the role/user name in public reports), the
  decision, the comment and the timestamps from `GetAutomationExecution`.

### Runbook safety pattern (every SSM document)

1. `aws:assertAwsResourceProperty`: re-check the precondition (e.g. the rule ID still exists with 0.0.0.0/0).
2. `aws:executeScript`: capture the before-state into the step output (also written to evidence).
3. (Mode 3) `aws:approve`.
4. `aws:executeAwsApi`: the single scoped change.
5. `aws:executeAwsApi`: `StartConfigRulesEvaluation` for the control's rule.
6. `aws:waitForAwsResourceProperty` / script: verify the after-state (rule gone, other rules unchanged).
7. `onFailure`: rollback step where supported (re-authorise the captured rule, restore the captured
   PublicAccessBlock, remove only the added tag keys), then `Abort`.

Retries: at most 2 runbook attempts per finding, never in a loop. A third failure escalates.

## 5. Data protection

| Data | Protection |
|---|---|
| Findings (DynamoDB) | AWS owned key encryption (default). Customer managed key in the prod reference |
| Evidence and reports (S3) | SSE-KMS CMK, Bucket Key, TLS-only, Object Lock (governance), versioning |
| SNS | KMS-encrypted topic. Messages carry finding key, control, severity, resource type and short ID, never full policies or secrets |
| Logs | Structured JSON. Account IDs masked. No event payload dumps at INFO level. 30-day retention (dev) |
| CI | `::add-mask::` for the account ID. No `terraform show` of sensitive values. Plan files never uploaded |
| Terraform variables | `aws_account_id`, `alert_email`, approver ARNs supplied as `TF_VAR_*` from GitHub environment secrets/variables, marked `sensitive` |

## 6. What the platform will never change automatically

IAM administrator permissions; production workloads; organization SCPs; existing security services
(CloudTrail, Config recorder, Security Hub CSPM, GuardDuty, Access Analyzer); unrelated resources;
account-wide network settings; encryption keys; audit evidence. Each item is enforced at three
layers: catalog eligibility (validated in CI), gatekeeper policy, and IAM (boundary + execution-role scope).
