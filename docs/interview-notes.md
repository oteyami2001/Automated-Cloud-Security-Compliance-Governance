# Interview notes

Short answers to questions this project invites. Evidence IDs refer to
[portfolio-evidence.md](portfolio-evidence.md).

**Why not let the platform fix everything automatically?**
A remediation bot with write access is a confused deputy. Here, remediation needs an enable flag, an
exact-ARN allowlist entry that expires, a live re-check that the violation still exists, an attempt
limit and a per-finding lock; high-risk changes also need an IAM-authenticated approval. Tags never
authorise anything (ADR 0006).

**How do you stop the gatekeeper approving its own changes?**
Its role and the permissions boundary explicitly deny `ssm:SendAutomationSignal`. Approvers are IAM
principals listed in the policy; the root user can never approve.

**How do you make sure what you apply is what was reviewed?**
The plan prints a SHA-256 digest of the planned changes; the apply re-plans and stops unless the
digest matches, after the owner approves the protected environment (ADR 0008). A destroy digest can
never equal an apply digest because the mode is part of it.

**Why OIDC?**
No long-lived keys in GitHub. Trust policies match the immutable repository and owner IDs plus the
environment, so a recreated repository with the same name, or a pull request, cannot assume the roles.

**What went wrong, and what did you learn?**
Seven defects in Phase 6 alone, for example a `ClientToken` format SSM rejects and verification
reading Config's stale result (P6-5…P6-9). Each made the platform refuse or stop, never cause damage.
The lesson: offline fakes must validate against the real API model; I now check every call and every
runbook input against botocore.

**How do you handle eventual consistency?**
Verification ignores Config results recorded before the remediation started; without a newer one,
the finding waits in `VERIFYING` until the next evaluation decides it (P6-7).

**How is the evidence tamper-evident?**
Each transition writes JSON with a SHA-256 checksum to a KMS-encrypted, versioned bucket with Object
Lock (governance). The verify workflow recomputes checksums. Only the cleanup role can bypass the lock.

**What does it cost?**
Measured USD 1.12 of usage for the whole account over the project's days (credits covered it). It is
serverless with no EC2, NAT, RDS or load balancers; Config is the main cost driver.

**How did you clean up safely?**
A read-only destroy plan, then an owner-approved destroy with the reviewed digest and a typed
confirmation; the evidence bucket was emptied only after the digest matched; a before/after discovery
diff proved nothing outside the project changed (P9-3, P9-4).

**What would you do next?**
Multi-account with an Organization aggregator and delegated administrator; Security Hub and GuardDuty
where allowed; per-project cost visibility through the management account's tag activation.
