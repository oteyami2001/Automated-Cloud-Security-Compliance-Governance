# ADR 0006: Report-only default, three remediation modes, allowlist-based authorization, SSM approval

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Automated remediation can cause outages or be abused as a confused deputy. The prompt requires report-only by default, an explicit enable flag and allowlist, distrust of tags, and human approval for higher-risk changes.

## Decision

- Modes: 1 report-only (default everywhere), 2 automatic for catalog-`auto_low_risk` controls, 3 human-approved.
- A remediation requires **all**: enable flag, mode, catalog eligibility, exact-ARN allowlist entry matching account/Region/control/action with an expiry, project-owned resource, not protected, live re-check, lock, attempt limit. Any error means deny.
- **Tags are never authorisation.**
- Execution through SSM Automation documents with per-runbook roles scoped by IAM to the allowlisted ARNs. Mode 3 uses the native `aws:approve` step: the approver must be a listed IAM principal acting authenticated. E-mails contain no approval links.
- Verification and rollback steps are part of every document.

## Consequences

- More configuration to open a demo window (PR + reviewed apply), which is intended friction.
- Approval UX is the console/CLI, not a one-click e-mail link.

## Alternatives considered

Custom approval tokens in DynamoDB with API Gateway links: more code and a bearer-token risk. Step Functions callback: workable, but more resources and no gain over `aws:approve` for single-step approvals.
