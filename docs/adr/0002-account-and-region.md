# ADR 0002: Target account and Region

- **Status:** Proposed (pending owner confirmation, blocker B1)
- **Date:** 2026-11-24

## Context

Projects 1 and 2 used one AWS Organizations member account in us-east-2, where an SCP denies regional services in us-east-1. The prompt says not to assume this project must use the same account. No AWS access was available from the Phase 1 build environment.

## Decision

- **Proposed:** the same member account, **us-east-2 only**, dev environment only. Rationale: the shared OIDC provider and existing trail can be reused (lower cost), and the SCP behaviour is already understood.
- Isolation from Projects 1–2 by prefix `acscg-`, tag `Project=acscg`, a separate state bucket, and explicit IAM denies on `aiops-*`/`idp-*` resources.
- The account ID is never committed. It reaches Terraform as `TF_VAR_aws_account_id` and is enforced with `allowed_account_ids`.
- Final acceptance requires: owner confirmation of the account and Region, and the discovery report (D1–D13).

## Consequences

- Single-Region limitations L1 (IAM events not near-real time, CIS all-Region items unmet).
- Moving to a dedicated account later changes only variables, backend configuration and the OIDC lookup flag.

## Alternatives considered

A dedicated new account: cleaner isolation but out of scope (no new accounts may be created). us-east-1: SCP-denied (recorded in Project 2).
