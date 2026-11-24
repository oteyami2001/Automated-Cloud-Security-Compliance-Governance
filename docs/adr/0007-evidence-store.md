# ADR 0007: Evidence store: SSE-KMS, versioning, Object Lock in governance mode, checksums

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Audit evidence must be encrypted, retained, access-restricted and integrity-checkable, separate from operational logs. The project must also be verifiably cleaned up, and must not describe evidence as tamper-proof unless that is implemented and verified.

## Decision

- Dedicated bucket, SSE-KMS with a project CMK, Bucket Key, versioning, **Object Lock governance mode** (dev 7 days default retention), TLS-only and KMS-only bucket policy, delete denied to all but the cleanup role.
- Each evidence document is canonical JSON with a SHA-256 checksum stored in object metadata and DynamoDB. A daily manifest hashes all keys and checksums.
- Wording: **tamper-evident**. Governance mode can be bypassed by principals holding `s3:BypassGovernanceRetention`, which only the approved cleanup role has.

## Consequences

- Cleanup of dev is possible (governance bypass in the approved cleanup workflow).
- One CMK costs USD 1/month.
- Compliance mode (true WORM) is documented as the prod recommendation, subject to an organisational decision.

## Alternatives considered

Compliance-mode Object Lock in dev: blocks verified cleanup for the retention period. SSE-S3: no key-level access control.
