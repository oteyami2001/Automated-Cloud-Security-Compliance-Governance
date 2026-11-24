# ADR 0008: Apply only the exact reviewed plan (digest-bound, fail closed)

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The prompt requires applying only the exact reviewed plan. In a public repository, uploading binary plan files would expose resource details. Project 2 verified a digest-based mechanism in AWS.

## Decision

- Reuse Project 2's mechanism: SHA-256 over mode + sorted planned changes (address, actions, after-values) from `terraform show -json`. The apply job re-plans from the same commit and refuses unless the digest equals the reviewer-supplied digest. A non-plan document fails closed.
- Add a **plan guard** (protected types/addresses in integrate mode, evidence deletion, roles without boundary).
- Destroy uses the same mechanism with a mode-bound digest, a typed confirmation and a separate environment.

## Consequences

- Any drift between review and apply forces a new review, which is intended.
- Unknown-after-apply values are hashed as unknown markers. Consistent with Project 2.

## Alternatives considered

Uploading the plan artifact: exposes details in a public repository. Apply without re-check: TOCTOU risk.
