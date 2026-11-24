# ADR 0009: Idempotency with DynamoDB conditional writes and a canonical finding key

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

EventBridge delivers at least once. Config re-evaluations and Security Hub can emit the same violation repeatedly. Duplicate remediation must be impossible (scenario 6).

## Decision

- Event-level: `PutItem` with `attribute_not_exists(pk)` on `EVENT#<event id>` (TTL 7 days).
- Finding-level: `finding_key = sha256(control | account | region | resource ARN)`. Updates use optimistic locking on a `version` attribute.
- Remediation-level: one `LOCK#<finding_key>` item per active execution (conditional put, TTL), plus at most 2 attempts.
- Notifications only on state transitions.

## Consequences

- One table, a few cheap conditional writes per event.
- Lambda async retry set to 0 for the gatekeeper. Retries happen only through the lifecycle.

## Alternatives considered

Lambda Powertools idempotency utility: adds a dependency and covers only the event level. Its pattern may still be adopted for the event-level layer in Phase 2.
