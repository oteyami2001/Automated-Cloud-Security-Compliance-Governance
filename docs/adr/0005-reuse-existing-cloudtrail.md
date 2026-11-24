# ADR 0005: Reuse the existing CloudTrail trail and do not create a second one

- **Status:** Proposed (pending discovery D4)
- **Date:** 2026-11-24

## Context

EventBridge receives `AWS API Call via CloudTrail` management events only when a trail with logging enabled exists (to be confirmed against AWS docs in Phase 4). Project 2 created the single-Region trail `idp-management-events`. A second trail recording management events is billed as an additional copy (USD 2.00 per 100,000 events, AWS Price List 2026-11-02).

## Decision

- `cloudtrail` module in `integrate` mode: data source + validation that logging is on and log file validation is enabled. Plan fails if not.
- The project never modifies, stops or deletes the trail (permissions boundary deny + SEC-012 escalation).
- If discovery shows no trail: stop and ask the owner. Creating one is a separate approved decision.

## Consequences

- Dependency on another project's bootstrap resource. If Project 2's bootstrap is destroyed, SEC-012/015 lose their source. SEC-012 detects this (critical finding).

## Alternatives considered

New project trail: duplicate cost and duplicate audit records.
