# ADR 0001: Record architecture decisions and a four-level status vocabulary

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Portfolio documentation tends to blur "designed", "coded", "tested" and "running in AWS". Reviewers and interviewers need to know which is which, and the project rules forbid claiming deployment without evidence.

## Decision

1. Significant decisions are recorded as ADRs in `docs/adr/` (context, decision, consequences, alternatives).
2. Every capability, control and scenario carries exactly one status: **planned** (📝), **implemented** (🧱, code exists), **tested offline** (✅, automated tests pass without AWS), **verified in AWS** (☁️, observed in AWS, with a run ID or evidence key and a UTC timestamp).
3. `verified-in-aws` cannot be set in the control catalog without evidence. The catalog validator rejects it in Phase 1, and later phases replace that check with an evidence-reference check.

## Consequences

- Documentation is longer, but every claim can be traced.
- Matches the evidence tables of Projects 1 and 2, so the three projects read consistently.

## Alternatives considered

Free-form status text: rejected because it cannot be validated.
