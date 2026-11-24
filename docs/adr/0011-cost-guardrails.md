# ADR 0011: Cost guardrails: scoped recording, disabled optional services, tag budget, short windows

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Security services bill account-wide and can exceed the USD 25 budget if left on (estimate: USD 40–62 for 30 days with everything on). The budget only alerts, it does not cap.

## Decision

- Config recorder (create mode) records only the catalog's resource types, continuously (periodic recording costs USD 0.012 per CI-day vs 0.003 per change).
- Security Hub CSPM and GuardDuty off by default. Enabled only in approved windows (start/end recorded), with GuardDuty protection plans off and Security Hub with no default standards.
- USD 25 budget on `Project=acscg` (50/80 % actual, 100 % forecast). The existing account-wide budget is the backstop for non-taggable charges.
- Cost review at each phase boundary. Cleanup at the end of Phase 9.

## Consequences

- Some CIS/FSBP coverage is only demonstrated during windows.
- Tag-based budgets miss account-level service charges, hence the account-wide backstop.

## Alternatives considered

Always-on full monitoring: realistic for production, unjustified for a portfolio dev environment.
