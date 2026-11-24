# ADR 0003: Integrate with, never take ownership of, account-level security services

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Config recorders (one customer-managed recorder per Region), CloudTrail trails, Security Hub CSPM, GuardDuty and Access Analyzer are account-level. If Terraform imports or recreates them, a later `destroy` would disable security monitoring that existed before this project. That is the worst possible side effect for a security project.

## Decision

Each service module has `ownership_mode`:
- `integrate`: **data sources only**. The project consumes events and findings and adds only its own rules. No `import` blocks. A plan guard rejects any change to these resource types in this mode.
- `create`: only when discovery shows the service absent **and** the owner approves. The resource is then tagged `Project=acscg`, and cleanup removes it.
- `disabled`: the module creates nothing (default for Security Hub CSPM and GuardDuty).
Cleanup verification compares the state of pre-existing services before and after (scenario 17).

## Consequences

- Some settings (e.g. the existing recorder's resource-type scope) are outside the project's control and are reported as limitations, not changed.
- Two modes per module to test (mocked-provider tests for both).

## Alternatives considered

`terraform import` of existing services: rejected (destroy risk, ownership confusion).
