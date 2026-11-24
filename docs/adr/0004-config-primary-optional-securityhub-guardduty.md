# ADR 0004: AWS Config is the primary detection engine. Security Hub CSPM and GuardDuty are optional

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The control catalog is configuration-centric. Security Hub CSPM and GuardDuty bill account-wide (security checks; analysed events and logs) and may already be enabled. The prompt requires both to be optional with explicit flags, and the platform must work without them.

## Decision

- Detection for SEC-001…014 comes from **AWS Config rules** (managed where suitable, custom Lambda evaluators where needed), delivered **directly** through EventBridge (`Config Rules Compliance Change`).
- SEC-012/015 use **CloudTrail management events through EventBridge**.
- `enable_security_hub` and `enable_guardduty` default `false`. When enabled, their findings enter the same normaliser. Security Hub findings generated from Config rules are filtered out at the rule to avoid double counting, and `finding_key` merges any that remain.
- If enabled, Security Hub CSPM starts with **no default standards**. Only catalog-related controls are enabled, to limit checks.
- GuardDuty findings are always report-only.

## Consequences

- Lower baseline cost. Fewer moving parts in the default path.
- Security Hub's cross-account aggregation is not used (single account).

## Alternatives considered

Security Hub as the central bus for everything: higher cost and a hard dependency on an optional service.
