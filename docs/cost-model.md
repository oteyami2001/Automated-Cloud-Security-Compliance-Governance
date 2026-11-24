# Cost model

**Status: 📝 estimate (Phase 1).** Planning numbers, not a quote. Actual charges depend on how many
resources the account contains, how often they change, and which services already run account-wide.
Re-check before every deployment phase (prompt §15). **The USD 25 budget is an alert, not a cap.**
Free tier and free trials are **not** assumed.

## 1. Unit prices (US East (Ohio), us-east-2)

Source: AWS Price List bulk API (`https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/<service>/current/us-east-2/index.json`),
retrieved 2026-11-24. The marketing pricing pages were not reachable from the build environment.

| Service | Dimension | Price | Price list publication |
|---|---|---|---|
| AWS Config | Configuration item recorded (continuous) | USD 0.003 per CI | 2026-11-08 |
| AWS Config | Configuration item recorded (periodic/daily) | USD 0.012 per CI-day | 2026-11-08 |
| AWS Config | Rule evaluations | 0.001 (first 100k) / 0.0008 (next 400k) / 0.0005 (>500k) per evaluation | 2026-11-08 |
| AWS Config | Conformance pack evaluations | same tiers as rule evaluations (not used) | 2026-11-08 |
| CloudTrail | Management events, additional copy ("paid event") | USD 0.00002 per event (= 2.00 per 100k) | 2026-11-02 |
| CloudTrail | Data events | USD 0.000001 per event (= 1.00 per 1M; not used) | 2026-11-02 |
| Security Hub CSPM | Security checks (AWS) | 0.001 (first 100k) / 0.0008 (100k–500k) / 0.0005 (>500k) per check, per account per Region per month | 2026-11-19 |
| Security Hub CSPM | Finding ingestion | first 10,000/month free, then USD 0.00003 per event. Findings from Security Hub's own checks always free | 2026-11-19 |
| GuardDuty | CloudTrail management events analysed | USD 0.000004 per event (= 4.00 per 1M) | 2026-10-30 |
| GuardDuty | VPC Flow Log / DNS log analysis | paid tier not found in the extract (only the free-trial line). **Unverified** | 2026-10-30 |
| CloudWatch | Logs ingestion (Standard) | USD 0.50 per GB | 2026-11-19 |
| CloudWatch | Logs storage | USD 0.03 per GB-month | 2026-11-19 |
| CloudWatch | Custom metrics | USD 0.30 per metric-month (first 10,000) | 2026-11-19 |
| CloudWatch | Standard alarm | USD 0.10 per alarm-month | 2026-11-19 |
| X-Ray | Traces stored / accessed | USD 0.000005 / 0.0000005 per trace (5.00 / 0.50 per million) | 2026-11-08 |
| CloudWatch | Dashboard | not found in the extract. **Unverified** (commonly cited: 3 free, then USD 3/dashboard-month) | — |
| KMS | Customer managed key | USD 1 per key-month | 2026-11-08 |
| KMS | Symmetric requests | USD 0.03 per 10,000 (20,000/month free tier) | 2026-11-08 |
| DynamoDB | On-demand writes / reads | USD 0.625 / 0.125 per million request units | 2026-11-11 |
| DynamoDB | Storage | first 25 GB-month free, then USD 0.25 per GB-month | 2026-11-11 |
| Lambda | Requests / arm64 compute | USD 0.20 per million requests / 0.0000133334 per GB-s | 2026-11-20 |
| SNS | E-mail notifications | first 1,000/month free, then USD 2.00 per 100,000 | 2026-11-22 |
| EventBridge | AWS service events on the default bus | price list not available (404). **Unverified** (commonly free) | — |
| S3, SQS, SSM Automation, AWS Budgets | — | not retrieved. **Unverified**. Expected negligible at this volume, but a third budget in the account may carry a small daily charge | — |

## 2. Planning assumptions (dev)

| # | Assumption | Value | Confirm in |
|---|---|---|---|
| A1 | Resources of recorded types in us-east-2 (buckets, SGs, volumes, instances, IAM users/roles/policies, log groups, trails, Lambda, DynamoDB) | **150** (range 80–300) | Discovery D5/D13 |
| A2 | Config CIs on active build/demo days (Terraform applies, tests) | 100/day | Phase 4 actuals |
| A3 | Config CIs on idle days | 10/day | Phase 4 actuals |
| A4 | Rules evaluated per changed CI | ~3 | Rule scopes |
| A5 | Periodic evaluations (IAM and account-level rules, 24 h) | ~100/day | Phase 4 |
| A6 | Existing CloudTrail trail reused | yes, USD 0 | D4 |
| A7 | Customer managed KMS keys (state + evidence/SNS) | 2 | Phase 3 |
| A8 | Custom metrics / alarms / dashboards | ≤ 8 / 4 / 1 | Phase 7 |
| A9 | Security Hub CSPM, if enabled: checks per day with only the ~20 catalog-related controls enabled (no full standard) | 300–600 (full FSBP standard: 1,000–3,000) | Window approval |
| A10 | GuardDuty, if enabled: CloudTrail management events per day | 20,000–100,000 | D11 / CloudTrail |
| A11 | If Config is already recording all types (integrate mode) | the project adds only rule evaluations, no CI cost | D5 |

## 3. Estimates

### Core platform (Config rules + recorder for selected types, processing, evidence, notifications, dashboard; optional services off)

| Item | Formula | Day 1 (initial recording) | Active day | Idle day |
|---|---|---|---|---|
| Config CIs | A1 × 0.003 / A2 × 0.003 / A3 × 0.003 | 0.45 | 0.30 | 0.03 |
| Config evaluations | (A1 × A4 + A5) × 0.001 / (A2 × A4 + A5 + 50 re-evals) × 0.001 / (A3 × A4 + A5) × 0.001 | 0.55 | 0.45 | 0.13 |
| KMS (2 keys) | 2 × 1 / 30 | 0.07 | 0.07 | 0.07 |
| CloudWatch (8 metrics, 4 alarms, logs; dashboard unverified) | (2.40 + 0.40 + 0.03) / 30, + 0.10 if the dashboard is billed | 0.09–0.19 | 0.09–0.19 | 0.09–0.19 |
| Lambda, DynamoDB (incl. PITR on a table well under 1 MB at USD 0.20/GB-month), SQS, SNS, S3, SSM, X-Ray (< 1,000 traces/day ≈ USD 0.005) | volume-based, < 1,000 events/day | < 0.05 | < 0.05 | < 0.01 |
| **Total** |  | **≈ 1.20–1.30** | **≈ 0.95–1.05** | **≈ 0.33–0.43** |

### Optional integrations (only in an approved window)

| Item | Formula | Per day |
|---|---|---|
| Security Hub CSPM, catalog-related controls only | 300–600 × 0.001 | 0.30–0.60 |
| Security Hub CSPM, full FSBP standard | 1,000–3,000 × 0.001 | 1.00–3.00 |
| GuardDuty, foundational only, protection plans off | 20k–100k × 0.000004 + flow/DNS (unverified, low: no workloads) | 0.08–0.40 + ? |
| Additional CloudTrail trail (avoided, ADR 0005) | events × 0.00002 | e.g. 50k events → 1.00 |

### Scenarios

| Scenario | Composition | Estimate |
|---|---|---|
| Demonstration window (recommended) | 3 days core (day 1 + 2 active) + Security Hub (catalog controls) for 2 days + GuardDuty for 2 days | **≈ 4.0–5.5** (+ unverified GuardDuty flow/DNS analysis) |
| Same, full FSBP standard instead | as above with full standard | ≈ 5.5–10.5 |
| Monthly, core platform left running mostly idle | 4 active days + 26 idle days | **≈ 12.5–15.5** |
| 30-day equivalent, everything on and active | 30 × (core active + Security Hub catalog controls + GuardDuty) | ≈ 40–62, **above the USD 25 budget**: do not leave optional services on |

## 4. Budget and guardrails

- `acscg` cost budget: USD 25/month, filtered on the cost-allocation tag `Project=acscg`. Alerts at
  50 % and 80 % actual, and 100 % forecast. The tag must be activated as a cost-allocation tag first
  (Phase 3 step). **Account-wide services** (Config recorder, Security Hub, GuardDuty) are **not
  tag-attributable**, so the existing account-wide budget (`aiops-account-monthly`, if confirmed)
  remains the backstop.
- Optional services default `disabled`. Enabling either requires an approved window with a
  start/end time recorded in `docs/portfolio-evidence.md`, and a cleanup run at the end.
- Config recorder (create mode) records only the resource types in the catalog, with continuous
  recording. Daily (periodic) recording costs 4× more per CI here and is not used.
- No EC2, ECS, EKS, RDS, ALB or NAT Gateway resources.
- Cost review at each phase boundary: Cost Explorer by service, last 7 days (one request, USD 0.01).

## 5. What can make this wrong

- A much larger resource count (A1) or frequent churn from other projects in the same account.
- An existing Config recorder that records all resource types (more rule evaluations), or
  Security Hub already enabled with all standards (its cost is already being paid, so not caused
  by this project, but it is visible).
- The unverified items in §1 (dashboard, GuardDuty flow/DNS analysis, EventBridge, Budgets).
