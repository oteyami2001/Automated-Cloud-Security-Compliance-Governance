# Portfolio evidence

Legend (ADR 0001): 📝 planned · 🧱 implemented · ✅ tested offline · ☁️ verified in AWS · ⏳ waiting on owner.
Only observed results are recorded, each with a GitHub run ID, AWS evidence key or command output,
and a UTC timestamp. Account IDs, IPs and e-mail addresses are never recorded here.

## Phase 0: discovery

| ID | Item | Evidence | Status |
|---|---|---|---|
| P0-1 | Repository inspected | GitHub API `list_branches` → `[]`. Local clone: "No commits yet" (2026-11-24) | ✅ |
| P0-2 | AWS access from the build environment | `sts:GetCallerIdentity` → `InvalidClientTokenId` (2026-11-24). No AWS call succeeded | ✅ (blocked, recorded) |
| P0-3 | Discovery script read-only + redaction | `tests/unit/test_discovery_script.py` (static verb check + stubbed-CLI redaction test) | ✅ |
| P0-4 | Live discovery in CloudShell | owner run of `scripts/discover_aws.sh us-east-2 us-east-1` | ⏳ |
| P0-5 | Account and Region confirmed | owner confirmation | ⏳ |

## Phase 1: design

| ID | Item | Evidence | Status |
|---|---|---|---|
| P1-1 | Control catalog (15 controls) validates against schema and framework files | `python3 scripts/validate_catalog.py` → valid; `pytest` (see commit) | ✅ |
| P1-2 | Catalog safety invariants (report-only default, audit services never remediated, no "verified-in-aws" claims) | `tests/unit/test_control_catalog.py` mutation-style tests | ✅ |
| P1-3 | NIST IDs/titles verified against primary source | NIST OSCAL catalog Release 5.2.0 | ✅ |
| P1-4 | CIS/PCI/SOC 2 references | Secondary source only; primary pending | ⏳ |
| P1-5 | Diagrams render (Mermaid) | `mmdc` render of all 4 diagrams in the build environment (2026-11-24) | ✅ |
| P1-6 | Docs generated sections in sync | `scripts/sync_diagrams.py --check`, `scripts/render_control_tables.py --check` | ✅ |
| P1-7 | Unit prices for the cost model | AWS Price List API, publication dates in `docs/cost-model.md` | ✅ |

## Validation scenarios (Phase 9 target)

See `docs/validation-scenarios.md`. Rows are filled in only as each scenario runs.

| # | Scenario | Offline | AWS | Run ID / evidence | Timestamp (UTC) |
|---|---|---|---|---|---|
| 1–17 | — | 📝 | 📝 | — | — |
