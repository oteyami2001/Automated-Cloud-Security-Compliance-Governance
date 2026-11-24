# ADR 0012: One stack root with per-environment variable files

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

Phase 1 planned `terraform/envs/{dev,staging,prod}/` as thin root modules. Three copies of the
same composition drift apart over time. Only dev is deployed, while staging and prod must still be
validated as reference configurations (prompt §7).

## Decision

- One root module, `terraform/stack/`, composes every module. `terraform/envs/<env>/` holds only
  `terraform.tfvars` (non-sensitive values) and `backend.hcl.example`. Each environment has its
  own state key (`stack/<env>/terraform.tfstate`).
- Every environment is validated in CI by `terraform test -filter=tests/environments.tftest.hcl
  -var-file=../envs/<env>/terraform.tfvars`. These invariants hold for all of them: report-only,
  no ownership of account-level services, synthetic events and fixtures in dev only, and prod
  deletion protection, PITR and 365-day logs. A negative check (synthetic events in staging)
  proved the variable files are actually applied.
- The bootstrap stays a separate root (applied once, from CloudShell, in Phase 3).

## Consequences

- Environment differences are visible in one short file per environment.
- `scripts/tf_ci.sh` selects the environment with `-var-file` and the backend with `-backend-config`.
- The prompt's `envs/` directory still exists, holding configuration rather than code.

## Alternatives considered

Root module per environment (Project 2 style): more duplication and no gain with a single
deployed environment. Terraform workspaces: implicit state selection is easy to get wrong.
