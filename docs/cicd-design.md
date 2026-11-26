# CI/CD and DevSecOps design

**Status:** `ci.yml` is 🧱 implemented (Phase 2; first GitHub run recorded in `docs/portfolio-evidence.md`).
`scripts/plan_guard.py` and `scripts/tf_ci.sh` are implemented and ✅ unit-tested. The AWS-facing workflows are Phase 8. Practices
reuse Project 2 where they were verified there (pinned SHAs, OIDC subjects with immutable IDs,
digest-bound apply, typed-confirmation cleanup).

## 1. Workflows

| Workflow | Trigger | AWS access | GitHub environment | Jobs |
|---|---|---|---|---|
| `ci.yml` | `pull_request`, `push` to `main` | **None** | — | pytest (+ coverage), Ruff (lint + format), Bandit, catalog validation, docs-sync checks, `terraform fmt -check`, `terraform validate`, `terraform test` (mock providers), TFLint (aws ruleset), Checkov, Trivy (config + secret + vuln), gitleaks, actionlint + zizmor (Actions security), Dependency review |
| `security-scan.yml` | weekly schedule + manual | None | — | Full-history secret scan, Trivy fs, zizmor. SARIF upload to code scanning |
| `terraform-plan.yml` ✅ (Phase 4) | manual (`workflow_dispatch`, dev only) | `acscg-github-dev-plan` (read-only + state lock file) | `dev-plan` | Build Lambda package → plan → plan guard (§3) → digest → job summary with addresses/actions only |
| `terraform-apply.yml` ✅ (Phase 4) | manual (input: reviewed digest) | `acscg-github-dev-apply` | `dev` (required reviewer) | Build Lambda package → re-plan → recompute digest → **fail closed** unless equal → apply the just-made plan file |
| `verify-deployment.yml` ✅ (Phase 5) | manual | `acscg-github-dev-plan` (read-only) | `dev-plan` | `scripts/verify_deployment.py`: platform health and validation scenarios 2, 3, 4, 6, 12, 13 as PASS/FAIL lines with fixture names only (no IDs). Replaces the CloudShell checks |
| `compliance-report.yml` ✅ (Phase 7) | weekly schedule (Mon 06:47 UTC) + manual | `acscg-github-dev-plan` (read-only) | `dev-plan` | `scripts/compliance_report.py`: newest stored report's SHA-256, posture metrics = stored report, DynamoDB recount = stored report (when recent), leak scan of the public Markdown → job summary. **Decision (Phase 7):** no `acscg-github-report` role; the report generator's daily schedule writes the report, so the workflow only reads and needs no invoke permission (no bootstrap change) |
| `drift-detection.yml` | weekly schedule + manual | `acscg-github-plan` | `dev-plan` | `plan -detailed-exitcode`. Exit 2 → open/update an issue with addresses only. Never applies. Empty state → "not deployed" (Project 2 fix P8-5) |
| `cleanup.yml` | manual (inputs: digest + `destroy-dev`) | `acscg-github-cleanup` | `dev-cleanup` (required reviewer) | Destroy plan digest check → destroy → `verify_cleanup.sh` (state empty, no `acscg-*` billable resources, **pre-existing services unchanged**) |

All workflows: `permissions: {}` at top level, minimal per job (`id-token: write` only where AWS is
needed, `contents: read`). `concurrency` per environment. `persist-credentials: false` on checkout.
Third-party actions pinned to full commit SHAs with a version comment. Dependabot updates them.
Runners: `ubuntu-24.04`. Every SHA is checked against the action's release tag when it is added
(Phase 8). No SHA is written from memory.

### 1.1 `ci.yml` as implemented (no AWS access)

| Job | Tools (pinned) | Fails on |
|---|---|---|
| python | Python 3.13, `requirements-dev.lock` (`--require-hashes`), Ruff 0.17.4, Bandit 1.9.4, pytest 9.2.0 + pytest-cov | lint/format, SAST, catalog, stale generated docs or packaged catalog, unregistered suppressions, tests, coverage < 90 % |
| terraform | Terraform 1.17.2 | fmt, validate, `terraform test` for 12 modules + bootstrap + stack, environment invariants (dev/staging/prod) |
| tflint | TFLint v0.55.1 + aws ruleset 0.49.0 | any issue |
| checkov | Checkov 3.4.3 (`requirements-scan.lock`) | Terraform and GitHub Actions findings |
| trivy | Trivy v0.76.1 | misconfiguration, secret or vulnerability findings |
| workflow-security | zizmor 1.32.0, actionlint 1.7.12 | workflow security findings |

Pins are the newest releases at least 14 days old (supply-chain cooldown). Dependabot updates
actions, pip and Terraform providers weekly with the same 14-day cooldown.

### 1.2 Terraform plan/apply as implemented (Phase 4)

- State: `s3://acscg-tfstate-<account>-us-east-2/stack/<env>/terraform.tfstate`, SSE-KMS
  `alias/acscg-tfstate`, native S3 lock file (`scripts/tf_ci.sh` passes `-backend-config`).
- Environment secrets (in both `dev-plan` and `dev`): `AWS_ACCOUNT_ID` (masked; also masked by
  `configure-aws-credentials`) and `ALERT_EMAIL`. Never committed, never printed.
- `aws-actions/configure-aws-credentials` pinned to `e1253824e5c10ff9df46874f81ed3ec929e19cfd`
  (v6.3.0, released 2026-09-15; verified with `git ls-remote` and the tag's commit).
- Both workflows run from `main` only (environment branch policy). The apply job waits for the
  owner's approval of the `dev` environment, then applies only if the re-plan's digest equals the
  digest the owner reviewed from the plan run.
- Checkov CKV_GHA_7 (no `workflow_dispatch` inputs) is suppressed for `terraform-apply.yml` only:
  the digest does not change what is built, it only gates the apply. Registered in
  `policies/exceptions/scanner-exceptions.yaml`.
- `tests/unit/test_phase4_workflows.py` asserts roles, environments, permissions, SHA pins,
  masking, no expressions inside `run:` and the backend settings.

## 2. Identity (OIDC)

| Role | `sub` condition (StringEquals) |
|---|---|
| plan | `repo:oteyami2001@<owner-id>/Automated-Cloud-Security-Compliance-Governance@<repo-id>:environment:dev-plan` |
| apply | `…:environment:dev` |
| cleanup | `…:environment:dev-cleanup` |
| report | `…:ref:refs/heads/main` + `job_workflow_ref` = `compliance-report.yml@refs/heads/main` |

`<owner-id>`/`<repo-id>` are numeric IDs read from the GitHub API in Phase 3. The repository is
configured to use immutable subject claims, as in Project 2 ADR 0005. No trust for
`pull_request`. Session duration 1 h.

## 3. Plan integrity (ADR 0008)

1. `terraform plan -out=tfplan` → `terraform show -json` → **fail if the document is not a plan**.
2. Plan guard (Python, unit-tested):
   - rejects any create/update/delete on **protected addresses/types** in `integrate` mode
     (`aws_config_configuration_recorder*`, `aws_cloudtrail`, `aws_securityhub_account`,
     `aws_guardduty_detector`, `aws_iam_openid_connect_provider`, anything matching `aiops-`/`idp-`);
   - rejects deletes of the evidence bucket/KMS key outside destroy mode;
   - rejects IAM roles without the permissions boundary.
3. Digest = SHA-256 over (mode, sorted `resource_changes[]` of address + actions + `after`). The
   digest and the address/action list are published. The plan file is **not** uploaded (public repo).
4. Apply re-plans from the same commit and recomputes. Any difference (code, variables, real-world
   drift) changes the digest, so the apply fails closed before any change.
5. The digest is bound to the mode, so an apply digest can never authorise a destroy.

## 4. Repository governance (configured and verified in Phase 8)

| Setting | Target | Verification |
|---|---|---|
| Default branch | `main` | `verify_github_settings.sh` (API) |
| Ruleset on `main` | PR required, 1 approval (owner-bypass documented for a single-maintainer repository), required checks = `ci` jobs, no force push, no deletion, linear history | API read-back, recorded with timestamp |
| Environments | `dev-plan` (deployment branches: `main`), `dev` and `dev-cleanup` (required reviewer = owner, `main` only, prevent self-review where available) | API read-back |
| Actions settings | Allow only verified and SHA-pinned actions where supported. Fork PR workflows need approval. Default `GITHUB_TOKEN` read-only | API read-back |
| Secret scanning + push protection | enabled | API read-back |
| Code scanning (SARIF) | enabled | First SARIF upload |

## 5. Findings policy

- No security check is disabled to make CI pass.
- Every suppression is inline, carries the rule ID and a justification, and is listed in
  `policies/exceptions/scanner-exceptions.yaml` with an owner and review date. CI fails on an
  inline suppression that is not in that list (script reused from Project 2 `sarif_unsuppressed.sh`).
- Scenario 5 (insecure Terraform change blocked): a PR adding an SG with 0.0.0.0/0 on 22 must
  fail Checkov/Trivy **and** the custom policy test. The run ID is recorded as evidence.
