# CI/CD and DevSecOps design

**Status: 📝 planned.** Workflows are implemented in Phase 8 (CI checks start in Phase 2). Practices
reuse Project 2 where they were verified there (pinned SHAs, OIDC subjects with immutable IDs,
digest-bound apply, typed-confirmation cleanup).

## 1. Workflows

| Workflow | Trigger | AWS access | GitHub environment | Jobs |
|---|---|---|---|---|
| `ci.yml` | `pull_request`, `push` to `main` | **None** | — | pytest (+ coverage), Ruff (lint + format), Bandit, catalog validation, docs-sync checks, `terraform fmt -check`, `terraform validate`, `terraform test` (mock providers), TFLint (aws ruleset), Checkov, Trivy (config + secret + vuln), gitleaks, actionlint + zizmor (Actions security), Dependency review |
| `security-scan.yml` | weekly schedule + manual | None | — | Full-history secret scan, Trivy fs, zizmor. SARIF upload to code scanning |
| `terraform-plan.yml` | manual (`workflow_dispatch`: env, mode apply/destroy) | `acscg-github-plan` (read-only) | `dev-plan` | Plan → plan guard (§3) → digest → summary with addresses/actions only |
| `terraform-apply.yml` | manual (input: reviewed digest) | `acscg-github-apply` | `dev` (required reviewer) | Re-plan → recompute digest → **fail closed** unless equal → apply the just-made plan file |
| `compliance-report.yml` | daily schedule + manual | `acscg-github-report` | — (`main` only) | Invoke report generator → download redacted Markdown summary → job summary |
| `drift-detection.yml` | weekly schedule + manual | `acscg-github-plan` | `dev-plan` | `plan -detailed-exitcode`. Exit 2 → open/update an issue with addresses only. Never applies. Empty state → "not deployed" (Project 2 fix P8-5) |
| `cleanup.yml` | manual (inputs: digest + `destroy-dev`) | `acscg-github-cleanup` | `dev-cleanup` (required reviewer) | Destroy plan digest check → destroy → `verify_cleanup.sh` (state empty, no `acscg-*` billable resources, **pre-existing services unchanged**) |

All workflows: `permissions: {}` at top level, minimal per job (`id-token: write` only where AWS is
needed, `contents: read`). `concurrency` per environment. `persist-credentials: false` on checkout.
Third-party actions pinned to full commit SHAs with a version comment. Dependabot updates them.
Runners: `ubuntu-24.04`. Every SHA is checked against the action's release tag when it is added
(Phase 8). No SHA is written from memory.

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
