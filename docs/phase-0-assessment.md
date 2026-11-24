# Phase 0: repository and AWS environment assessment

- **Date:** 2026-11-24
- **Status:** Repository assessment complete. AWS discovery **not yet run** (blocked, see §2).
- **Scope:** read-only. No AWS resource was created, changed or deleted. No AWS API call succeeded from
  the build environment.

## 1. Existing repository assessment

| Check | Result |
|---|---|
| Remote `oteyami2001/Automated-Cloud-Security-Compliance-Governance` | Exists, **empty**: no branches, no commits, no files (GitHub API `list_branches` → `[]`, `git ls-remote` → no refs) |
| Local clone | No commits; working tree empty |
| Git history to preserve | None exists. The first commits in this repository are the Phase 0/1 commits on `claude/affectionate-dijkstra-c7gtjv` |
| Default branch | None yet. **Pushing the feature branch to an empty repository makes it the default branch**, see §4 |
| Branch protection / rulesets / environments | Cannot exist on a branchless repository. To be created and **verified** in Phase 8 (`scripts/verify_github_settings.sh`, reused from Project 2) |
| Secrets in history | None (no history) |

### Reusable engineering practices from earlier projects (read-only clones, nothing copied blindly)

| Source | Practice | How ACSCG reuses it |
|---|---|---|
| Project 2 `scripts/tf_ci.sh` | Fail-closed **plan digest**: SHA-256 over the planned changes, recomputed at apply and compared with the reviewed digest. Mode-bound (apply ≠ destroy). The plan file is never uploaded from a public repository | ADR 0008. Same mechanism, extended with a check that the plan contains no change to `protected_resource_addresses` |
| Project 2 ADR 0003 | No OIDC trust for `pull_request` | Same: fork and PR runs get no AWS credentials |
| Project 2 ADR 0005 | Shared account. Never manage `aiops-*` resources or the shared OIDC provider; look it up with a data source (`create_oidc_provider = false`) | ADR 0002 / ADR 0003. Prefix `acscg-`, tag `Project=acscg`, and an explicit deny on `aiops-*`/`idp-*` resources in the boundary |
| Project 2 OIDC subjects | Immutable-ID subjects (`repo:owner@<id>/<repo>@<id>:environment:<env>`) | Same. The repository ID is read from the GitHub API in Phase 3 |
| Project 2 `aws_discovery.sh` | Read-only discovery that records DENIED calls as findings | Extended into `scripts/discover_aws.sh` (security services, quotas, default redaction, test that only `describe/list/get` verbs are used) |
| Project 2 cleanup | Destroy needs digest + typed confirmation + environment approval. Cleanup verifies an empty state afterwards | Same, plus a check that pre-existing security services are untouched (`scripts/verify_cleanup.sh`, Phase 9) |
| Project 1 SSM documents | Remediation as SSM Automation documents with explicit assume roles | Same pattern for the security runbooks, with an `aws:approve` step for Mode 3 |
| Projects 1 and 2 | Evidence tables that mark ✅ offline / ☁️ AWS, with run IDs and timestamps | `docs/portfolio-evidence.md` uses the same status vocabulary (ADR 0001) |

## 2. AWS environment assessment

### 2.1 What was attempted from this build environment

| Attempt | Result |
|---|---|
| `sts:GetCallerIdentity` with the credentials present in the build container | **`InvalidClientTokenId`**: the token is not valid. No AWS read access is available here |
| AWS documentation and pricing pages (docs.aws.amazon.com, aws.amazon.com) | Not reachable (DNS blocked by the environment's network policy) |
| AWS Price List bulk API (pricing.us-east-1.amazonaws.com) | **Reachable.** Used for the cost model (publication dates recorded in `docs/cost-model.md`) |

**Consequence:** live discovery must be run by you in **AWS CloudShell** with
`scripts/discover_aws.sh` (read-only; see `docs/bootstrap-runbook.md` §1).

### 2.2 What is already known (from Project 2 records dated 2026-11-23, NOT re-verified)

These facts come from `Internal-Developer-Platform-CI-CD-Automation/docs/aws-discovery-2026-11-23.md`
and `docs/portfolio-evidence.md`. They describe the account Projects 1 and 2 used. **This project
does not assume the same account.** Your confirmation is required (blocker B1).

| Item | Recorded state | Impact on ACSCG |
|---|---|---|
| Organizations | Member account, all features, SCPs enabled | Cannot read SCPs. Infer them from DENIED calls |
| Regional SCP | **Explicit deny of regional services in us-east-1** | Single-Region design (us-east-2). IAM CloudTrail events, which EventBridge delivers in us-east-1, are **not** available in near-real time (SEC-015 limitation). CIS "Config enabled in all Regions" cannot be met |
| Second SCP | Denies `iam:ListAccountAliases` | Unknown further IAM denies. The Phase 3 bootstrap applies IAM first in a small plan |
| GitHub OIDC provider | Exists (shared) | Looked up with a data source, never managed |
| CloudTrail | Trail `idp-management-events` (single-Region, management events, log file validation) owned by the Project 2 bootstrap; retained after Project 2 cleanup | **Reuse it, do not create a second trail.** A second copy of management events is billed at USD 2.00 per 100,000 events (ADR 0005) |
| Terraform state | `aiops-tfstate-…`, `idp-tfstate-…` | New `acscg-tfstate-…` bucket, separate key |
| Budgets | `aiops-account-monthly` (USD 30, account-wide), `idp` project budget (USD 25, tag-filtered) | Add a third, tag-filtered `acscg` budget (USD 25). A third budget may carry a small charge (see cost model) |
| AWS Config, Security Hub CSPM, GuardDuty, Access Analyzer | **Never inspected** in Projects 1–2 | Unknown. Discovery decides between the "create" and "integrate" modes for each (ADR 0003) |
| Cross-project risk | AIOps apply role allows broad ECS/ELB/VPC writes in us-east-2 (Project 2 T23) | Carried into the threat model as T-14 |

### 2.3 Discovery checklist (to be filled from your CloudShell report)

| # | Item | How | Decision it drives |
|---|---|---|---|
| D1 | Account ID and caller | `sts get-caller-identity` | Confirm the account (B1). The ID reaches Terraform only as `TF_VAR_aws_account_id` |
| D2 | Region | CloudShell Region, us-east-1 deny test | Confirm us-east-2 |
| D3 | Organization, SCP behaviour | DENIED entries | Feasible features |
| D4 | CloudTrail trails + status + selectors | `describe-trails`, `get-trail-status` | Reuse the existing trail (SEC-012/015 event source) |
| D5 | Config recorder(s), delivery channel, rules, conformance packs | `configservice describe-*` | **One customer-managed recorder per Region.** Recorder exists → integrate mode (add rules only, never alter the recorder). None → create a recorder limited to the selected resource types |
| D6 | Security Hub CSPM | `describe-hub`, `get-enabled-standards` | Enabled → integrate (consume findings only). Not enabled → keep disabled until approved |
| D7 | GuardDuty detectors and plans | `list-detectors`, `get-detector` | Same as D6 |
| D8 | IAM Access Analyzer | `list-analyzers` | Existing account analyzer → consume. None → create one account analyzer (external access, no charge) |
| D9 | OIDC provider, project roles | `list-open-id-connect-providers`, `list-roles` | Lookup vs create; name collisions |
| D10 | State buckets, existing project buckets | `list-buckets` | Name collisions |
| D11 | Budgets, month-to-date cost | `describe-budgets`, Cost Explorer | Budget count, cost baseline |
| D12 | Quotas: Config rules per Region, Lambda concurrency, EventBridge rules | Service Quotas | Capacity |
| D13 | Pre-existing open security groups, never-expire log groups, EBS default encryption | Describe calls | **Protected-resource list**: pre-existing violations are reported, never remediated |

## 3. Security risks found in Phase 0

| ID | Risk | Severity | Handling |
|---|---|---|---|
| P0-R1 | Unusable AWS credentials present in the build environment as environment variables | Low (invalid) | Not used. This project never relies on static keys (OIDC only). Recommend removing them from the environment configuration |
| P0-R2 | Public repository: CI logs could reveal the account ID, IPs or e-mail | Medium | `::add-mask::`, redaction in reports, no plan files in artifacts (ADR 0008) |
| P0-R3 | Shared account with two earlier projects | Medium | Prefix/tag separation, explicit denies, protected-resource list in Terraform (ADR 0003) |
| P0-R4 | First push makes the feature branch the default branch | Low | See §4 |
| P0-R5 | Framework and Security Hub references could not be checked against primary sources from here | Medium (accuracy) | Recorded as `pending`. Verification log in `docs/compliance-mapping.md` |

## 4. Branch note

The repository has no branches. Pushing `claude/affectionate-dijkstra-c7gtjv` makes GitHub select
it as the default branch. Recommended: create `main` from the first commit
(`chore: initialize repository`), make `main` the default branch, then review Phase 0/1 as a pull
request into `main`. This needs your approval because it pushes to a branch other than the feature
branch.
