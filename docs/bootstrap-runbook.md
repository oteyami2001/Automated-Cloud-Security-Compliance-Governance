# Bootstrap runbook

**Status: §1 ready to run (read-only). §2–§4 are 📝 planned for Phase 3 and must not be run before approval.**

## 1. Phase 0: read-only discovery in AWS CloudShell (run now)

Why CloudShell: no local access keys, and the session uses your console identity.

1. Sign in to the AWS console for the account you intend to use. Open **CloudShell in us-east-2**.
2. Get the script (read-only clone of the public repository branch):

```bash
git clone --depth 1 --branch claude/affectionate-dijkstra-c7gtjv https://github.com/oteyami2001/Automated-Cloud-Security-Compliance-Governance.git acscg
```

   If the repository is private, upload `scripts/discover_aws.sh` with CloudShell **Actions → Upload file** instead.

3. Read the script before running it. It uses only `describe-*`, `list-*` and `get-*` calls (a unit
   test enforces this), plus one optional Cost Explorer query (USD 0.01; set `SKIP_COST_EXPLORER=1` to skip):

```bash
less acscg/scripts/discover_aws.sh
```

4. Run it for the target Region and us-east-1 (us-east-1 confirms the SCP behaviour):

```bash
bash acscg/scripts/discover_aws.sh us-east-2 us-east-1 > discovery-report-$(date -u +%Y%m%d).md
```

5. The output is redacted by default (account ID, e-mail addresses, IPv4 addresses, organization IDs).
   Review it, then share it (or the sections listed in `docs/phase-0-assessment.md` §2.3) in the chat.
   Do **not** commit it. `discovery-report*.md` is git-ignored.
6. Also tell me, separately: the account ID is the intended one (yes/no) and the Region is us-east-2 (yes/no).

## 2. Phase 3 bootstrap (planned outline)

1. Pin Terraform in CloudShell (`~/bin/terraform`, checksum-verified, version fixed in `versions.tf`).
2. `terraform -chdir=terraform/bootstrap init` (local state) → `plan -out` → **review with the owner** → `apply` the reviewed plan.
3. Resources: state bucket (SSE-KMS, versioning, TLS-only policy, public access block, native S3
   locking with `use_lockfile = true`), KMS key, OIDC roles (lookup of the existing provider),
   permissions boundary, USD 25 tag-filtered budget.
4. Migrate the bootstrap state to the new bucket (`backend.tf` from `backend.tf.example`, git-ignored).
5. Activate the `Project` cost-allocation tag (Billing console. It can take up to 24 h to appear).
6. `scripts/verify_bootstrap.sh`, with results and timestamps recorded in `docs/portfolio-evidence.md`.

## 3. Ownership decisions taken from discovery

| Discovery result | Terraform setting |
|---|---|
| Config recorder exists | `config_ownership_mode = "integrate"` (rules only) |
| No Config recorder | `config_ownership_mode = "create"` (selected resource types, own delivery bucket) |
| Security Hub / GuardDuty enabled | `*_ownership_mode = "integrate"` |
| Not enabled | `"disabled"` (default) |
| Trail exists with logging on | `cloudtrail_mode = "integrate"` (data source + validation) |

## 4. Rollback of the bootstrap (planned)

`terraform destroy` of the bootstrap only after workload cleanup is verified. The state bucket
and KMS key have `prevent_destroy`, and are removed manually after an explicit owner decision.
