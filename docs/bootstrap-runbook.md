# Bootstrap runbook

**Status: §1 done (2026-11-24). §2 and §2a done and verified 2026-11-24 (evidence P3-4…P3-7). Remaining: cost-allocation tag (P3-8). §5 (Phase 4) ready after the Phase 4 PR is merged.**

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

## 2. Phase 3 bootstrap (approved 2026-11-24; run by the owner in CloudShell us-east-2)

What it creates (about 20 resources, cents per month; nothing account-wide):

| Resource | Purpose |
|---|---|
| `acscg-tfstate-<account>-us-east-2` + KMS key `alias/acscg-tfstate` | Encrypted, versioned, TLS-only state with native S3 locking |
| IAM policy `acscg-workload-boundary` | Ceiling for every workload role the stack will create |
| Roles `acscg-github-dev-plan`, `-dev-apply`, `-dev-cleanup`, `acscg-github-report` | GitHub OIDC roles, one immutable subject each. The existing OIDC provider is only looked up |
| Budget `acscg-monthly` (USD 25, `Project=acscg`) | Alert at 50/80 % actual and 100 % forecast |

It never touches the `aiops-*`/`idp-*` resources, the shared OIDC provider or the existing trail.
`scripts/verify_bootstrap.sh` checks that afterwards.

**Step 1: get the code (after PR #2 is merged, so `main` has the Phase 3 files).**

```bash
cd ~ && git clone --depth 1 https://github.com/oteyami2001/Automated-Cloud-Security-Compliance-Governance.git acscg-phase3 && cd acscg-phase3
```

**Step 2: install the pinned Terraform (checksum-verified, into `~/bin`).**

```bash
bash scripts/install_terraform.sh && export PATH=$HOME/bin:$PATH
```

**Step 3: set the inputs (never committed).** The account ID is read from your session. The
script refuses to run if the two ever differ.

```bash
export TF_VAR_aws_account_id=$(aws sts get-caller-identity --query Account --output text)
```

```bash
export TF_VAR_alert_email="you@example.com"
```

**Step 4: plan.** This creates nothing. It prints the planned addresses and actions plus a digest,
with no account ID or e-mail. Share that output for review.

```bash
bash scripts/bootstrap.sh plan
```

**Step 5: apply, only after the plan has been reviewed and approved.** Only the saved plan whose
digest matches is applied. A changed plan is refused.

```bash
bash scripts/bootstrap.sh apply <digest>
```

**Step 6: migrate the state into the new bucket, then remove the local copies.**

```bash
bash scripts/bootstrap.sh migrate
```

**Step 7: verify (read-only) and share the PASS/FAIL output.**

```bash
bash scripts/bootstrap.sh verify
```

Budget e-mails: AWS Budgets sends alerts to the address directly (no subscription confirmation).
The tag filter needs the `Project` cost-allocation tag to be **Active**. On 2026-11-24 it was not
found. Check `aws ce list-cost-allocation-tags --tag-keys Project` after 24 h. If it is `Inactive`, run
`aws ce update-cost-allocation-tags-status --cost-allocation-tags-status TagKey=Project,Status=Active`.
In an AWS Organization this may only be allowed from the management account. Until then the
account-wide `aiops-account-monthly` budget is the backstop.

CloudShell's home is 1 GB and the AWS provider is ~700 MB, so `bootstrap.sh` keeps `.terraform` in
`/tmp` (`TF_DATA_DIR`). After a CloudShell restart, run `plan` again before `apply`.

## 2a. GitHub settings (owner, once)

See `docs/github-settings.md`. Run `scripts/configure_github.sh` as the owner, then
`scripts/verify_github_settings.sh`. The verify script must show `use_immutable_subject = true`.
Otherwise the CI roles' trust policies (immutable IDs) will not match and must be adjusted before CI uses them.

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

## 5. Phase 4: first workload deployment (dev, report-only)

What is deployed: AWS Config recorder (catalog resource types only) and delivery bucket, 18 managed
and 3 custom Config rules, EventBridge rules, findings processor / Config evaluator / report
Lambdas, DynamoDB table, DLQ, encrypted SNS topic (e-mail), evidence bucket (Object Lock
GOVERNANCE, 7 days), KMS key, platform policy parameter (report-only), dashboard and alarms.
**Not** deployed: remediation (Phase 6), scenario fixtures, Security Hub, GuardDuty, Access Analyzer
(all SCP-denied or later phases), any trail (the existing one is only referenced).

**Step 1: update the bootstrap (CloudShell, us-east-2).** Two least-privilege changes: the plan
role may only write the state lock file, and the workload boundary allows the read-only calls the
Config recorder needs. `bootstrap.sh plan` now finds the S3 state by itself.

```bash
cd ~ && rm -rf acscg-phase4 && git clone --depth 1 https://github.com/oteyami2001/Automated-Cloud-Security-Compliance-Governance.git acscg-phase4 && cd acscg-phase4
```

```bash
bash scripts/install_terraform.sh && export PATH=$HOME/bin:$PATH
```

```bash
export TF_VAR_aws_account_id=$(aws sts get-caller-identity --query Account --output text)
```

```bash
export TF_VAR_alert_email="you@example.com"
```

```bash
bash scripts/bootstrap.sh plan
```

Expected: `Using the S3 state`, then `Plan: 0 to add, 2 to change, 0 to destroy.` (the boundary
policy and the dev-plan inline policy). Share the output. After approval:

```bash
bash scripts/bootstrap.sh apply <digest>
```

```bash
bash scripts/bootstrap.sh verify
```

**Step 2: environment secrets (once).** In GitHub: Settings → Environments → `dev-plan` → Add
environment secret, then the same for `dev`:

| Secret | Value |
|---|---|
| `AWS_ACCOUNT_ID` | the 12-digit account ID |
| `ALERT_EMAIL` | the address for security alerts (an SNS confirmation e-mail follows the apply) |

**Step 3: plan.** Actions → `terraform-plan` → Run workflow (branch `main`). The job summary lists
planned addresses/actions and the digest, with no values. Share the run link for review.

**Step 4: apply, only after the plan is reviewed and approved.** Actions → `terraform-apply` → Run
workflow with the reviewed digest. Approve the `dev` deployment when GitHub asks. The job re-plans
and stops unless the digest is identical.

**Step 5: confirm the SNS subscription e-mail.** Then verification follows (Config rules evaluating,
processor receiving events, findings in DynamoDB), recorded in `docs/portfolio-evidence.md`.

Rollback: Config recording and rules can be stopped by a reviewed destroy plan (Phase 9 cleanup
workflow). The state, evidence bucket and keys are protected and are never removed by Phase 4.

