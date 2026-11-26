# Rebuilding the platform after cleanup

The Phase 9 cleanup destroys the **workload stack** (Lambdas, DynamoDB, Config recorder and rules,
EventBridge, SNS, dashboard, evidence bucket, KMS keys, fixtures). The **bootstrap layer** (Terraform
state bucket, GitHub OIDC roles, permissions boundary, budget) is kept: it costs a few cents a month
and makes a rebuild two steps. GitHub secrets and environments are unchanged.

## Option A: GitHub Actions (recommended)

1. Actions → **terraform-plan** → Run workflow (branch `main`). Review the summary: everything is
   "to add". Copy the digest.
2. Actions → **terraform-apply** → Run workflow with that digest → approve the `dev` deployment.
   About 10–15 minutes.
3. Confirm the SNS subscription e-mail (the topic is new).
4. After ~30 minutes (Config's first evaluation), Actions → **verify-deployment** → Run workflow.

## Option B: AWS CloudShell, one command

```bash
git clone https://github.com/oteyami2001/Automated-Cloud-Security-Compliance-Governance.git && cd Automated-Cloud-Security-Compliance-Governance && bash scripts/rebuild.sh
```

`scripts/rebuild.sh` installs the pinned Terraform version, builds the Lambda package, plans with the
same guard and digest as the pipeline, asks you to type the first 8 characters of the digest, then
re-plans and applies only if the digest is unchanged. It asks for the alert e-mail; set `APPROVERS`
first if a remediation window will be opened later. It runs as your CloudShell identity, not the
apply role, so the platform may report the rebuild's changes as SEC-015 "unapproved change
principal" findings: expected.

## If the bootstrap layer was removed too

Rebuild it first, as in Phase 3 ([bootstrap-runbook.md](bootstrap-runbook.md)):
`bash scripts/bootstrap.sh plan`, review, `bash scripts/bootstrap.sh apply <digest>`, then
`bash scripts/bootstrap.sh migrate`. Then Option A or B.

## What does not come back

The findings history, stored reports and evidence objects in AWS start empty. The written evidence
(run IDs, timestamps, results) stays in [portfolio-evidence.md](portfolio-evidence.md). The old KMS
keys finish their deletion window; new keys are created.
