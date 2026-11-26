#!/usr/bin/env bash
# Rebuild the dev workload stack from AWS CloudShell (Phase 9; docs/rebuild.md).
#
#   bash scripts/rebuild.sh
#
# The recommended path is GitHub Actions (terraform-plan, then terraform-apply with the digest and
# the owner's approval). This script is the alternative when GitHub is not wanted: the same
# tf_ci.sh plan → guard → digest → re-plan → digest must match → apply that exact plan, with a
# typed confirmation instead of the environment approval.
#
# Needs the bootstrap layer (state bucket, KMS alias): if it is gone, run scripts/bootstrap.sh first.
# Runs as YOUR CloudShell identity, not the pipeline's apply role, so the platform may report the
# rebuild's changes as SEC-015 "unapproved change principal" findings. That is expected.
set -euo pipefail

ENV=dev
export AWS_REGION=us-east-2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# The AWS provider is ~700 MB unpacked; CloudShell's home is 1 GB.
export TF_DATA_DIR=${TF_DATA_DIR:-/tmp/acscg-stack-tf}
export TF_IN_AUTOMATION=1
clean() { grep -v '^::add-mask::'; } # GitHub Actions masking lines mean nothing here

echo "== 1/6 identity and region"
TF_VAR_aws_account_id=$(aws sts get-caller-identity --query Account --output text)
export TF_VAR_aws_account_id
[[ $TF_VAR_aws_account_id =~ ^[0-9]{12}$ ]] || { echo "cannot read the account ID" >&2; exit 2; }
echo "signed in; region $AWS_REGION"

echo "== 2/6 bootstrap layer present?"
if ! aws s3api head-bucket --bucket "acscg-tfstate-${TF_VAR_aws_account_id}-${AWS_REGION}" 2>/dev/null; then
  echo "The Terraform state bucket is missing: the bootstrap layer was removed too."
  echo "Rebuild it first (docs/bootstrap-runbook.md): bash scripts/bootstrap.sh plan, then apply <digest>."
  exit 2
fi
echo "state bucket found"

echo "== 3/6 tools"
command -v terraform >/dev/null || bash "$ROOT/scripts/install_terraform.sh"
export PATH="$HOME/bin:$PATH"
python3 -c "import yaml" 2>/dev/null || python3 -m pip install --user --quiet pyyaml
terraform version | head -1

echo "== 4/6 inputs"
if [ -z "${TF_VAR_alert_email:-}" ]; then
  read -r -p "Alert e-mail for SNS notifications: " TF_VAR_alert_email
fi
export TF_VAR_alert_email
if [ -n "${APPROVERS:-}" ]; then
  TF_VAR_approvers=$(python3 "$ROOT/scripts/normalise_approvers.py")
  export TF_VAR_approvers
fi
python3 "$ROOT/scripts/build_lambda.py"

echo "== 5/6 plan, guard and digest (nothing changes yet)"
bash "$ROOT/scripts/tf_ci.sh" plan "$ENV" apply | clean | tee /tmp/acscg-rebuild-plan.txt
DIGEST=$(sed -n 's/^digest=//p' /tmp/acscg-rebuild-plan.txt)
[[ $DIGEST =~ ^[0-9a-f]{64}$ ]] || { echo "no digest: the plan or the guard failed" >&2; exit 1; }
if grep -q '^No changes' /tmp/acscg-rebuild-plan.txt; then
  echo "Nothing to rebuild: the stack already exists."
  exit 0
fi
echo
echo "Review the summary above. To apply exactly this plan, type the first 8 characters of the digest."
read -r -p "> " ANSWER
[ "$ANSWER" = "${DIGEST:0:8}" ] || { echo "not confirmed; nothing was changed"; exit 1; }

echo "== 6/6 re-plan, digest must match, apply"
EXPECTED_DIGEST=$DIGEST bash "$ROOT/scripts/tf_ci.sh" apply "$ENV" apply | clean

cat <<'EOF'

Rebuild applied. Next:
  1. Confirm the new SNS subscription from the e-mail AWS just sent (the topic is new).
  2. Give AWS Config about 30 minutes to evaluate every resource.
  3. Verify: GitHub Actions → verify-deployment → Run workflow (read-only).
Changes made from CloudShell may appear as SEC-015 "unapproved change principal" findings: expected.
EOF
