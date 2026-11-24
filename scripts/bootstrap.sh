#!/usr/bin/env bash
# Phase 3 bootstrap from AWS CloudShell, with the same fail-closed digest as CI (ADR 0008).
#
#   bash scripts/bootstrap.sh plan               # init (local state) → plan → guard → digest + summary
#   bash scripts/bootstrap.sh apply <digest>     # applies ONLY the saved plan whose digest was reviewed
#   bash scripts/bootstrap.sh migrate            # move the bootstrap state into the new S3 bucket
#   bash scripts/bootstrap.sh verify             # read-only checks (scripts/verify_bootstrap.sh)
#
# Requires: TF_VAR_aws_account_id (12 digits) equal to the signed-in account (checked), optional
# TF_VAR_alert_email, terraform (scripts/install_terraform.sh), python3, aws CLI.
# Output that is meant to be shared (summary, digest) never contains the account ID or e-mail.
set -euo pipefail

CMD=${1:?usage: bootstrap.sh plan | apply <digest> | migrate | verify}
# The AWS provider is ~700 MB unpacked; CloudShell's home is 1 GB. Keep .terraform in /tmp
# (cleared on restart: just run `plan` again; the digest of an unchanged plan stays the same).
export TF_DATA_DIR=${TF_DATA_DIR:-/tmp/acscg-bootstrap-tf}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIR="$ROOT/terraform/bootstrap"
PLAN="$HOME/acscg-bootstrap.tfplan"
JSON="$HOME/acscg-bootstrap-plan.json"
LOG="$HOME/acscg-bootstrap-$CMD.log"

[[ ${TF_VAR_aws_account_id:-} =~ ^[0-9]{12}$ ]] || { echo "set TF_VAR_aws_account_id (12 digits) first" >&2; exit 2; }
CALLER=$(aws sts get-caller-identity --query Account --output text)
[ "$CALLER" = "$TF_VAR_aws_account_id" ] || { echo "signed-in account does not match TF_VAR_aws_account_id; refusing" >&2; exit 2; }
redact() { sed -E -e "s/${TF_VAR_aws_account_id}/<ACCOUNT_ID>/g" -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/<EMAIL>/g'; }

case "$CMD" in
  plan)
    terraform -chdir="$DIR" init -input=false -no-color >"$LOG" 2>&1 || { redact <"$LOG" | tail -20; exit 1; }
    terraform -chdir="$DIR" plan -input=false -no-color -out="$PLAN" >>"$LOG" 2>&1 || { redact <"$LOG" | grep -E '^(Error|│)' | head -40; exit 1; }
    terraform -chdir="$DIR" show -json "$PLAN" >"$JSON"
    echo "== Plan summary (addresses and actions only; full plan in $LOG, keep it private)"
    grep -E '^Plan:' "$LOG"
    python3 "$ROOT/scripts/plan_guard.py" check "$JSON" --mode apply --no-boundary-check | redact
    echo "Share the summary and digest above for review. Apply only after approval:"
    echo "  bash scripts/bootstrap.sh apply <digest>"
    ;;
  apply)
    DIGEST=${2:?usage: bootstrap.sh apply <digest>}
    [ -f "$PLAN" ] && [ -f "$JSON" ] || { echo "no saved plan; run: bash scripts/bootstrap.sh plan" >&2; exit 2; }
    python3 "$ROOT/scripts/plan_guard.py" verify "$JSON" --mode apply --no-boundary-check --expected "$DIGEST" | tail -1
    # A saved plan cannot be applied if anything changed since it was made (Terraform refuses: stale plan).
    terraform -chdir="$DIR" apply -input=false -no-color "$PLAN" >"$LOG" 2>&1 || { redact <"$LOG" | grep -E '^(Error|│)' | head -40; exit 1; }
    redact <"$LOG" | grep -E '^Apply complete'
    rm -f "$PLAN"
    ;;
  migrate)
    BUCKET="acscg-tfstate-${TF_VAR_aws_account_id}-us-east-2"
    aws s3api head-bucket --bucket "$BUCKET" >/dev/null || { echo "state bucket not found; apply first" >&2; exit 2; }
    sed "s/<ACCOUNT_ID>/${TF_VAR_aws_account_id}/" "$DIR/backend.tf.example" >"$DIR/backend.tf" # git-ignored
    terraform -chdir="$DIR" init -input=false -no-color -migrate-state -force-copy >"$LOG" 2>&1 || { redact <"$LOG" | tail -20; exit 1; }
    aws s3api head-object --bucket "$BUCKET" --key bootstrap/terraform.tfstate --query ServerSideEncryption --output text
    terraform -chdir="$DIR" state list >/dev/null && echo "State migrated and readable from S3."
    echo "After checking, remove the local copies: rm $DIR/terraform.tfstate $DIR/terraform.tfstate.backup"
    ;;
  verify)
    bash "$ROOT/scripts/verify_bootstrap.sh"
    ;;
  *) echo "unknown command $CMD" >&2; exit 2 ;;
esac
