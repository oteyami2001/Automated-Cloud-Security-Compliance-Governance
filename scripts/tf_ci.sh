#!/usr/bin/env bash
# Terraform CI wrapper for the stack (ADR 0008). Used by terraform-plan.yml and terraform-apply.yml.
# State: s3://acscg-tfstate-<account>-<region>/stack/<env>/terraform.tfstate (bootstrap bucket,
# SSE-KMS alias/acscg-tfstate, native S3 lock file).
#
#   tf_ci.sh plan    <env> [apply|destroy]   plan → guard → digest (addresses/actions only)
#   tf_ci.sh apply   <env> [apply|destroy]   re-plan → guard → digest must equal $EXPECTED_DIGEST → apply that plan
#   tf_ci.sh drift   <env>                   read-only: exit 0 no drift, 3 drift (never applies)
#
# Destroy additionally needs CONFIRM_DESTROY=destroy-<env>. The digest covers the mode, so a reviewed
# apply digest can never authorise a destroy. The plan file never leaves the runner (public repo).
set -euo pipefail

CMD=${1:?usage: tf_ci.sh plan|apply|drift <env> [apply|destroy]}
ENV=${2:?environment required}
MODE=${3:-apply}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
STACK="$ROOT/terraform/stack"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

[[ $ENV =~ ^(dev|staging|prod)$ ]] || { echo "::error::unknown environment $ENV"; exit 2; }
[[ $MODE =~ ^(apply|destroy)$ ]] || { echo "::error::mode must be apply or destroy"; exit 2; }
[[ ${TF_VAR_aws_account_id:-} =~ ^[0-9]{12}$ ]] || { echo "::error::TF_VAR_aws_account_id missing"; exit 2; }
echo "::add-mask::$TF_VAR_aws_account_id"

if [ "$MODE" = destroy ] && [ "$CMD" = apply ] && [ "${CONFIRM_DESTROY:-}" != "destroy-$ENV" ]; then
  echo "::error::destroying $ENV needs CONFIRM_DESTROY=destroy-$ENV"
  exit 2
fi

REGION=${AWS_REGION:-us-east-2}
[[ $REGION =~ ^[a-z]{2}-[a-z]+-[0-9]$ ]] || { echo "::error::invalid AWS_REGION"; exit 2; }

redact() {
  sed -E -e 's/[0-9]{12}/***/g' \
    -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/<email>/g' \
    -e 's/\b(vpc|sg|sgr|subnet|igw|eni|vol|i|ami|snap|rtb|acl|nat|vpce)-[0-9a-f]{8,17}\b/\1-<id>/g' \
    -e 's/(Encoded authorization failure message:) [A-Za-z0-9_-]+/\1 <removed>/g' \
    -e 's/[A-Za-z0-9_-]{100,}/<removed>/g' # the same message when Terraform wraps it onto its own line
}

init() {
  terraform -chdir="$STACK" init -input=false -no-color -reconfigure \
    -backend-config="bucket=acscg-tfstate-${TF_VAR_aws_account_id}-${REGION}" \
    -backend-config="key=stack/${ENV}/terraform.tfstate" \
    -backend-config="region=${REGION}" \
    -backend-config="encrypt=true" \
    -backend-config="kms_key_id=alias/acscg-tfstate" \
    -backend-config="use_lockfile=true" >"$WORK/init.log" 2>&1 || {
    grep -E '^(Error|│)' "$WORK/init.log" | redact | head -40
    return 1
  }
}

plan() {
  local extra=()
  [ "$MODE" = destroy ] && extra+=(-destroy)
  terraform -chdir="$STACK" plan -input=false -lock-timeout=120s -no-color \
    -var-file="../envs/$ENV/terraform.tfvars" "${extra[@]}" -out="$WORK/tfplan" >"$WORK/plan.log" 2>&1 || {
    grep -E '^(Error|│)' "$WORK/plan.log" | redact | head -40
    return 1
  }
  terraform -chdir="$STACK" show -json "$WORK/tfplan" >"$WORK/plan.json"
  grep -E '^Plan:|^No changes' "$WORK/plan.log" || true
}

init

case "$CMD" in
  plan)
    plan
    python3 "$ROOT/scripts/plan_guard.py" check "$WORK/plan.json" --mode "$MODE" | tee "$WORK/guard.txt"
    DIGEST=$(sed -n 's/^digest=//p' "$WORK/guard.txt")
    if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "digest=$DIGEST" >>"$GITHUB_OUTPUT"; fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "### Terraform plan: $ENV ($MODE)"
        echo '```'
        grep -E '^Plan:' "$WORK/plan.log" || true
        grep -v '^digest=' "$WORK/guard.txt" | redact
        echo '```'
        echo "Digest for terraform-apply: \`$DIGEST\`"
      } >>"$GITHUB_STEP_SUMMARY"
    fi
    ;;
  apply)
    [[ ${EXPECTED_DIGEST:-} =~ ^[0-9a-f]{64}$ ]] || { echo "::error::EXPECTED_DIGEST must be 64 lowercase hex"; exit 2; }
    plan
    python3 "$ROOT/scripts/plan_guard.py" verify "$WORK/plan.json" --mode "$MODE" --expected "$EXPECTED_DIGEST"
    if terraform -chdir="$STACK" apply -input=false -lock-timeout=120s -no-color "$WORK/tfplan" >"$WORK/apply.log" 2>&1; then
      grep -E '^(Apply complete|Destroy complete)' "$WORK/apply.log"
    else
      # Print each error block (summary, address, provider message) without account IDs or e-mails.
      sed -n '/^Error/,$p' "$WORK/apply.log" | redact | head -80
      echo "Resources completed before the error: $(grep -cE ': Creation complete|: Modifications complete|: Destruction complete' "$WORK/apply.log")"
      exit 1
    fi
    ;;
  drift)
    set +e
    terraform -chdir="$STACK" plan -input=false -lock-timeout=120s -no-color -detailed-exitcode \
      -var-file="../envs/$ENV/terraform.tfvars" -out="$WORK/tfplan" >"$WORK/plan.log" 2>&1
    CODE=$?
    set -e
    case $CODE in
      0) echo "No drift." ;;
      2)
        terraform -chdir="$STACK" show -json "$WORK/tfplan" >"$WORK/plan.json"
        echo "Drift detected (addresses and actions only):"
        python3 "$ROOT/scripts/plan_guard.py" check "$WORK/plan.json" --mode apply >/dev/null || true
        python3 - "$WORK/plan.json" <<'PY'
import json, sys
plan = json.load(open(sys.argv[1]))
for rc in plan.get("resource_changes", []):
    actions = rc["change"]["actions"]
    if actions != ["no-op"] and rc.get("mode") == "managed":
        print(f"- {'/'.join(actions)}: {rc['address']}")
PY
        exit 3
        ;;
      *) grep -E '^(Error|│)' "$WORK/plan.log" | redact | head -40; exit 1 ;;
    esac
    ;;
  *) echo "::error::unknown command $CMD"; exit 2 ;;
esac
