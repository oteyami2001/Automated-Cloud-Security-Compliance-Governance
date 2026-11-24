#!/usr/bin/env bash
# Terraform CI wrapper for the stack (ADR 0008). Used by the GitHub workflows in Phase 8.
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

plan() {
  local extra=()
  [ "$MODE" = destroy ] && extra+=(-destroy)
  terraform -chdir="$STACK" plan -input=false -lock-timeout=120s -no-color \
    -var-file="../envs/$ENV/terraform.tfvars" "${extra[@]}" -out="$WORK/tfplan" >"$WORK/plan.log" 2>&1 || {
    grep -E '^(Error|│)' "$WORK/plan.log" | sed -E 's/[0-9]{12}/***/g' | head -40
    return 1
  }
  terraform -chdir="$STACK" show -json "$WORK/tfplan" >"$WORK/plan.json"
}

case "$CMD" in
  plan)
    plan
    python3 "$ROOT/scripts/plan_guard.py" check "$WORK/plan.json" --mode "$MODE" | tee "$WORK/guard.txt"
    DIGEST=$(sed -n 's/^digest=//p' "$WORK/guard.txt")
    if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "digest=$DIGEST" >>"$GITHUB_OUTPUT"; fi
    ;;
  apply)
    [[ ${EXPECTED_DIGEST:-} =~ ^[0-9a-f]{64}$ ]] || { echo "::error::EXPECTED_DIGEST must be 64 lowercase hex"; exit 2; }
    plan
    python3 "$ROOT/scripts/plan_guard.py" verify "$WORK/plan.json" --mode "$MODE" --expected "$EXPECTED_DIGEST"
    terraform -chdir="$STACK" apply -input=false -lock-timeout=120s -no-color "$WORK/tfplan" 2>&1 |
      grep -E '^(Apply complete|Destroy complete|Error)' | sed -E 's/[0-9]{12}/***/g'
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
      *) grep -E '^(Error|│)' "$WORK/plan.log" | sed -E 's/[0-9]{12}/***/g' | head -40; exit 1 ;;
    esac
    ;;
  *) echo "::error::unknown command $CMD"; exit 2 ;;
esac
