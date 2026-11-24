#!/usr/bin/env bash
# Verify the Phase 3 bootstrap in AWS - READ-ONLY (Describe/Get/List only).
# Prints PASS/FAIL per check with the account ID redacted; exit 0 only if every check passes.
#
#   TF_VAR_aws_account_id=<12 digits> bash scripts/verify_bootstrap.sh
set -uo pipefail

A=${TF_VAR_aws_account_id:?set TF_VAR_aws_account_id}
R=us-east-2
SUB_PREFIX="repo:oteyami2001@157901928/Automated-Cloud-Security-Compliance-Governance@1465572625"
BUCKET="acscg-tfstate-${A}-${R}"
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails + 1)); }
q() { aws --region "$R" "$@" --output text 2>/dev/null; }

echo "# ACSCG bootstrap verification ($(date -u +%Y-%m-%dT%H:%M:%SZ), us-east-2)"

[ "$(q sts get-caller-identity --query Account)" = "$A" ] && pass "signed in to the target account" || fail "wrong account"

# --- state bucket ---
[ "$(q s3api get-bucket-versioning --bucket "$BUCKET" --query Status)" = "Enabled" ] && pass "state bucket versioning" || fail "state bucket versioning"
[ "$(q s3api get-bucket-encryption --bucket "$BUCKET" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm')" = "aws:kms" ] && pass "state bucket SSE-KMS" || fail "state bucket SSE-KMS"
[ "$(q s3api get-public-access-block --bucket "$BUCKET" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' | tr -s '[:space:]' ' ' | xargs)" = "True True True True" ] && pass "state bucket public access blocked" || fail "state bucket public access block"
q s3api get-bucket-policy --bucket "$BUCKET" --query Policy | grep -q 'aws:SecureTransport' && pass "state bucket denies non-TLS" || fail "state bucket TLS-only policy"

# --- KMS ---
KEY=$(q kms describe-key --key-id alias/acscg-tfstate --query KeyMetadata.KeyId)
[ -n "$KEY" ] && [ "$(q kms get-key-rotation-status --key-id "$KEY" --query KeyRotationEnabled)" = "True" ] && pass "state key rotation enabled" || fail "state key rotation"

# --- boundary ---
q iam get-policy --policy-arn "arn:aws:iam::${A}:policy/acscg-workload-boundary" --query Policy.PolicyName | grep -q acscg-workload-boundary && pass "workload boundary exists" || fail "workload boundary missing"

# --- CI roles: each trusts exactly one immutable subject ---
for pair in "dev-plan:environment:dev-plan" "dev-apply:environment:dev" "dev-cleanup:environment:dev-cleanup" "report:ref:refs/heads/main"; do
  role="acscg-github-${pair%%:*}"
  expected="${SUB_PREFIX}:${pair#*:}"
  trust=$(aws iam get-role --role-name "$role" --query Role.AssumeRolePolicyDocument --output json 2>/dev/null)
  if [ -z "$trust" ]; then fail "$role missing"; continue; fi
  got=$(python3 -c 'import json,sys; s=json.load(sys.stdin)["Statement"]; print(len(s), s[0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"], s[0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:aud"], "StringLike" in s[0]["Condition"])' <<<"$trust")
  [ "$got" = "1 $expected sts.amazonaws.com False" ] && pass "$role trusts exactly ${pair#*:}" || fail "$role trust ($got)"
done
q iam list-attached-role-policies --role-name acscg-github-dev-plan --query 'AttachedPolicies[].PolicyName' | grep -qw ReadOnlyAccess && pass "plan role is read-only (ReadOnlyAccess)" || fail "plan role managed policy"

# --- budget ---
q budgets describe-budget --account-id "$A" --budget-name acscg-monthly --query 'Budget.CostFilters.TagKeyValue' | grep -q 'user:Project$acscg' && pass "budget acscg-monthly filtered on Project=acscg" || fail "budget acscg-monthly"

# --- pre-existing resources untouched ---
q iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' | grep -q token.actions.githubusercontent.com && pass "shared GitHub OIDC provider present" || fail "OIDC provider"
for role in aiops-github-plan idp-dev-github-plan; do
  q iam get-role --role-name "$role" --query Role.RoleName >/dev/null && pass "other project role $role untouched" || fail "$role missing"
done
[ "$(q cloudtrail get-trail-status --name idp-management-events --query IsLogging)" = "True" ] && pass "existing trail still logging" || fail "trail not logging"

# --- informational ---
status=$(q ce list-cost-allocation-tags --tag-keys Project --query 'CostAllocationTags[0].Status')
echo "INFO  cost-allocation tag Project: ${status:-not found} (must be Active for the tag-filtered budget)"

echo
if [ "$fails" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) failed"; fi
exit $(( fails > 0 ))
