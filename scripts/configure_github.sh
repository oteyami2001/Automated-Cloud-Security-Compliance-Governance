#!/usr/bin/env bash
# Apply the repository settings the pipeline relies on (OWNER ACTION, changes settings).
# Run once, signed in to gh as the repository owner (`gh auth login`), from a clone of this repo.
# Afterwards run scripts/verify_github_settings.sh: its read-back is the evidence.
#
#   bash scripts/configure_github.sh
set -euo pipefail

REPO=oteyami2001/Automated-Cloud-Security-Compliance-Governance
OWNER_ID=157901928 # numeric GitHub user ID of the owner (required reviewer)
cd "$(dirname "$0")/.."
command -v gh >/dev/null || { echo "gh CLI not found" >&2; exit 2; }
[ -z "${GITHUB_TOKEN:-}" ] || { echo "unset GITHUB_TOKEN and use 'gh auth login' as the owner" >&2; exit 2; }

echo "1/6 default branch = main"
gh api -X PATCH "repos/$REPO" -f default_branch=main --silent

echo "2/6 secret scanning, push protection, Dependabot"
gh api -X PATCH "repos/$REPO" --silent --input - <<'EOF'
{"security_and_analysis": {
  "secret_scanning": {"status": "enabled"},
  "secret_scanning_push_protection": {"status": "enabled"},
  "dependabot_security_updates": {"status": "enabled"}}}
EOF
gh api -X PUT "repos/$REPO/vulnerability-alerts" --silent

echo "3/6 Actions: read-only default token, Actions cannot approve PRs"
gh api -X PUT "repos/$REPO/actions/permissions/workflow" -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false --silent

echo "4/6 main ruleset (PR required, ci-ok required, no force push, no deletion)"
if gh api "repos/$REPO/rulesets" --jq '.[].name' | grep -qx main; then
  echo "    ruleset 'main' already exists: skipped (compare it with .github/rulesets/main.json)"
else
  gh api -X POST "repos/$REPO/rulesets" --input .github/rulesets/main.json --silent
fi

echo "5/6 environments: dev-plan (main only), dev and dev-cleanup (main only + owner approval)"
for env in dev-plan dev dev-cleanup; do
  if [ "$env" = dev-plan ]; then
    body='{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
  else
    body="{\"wait_timer\":0,\"prevent_self_review\":false,\"reviewers\":[{\"type\":\"User\",\"id\":$OWNER_ID}],\"deployment_branch_policy\":{\"protected_branches\":false,\"custom_branch_policies\":true}}"
  fi
  gh api -X PUT "repos/$REPO/environments/$env" --input - --silent <<<"$body"
  if ! gh api "repos/$REPO/environments/$env/deployment-branch-policies" --jq '.branch_policies[].name' | grep -qx main; then
    gh api -X POST "repos/$REPO/environments/$env/deployment-branch-policies" -f name=main -f type=branch --silent
  fi
done

echo "6/6 OIDC subject format (read-only)"
gh api "repos/$REPO/actions/oidc/customization/sub" || true
echo
echo "Done. Now run: bash scripts/verify_github_settings.sh"
