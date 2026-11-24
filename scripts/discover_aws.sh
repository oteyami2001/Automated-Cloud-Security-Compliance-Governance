#!/usr/bin/env bash
# Phase 0 AWS discovery for ACSCG. READ-ONLY.
#
# Every call is a Describe/List/Get API (plus one optional Cost Explorer query). Nothing is created,
# modified, enabled or deleted. In particular the script never calls iam generate-credential-report,
# securityhub enable-*, guardduty create-*, config put-* or access-analyzer create-*.
# A denied call is recorded as DENIED (often itself a finding, e.g. an SCP) and the script continues.
#
# Usage (AWS CloudShell, signed in to the account you intend to use):
#   bash scripts/discover_aws.sh us-east-2 us-east-1 > discovery-report-$(date -u +%Y%m%d).md
#
# Output: Markdown on stdout. By default the account ID, ARNs' account segment, e-mail addresses and
# IPv4 addresses are replaced with placeholders (REDACT=0 disables this for your private copy).
# discovery-report*.md is git-ignored. Review the report before sharing any part of it.
#
# Cost: ce:GetCostAndUsage is billed at USD 0.01 per request and runs once; SKIP_COST_EXPLORER=1 skips it.
# Requires: aws CLI v2 (pre-installed in CloudShell). jq is optional.
set -uo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <region> [<region> ...]   e.g. $0 us-east-2 us-east-1" >&2
  exit 2
fi
command -v aws >/dev/null || { echo "aws CLI not found" >&2; exit 2; }

REDACT=${REDACT:-1}
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)
[[ $ACCOUNT_ID =~ ^[0-9]{12}$ ]] || { echo "Cannot call sts:GetCallerIdentity; sign in first" >&2; exit 2; }

redact() {
  if [ "$REDACT" = "1" ]; then
    # Own account, then ANY other 12-digit account ID (e.g. the Organizations management account),
    # AWS unique IDs, session UUIDs, authorization IDs, e-mails, IPv4 (0.0.0.0/0 stays readable).
    sed -E \
      -e "s/${ACCOUNT_ID}/<ACCOUNT_ID>/g" \
      -e 's/(^|[^0-9])[0-9]{12}([^0-9]|$)/\1<OTHER_ACCOUNT_ID>\2/g' \
      -e 's/(^|[^0-9])[0-9]{12}([^0-9]|$)/\1<OTHER_ACCOUNT_ID>\2/g' \
      -e 's/\b(AROA|AIDA|AKIA|ASIA|ANPA|AGPA|AIPA)[A-Z0-9]{12,}\b/<UNIQUE_ID>/g' \
      -e 's/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/<UUID>/g' \
      -e 's/(authorization[ -]?id:? )[a-z0-9]{20,}/\1<AUTH_ID>/g; s/authorization-details\/[a-z0-9]{20,}/authorization-details\/<AUTH_ID>/g' \
      -e 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/<EMAIL>/g' \
      -e 's/0\.0\.0\.0\/0/__ANY_IPV4__/g' \
      -e 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?\b/<IPV4>/g' \
      -e 's/__ANY_IPV4__/0.0.0.0\/0/g' \
      -e 's/\b(o-[a-z0-9]{10,32}|r-[a-z0-9]{4,32}|p-[a-z0-9]{8,128})\b/<ORG_ID>/g'
  else
    cat
  fi
}

# run <label> <aws args...>: prints an OK/DENIED section with (truncated) JSON output.
run() {
  local label=$1; shift
  local out reason
  if out=$(aws "$@" --output json 2>&1); then
    printf -- '- **%s**: OK\n\n```json\n%s\n```\n\n' "$label" "$(printf '%s' "$out" | head -c 6000)"
  else
    reason=$(printf '%s' "$out" | grep -oE '(AccessDenied[A-Za-z]*|UnauthorizedOperation|explicit deny[^.]*|AWSOrganizationsNotInUse[A-Za-z]*|InvalidAccessException|NoSuchConfigurationRecorder[A-Za-z]*|[A-Za-z]+NotFound[A-Za-z]*|[A-Za-z]+Exception)' | head -1)
    printf -- '- **%s**: DENIED/ERROR (%s)\n\n```\n%s\n```\n\n' "$label" "${reason:-see output}" "$(printf '%s' "$out" | head -c 1500)"
  fi
}

{
echo "# ACSCG AWS discovery report"
echo
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) by scripts/discover_aws.sh (read-only). Regions: $*. Redaction: $REDACT."
echo
echo "## 1. Identity and organization (global)"
run "Caller identity" sts get-caller-identity
run "Organization membership" organizations describe-organization
run "SCPs visible to this account (fails in member accounts; expected)" organizations list-policies --filter SERVICE_CONTROL_POLICY
run "Account aliases (Project 2 recorded an SCP deny here)" iam list-account-aliases
run "IAM account summary" iam get-account-summary --query "SummaryMap.{Users:Users,Roles:Roles,Policies:Policies,MFADevices:MFADevices,AccountMFAEnabled:AccountMFAEnabled,AccountAccessKeysPresent:AccountAccessKeysPresent}"
run "IAM password policy" iam get-account-password-policy
run "IAM users (names only) and console/MFA posture is evaluated later by Config, not here" iam list-users --query "length(Users)"
run "GitHub OIDC providers" iam list-open-id-connect-providers
run "Existing project roles (acscg-*)" iam list-roles --query "Roles[?starts_with(RoleName, 'acscg-')].RoleName"
run "Other project roles (aiops-*, idp-*) - never modified by this project" iam list-roles --query "Roles[?starts_with(RoleName, 'aiops-') || starts_with(RoleName, 'idp-')].RoleName"
run "Service-linked roles for security services" iam list-roles --path-prefix /aws-service-role/ --query "Roles[?contains(RoleName, 'Config') || contains(RoleName, 'SecurityHub') || contains(RoleName, 'GuardDuty') || contains(RoleName, 'AccessAnalyzer')].RoleName"
run "Permissions boundaries in use (customer policies named *boundary*)" iam list-policies --scope Local --query "Policies[?contains(PolicyName, 'boundary')].PolicyName"
run "S3 buckets: state, trail, evidence, config" s3api list-buckets --query "Buckets[?contains(Name, 'tfstate') || contains(Name, 'trail') || contains(Name, 'config') || contains(Name, 'acscg') || contains(Name, 'evidence')].Name"
run "S3 account-level Block Public Access" s3control get-public-access-block --account-id "$ACCOUNT_ID"
run "Budgets" budgets describe-budgets --account-id "$ACCOUNT_ID" --query "Budgets[].{Name:BudgetName,Limit:BudgetLimit,Type:BudgetType,Filters:CostFilters}"

if [ "${SKIP_COST_EXPLORER:-0}" != "1" ]; then
  START=$(date -u +%Y-%m-01)
  END=$(date -u -d tomorrow +%Y-%m-%d 2>/dev/null || date -u -v+1d +%Y-%m-%d)
  run "Month-to-date cost by service (Cost Explorer, USD 0.01)" ce get-cost-and-usage \
    --time-period "Start=$START,End=$END" --granularity MONTHLY --metrics UnblendedCost \
    --group-by Type=DIMENSION,Key=SERVICE \
    --query "ResultsByTime[0].Groups[?to_number(Metrics.UnblendedCost.Amount) > \`0.001\`].{Service:Keys[0],USD:Metrics.UnblendedCost.Amount}"
fi

for REGION in "$@"; do
  echo "## 2. Region $REGION"
  echo
  echo "### CloudTrail"
  run "Trails (incl. shadow/organization trails)" cloudtrail describe-trails --region "$REGION" --include-shadow-trails --query "trailList[].{Name:Name,Home:HomeRegion,MultiRegion:IsMultiRegionTrail,Org:IsOrganizationTrail,Validation:LogFileValidationEnabled,KMS:KmsKeyId,Bucket:S3BucketName,CWLogs:CloudWatchLogsLogGroupArn}"
  for T in $(aws cloudtrail describe-trails --region "$REGION" --query "trailList[?HomeRegion=='$REGION'].TrailARN" --output text 2>/dev/null); do
    run "Trail status ${T##*/}" cloudtrail get-trail-status --region "$REGION" --name "$T" --query "{IsLogging:IsLogging,LatestDelivery:LatestDeliveryTime,LatestDeliveryError:LatestDeliveryError}"
    run "Event selectors ${T##*/}" cloudtrail get-event-selectors --region "$REGION" --trail-name "$T"
  done
  run "CloudTrail Lake event data stores" cloudtrail list-event-data-stores --region "$REGION" --query "EventDataStores[].{Name:Name,Status:Status}"

  echo "### AWS Config"
  run "Configuration recorders" configservice describe-configuration-recorders --region "$REGION"
  run "Recorder status" configservice describe-configuration-recorder-status --region "$REGION"
  run "Configuration recorders (incl. service-linked)" configservice list-configuration-recorders --region "$REGION"
  run "Delivery channels" configservice describe-delivery-channels --region "$REGION"
  run "Config rules (name, source, owner)" configservice describe-config-rules --region "$REGION" --query "ConfigRules[].{Name:ConfigRuleName,Source:Source.SourceIdentifier,Owner:Source.Owner,CreatedBy:CreatedBy,State:ConfigRuleState}"
  run "Conformance packs" configservice describe-conformance-packs --region "$REGION" --query "ConformancePackDetails[].ConformancePackName"
  run "Aggregators" configservice describe-configuration-aggregators --region "$REGION" --query "ConfigurationAggregators[].ConfigurationAggregatorName"
  run "Remediation configurations (existing auto-remediation)" configservice describe-remediation-configurations --region "$REGION" --config-rule-names $(aws configservice describe-config-rules --region "$REGION" --query "ConfigRules[].ConfigRuleName" --output text 2>/dev/null | head -c 2000) 2>/dev/null

  echo "### Security Hub CSPM"
  run "Hub" securityhub describe-hub --region "$REGION"
  run "Enabled standards" securityhub get-enabled-standards --region "$REGION" --query "StandardsSubscriptions[].{Arn:StandardsArn,Status:StandardsStatus}"
  run "Administrator account" securityhub get-administrator-account --region "$REGION"
  run "Finding aggregator" securityhub list-finding-aggregators --region "$REGION"

  echo "### GuardDuty"
  run "Detectors" guardduty list-detectors --region "$REGION"
  for D in $(aws guardduty list-detectors --region "$REGION" --query "DetectorIds[]" --output text 2>/dev/null); do
    run "Detector $D (status and protection plans)" guardduty get-detector --region "$REGION" --detector-id "$D" --query "{Status:Status,Created:CreatedAt,Features:Features[].{Name:Name,Status:Status}}"
    run "Detector $D administrator" guardduty get-administrator-account --region "$REGION" --detector-id "$D"
  done

  echo "### IAM Access Analyzer"
  run "Analyzers" accessanalyzer list-analyzers --region "$REGION" --query "analyzers[].{Name:name,Type:type,Status:status}"

  echo "### Event routing, compute and storage used by the platform"
  run "EventBridge buses" events list-event-buses --region "$REGION" --query "EventBuses[].Name"
  run "EventBridge rules on default bus (names)" events list-rules --region "$REGION" --query "Rules[].{Name:Name,State:State,ManagedBy:ManagedBy}"
  run "Lambda functions (names)" lambda list-functions --region "$REGION" --query "Functions[].FunctionName"
  run "DynamoDB tables" dynamodb list-tables --region "$REGION"
  run "SNS topics" sns list-topics --region "$REGION" --query "Topics[].TopicArn"
  run "SSM Automation documents owned by the account" ssm list-documents --region "$REGION" --filters Key=Owner,Values=Self Key=DocumentType,Values=Automation --query "DocumentIdentifiers[].Name"
  run "KMS aliases (customer)" kms list-aliases --region "$REGION" --query "Aliases[?!starts_with(AliasName, 'alias/aws/')].AliasName"
  run "CloudWatch dashboards" cloudwatch list-dashboards --region "$REGION" --query "DashboardEntries[].DashboardName"
  run "Log groups without retention (count)" logs describe-log-groups --region "$REGION" --query "length(logGroups[?!retentionInDays])"

  echo "### Network baseline (to protect unrelated resources)"
  run "VPCs" ec2 describe-vpcs --region "$REGION" --query "Vpcs[].{Id:VpcId,Default:IsDefault,Cidr:CidrBlock}"
  run "Security groups with 0.0.0.0/0 or ::/0 ingress (pre-existing; never remediated by this project)" ec2 describe-security-groups --region "$REGION" --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0'] || Ipv6Ranges[?CidrIpv6=='::/0']]].{Id:GroupId,Name:GroupName,Vpc:VpcId}"
  run "EBS encryption by default" ec2 get-ebs-encryption-by-default --region "$REGION"
  run "Running/stopped EC2 instances (count)" ec2 describe-instances --region "$REGION" --query "length(Reservations[].Instances[])"

  echo "### Quotas relevant to the design"
  run "AWS Config quotas" service-quotas list-service-quotas --region "$REGION" --service-code config --query "Quotas[].{Name:QuotaName,Value:Value}"
  run "Lambda concurrent executions" service-quotas get-service-quota --region "$REGION" --service-code lambda --quota-code L-B99A9384 --query "Quota.Value"
  run "EventBridge quotas" service-quotas list-service-quotas --region "$REGION" --service-code events --query "Quotas[].{Name:QuotaName,Value:Value}"
done

echo "## 3. Notes"
echo
echo "- Organization SCP documents cannot be read from a member account. Infer SCP scope from DENIED entries."
echo "- IAM is global: its CloudTrail events are delivered to EventBridge in us-east-1 only."
echo "- This report is read-only evidence for Phase 0. Commit only the redacted summary (docs/phase-0-assessment.md)."
} | redact
