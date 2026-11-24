"""Live re-checks: read the resource *now* and confirm the violation still exists.

Each checker returns a :class:`LiveCheck` built from AWS read APIs only. The parameters it returns
(e.g. the exact security-group rule IDs) are what the runbook acts on, so the runbook never acts on
data from the triggering event. Any error returns ``None`` (the gatekeeper then denies).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from acscg.compliance_evaluator.security_groups import ADMIN_PORTS, open_rules
from acscg.compliance_evaluator.tags import evaluate_tags
from acscg.remediation_engine.gatekeeper import LiveCheck

BPA_FIELDS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


class Clients(Protocol):
    def client(self, service: str) -> Any: ...


def _identity(finding: dict[str, Any]) -> dict[str, str]:
    return {
        "account": str(finding["account"]),
        "region": str(finding["region"]),
        "resource_arn": str(finding["resource_identifier"]),
    }


def check_security_group(finding: dict[str, Any], clients: Clients) -> LiveCheck:
    group_id = finding["resource_id"]
    ec2 = clients.client("ec2")
    rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [group_id]}])[
        "SecurityGroupRules"
    ]
    offending = open_rules(rules, ADMIN_PORTS[finding["control_id"]])
    enis = ec2.describe_network_interfaces(Filters=[{"Name": "group-id", "Values": [group_id]}])["NetworkInterfaces"]
    return LiveCheck(
        violation_present=bool(offending),
        parameters={
            "SecurityGroupId": group_id,
            "SecurityGroupRuleIds": sorted(r.rule_id for r in offending if r.rule_id),
        },
        needs_approval=True,
        note=f"{len(offending)} offending rule(s); attached to {len(enis)} network interface(s)",
        **_identity(finding),
    )


def check_bucket_public_access(finding: dict[str, Any], clients: Clients) -> LiveCheck:
    from botocore.exceptions import ClientError  # noqa: PLC0415

    bucket = finding["resource_id"]
    try:
        config = clients.client("s3").get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        config = {}
    previous = {k: bool(config.get(k, False)) for k in BPA_FIELDS}
    return LiveCheck(
        violation_present=not all(previous.values()),
        parameters={"BucketName": bucket, "Previous": previous},
        **_identity(finding),
    )


def check_required_tags(finding: dict[str, Any], clients: Clients, required: tuple[str, ...]) -> LiveCheck:
    arn = finding["resource_identifier"]
    mappings = clients.client("resourcegroupstaggingapi").get_resources(ResourceARNList=[arn])["ResourceTagMappingList"]
    tags = mappings[0]["Tags"] if mappings else []
    result = evaluate_tags(tags, required)
    return LiveCheck(
        violation_present=bool(result.missing),
        parameters={"ResourceArn": arn, "MissingTagKeys": list(result.missing)},
        note="invalid tag values are reported, never overwritten" if result.invalid else "",
        **_identity(finding),
    )


def check_log_retention(
    finding: dict[str, Any], clients: Clients, target_days: int, now: datetime | None = None
) -> LiveCheck:
    name = finding["resource_id"]
    groups = clients.client("logs").describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    group = next((g for g in groups if g["logGroupName"] == name), None)
    if group is None:
        return LiveCheck(False, parameters={"LogGroupName": name}, note="log group not found", **_identity(finding))
    never_expires = "retentionInDays" not in group
    created = datetime.fromtimestamp(group["creationTime"] / 1000, tz=UTC)
    current = now or datetime.now(UTC)
    # Data older than the target would be deleted by the new retention: require a human.
    may_delete_data = created < current - timedelta(days=target_days)
    return LiveCheck(
        violation_present=never_expires,
        parameters={"LogGroupName": name, "RetentionInDays": str(target_days)},
        needs_approval=may_delete_data,
        note="existing data older than target retention" if may_delete_data else "",
        **_identity(finding),
    )


def check_imdsv2(finding: dict[str, Any], clients: Clients) -> LiveCheck:
    instance_id = finding["resource_id"]
    reservations = clients.client("ec2").describe_instances(InstanceIds=[instance_id])["Reservations"]
    instance = reservations[0]["Instances"][0]
    options = instance.get("MetadataOptions", {})
    return LiveCheck(
        violation_present=options.get("HttpTokens") == "optional"
        and options.get("HttpEndpoint", "enabled") == "enabled",
        parameters={"InstanceId": instance_id, "PreviousHttpTokens": options.get("HttpTokens")},
        needs_approval=True,
        **_identity(finding),
    )


def run_check(
    finding: dict[str, Any], clients: Clients, *, required_tags: tuple[str, ...], log_retention_days: int
) -> LiveCheck | None:
    checkers = {
        "SEC-001": lambda: check_bucket_public_access(finding, clients),
        "SEC-005": lambda: check_security_group(finding, clients),
        "SEC-006": lambda: check_security_group(finding, clients),
        "SEC-008": lambda: check_imdsv2(finding, clients),
        "SEC-013": lambda: check_required_tags(finding, clients, required_tags),
        "SEC-014": lambda: check_log_retention(finding, clients, log_retention_days),
    }
    checker = checkers.get(finding["control_id"])
    if checker is None:
        return None
    try:
        return checker()
    except Exception:  # noqa: BLE001 - any failure to read the resource means "cannot confirm", so the gatekeeper denies
        return None
