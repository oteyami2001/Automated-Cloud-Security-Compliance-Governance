#!/usr/bin/env python3
"""Read-only verification of the dev deployment and the validation scenarios (Phase 5+).

Runs in GitHub Actions with the read-only plan role (terraform-plan's OIDC role), so it can be
started without CloudShell. It only calls Describe/Get/List/Filter APIs and reads one evidence
object. Output is one line per check - PASS / FAIL / INFO - with fixture *names*, never account
IDs, resource IDs or ARNs (public logs). Exit code 1 if any check fails.

    python scripts/verify_deployment.py --env dev --region us-east-2
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

# Alerts are sent only when a finding changes state, so a quiet day has none. Seven days covers the
# last scenario run; the first verification used 24 h and reported a false FAIL (evidence P5-11).
SNS_WINDOW_HOURS = 7 * 24
# Fixture violations are switched on only during a scenario (Phase 6 closed them), so the checks
# accept either an open violation or a resolved one, as long as Config and the finding agree.
OPEN_STATES = {
    "OPEN",
    "REPORTED",
    "REJECTED_POLICY",
    "PENDING_APPROVAL",
    "REMEDIATING",
    "REMEDIATION_REJECTED",
    "APPROVAL_EXPIRED",
    "REMEDIATION_FAILED",
    "VERIFYING",
    "VERIFICATION_FAILED",
    "SUPPRESSED_EXCEPTION",
}
RESOLVED_STATES = {"COMPLIANT", "VERIFIED_RESOLVED", "RESOLVED_EXTERNALLY"}

REQUIRED_EVIDENCE_FIELDS = (
    "finding_id",
    "control_id",
    "resource",
    "detection_timestamp",
    "previous_compliance_state",
    "proposed_remediation",
    "approval",
    "execution_result",
    "updated_compliance_state",
    "verification_timestamp",
    "checksum",
)


@dataclass
class Report:
    lines: list[str] = field(default_factory=list)
    failed: int = 0

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.lines.append(f"{'PASS' if ok else 'FAIL'}  {name}" + (f": {detail}" if detail else ""))
        self.failed += 0 if ok else 1
        return ok

    def info(self, name: str, detail: str) -> None:
        self.lines.append(f"INFO  {name}: {detail}")


@dataclass
class Clients:
    config: Any
    ec2: Any
    dynamodb: Any
    s3: Any
    logs: Any
    cloudwatch: Any
    sqs: Any
    sts: Any


def canonical_sha256(body: dict[str, Any]) -> str:
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _group_id(ec2: Any, name: str) -> str | None:
    groups = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [name]}])["SecurityGroups"]
    return groups[0]["GroupId"] if groups else None


def _rule_results(config: Any, resource_type: str, resource_id: str) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    token = None
    while True:
        args = {"ResourceType": resource_type, "ResourceId": resource_id}
        if token:
            args["NextToken"] = token
        page = config.get_compliance_details_by_resource(**args)
        for r in page.get("EvaluationResults", []):
            rule = r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ConfigRuleName"]
            out[rule] = (r["ComplianceType"], r.get("Annotation", ""))
        token = page.get("NextToken")
        if not token:
            return out


def _findings(dynamodb: Any, table: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    args: dict[str, Any] = {
        "TableName": table,
        "FilterExpression": "sk = :s",
        "ExpressionAttributeValues": {":s": {"S": "STATE"}},
    }
    while True:
        page = dynamodb.scan(**args)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return items
        args["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def _s(item: dict[str, Any], key: str) -> str:
    return str(item.get(key, {}).get("S", ""))


CORE_FUNCTIONS = ("findings-processor", "config-evaluator", "findings-reconciler", "report-generator")


def _project_functions(cw: Any, prefix: str) -> set[str]:
    """Lambda functions of this project with an Errors metric in the last two weeks."""
    names: set[str] = set()
    kwargs: dict[str, Any] = {"Namespace": "AWS/Lambda", "MetricName": "Errors"}
    while True:
        page = cw.list_metrics(**kwargs)
        for metric in page.get("Metrics", []):
            for dim in metric.get("Dimensions", []):
                if dim["Name"] == "FunctionName" and dim["Value"].startswith(f"{prefix}-"):
                    names.add(dim["Value"])
        if not page.get("NextToken"):
            return names
        kwargs["NextToken"] = page["NextToken"]


def _metric_sum(cw: Any, metric: tuple[str, str], dims: dict[str, str], *, hours: int, now: datetime) -> float:
    """Sum of a CloudWatch metric over the last ``hours``; ``metric`` is (namespace, name)."""
    stats = cw.get_metric_statistics(
        Namespace=metric[0],
        MetricName=metric[1],
        Dimensions=[{"Name": k, "Value": v} for k, v in dims.items()],
        StartTime=now - timedelta(hours=hours),
        EndTime=now,
        Period=hours * 3600,
        Statistics=["Sum"],
    )
    return float(sum(p["Sum"] for p in stats.get("Datapoints", [])))


def _count_log_events(logs: Any, group: str, pattern: str, hours: int, now: datetime) -> int:
    total, token = 0, None
    start = int((now - timedelta(hours=hours)).timestamp() * 1000)
    while True:
        args: dict[str, Any] = {"logGroupName": group, "filterPattern": pattern, "startTime": start}
        if token:
            args["nextToken"] = token
        page = logs.filter_log_events(**args)
        total += len(page.get("events", []))
        token = page.get("nextToken")
        if not token:
            return total


def verify(c: Clients, env: str, region: str, now: datetime | None = None) -> Report:  # noqa: PLR0915 - one flat checklist
    now = now or datetime.now(UTC)
    rep = Report()
    account = c.sts.get_caller_identity()["Account"]
    prefix = f"acscg-{env}"

    # -- platform health
    status = c.config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
    own = [s for s in status if s["name"] == f"{prefix}-recorder"]
    rep.check("config recorder recording", bool(own) and own[0]["recording"] and own[0].get("lastStatus") == "SUCCESS")
    names = [r["ConfigRuleName"] for r in c.config.describe_config_rules()["ConfigRules"]]
    rep.info("project config rules", str(sum(n.startswith("acscg-") for n in names)))
    # Every project function that reported metrics recently, not a fixed list: a fixed list missed the
    # Phase 6 gatekeeper's errors (evidence P7-3).
    functions = sorted(_project_functions(c.cloudwatch, prefix) | {f"{prefix}-{f}" for f in CORE_FUNCTIONS})
    errors = sum(
        _metric_sum(c.cloudwatch, ("AWS/Lambda", "Errors"), {"FunctionName": fn}, hours=24, now=now) for fn in functions
    )
    rep.check(f"lambda errors (24 h, {len(functions)} functions)", errors == 0, f"{errors:.0f}")
    url = c.sqs.get_queue_url(QueueName=f"{prefix}-findings-dlq")["QueueUrl"]
    depth = int(
        c.sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"][
            "ApproximateNumberOfMessages"
        ]
    )
    rep.check("dead-letter queue empty", depth == 0, str(depth))

    # -- fixtures (scenarios 2, 3, 4)
    sg = _group_id(c.ec2, f"{prefix}-fixture-sg")
    untagged = _group_id(c.ec2, f"{prefix}-fixture-untagged-sg")
    bucket = f"{prefix}-fixture-{account}-{region}"
    findings = _findings(c.dynamodb, f"{prefix}-findings")

    def finding(control: str, ident: str | None) -> dict[str, Any] | None:
        return next((f for f in findings if _s(f, "control_id") == control and ident and ident in json.dumps(f)), None)

    def agree(scenario: str, control: str, result: str, f: dict[str, Any] | None, *, severity: str) -> None:
        """Config's result and the finding agree, with or without an active fixture violation (P7)."""
        state = _s(f, "state") if f else ""
        if result == "NON_COMPLIANT":
            ok = bool(f) and state in OPEN_STATES and _s(f, "severity") == severity
            expect = f"open, {severity}"
        else:
            ok = result == "COMPLIANT" and (not f or state in RESOLVED_STATES)
            expect = "resolved or none"
        rep.check(
            f"{scenario}: Config {control} result and finding agree ({expect})",
            ok,
            f"{result or 'no result'} / {state or 'no finding'}",
        )

    if sg:
        rules = _rule_results(c.config, "AWS::EC2::SecurityGroup", sg)
        ssh = rules.get("acscg-sec005-restricted-ssh", ("", ""))[0]
        agree("scenario 2", "SEC-005", ssh, finding("SEC-005", sg), severity="high")
    else:
        rep.info("scenario 2", "fixture-sg not present")
    if untagged:
        rules = _rule_results(c.config, "AWS::EC2::SecurityGroup", untagged)
        tags = rules.get("acscg-sec013-tags-custom", ("", ""))
        f = finding("SEC-013", untagged)
        agree("scenario 3", "SEC-013", tags[0], f, severity="low")
        if tags[0] == "NON_COMPLIANT":
            rep.check(
                "scenario 3: the custom tag rule and the finding name the missing keys",
                "missing:" in tags[1] and bool(f) and "missing:" in _s(f, "annotation"),
                tags[1][:80],
            )
    else:
        rep.info("scenario 3", "fixture-untagged-sg not present")
    try:
        rules = _rule_results(c.config, "AWS::S3::Bucket", bucket)
        bpa = rules.get("acscg-sec001-bucket-public-access", ("", ""))[0]
        agree("scenario 4", "SEC-001", bpa, finding("SEC-001", bucket), severity="high")
        public = c.s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"]
        rep.check("scenario 4 live check: fixture bucket is NOT public", public is False, f"IsPublic={public}")
    except c.s3.exceptions.NoSuchBucket:
        rep.info("scenario 4", "fixture bucket not present")

    # -- scenario 6: duplicates are dropped
    dups = sum(
        _count_log_events(c.logs, f"/aws/lambda/{prefix}-{f}", '"duplicate event"', 24, now)
        for f in ("findings-processor", "findings-reconciler")
    )
    rep.check("scenario 6: duplicate events dropped (24 h log lines)", dups > 0, str(dups))

    # -- scenario 12: notifications delivered
    topic = f"{prefix}-security-alerts"
    delivered = _metric_sum(
        c.cloudwatch,
        ("AWS/SNS", "NumberOfNotificationsDelivered"),
        {"TopicName": topic},
        hours=SNS_WINDOW_HOURS,
        now=now,
    )
    failed = _metric_sum(
        c.cloudwatch, ("AWS/SNS", "NumberOfNotificationsFailed"), {"TopicName": topic}, hours=SNS_WINDOW_HOURS, now=now
    )
    rep.check(
        f"scenario 12: SNS notifications delivered ({SNS_WINDOW_HOURS // 24} days)",
        delivered > 0 and failed == 0,
        f"delivered {delivered:.0f}, failed {failed:.0f}",
    )

    # -- scenario 13: evidence integrity
    ebucket = f"{prefix}-evidence-{account}-{region}"
    objects: list[dict[str, Any]] = []
    for page in c.s3.get_paginator("list_objects_v2").paginate(Bucket=ebucket, Prefix="evidence/"):
        objects.extend(page.get("Contents", []))
    rep.check("scenario 13: evidence objects exist", bool(objects), str(len(objects)))
    if objects:
        newest = max(objects, key=lambda o: o["LastModified"])
        obj = c.s3.get_object(Bucket=ebucket, Key=newest["Key"])
        doc = json.loads(obj["Body"].read())
        missing = [k for k in REQUIRED_EVIDENCE_FIELDS if k not in doc]
        rep.check("scenario 13: all required evidence fields", not missing, ",".join(missing) or "none missing")
        stored = doc.get("checksum", {}).get("sha256", "")
        calc = canonical_sha256({k: v for k, v in doc.items() if k != "checksum"})
        rep.check("scenario 13: recomputed SHA-256 equals stored", calc == stored)
        rep.check(
            "scenario 13: S3 metadata checksum equals stored", obj.get("Metadata", {}).get("acscg-sha256") == stored
        )
        retention = c.s3.get_object_retention(Bucket=ebucket, Key=newest["Key"])["Retention"]
        rep.check(
            "scenario 13: Object Lock GOVERNANCE retention",
            retention["Mode"] == "GOVERNANCE",
            f"until {retention['RetainUntilDate']}",
        )
    return rep


def main(argv: list[str] | None = None, factory: Callable[[str], Clients] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env", default="dev", choices=["dev", "staging", "prod"])
    parser.add_argument("--region", default="us-east-2")
    args = parser.parse_args(argv)
    if factory is None:  # pragma: no cover - real AWS clients only in the workflow
        import boto3  # noqa: PLC0415

        def factory(region: str) -> Clients:
            return Clients(
                *(
                    boto3.client(s, region_name=region)
                    for s in ("config", "ec2", "dynamodb", "s3", "logs", "cloudwatch", "sqs", "sts")
                )
            )

    report = verify(factory(args.region), args.env, args.region)
    print(f"# ACSCG deployment verification ({datetime.now(UTC):%Y-%m-%dT%H:%M:%SZ}, {args.env}, {args.region})")
    print("\n".join(report.lines))
    print("RESULT: " + ("all checks passed" if report.failed == 0 else f"{report.failed} check(s) failed"))
    return 0 if report.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
