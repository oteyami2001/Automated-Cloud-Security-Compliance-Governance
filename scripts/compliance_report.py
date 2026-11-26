#!/usr/bin/env python3
"""Read-only check of the latest compliance report (scenario 14, Phase 7).

Runs in GitHub Actions with the read-only plan role. It never invokes or writes anything:

1. finds the newest ``reports/<timestamp>/report.json`` in the evidence bucket and checks that its
   SHA-256 equals the checksum stored with it, for the JSON and the public Markdown;
2. checks that the posture metrics the report generator published (Embedded Metric Format, at the
   report's timestamp) equal the stored report's numbers;
3. recounts the findings table now with the same code (``build_report``) and compares: equal when
   the report is recent, otherwise listed as INFO, because findings change between reports;
4. scans the public Markdown for account IDs, e-mail addresses, IPv4 addresses, ARNs and resource
   IDs, and writes it to ``--public-out`` only if it is clean.

Output is PASS / FAIL / INFO lines without identifiers. Exit code 1 if any check fails.

    PYTHONPATH=src python scripts/compliance_report.py --env dev --region us-east-2 --public-out report.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from acscg.common.catalog import Catalog
from acscg.report_generator.report import DISCLAIMER, build_report, metric_namespace

# The stored report and a recount must be equal only when nothing can have changed in between.
RECENT_MINUTES = 30
SUMMARY_METRICS = {
    "ComplianceScore": "compliance_score",
    "ResourcesEvaluated": "resources_evaluated",
    "OpenFindings": "open_findings",
    "RemediatedFindings": "remediated_findings",
    "ExcludedSyntheticOrSample": "excluded_synthetic_or_sample",
}
LEAKS = {
    "account ID": re.compile(r"(?<![\d.])\d{12}(?![\d.])"),
    "e-mail address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "IPv4 address": re.compile(r"(?<![\d.])(?!0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "ARN": re.compile(r"\barn:aws"),
    "resource ID": re.compile(r"\b(?:sg|sgr|vpc|subnet|i|eni|vol|ami)-[0-9a-f]{8,17}\b"),
    "access key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}


@dataclass
class Result:
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
    s3: Any
    dynamodb: Any
    cloudwatch: Any
    sts: Any


def leaks(text: str) -> list[str]:
    """Kinds of identifier found in ``text`` (never the values)."""
    return [kind for kind, pattern in LEAKS.items() if pattern.search(text)]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _latest_report_key(s3: Any, bucket: str) -> str | None:
    newest: tuple[datetime, str] | None = None
    kwargs: dict[str, Any] = {"Bucket": bucket, "Prefix": "reports/"}
    while True:
        page = s3.list_objects_v2(**kwargs)
        for obj in page.get("Contents", []):
            if obj["Key"].endswith("/report.json") and (newest is None or obj["LastModified"] > newest[0]):
                newest = (obj["LastModified"], obj["Key"])
        if not page.get("IsTruncated"):
            return newest[1] if newest else None
        kwargs["ContinuationToken"] = page["NextContinuationToken"]


def _object(s3: Any, bucket: str, key: str) -> tuple[bytes, str]:
    obj = s3.get_object(Bucket=bucket, Key=key)
    return obj["Body"].read(), obj.get("Metadata", {}).get("acscg-sha256", "")


def _findings(dynamodb: Any, table: str) -> list[dict[str, Any]]:
    from boto3.dynamodb.types import TypeDeserializer  # noqa: PLC0415 - only needed against AWS

    plain = TypeDeserializer()
    items: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {
        "TableName": table,
        "FilterExpression": "sk = :s AND begins_with(pk, :p)",
        "ExpressionAttributeValues": {":s": {"S": "STATE"}, ":p": {"S": "FINDING#"}},
    }
    while True:
        page = dynamodb.scan(**kwargs)
        for raw in page.get("Items", []):
            item = {k: plain.deserialize(v) for k, v in raw.items() if k not in {"pk", "sk"}}
            items.append({k: (float(v) if type(v).__name__ == "Decimal" else v) for k, v in item.items()})
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def _metric(cloudwatch: Any, namespace: str, name: str, at: datetime, dims: list[dict[str, str]]) -> float | None:
    points = cloudwatch.get_metric_statistics(
        Namespace=namespace,
        MetricName=name,
        Dimensions=dims,
        StartTime=at - timedelta(minutes=1),
        EndTime=at + timedelta(minutes=1),
        Period=60,
        Statistics=["Maximum"],
    ).get("Datapoints", [])
    return max(p["Maximum"] for p in points) if points else None


def _summary_diff(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    return [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]


def check(clients: Clients, env: str, region: str, now: datetime, catalog: Catalog) -> tuple[Result, str]:
    res = Result()
    prefix = f"acscg-{env}"
    account = clients.sts.get_caller_identity()["Account"]
    bucket = f"{prefix}-evidence-{account}-{region}"

    key = _latest_report_key(clients.s3, bucket)
    res.check("a stored report exists", key is not None)
    if key is None:
        return res, ""
    folder = key.rsplit("/", 1)[0]
    body, stored = _object(clients.s3, bucket, key)
    res.check("report.json SHA-256 equals the stored checksum", bool(stored) and _sha(body) == stored)
    report = json.loads(body)
    generated = datetime.fromisoformat(report["generated_at"].replace("Z", "+00:00"))
    age = now - generated
    res.info("latest report", f"generated {report['generated_at']} ({int(age.total_seconds() // 60)} min ago)")
    res.check("disclaimer present (not a certification)", report.get("disclaimer") == DISCLAIMER)
    summary = report["summary"]
    res.info(
        "summary",
        f"score {summary['compliance_score']}%, evaluated {summary['resources_evaluated']}, "
        f"open {summary['open_findings']}, remediated {summary['remediated_findings']}",
    )

    public_bytes, public_stored = _object(clients.s3, bucket, f"{folder}/report-public.md")
    res.check("report-public.md SHA-256 equals the stored checksum", _sha(public_bytes) == public_stored)
    public = public_bytes.decode("utf-8")
    found = leaks(public)
    clean = res.check("public report has no identifiers", not found, ", ".join(found) or "none found")

    namespace = metric_namespace(env)
    mismatched, missing = [], []
    for metric, field_name in SUMMARY_METRICS.items():
        value = _metric(clients.cloudwatch, namespace, metric, generated, [])
        expected = summary[field_name]
        if value is None:
            if expected is not None:
                missing.append(metric)
        elif expected is None or abs(value - expected) > 1e-6:
            mismatched.append(f"{metric} {value:g}≠{expected}")
    for severity, expected in summary["open_by_severity"].items():
        dims = [{"Name": "Severity", "Value": severity}]
        value = _metric(clients.cloudwatch, namespace, "OpenFindingsBySeverity", generated, dims)
        if value is None:
            missing.append(f"OpenFindingsBySeverity[{severity}]")
        elif abs(value - expected) > 1e-6:
            mismatched.append(f"{severity} {value:g}≠{expected}")
    res.check(
        "posture metrics equal the stored report",
        not mismatched and not missing,
        "; ".join(mismatched + [f"no datapoint: {m}" for m in missing]) or "all equal",
    )

    recount = build_report(
        _findings(clients.dynamodb, f"{prefix}-findings"), catalog, environment=env, generated_at="recount"
    )["summary"]
    diff = _summary_diff(recount, summary)
    if age <= timedelta(minutes=RECENT_MINUTES):
        res.check("DynamoDB recount equals the stored report", not diff, ", ".join(diff) or "all equal")
    else:
        res.info(
            "DynamoDB recount vs stored report",
            f"report older than {RECENT_MINUTES} min; differs in: {', '.join(diff) or 'nothing'}",
        )
    return res, public if clean else ""


def default_factory(region: str) -> Clients:  # pragma: no cover - real AWS wiring
    import boto3  # noqa: PLC0415

    session = boto3.Session(region_name=region)
    return Clients(*(session.client(n) for n in ("s3", "dynamodb", "cloudwatch", "sts")))


def main(argv: list[str] | None = None, factory: Callable[[str], Clients] = default_factory) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env", default="dev", choices=["dev", "staging", "prod"])
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--public-out", type=Path, help="write the public Markdown here if it is clean")
    args = parser.parse_args(argv)
    res, public = check(factory(args.region), args.env, args.region, datetime.now(UTC), Catalog.load_packaged())
    for line in res.lines:
        print(line)
    if args.public_out and public:
        args.public_out.write_text(public, "utf-8")
    print(f"RESULT: {'all checks passed' if res.failed == 0 else f'{res.failed} check(s) failed'}")
    return 1 if res.failed else 0


if __name__ == "__main__":
    sys.exit(main())
