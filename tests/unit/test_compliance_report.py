"""scripts/compliance_report.py against fake AWS clients: integrity, metrics, recount and leak scan (scenario 14)."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import ROOT, SG_ID, Harness, config_event, make_settings

from acscg.common.catalog import Catalog
from acscg.report_generator.handler import generate

spec = importlib.util.spec_from_file_location("compliance_report", ROOT / "scripts" / "compliance_report.py")
assert spec and spec.loader
cr = importlib.util.module_from_spec(spec)
sys.modules["compliance_report"] = cr
spec.loader.exec_module(cr)

ACCOUNT = "111122223333"
GENERATED = "2026-11-26T06:17:00Z"
GEN_DT = datetime(2026, 11, 26, 6, 17, tzinfo=UTC)


class S3Capture:
    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, dict[str, str]]] = {}

    def put_object(self, **kw: Any) -> None:
        self.objects[kw["Key"]] = (kw["Body"], kw.get("Metadata", {}))


def _typed(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, int | float):
        return {"N": str(value)}
    if isinstance(value, dict):
        return {"M": {k: _typed(v) for k, v in value.items()}}
    if isinstance(value, list):
        return {"L": [_typed(v) for v in value]}
    if value is None:
        return {"NULL": True}
    return {"S": str(value)}


class Fake:
    """S3 + DynamoDB + CloudWatch + STS, built from a real generated report."""

    def __init__(self, harness: Harness, catalog: Catalog, capsys: pytest.CaptureFixture[str]) -> None:
        cap = S3Capture()
        generate(harness.store, catalog, make_settings(), cap, GENERATED)
        self.emf = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
        self.objects = cap.objects
        self.findings = harness.store.all_findings()
        self.metrics_present = True

    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": ACCOUNT}

    def list_objects_v2(self, **kw: Any) -> dict[str, Any]:
        older = {"Key": "reports/2026-11-25T06-17-00Z/report.json", "LastModified": GEN_DT - timedelta(days=1)}
        if "ContinuationToken" not in kw:
            return {"Contents": [older], "IsTruncated": True, "NextContinuationToken": "p2"}
        return {"Contents": [{"Key": k, "LastModified": GEN_DT} for k in self.objects], "IsTruncated": False}

    def get_object(self, **kw: Any) -> dict[str, Any]:
        body, meta = self.objects[kw["Key"]]
        return {"Body": io.BytesIO(body), "Metadata": meta}

    def scan(self, **kw: Any) -> dict[str, Any]:
        items = [
            {"pk": {"S": "FINDING#x"}, "sk": {"S": "STATE"}, **{k: _typed(v) for k, v in f.items()}}
            for f in self.findings
        ]
        if "ExclusiveStartKey" not in kw:
            return {"Items": items[:1], "LastEvaluatedKey": {"pk": {"S": "x"}}}
        return {"Items": items[1:]}

    def get_metric_statistics(self, **kw: Any) -> dict[str, Any]:
        if not self.metrics_present:
            return {"Datapoints": []}
        dims = {d["Name"]: d["Value"] for d in kw["Dimensions"]}
        for record in self.emf:
            if kw["MetricName"] in record and all(record.get(k) == v for k, v in dims.items()):
                assert kw["Namespace"] == record["_aws"]["CloudWatchMetrics"][0]["Namespace"]
                return {"Datapoints": [{"Maximum": float(record[kw["MetricName"]])}]}
        return {"Datapoints": []}


@pytest.fixture
def fake(harness: Harness, catalog: Catalog, capsys: pytest.CaptureFixture[str]) -> Fake:
    harness.processor.process(config_event())
    return Fake(harness, catalog, capsys)


def run(fake: Fake, catalog: Catalog, now: datetime = GEN_DT + timedelta(minutes=5)) -> tuple[Any, str]:
    return cr.check(cr.Clients(fake, fake, fake, fake), "dev", "us-east-2", now, catalog)


def test_fresh_report_passes_every_check(fake: Fake, catalog: Catalog) -> None:
    res, public = run(fake, catalog)
    assert res.failed == 0, res.lines
    assert "PASS  posture metrics equal the stored report: all equal" in res.lines
    assert "PASS  DynamoDB recount equals the stored report: all equal" in res.lines
    assert "ACSCG compliance report" in public and "Not a certification" in public
    out = "\n".join(res.lines) + public
    assert ACCOUNT not in out and SG_ID not in out


def test_old_report_compares_recount_as_info(fake: Fake, catalog: Catalog) -> None:
    fake.findings = []  # findings changed since the report
    res, _ = run(fake, catalog, now=GEN_DT + timedelta(hours=5))
    assert res.failed == 0
    assert any(x.startswith("INFO  DynamoDB recount vs stored report") and "open_findings" in x for x in res.lines)
    res, _ = run(fake, catalog)  # the same difference on a fresh report is a failure
    assert any(x.startswith("FAIL  DynamoDB recount equals the stored report") for x in res.lines)


def test_missing_or_wrong_metrics_fail(fake: Fake, catalog: Catalog) -> None:
    fake.metrics_present = False
    res, _ = run(fake, catalog)
    assert any(x.startswith("FAIL  posture metrics") and "no datapoint: OpenFindings" in x for x in res.lines)
    fake.metrics_present = True
    fake.emf[0]["OpenFindings"] = 99
    res, _ = run(fake, catalog)
    assert any(x.startswith("FAIL  posture metrics") and "OpenFindings 99≠1" in x for x in res.lines)


def test_tampered_report_and_leaky_public_markdown_fail(fake: Fake, catalog: Catalog) -> None:
    key = next(k for k in fake.objects if k.endswith("report.json"))
    body, meta = fake.objects[key]
    fake.objects[key] = (body.replace(b'"dev"', b'"prod"'), meta)
    leaky = f"| SEC-005 | high | REPORTED | AWS::EC2::SecurityGroup | {SG_ID} in {ACCOUNT} |".encode()
    pub = next(k for k in fake.objects if k.endswith("report-public.md"))
    fake.objects[pub] = (leaky, {"acscg-sha256": hashlib.sha256(leaky).hexdigest()})
    res, public = run(fake, catalog)
    assert "FAIL  report.json SHA-256 equals the stored checksum" in res.lines
    assert any(
        x.startswith("FAIL  public report has no identifiers: account ID") and "resource ID" in x for x in res.lines
    )
    assert public == ""  # never written out
    assert SG_ID not in "\n".join(res.lines) and ACCOUNT not in "\n".join(res.lines)


def test_leak_scanner_keeps_security_semantics() -> None:
    assert cr.leaks("SSH open to 0.0.0.0/0 on res-1a2b3c4d5e") == []
    assert cr.leaks("from 10.0.0.1 by a@b.io arn:aws:iam::x AKIAABCDEFGHIJKLMNOP") == [
        "e-mail address",
        "IPv4 address",
        "ARN",
        "access key ID",
    ]


def test_no_report_yet(catalog: Catalog) -> None:
    class Empty:
        def get_caller_identity(self) -> dict[str, str]:
            return {"Account": ACCOUNT}

        def list_objects_v2(self, **_kw: Any) -> dict[str, Any]:
            return {"IsTruncated": False}

    res, public = cr.check(cr.Clients(Empty(), None, None, Empty()), "dev", "us-east-2", GEN_DT, catalog)
    assert res.lines == ["FAIL  a stored report exists"] and public == ""


def test_main_writes_public_markdown_only_when_clean(
    fake: Fake, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "public.md"
    code = cr.main(["--public-out", str(out)], factory=lambda _r: cr.Clients(fake, fake, fake, fake))
    text = capsys.readouterr().out
    # the real clock makes the fixture report old: recount is INFO, everything else passes
    assert code == 0 and "RESULT: all checks passed" in text and out.read_text("utf-8").startswith("# ACSCG")
