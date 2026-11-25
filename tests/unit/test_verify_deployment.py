"""scripts/verify_deployment.py against fake AWS clients: checks, verdicts and redaction."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from datetime import UTC, datetime
from typing import Any

import pytest
from conftest import ROOT

spec = importlib.util.spec_from_file_location("verify_deployment", ROOT / "scripts" / "verify_deployment.py")
assert spec and spec.loader
vd = importlib.util.module_from_spec(spec)
sys.modules["verify_deployment"] = vd  # dataclasses resolve their module by name
spec.loader.exec_module(vd)

ACCOUNT = "111122223333"
SG, UNTAGGED = "sg-0aaaaaaaaaaaaaaa1", "sg-0bbbbbbbbbbbbbbb2"
BUCKET = f"acscg-dev-fixture-{ACCOUNT}-us-east-2"
NOW = datetime(2026, 11, 24, 19, 0, tzinfo=UTC)


def evidence_doc() -> dict[str, Any]:
    body = {k: "x" for k in vd.REQUIRED_EVIDENCE_FIELDS if k != "checksum"}
    return {**body, "checksum": {"algorithm": "SHA-256", "sha256": vd.canonical_sha256(body)}}


class NoSuchBucketError(Exception):
    pass


class Fake:
    """One object playing every client; behaviour switches via flags."""

    def __init__(self, *, healthy: bool = True) -> None:
        self.healthy = healthy
        self.doc = evidence_doc()
        self.exceptions = type("E", (), {"NoSuchBucket": NoSuchBucketError})

    # sts / config
    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": ACCOUNT}

    def describe_configuration_recorder_status(self) -> dict[str, Any]:
        return {
            "ConfigurationRecordersStatus": [{"name": "acscg-dev-recorder", "recording": True, "lastStatus": "SUCCESS"}]
        }

    def describe_config_rules(self) -> dict[str, Any]:
        return {"ConfigRules": [{"ConfigRuleName": "acscg-sec005-restricted-ssh"}, {"ConfigRuleName": "other"}]}

    def get_compliance_details_by_resource(self, **kw: Any) -> dict[str, Any]:
        def res(rule: str, ctype: str, note: str = "") -> dict[str, Any]:
            return {
                "EvaluationResultIdentifier": {"EvaluationResultQualifier": {"ConfigRuleName": rule}},
                "ComplianceType": ctype,
                "Annotation": note,
            }

        bad = "NON_COMPLIANT" if self.healthy else "COMPLIANT"
        by_id = {
            SG: [res("acscg-sec005-restricted-ssh", bad)],
            UNTAGGED: [res("acscg-sec013-tags-custom", bad, "missing: Owner,ManagedBy,DataClassification")],
            BUCKET: [res("acscg-sec001-bucket-public-access", bad)],
        }
        if "NextToken" not in kw and kw["ResourceId"] == SG:
            return {"EvaluationResults": [], "NextToken": "p2"}  # exercise pagination
        return {"EvaluationResults": by_id.get(kw["ResourceId"], [])}

    # ec2 / dynamodb
    def describe_security_groups(self, Filters: list[dict[str, Any]]) -> dict[str, Any]:  # noqa: N803 - boto3 argument name
        ids = {"acscg-dev-fixture-sg": SG, "acscg-dev-fixture-untagged-sg": UNTAGGED}
        gid = ids.get(Filters[0]["Values"][0])
        return {"SecurityGroups": [{"GroupId": gid}] if gid else []}

    def scan(self, **kw: Any) -> dict[str, Any]:
        def item(control: str, ident: str, sev: str, note: str = "") -> dict[str, Any]:
            return {
                "control_id": {"S": control},
                "state": {"S": "REPORTED"},
                "severity": {"S": sev},
                "resource_identifier": {"S": ident},
                "annotation": {"S": note},
            }

        if "ExclusiveStartKey" not in kw:
            return {"Items": [item("SEC-005", SG, "high")], "LastEvaluatedKey": {"pk": "x"}}
        return {
            "Items": [
                item("SEC-013", UNTAGGED, "low", "acscg-sec013-tags-custom: missing: Owner"),
                item("SEC-001", BUCKET, "high"),
            ]
        }

    # s3
    def get_bucket_policy_status(self, Bucket: str) -> dict[str, Any]:  # noqa: N803
        return {"PolicyStatus": {"IsPublic": not self.healthy}}

    def get_paginator(self, _name: str) -> Any:
        fake = self

        class P:
            def paginate(self, **_kw: Any) -> list[dict[str, Any]]:
                return (
                    [{"Contents": [{"Key": "evidence/SEC-005/a/1.json", "LastModified": NOW}]}]
                    if fake.healthy
                    else [{}]
                )

        return P()

    def get_object(self, **_kw: Any) -> dict[str, Any]:
        return {
            "Body": io.BytesIO(json.dumps(self.doc).encode()),
            "Metadata": {"acscg-sha256": self.doc["checksum"]["sha256"]},
        }

    def get_object_retention(self, **_kw: Any) -> dict[str, Any]:
        return {"Retention": {"Mode": "GOVERNANCE", "RetainUntilDate": "2026-12-01T00:00:00Z"}}

    # logs / cloudwatch / sqs
    def filter_log_events(self, **kw: Any) -> dict[str, Any]:
        if "nextToken" not in kw:
            return {"events": [{}], "nextToken": "n"}
        return {"events": [{}] if self.healthy else []}

    def get_metric_statistics(self, **kw: Any) -> dict[str, Any]:
        value = {"NumberOfNotificationsDelivered": 12.0}.get(kw["MetricName"], 0.0)
        return {"Datapoints": [{"Sum": value}]}

    def get_queue_url(self, **_kw: Any) -> dict[str, str]:
        return {"QueueUrl": f"https://sqs.us-east-2.amazonaws.com/{ACCOUNT}/acscg-dev-findings-dlq"}

    def get_queue_attributes(self, **_kw: Any) -> dict[str, Any]:
        return {"Attributes": {"ApproximateNumberOfMessages": "0"}}


def clients(fake: Fake) -> Any:
    return vd.Clients(*([fake] * 8))


def test_all_checks_pass_and_nothing_identifying_is_printed(capsys: pytest.CaptureFixture[str]) -> None:
    fake = Fake()
    assert vd.main(["--env", "dev"], factory=lambda _r: clients(fake)) == 0
    out = capsys.readouterr().out
    assert "RESULT: all checks passed" in out
    assert out.count("PASS  ") == 17
    for secret in (ACCOUNT, SG, UNTAGGED, BUCKET):
        assert secret not in out


def test_failures_are_reported() -> None:
    report = vd.verify(clients(Fake(healthy=False)), "dev", "us-east-2", NOW)
    failed = [line for line in report.lines if line.startswith("FAIL")]
    assert report.failed == len(failed) == 5
    assert any("NOT public" in line for line in failed)


def test_tampered_evidence_is_detected() -> None:
    fake = Fake()
    fake.doc = {**fake.doc, "control_id": "changed"}  # body no longer matches its checksum
    report = vd.verify(clients(fake), "dev", "us-east-2", NOW)
    assert "FAIL  scenario 13: recomputed SHA-256 equals stored" in report.lines


def test_missing_fixtures_are_info_not_failures() -> None:
    fake = Fake()
    fake.describe_security_groups = lambda Filters: {"SecurityGroups": []}  # type: ignore[method-assign]  # noqa: N803

    def no_bucket(**_kw: Any) -> dict[str, Any]:
        raise NoSuchBucketError

    fake.get_compliance_details_by_resource = no_bucket  # type: ignore[method-assign]
    report = vd.verify(clients(fake), "dev", "us-east-2", NOW)
    assert any(line.startswith("INFO  scenario 2") for line in report.lines)
    assert any(line.startswith("INFO  scenario 4") for line in report.lines)
