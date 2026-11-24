"""Reconciliation of the findings table with AWS Config's current results (gap P4-13)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from conftest import ACCOUNT, BUCKET, REGION, SG_ID, Harness

from acscg.findings_processor import reconcile


def result(rule: str, rtype: str, rid: str, compliance: str, minute: int = 0) -> dict[str, Any]:
    return {
        "EvaluationResultIdentifier": {
            "EvaluationResultQualifier": {"ConfigRuleName": rule, "ResourceType": rtype, "ResourceId": rid},
            "OrderingTimestamp": datetime(2026, 11, 24, 15, minute, tzinfo=UTC),
        },
        "ComplianceType": compliance,
        "ResultRecordedTime": datetime(2026, 11, 24, 15, minute, 30, tzinfo=UTC),
        "Annotation": "from Config",
    }


class FakeConfig:
    """Two pages of rules (one foreign) and two pages of results for one rule."""

    def __init__(self, results: dict[str, list[dict[str, Any]]]) -> None:
        self.results = results
        self.calls: list[dict[str, Any]] = []

    def describe_config_rules(self, **kwargs: Any) -> dict[str, Any]:
        if "NextToken" not in kwargs:
            return {
                "ConfigRules": [
                    {"ConfigRuleName": "aiops-other-rule"},
                    {"ConfigRuleName": "acscg-sec004-ssl-requests-only"},
                ],
                "NextToken": "p2",
            }
        return {"ConfigRules": [{"ConfigRuleName": "acscg-sec005-restricted-ssh"}]}

    def get_compliance_details_by_config_rule(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        assert kwargs["ComplianceTypes"] == ["COMPLIANT", "NON_COMPLIANT"] and kwargs["Limit"] == 100
        items = self.results.get(kwargs["ConfigRuleName"], [])
        if "NextToken" not in kwargs and len(items) > 1:
            return {"EvaluationResults": items[:1], "NextToken": "r2"}
        return {"EvaluationResults": items[1:] if "NextToken" in kwargs else items}


def test_only_project_rules_and_all_pages(report_only_harness: Harness) -> None:
    config = FakeConfig(
        {
            "acscg-sec004-ssl-requests-only": [
                result("acscg-sec004-ssl-requests-only", "AWS::S3::Bucket", BUCKET, "NON_COMPLIANT"),
                result("acscg-sec004-ssl-requests-only", "AWS::S3::Bucket", "other-bucket", "COMPLIANT"),
            ],
            "acscg-sec005-restricted-ssh": [
                result("acscg-sec005-restricted-ssh", "AWS::EC2::SecurityGroup", SG_ID, "COMPLIANT")
            ],
        }
    )
    summary = reconcile.reconcile(config, report_only_harness.processor, ACCOUNT, REGION)
    assert (summary.rules, summary.results, summary.processed, summary.failed) == (2, 3, 3, 0)
    assert {c["ConfigRuleName"] for c in config.calls} == {
        "acscg-sec004-ssl-requests-only",
        "acscg-sec005-restricted-ssh",
    }
    states = sorted((f["control_id"], f["state"]) for f in report_only_harness.store.all_findings())
    # The NON_COMPLIANT result that EventBridge never delivered is now an open (reported) finding.
    assert states == [("SEC-004", "COMPLIANT"), ("SEC-004", "REPORTED"), ("SEC-005", "COMPLIANT")]


def test_rerun_is_idempotent_and_newer_result_is_processed(report_only_harness: Harness) -> None:
    rule = "acscg-sec004-ssl-requests-only"
    first = FakeConfig({rule: [result(rule, "AWS::S3::Bucket", BUCKET, "NON_COMPLIANT")]})
    reconcile.reconcile(first, report_only_harness.processor, ACCOUNT, REGION)
    notified = len(report_only_harness.notifier.sent)
    again = reconcile.reconcile(first, report_only_harness.processor, ACCOUNT, REGION)
    assert (again.processed, again.duplicates) == (0, 1)
    assert len(report_only_harness.notifier.sent) == notified  # no second e-mail for the same result
    fixed = FakeConfig({rule: [result(rule, "AWS::S3::Bucket", BUCKET, "COMPLIANT", minute=30)]})
    later = reconcile.reconcile(fixed, report_only_harness.processor, ACCOUNT, REGION)
    assert later.processed == 1 and later.transitions >= 1


def test_event_shape_passes_validation_and_ids_are_deterministic() -> None:
    item = result("acscg-sec005-restricted-ssh", "AWS::EC2::SecurityGroup", SG_ID, "NON_COMPLIANT")
    a, b = reconcile.to_event(item, ACCOUNT, REGION), reconcile.to_event(item, ACCOUNT, REGION)
    assert a["id"] == b["id"] and a["id"].startswith("reconcile-")
    assert a["time"] == "2026-11-24T15:00:30Z" and a["detail"]["newEvaluationResult"]["annotation"] == "from Config"
    other = reconcile.to_event({**item, "ComplianceType": "COMPLIANT"}, ACCOUNT, REGION)
    assert other["id"] != a["id"]
    no_time = {**item, "ResultRecordedTime": None, "Annotation": ""}
    assert reconcile.to_event(no_time, ACCOUNT, REGION)["time"] == "2026-11-24T15:00:00Z"
    assert reconcile._iso(datetime(2026, 11, 24, 15, 0)) == "2026-11-24T15:00:00Z"  # naive → UTC
    assert reconcile._iso("2026-11-24T15:00:00Z") == "2026-11-24T15:00:00Z"


def test_one_bad_result_does_not_stop_the_run(report_only_harness: Harness) -> None:
    rule = "acscg-sec004-ssl-requests-only"
    bad = result(rule, "AWS::S3::Bucket", BUCKET, "NON_COMPLIANT")
    bad["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"] = 7  # not a string: rejected
    config = FakeConfig({rule: [bad, result(rule, "AWS::S3::Bucket", BUCKET, "NON_COMPLIANT")]})
    summary = reconcile.reconcile(config, report_only_harness.processor, ACCOUNT, REGION)
    assert (summary.failed, summary.processed) == (1, 1)
