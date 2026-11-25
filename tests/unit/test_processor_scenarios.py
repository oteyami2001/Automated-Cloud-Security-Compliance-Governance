"""Validation scenarios proven offline against the full processing pipeline (docs/validation-scenarios.md)."""

from __future__ import annotations

import pytest
from conftest import (
    ACCOUNT,
    APPLY_ROLE,
    BUCKET,
    SG_ARN,
    SG_ID,
    Harness,
    cloudtrail_event,
    config_event,
    make_policy,
    make_settings,
    ssm_status_event,
)

from acscg.common.models import Compliance, FindingState, Resource, finding_key
from acscg.evidence_collector.builder import REQUIRED_FIELDS, verify_checksum
from acscg.findings_processor.store import ConflictError
from acscg.findings_processor.validation import InvalidEventError

SG_KEY = finding_key("SEC-005", Resource("AWS::EC2::SecurityGroup", SG_ID, ACCOUNT, "us-east-2", SG_ARN))


def test_scenario_1_compliant_resource_passes(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.processor.process(
        config_event(
            rule="acscg-sec004-ssl-requests-only",
            resource_type="AWS::S3::Bucket",
            resource_id=BUCKET,
            compliance="COMPLIANT",
        )
    )
    items = h.store.all_findings()
    assert len(items) == 1
    assert items[0]["state"] == "COMPLIANT"
    assert h.notifier.sent == []
    assert h.requester.requested == []


def test_scenario_2_noncompliant_security_group_detected(report_only_harness: Harness) -> None:
    h = report_only_harness
    outcome = h.processor.process(config_event())
    item = h.finding(SG_KEY)
    assert item["state"] == "REPORTED"  # report-only environment
    assert item["severity"] == "high"
    assert item["ownership"] == "project-owned"
    assert [t[2] for t in outcome.transitions] == ["OPEN", "REPORTED"]
    assert len(h.notifier.sent) == 1
    subject, message = h.notifier.sent[0]
    assert "SEC-005" in subject and message["state"] == "REPORTED"
    assert len(h.evidence.objects) == 2
    assert h.requester.requested == []


def test_scenario_3_missing_tags_detected(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.processor.process(
        config_event(
            rule="acscg-sec013-required-tags", resource_type="AWS::Logs::LogGroup", resource_id="/acscg/dev/fixture"
        )
    )
    item = h.store.all_findings()[0]
    assert item["control_id"] == "SEC-013"
    assert item["resource_identifier"] == f"arn:aws:logs:us-east-2:{ACCOUNT}:log-group:/acscg/dev/fixture"
    assert item["state"] == "REPORTED"


def test_scenario_4_s3_protection_violation_detected(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.processor.process(
        config_event(rule="acscg-sec001-bucket-public-access", resource_type="AWS::S3::Bucket", resource_id=BUCKET)
    )
    item = h.store.all_findings()[0]
    assert item["control_id"] == "SEC-001" and item["state"] == "REPORTED"
    assert item["resource_identifier"] == f"arn:aws:s3:::{BUCKET}"


def test_scenario_6_duplicate_events_do_not_duplicate_work(harness: Harness) -> None:
    event = config_event(event_id="dup-1")
    first = harness.processor.process(event)
    second = harness.processor.process(event)
    third = harness.processor.process(event)
    assert first.processed == 1
    assert second.duplicates == 1 and third.duplicates == 1
    assert len(harness.store.all_findings()) == 1
    assert harness.requester.requested == [SG_KEY]  # exactly one remediation request
    assert len(harness.notifier.sent) == 1


def test_repeated_noncompliant_evaluation_updates_without_notifying(harness: Harness) -> None:
    harness.processor.process(config_event())
    harness.processor.process(config_event())  # new event id, same violation
    assert len(harness.notifier.sent) == 1
    # The fake requester records no decision, so the finding is still OPEN: a later evaluation asks the
    # gatekeeper again (its per-finding lock refuses a concurrent duplicate). In AWS a gatekeeper crash
    # left a finding OPEN with nothing to retry it (evidence P6-6).
    assert harness.requester.requested == [SG_KEY, SG_KEY]
    assert harness.finding(SG_KEY)["version"] == 2


def test_scenario_7_unowned_resource_is_never_requested(catalog) -> None:
    h = Harness(
        catalog,
        make_settings(remediation_enabled=True, remediation_mode="human_approval"),
        make_policy(project_inventory=[]),
    )
    h.processor.process(config_event())
    item = h.finding(SG_KEY)
    assert item["state"] == "REPORTED"
    assert item["ownership"] == "unknown"
    assert h.requester.requested == []


def test_synthetic_events_are_never_remediated(harness: Harness) -> None:
    harness.processor.process(config_event(source="acscg.synthetic"))
    item = harness.finding(SG_KEY)
    assert item["synthetic"] is True
    assert item["state"] == "REPORTED"
    assert harness.requester.requested == []


def test_synthetic_events_rejected_outside_dev(catalog) -> None:
    h = Harness(catalog, make_settings(allow_synthetic_events=False), make_policy())
    with pytest.raises(InvalidEventError):
        h.processor.process(config_event(source="acscg.synthetic"))


def test_escalation_control_is_reported_with_escalation(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.processor.process(
        cloudtrail_event(
            "StopLogging", "cloudtrail.amazonaws.com", params={"name": "idp-management-events"}, source="aws.cloudtrail"
        )
    )
    item = h.store.all_findings()[0]
    assert item["control_id"] == "SEC-012"
    assert item["severity"] == "critical"
    assert item["escalate"] is True
    assert "ESCALATION" in h.notifier.sent[0][0]


def test_scenario_15_unauthorized_change_then_restored_by_pipeline(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.processor.process(cloudtrail_event())
    item = h.store.all_findings()[0]
    assert item["control_id"] == "SEC-015" and item["state"] == "REPORTED"
    h.processor.process(cloudtrail_event(principal=APPLY_ROLE))
    assert h.store.get_finding(item["finding_key"])["state"] == "RESOLVED_EXTERNALLY"


def test_failed_api_calls_are_ignored(report_only_harness: Harness) -> None:
    outcome = report_only_harness.processor.process(cloudtrail_event(error="AccessDenied"))
    assert outcome.ignored == 1
    assert report_only_harness.store.all_findings() == []


def test_unrelated_config_rules_are_ignored(report_only_harness: Harness) -> None:
    outcome = report_only_harness.processor.process(config_event(rule="securityhub-restricted-ssh-abc"))
    assert outcome.ignored == 1


def test_exception_suppresses_finding(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.store.exceptions[("SEC-005", SG_ARN)] = {"expires_at": "2099-01-01T00:00:00Z", "approver": "x"}
    h.processor.process(config_event())
    assert h.finding(SG_KEY)["state"] == "SUPPRESSED_EXCEPTION"


def test_expired_exception_reopens(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.store.exceptions[("SEC-005", SG_ARN)] = {"expires_at": "2099-01-01T00:00:00Z"}
    h.processor.process(config_event())
    h.store.exceptions[("SEC-005", SG_ARN)] = {"expires_at": "2000-01-01T00:00:00Z"}
    h.processor.process(config_event())
    assert h.finding(SG_KEY)["state"] == "REPORTED"


def test_compliant_after_report_resolves_externally(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.processor.process(config_event())
    h.processor.process(config_event(compliance="COMPLIANT"))
    assert h.finding(SG_KEY)["state"] == "RESOLVED_EXTERNALLY"
    h.processor.process(config_event())  # regression
    assert h.finding(SG_KEY)["state"] == "REPORTED"


def test_insufficient_data_changes_nothing(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.processor.process(config_event())
    h.processor.process(config_event(compliance="INSUFFICIENT_DATA"))
    assert h.finding(SG_KEY)["state"] == "REPORTED"


def _start_remediation(h: Harness, mode: str = "human_approval", execution_id: str = "exec-1") -> None:
    """Simulate what the gatekeeper does after authorizing (tested separately)."""
    h.processor.process(config_event())
    item = h.finding(SG_KEY)
    state = FindingState.PENDING_APPROVAL if mode == "human_approval" else FindingState.REMEDIATING
    request = {
        "request_id": "req-1",
        "execution_id": execution_id,
        "mode": mode,
        "action": "ec2:RevokeSecurityGroupIngress",
        "document": "acscg-RestrictSecurityGroupIngress",
    }
    h.store.put_remediation(SG_KEY, request)
    h.store.acquire_lock(SG_KEY, "req-1")
    h.processor.recorder.save(item, item["version"], [(FindingState.OPEN, state, "test start")], execution=request)


def test_scenarios_9_and_11_approved_remediation_is_verified(harness: Harness) -> None:
    _start_remediation(harness)
    harness.inspector.results["exec-1"] = {
        "approval_status": "Approved",
        "approver": "security-approver",
        "approval_time": "2026-11-24T09:20:00Z",
        "approval_comment": "CHG-1",
    }
    harness.processor.process(ssm_status_event("exec-1", "Success"))
    item = harness.finding(SG_KEY)
    assert item["state"] == "VERIFIED_RESOLVED"
    states = [h["to"] for h in harness.store.history(SG_KEY)]
    assert states[-3:] == ["REMEDIATING", "VERIFYING", "VERIFIED_RESOLVED"]
    rem = harness.store.remediations(SG_KEY)[0]
    assert rem["approval"]["identity"] == "security-approver" and rem["status"] == "Success"
    assert SG_KEY not in harness.store.locks
    final = next(d for d in harness.evidence.objects.values() if d["lifecycle"]["to"] == "VERIFIED_RESOLVED")
    assert final["approval"]["timestamp"] == "2026-11-24T09:20:00Z"
    assert final["verification_timestamp"] is not None
    assert final["updated_compliance_state"] == "COMPLIANT"


def test_scenario_10_rejected_approval_prevents_execution(harness: Harness) -> None:
    _start_remediation(harness)
    harness.inspector.results["exec-1"] = {"approval_status": "Rejected", "approver": "security-approver"}
    harness.processor.process(ssm_status_event("exec-1", "Failed"))
    assert harness.finding(SG_KEY)["state"] == "REMEDIATION_REJECTED"
    assert harness.finding(SG_KEY)["compliance"] == "NON_COMPLIANT"


def test_approval_timeout_expires(harness: Harness) -> None:
    _start_remediation(harness)
    harness.processor.process(ssm_status_event("exec-1", "TimedOut"))
    assert harness.finding(SG_KEY)["state"] == "APPROVAL_EXPIRED"


def test_failed_runbook_escalates(harness: Harness) -> None:
    _start_remediation(harness, mode="auto_low_risk")
    harness.inspector.results["exec-1"] = {"failure_message": "Step verify failed"}
    harness.processor.process(ssm_status_event("exec-1", "Failed"))
    item = harness.finding(SG_KEY)
    assert item["state"] == "REMEDIATION_FAILED" and item["escalate"] is True


def test_verification_failure_escalates(harness: Harness) -> None:
    _start_remediation(harness, mode="auto_low_risk")
    harness.verifier.result = Compliance.NON_COMPLIANT
    harness.processor.process(ssm_status_event("exec-1", "Success"))
    assert harness.finding(SG_KEY)["state"] == "VERIFICATION_FAILED"


def test_pending_verification_resolved_by_later_config_event(harness: Harness) -> None:
    _start_remediation(harness, mode="auto_low_risk")
    harness.verifier.result = None  # Config has not re-evaluated yet
    harness.processor.process(ssm_status_event("exec-1", "Success"))
    assert harness.finding(SG_KEY)["state"] == "VERIFYING"
    harness.processor.process(config_event(compliance="COMPLIANT"))
    assert harness.finding(SG_KEY)["state"] == "VERIFIED_RESOLVED"


def test_status_events_are_idempotent_and_ignore_unknown(harness: Harness) -> None:
    _start_remediation(harness)
    harness.processor.process(ssm_status_event("exec-1", "InProgress"))
    assert harness.finding(SG_KEY)["state"] == "PENDING_APPROVAL"
    harness.processor.process(ssm_status_event("exec-1", "Success"))
    harness.processor.process(ssm_status_event("exec-1", "Failed"))  # late/conflicting event
    assert harness.finding(SG_KEY)["state"] == "VERIFIED_RESOLVED"
    outcome = harness.processor.process(ssm_status_event("exec-unknown", "Success"))
    assert outcome.processed == 1
    other = harness.processor.process(ssm_status_event("exec-x", "Success", definition="AWS-RestartEC2Instance"))
    assert other.ignored == 1


def test_scenario_13_every_evidence_object_is_complete_and_verifiable(harness: Harness) -> None:
    test_scenarios_9_and_11_approved_remediation_is_verified(harness)
    assert harness.evidence.objects
    for document in harness.evidence.objects.values():
        for field in REQUIRED_FIELDS:
            assert field in document, field
        assert verify_checksum(document)


def test_processing_failure_releases_idempotency_claim(harness: Harness) -> None:
    calls = {"n": 0}
    original = harness.store.put_finding

    def flaky(item, expected_version):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] <= 3:
            raise ConflictError("simulated")
        return original(item, expected_version)

    harness.store.put_finding = flaky  # type: ignore[method-assign]
    event = config_event(event_id="retry-1")
    with pytest.raises(ConflictError):
        harness.processor.process(event)
    outcome = harness.processor.process(event)  # EventBridge retry
    assert outcome.processed == 1 and outcome.duplicates == 0


def test_one_compliant_rule_cannot_close_a_violation_another_rule_sees(report_only_harness: Harness) -> None:
    """SEC-001 has several rules. Found in AWS (P5-10): last-writer-wins could resolve a live violation."""
    h = report_only_harness
    bpa = "acscg-sec001-bucket-public-access"
    read = "acscg-sec001-public-read"
    h.processor.process(
        config_event(rule=bpa, resource_type="AWS::S3::Bucket", resource_id=BUCKET, compliance="NON_COMPLIANT")
    )
    h.processor.process(
        config_event(rule=read, resource_type="AWS::S3::Bucket", resource_id=BUCKET, compliance="COMPLIANT")
    )
    (item,) = h.store.all_findings()
    assert item["compliance"] == "NON_COMPLIANT" and item["state"] == "REPORTED"
    assert item["rule_results"][bpa]["compliance"] == "NON_COMPLIANT"
    assert item["rule_results"][read]["compliance"] == "COMPLIANT"
    # Resolves only once every rule that reported is compliant.
    h.processor.process(
        config_event(rule=bpa, resource_type="AWS::S3::Bucket", resource_id=BUCKET, compliance="COMPLIANT")
    )
    (item,) = h.store.all_findings()
    assert item["compliance"] == "COMPLIANT" and item["state"] == "RESOLVED_EXTERNALLY"


def test_annotation_of_the_failing_rule_survives_a_silent_rule(report_only_harness: Harness) -> None:
    """Scenario 3: the custom tag rule names the missing keys; REQUIRED_TAGS gives no annotation."""
    h = report_only_harness
    custom = config_event(rule="acscg-sec013-tags-custom", compliance="NON_COMPLIANT")
    custom["detail"]["newEvaluationResult"]["annotation"] = "missing: Owner,ManagedBy,DataClassification"
    h.processor.process(custom)
    managed = config_event(rule="acscg-sec013-required-tags", compliance="NON_COMPLIANT")
    managed["detail"]["newEvaluationResult"]["annotation"] = ""  # REQUIRED_TAGS gives none
    h.processor.process(managed)
    (item,) = h.store.all_findings()
    assert item["annotation"] == "acscg-sec013-tags-custom: missing: Owner,ManagedBy,DataClassification"


def test_legacy_finding_without_rule_results_keeps_its_violation(report_only_harness: Harness) -> None:
    h = report_only_harness
    h.processor.process(
        config_event(rule="acscg-sec001-bucket-public-access", resource_type="AWS::S3::Bucket", resource_id=BUCKET)
    )
    (item,) = h.store.all_findings()
    item.pop("rule_results")  # as stored before this change
    h.store.findings[item["finding_key"]] = item
    h.processor.process(
        config_event(
            rule="acscg-sec001-public-read", resource_type="AWS::S3::Bucket", resource_id=BUCKET, compliance="COMPLIANT"
        )
    )
    (item,) = h.store.all_findings()
    assert item["compliance"] == "NON_COMPLIANT" and item["state"] == "REPORTED"


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (["COMPLIANT", "INSUFFICIENT_DATA"], "COMPLIANT"),
        (["NOT_APPLICABLE"], "NOT_APPLICABLE"),
        (["INSUFFICIENT_DATA", "NOT_APPLICABLE"], "INSUFFICIENT_DATA"),
        (["COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE"], "NON_COMPLIANT"),
    ],
)
def test_aggregate_compliance(values: list[str], expected: str) -> None:
    from acscg.findings_processor.processor import aggregate_compliance

    results = {f"rule-{i}": {"compliance": v} for i, v in enumerate(values)}
    assert aggregate_compliance(results) == expected
