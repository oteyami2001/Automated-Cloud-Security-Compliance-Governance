"""Remediation authorization: every deny reason, the modes, and the gatekeeper service (scenarios 7-9)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import botocore.session
import pytest
from botocore.validate import validate_parameters
from conftest import (
    ACCOUNT,
    APPLY_ROLE,
    APPROVER,
    BUCKET,
    BUCKET_ARN,
    REGION,
    SG_ARN,
    SG_ID,
    Clock,
    config_event,
    make_policy,
    make_settings,
    policy_document,
)

from acscg.common.catalog import Catalog
from acscg.evidence_collector.sink import InMemoryEvidenceSink
from acscg.findings_processor.ports import RecordingNotifier, StaticPolicyProvider
from acscg.findings_processor.recorder import Recorder
from acscg.findings_processor.store import InMemoryStore
from acscg.remediation_engine.gatekeeper import LiveCheck, decide
from acscg.remediation_engine.handler import handle
from acscg.remediation_engine.policy import PolicyError, parse_policy
from acscg.remediation_engine.service import Gatekeeper, client_token

NOW = datetime(2026, 11, 24, 12, tzinfo=UTC)


def sg_finding(**overrides: Any) -> dict[str, Any]:
    item = {
        "finding_key": "a" * 64,
        "control_id": "SEC-005",
        "state": "OPEN",
        "ownership": "project-owned",
        "account": ACCOUNT,
        "region": REGION,
        "resource_type": "AWS::EC2::SecurityGroup",
        "resource_id": SG_ID,
        "resource_identifier": SG_ARN,
        "synthetic": False,
        "sample": False,
        "severity": "high",
        "version": 1,
        "first_seen": "2026-11-24T09:00:00Z",
    }
    item.update(overrides)
    return item


def sg_live(**overrides: Any) -> LiveCheck:
    values: dict[str, Any] = {
        "violation_present": True,
        "account": ACCOUNT,
        "region": REGION,
        "resource_arn": SG_ARN,
        "parameters": {"SecurityGroupId": SG_ID, "SecurityGroupRuleIds": ["sgr-1"]},
        "needs_approval": True,
    }
    values.update(overrides)
    return LiveCheck(**values)


def run_decide(
    catalog: Catalog, finding=None, policy=None, settings=None, live=None, attempts=0, lock=True, control_id="SEC-005"
):  # type: ignore[no-untyped-def]
    finding = finding if finding is not None else sg_finding()
    return decide(
        finding=finding,
        control=catalog.get(control_id),
        policy=policy if policy is not None else make_policy(),
        settings=settings
        if settings is not None
        else make_settings(remediation_enabled=True, remediation_mode="human_approval"),
        live=live if live is not None else sg_live(),
        attempts=attempts,
        lock_available=lock,
        now=NOW,
    )


def test_authorized_security_group_requires_human_approval(catalog: Catalog) -> None:
    decision = run_decide(catalog)
    assert decision.allowed and decision.mode == "human_approval"
    assert decision.entry is not None and decision.entry.entry_id == "AL-001"


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"settings": make_settings()}, "disabled"),
        ({"policy": make_policy(remediation_enabled=False)}, "disabled"),
        ({"policy": make_policy(remediation_mode="report_only")}, "report-only"),
        ({"finding": sg_finding(synthetic=True)}, "synthetic"),
        ({"finding": sg_finding(sample=True)}, "synthetic or sample"),
        ({"finding": sg_finding(state="PENDING_APPROVAL")}, "not eligible"),
        ({"finding": sg_finding(state="bogus")}, "not eligible"),
        ({"finding": sg_finding(ownership="unknown")}, "not project-owned"),
        ({"policy": make_policy(protected_resources=[SG_ARN])}, "protected"),
        ({"attempts": 2}, "attempt limit"),
        ({"lock": False}, "active"),
        ({"live": sg_live(violation_present=False)}, "no longer present"),
        ({"live": sg_live(region="us-west-2")}, "identity does not match"),
        ({"live": sg_live(account="444455556666")}, "identity does not match"),
    ],
)
def test_each_condition_denies(catalog: Catalog, kwargs: dict[str, Any], reason: str) -> None:
    decision = run_decide(catalog, **kwargs)
    assert not decision.allowed
    assert any(reason in r for r in decision.reasons), decision.reasons


def test_tag_alone_never_authorizes(catalog: Catalog) -> None:
    """Scenario 7a: project-tagged but not allowlisted."""
    other = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0ffff"
    finding = sg_finding(resource_identifier=other, resource_id="sg-0ffff", tags={"Project": "acscg"})
    decision = run_decide(catalog, finding=finding, live=sg_live(resource_arn=other))
    assert not decision.allowed
    assert any("no allowlist entry" in r for r in decision.reasons)


def test_wrong_region_allowlist_entry_denies(catalog: Catalog) -> None:
    """Scenario 7b: entry for another Region never matches this deployment."""
    doc = policy_document()
    doc["allowlist"][0]["region"] = "us-west-2"
    decision = run_decide(catalog, policy=parse_policy(doc))
    assert not decision.allowed


def test_entry_for_other_deployment_account_denies(catalog: Catalog) -> None:
    settings = make_settings(account_id="444455556666", remediation_enabled=True, remediation_mode="human_approval")
    decision = run_decide(catalog, settings=settings)
    assert any("different account" in r for r in decision.reasons)


def test_expired_allowlist_entry_denies(catalog: Catalog) -> None:
    doc = policy_document()
    doc["allowlist"][0]["expires_at"] = "2026-01-01T00:00:00Z"
    assert any("expired" in r for r in run_decide(catalog, policy=parse_policy(doc)).reasons)


def test_report_only_control_never_remediated(catalog: Catalog) -> None:
    decision = run_decide(catalog, finding=sg_finding(control_id="SEC-009"), control_id="SEC-009")
    assert not decision.allowed and any("not eligible" in r for r in decision.reasons)


def test_missing_inputs_deny(catalog: Catalog) -> None:
    assert not decide(
        finding=None,
        control=None,
        policy=None,
        settings=make_settings(),
        live=None,
        attempts=0,
        lock_available=True,
        now=NOW,
    ).allowed
    decision = decide(
        finding=sg_finding(),
        control=catalog.get("SEC-005"),
        policy=make_policy(),
        settings=make_settings(remediation_enabled=True, remediation_mode="human_approval"),
        live=None,
        attempts=0,
        lock_available=True,
        now=NOW,
    )
    assert "live check unavailable" in decision.reasons


def bucket_finding() -> dict[str, Any]:
    return sg_finding(
        control_id="SEC-001", resource_type="AWS::S3::Bucket", resource_id=BUCKET, resource_identifier=BUCKET_ARN
    )


def bucket_live(**kw: Any) -> LiveCheck:
    return LiveCheck(True, ACCOUNT, REGION, BUCKET_ARN, {"BucketName": BUCKET}, **kw)


def test_low_risk_control_is_automatic_only_in_auto_mode(catalog: Catalog) -> None:
    auto = make_settings(remediation_enabled=True, remediation_mode="auto_low_risk")
    decision = run_decide(
        catalog,
        finding=bucket_finding(),
        live=bucket_live(),
        control_id="SEC-001",
        settings=auto,
        policy=make_policy(remediation_mode="auto_low_risk"),
    )
    assert decision.allowed and decision.mode == "auto_low_risk"
    in_approval_mode = run_decide(catalog, finding=bucket_finding(), live=bucket_live(), control_id="SEC-001")
    assert in_approval_mode.mode == "human_approval"
    needs_human = run_decide(
        catalog,
        finding=bucket_finding(),
        live=bucket_live(needs_approval=True),
        control_id="SEC-001",
        settings=auto,
        policy=make_policy(remediation_mode="auto_low_risk"),
    )
    assert needs_human.mode == "human_approval"


def test_approval_without_approvers_denies(catalog: Catalog) -> None:
    doc = policy_document(remediation_mode="auto_low_risk")
    doc["approval"]["approvers"] = []
    decision = run_decide(catalog, policy=parse_policy(doc))
    assert not decision.allowed and "no approvers" in decision.reasons[0]


# ------------------------------------------------------------------ policy parsing


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(remediation_mode="yolo"), "remediation_mode"),
        (lambda d: d.update(remediation_enabled="true"), "remediation_enabled"),
        (lambda d: d.pop("environment"), "missing environment"),
        (lambda d: d.update(environment="prod"), "prod"),
        (
            lambda d: d["allowlist"][0].update(resource_arn="arn:aws:ec2:us-east-2:111122223333:security-group/*"),
            "wildcards",
        ),
        (lambda d: d["allowlist"][0].update(action="ec2:DeleteSecurityGroup"), "not permitted"),
        (lambda d: d["allowlist"][0].update(account="1234"), "12 digits"),
        (lambda d: d["allowlist"][0].update(expires_at="soon"), "expires_at"),
        (lambda d: d["allowlist"][0].pop("reason"), "reason"),
        (lambda d: d["allowlist"][0].update(parameters={"Owner": 5}), "parameters"),
        (lambda d: d["allowlist"].append(dict(d["allowlist"][0])), "duplicate"),
        (lambda d: d["approval"].update(approvers=[APPLY_ROLE]), "separation of duties"),
        (lambda d: d["approval"].update(approvers=["someone@example.com"]), "not an IAM"),
        (lambda d: d["approval"].update(approvers=[]), "needs at least one approver"),
        (lambda d: d["approval"].update(timeout_minutes=0), "timeout"),
        (lambda d: d.update(limits={"max_attempts_per_finding": 9}), "max_attempts"),
    ],
)
def test_invalid_policies_are_rejected(mutate, message: str) -> None:  # type: ignore[no-untyped-def]
    doc = policy_document()
    mutate(doc)
    with pytest.raises(PolicyError, match=message):
        parse_policy(doc)


def test_policy_parses_json_string_and_rejects_non_object() -> None:
    import json

    assert parse_policy(json.dumps(policy_document())).approvers == (APPROVER,)
    with pytest.raises(PolicyError):
        parse_policy("[]")


def test_policy_parameters_are_parsed() -> None:
    doc = policy_document()
    doc["allowlist"][0]["parameters"] = {"Owner": "platform-team"}
    assert parse_policy(doc).allowlist[0].parameters == (("Owner", "platform-team"),)


# ------------------------------------------------------------------ service


SSM_START = botocore.session.get_session().get_service_model("ssm").operation_model("StartAutomationExecution")


class FakeSsm:
    """Validates every call against the real botocore model, as the AWS client does (P6-5)."""

    def __init__(self, fail: bool = False) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail = fail

    def start_automation_execution(self, **kwargs: Any) -> dict[str, Any]:
        if self.fail:
            raise RuntimeError("throttled")
        validate_parameters(kwargs, SSM_START.input_shape)  # raises ParamValidationError like boto3
        self.calls.append(kwargs)
        return {"AutomationExecutionId": f"exec-{len(self.calls)}"}


def service(catalog: Catalog, *, policy=None, live=None, settings=None, ssm=None):  # type: ignore[no-untyped-def]
    store = InMemoryStore()
    settings = settings or make_settings(remediation_enabled=True, remediation_mode="human_approval")
    clock = Clock()
    recorder = Recorder(settings, store, InMemoryEvidenceSink(), RecordingNotifier(), clock)
    gk = Gatekeeper(
        settings=settings,
        catalog=catalog,
        store=store,
        recorder=recorder,
        policy_provider=StaticPolicyProvider(policy or make_policy()),
        live_check=lambda f: live if live is not None else sg_live(),
        ssm=ssm or FakeSsm(),
        clock=clock,
        id_factory=lambda: "req-1",
    )
    store.put_finding(sg_finding(version=None) | {"finding_key": "a" * 64}, None)
    return gk, store


def test_service_starts_approval_runbook_with_live_parameters(catalog: Catalog) -> None:
    gk, store = service(catalog)
    result = handle({"finding_key": "a" * 64}, gk)
    assert result["started"] and result["mode"] == "human_approval"
    call = gk.ssm.calls[0]
    assert call["DocumentName"] == "acscg-RestrictSecurityGroupIngress"
    assert call["Parameters"]["SecurityGroupRuleIds"] == ["sgr-1"]
    assert call["Parameters"]["RequireApproval"] == ["true"]
    assert call["Parameters"]["Approvers"] == [APPROVER]
    assert call["ClientToken"] == client_token("req-1")
    assert store.get_finding("a" * 64)["state"] == "PENDING_APPROVAL"
    assert store.locks["a" * 64] == "req-1"  # held until the execution ends


def test_service_denial_is_recorded_and_unlocks(catalog: Catalog) -> None:
    gk, store = service(catalog, policy=make_policy(allowlist=[]))
    result = handle({"finding_key": "a" * 64}, gk)
    assert not result["allowed"]
    assert gk.ssm.calls == []  # no AWS write call issued
    assert store.get_finding("a" * 64)["state"] == "REJECTED_POLICY"
    assert store.remediations("a" * 64)[0]["status"] == "Denied"
    assert store.locks == {}


def test_service_concurrent_request_is_refused(catalog: Catalog) -> None:
    gk, store = service(catalog)
    store.acquire_lock("a" * 64, "other")
    assert "active" in handle({"finding_key": "a" * 64}, gk)["reasons"][0]
    assert gk.ssm.calls == []


def test_service_start_failure_marks_failed(catalog: Catalog) -> None:
    gk, store = service(catalog, ssm=FakeSsm(fail=True))
    result = handle({"finding_key": "a" * 64}, gk)
    assert result["started"] is False
    assert store.get_finding("a" * 64)["state"] == "REMEDIATION_FAILED"
    assert store.locks == {}


def test_service_policy_error_denies(catalog: Catalog) -> None:
    gk, _store = service(catalog)

    class Broken:
        def get(self):  # type: ignore[no-untyped-def]
            raise PolicyError("bad")

    gk.policy_provider = Broken()
    assert not handle({"finding_key": "a" * 64}, gk)["allowed"]
    assert gk.ssm.calls == []


def test_handler_rejects_malformed_requests(catalog: Catalog) -> None:
    gk, _ = service(catalog)
    assert handle({"finding_key": "../../etc"}, gk)["reasons"] == ["invalid request"]
    assert handle([], gk)["reasons"] == ["invalid request"]  # type: ignore[arg-type]
    assert handle({"finding_key": "b" * 64}, gk)["reasons"] == ["unknown finding"]


def test_tag_remediation_uses_only_allowlisted_values(catalog: Catalog) -> None:
    arn = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/acscg/dev/fixture"
    doc = policy_document()
    doc["allowlist"].append(
        {
            "id": "AL-003",
            "control_id": "SEC-013",
            "action": "tag:TagResources",
            "account": ACCOUNT,
            "region": REGION,
            "resource_arn": arn,
            "expires_at": "2099-01-01T00:00:00Z",
            "reason": "scenario 8",
            "parameters": {"Owner": "platform-team"},
        }
    )
    live = LiveCheck(
        True, ACCOUNT, REGION, arn, {"ResourceArn": arn, "MissingTagKeys": ["Owner", "DataClassification"]}
    )
    gk, store = service(catalog, policy=parse_policy(doc), live=live)
    store.findings.clear()
    store.put_finding(
        sg_finding(
            control_id="SEC-013",
            resource_type="AWS::Logs::LogGroup",
            resource_id="/acscg/dev/fixture",
            resource_identifier=arn,
        ),
        None,
    )
    result = handle({"finding_key": "a" * 64}, gk)
    assert result["started"]
    params = gk.ssm.calls[0]["Parameters"]
    assert params["TagKeys"] == ["Owner"] and params["TagValues"] == [
        "platform-team"
    ]  # never invents DataClassification


def test_end_to_end_detection_to_request(catalog: Catalog) -> None:
    """Processor requests → gatekeeper authorizes → runbook starts (offline)."""
    from conftest import Harness

    h = Harness(catalog, make_settings(remediation_enabled=True, remediation_mode="human_approval"), make_policy())
    h.processor.process(config_event())
    key = h.requester.requested[0]
    gk = Gatekeeper(
        settings=h.processor.settings,
        catalog=catalog,
        store=h.store,
        recorder=h.processor.recorder,
        policy_provider=StaticPolicyProvider(make_policy()),
        live_check=lambda f: sg_live(),
        ssm=FakeSsm(),
        clock=h.clock,
    )
    assert gk.handle(key)["started"]
    assert h.finding(key)["state"] == "PENDING_APPROVAL"


def test_client_token_is_a_uuid_ssm_accepts() -> None:
    hex_id = "0123456789abcdef0123456789abcdef"
    assert client_token(hex_id) == "01234567-89ab-cdef-0123-456789abcdef"
    assert client_token("req-1") == client_token("req-1") != client_token("req-2")
    for rid in (hex_id, "req-1"):
        validate_parameters(
            {"DocumentName": "acscg-SetLogRetention", "ClientToken": client_token(rid)}, SSM_START.input_shape
        )


def test_the_old_32_character_token_is_rejected_by_botocore() -> None:
    from botocore.exceptions import ParamValidationError

    with pytest.raises(ParamValidationError):
        validate_parameters({"DocumentName": "x", "ClientToken": "0" * 32}, SSM_START.input_shape)


def test_repeated_start_failure_stays_failed_and_unlocks(catalog: Catalog) -> None:
    """Found in AWS (P6-6): a retry of a REMEDIATION_FAILED finding crashed on a self-transition and kept the lock."""
    gk, store = service(catalog, ssm=FakeSsm(fail=True))
    ids = iter(["req-1", "req-2"])
    gk.id_factory = lambda: next(ids)
    handle({"finding_key": "a" * 64}, gk)
    assert store.get_finding("a" * 64)["state"] == "REMEDIATION_FAILED"
    again = handle({"finding_key": "a" * 64}, gk)
    assert again["started"] is False
    assert store.get_finding("a" * 64)["state"] == "REMEDIATION_FAILED"
    assert store.locks == {}
    assert [r["status"] for r in store.remediations("a" * 64)] == ["StartFailed", "StartFailed"]


def test_any_error_before_start_releases_the_lock(catalog: Catalog) -> None:
    gk, store = service(catalog)

    def broken(_finding: dict[str, Any]) -> LiveCheck:
        raise RuntimeError("live check crashed")

    gk.live_check = broken
    with pytest.raises(RuntimeError):
        handle({"finding_key": "a" * 64}, gk)
    assert store.locks == {}  # the next request is not blocked for the lock TTL


def test_start_failure_logs_the_aws_error_code_only(catalog: Catalog, caplog: pytest.LogCaptureFixture) -> None:
    class DeniedError(Exception):
        def __init__(self) -> None:
            super().__init__("denied")
            self.response = {
                "Error": {"Code": "AccessDeniedException", "Message": "arn:aws:sts::111122223333:assumed-role/x"}
            }

    class DeniedSsm(FakeSsm):
        def start_automation_execution(self, **kwargs: Any) -> dict[str, Any]:
            raise DeniedError

    gk, _store = service(catalog, ssm=DeniedSsm())
    with caplog.at_level("ERROR"):
        handle({"finding_key": "a" * 64}, gk)
    text = " ".join(str(getattr(r, "__dict__", r)) for r in caplog.records)
    assert "AccessDeniedException" in text and "111122223333" not in text


def test_attempt_limit_counts_only_the_current_violation(catalog: Catalog) -> None:
    """Found in AWS (P6-9): attempts from an earlier, verified episode refused a fresh violation."""
    gk, store = service(catalog)
    key = "a" * 64
    finding = store.get_finding(key)
    store.put_finding({**finding, "first_seen": "2026-11-25T23:30:00Z"}, finding["version"])
    for n, at in enumerate(["2026-11-25T23:02:06Z", "2026-11-25T23:15:01Z"]):  # previous episode
        store.put_remediation(key, {"request_id": f"old-{n}", "execution_id": f"e-{n}", "requested_at": at})
    assert handle({"finding_key": key}, gk)["started"]  # 0 attempts in this episode

    gk2, store2 = service(catalog)
    finding = store2.get_finding(key)
    store2.put_finding({**finding, "first_seen": "2026-11-25T23:00:00Z"}, finding["version"])
    for n, at in enumerate(["2026-11-25T23:02:06Z", "2026-11-25T23:15:01Z"]):  # this episode
        store2.put_remediation(key, {"request_id": f"cur-{n}", "execution_id": f"e-{n}", "requested_at": at})
    result = handle({"finding_key": key}, gk2)
    assert not result["allowed"] and any("attempt limit" in r for r in result["reasons"])
