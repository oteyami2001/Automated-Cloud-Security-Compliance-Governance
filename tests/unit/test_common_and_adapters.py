"""Common modules, lifecycle rules, AWS adapters (moto / stubs), evidence, reports and packaging."""

from __future__ import annotations

import json
import logging
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import pytest
from conftest import ACCOUNT, BUCKET, REGION, SG_ID, Harness, config_event, make_settings, policy_document
from moto import mock_aws

from acscg.common.canonical import canonical_json, parse_time, utc_now
from acscg.common.catalog import Catalog
from acscg.common.log import get_logger, log_event, mask
from acscg.common.models import Compliance, FindingState, Severity
from acscg.common.settings import Settings, SettingsError
from acscg.evidence_collector.builder import build_evidence, build_manifest, evidence_key, verify_checksum
from acscg.evidence_collector.sink import InMemoryEvidenceSink, S3EvidenceSink
from acscg.findings_processor import lifecycle
from acscg.findings_processor.handler import handle as processor_handle
from acscg.findings_processor.ports import (
    ConfigVerifier,
    LambdaRequester,
    SnsNotifier,
    SsmInspector,
    SsmPolicyProvider,
)
from acscg.findings_processor.store import ConflictError, DynamoStore
from acscg.findings_processor.validation import InvalidEventError
from acscg.remediation_engine import live_checks
from acscg.remediation_engine.actions import action_for, document_names
from acscg.remediation_engine.policy import supported_actions
from acscg.report_generator.handler import generate
from acscg.report_generator.report import build_report, render_markdown

# ------------------------------------------------------------------ common


def test_severity_ordering_and_parse() -> None:
    assert Severity.CRITICAL > Severity.HIGH >= Severity.HIGH > Severity.LOW
    assert Severity.LOW < Severity.MEDIUM <= Severity.MEDIUM
    assert Severity.parse(" High ") == Severity.HIGH
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("urgent")


def test_canonical_and_time() -> None:
    assert canonical_json({"b": 1, "a": [2, "é"]}) == '{"a":[2,"é"],"b":1}'
    assert parse_time("2026-11-24T10:00:00Z").tzinfo is not None
    assert parse_time("2026-11-24T10:00:00").tzinfo is not None
    assert utc_now().endswith("Z")


def test_mask_identifiers() -> None:
    text = f"arn:aws:iam::{ACCOUNT}:role/x from 203.0.113.7 by a.b@example.com key AKIAABCDEFGHIJKLMNOP cidr 0.0.0.0/0"
    masked = mask({"m": [text]})["m"][0]
    for secret in (ACCOUNT, "203.0.113.7", "a.b@example.com", "AKIAABCDEFGHIJKLMNOP"):
        assert secret not in masked
    assert "0.0.0.0/0" in masked
    assert mask(5) == 5


def test_json_logger_masks(capsys: pytest.CaptureFixture[str]) -> None:
    logger = get_logger("acscg.test")
    get_logger("acscg.test")  # idempotent handler setup
    log_event(logger, f"account {ACCOUNT}", logging.WARNING, ip="203.0.113.9")
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        logger.exception("failed")
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[0]["message"] == "account <ACCOUNT_ID>" and lines[0]["ip"] == "<IPV4>"
    assert "boom" in lines[1]["exception"]


def env(**overrides: str) -> dict[str, str]:
    values = {
        "ACSCG_ENV": "dev",
        "ACSCG_ACCOUNT_ID": ACCOUNT,
        "ACSCG_REGION": REGION,
        "ACSCG_TABLE": "t",
        "ACSCG_EVIDENCE_BUCKET": "b",
        "ACSCG_TOPIC_ARN": "arn:aws:sns:us-east-2:111122223333:t",
    }
    values.update(overrides)
    return values


def test_settings_defaults_fail_safe() -> None:
    settings = Settings.from_env(env())
    assert settings.remediation_mode == "report_only" and not settings.remediation_enabled
    assert Settings.from_env(env(ACSCG_REMEDIATION_ENABLED="true", ACSCG_ALLOW_SYNTHETIC="1")).remediation_enabled


@pytest.mark.parametrize(
    "overrides",
    [
        {"ACSCG_TABLE": ""},
        {"ACSCG_ENV": "qa"},
        {"ACSCG_ACCOUNT_ID": "123"},
        {"ACSCG_REGION": "mars"},
        {"ACSCG_REMEDIATION_MODE": "yolo"},
        {"ACSCG_REMEDIATION_ENABLED": "maybe"},
        {"ACSCG_ENV": "prod", "ACSCG_ALLOW_SYNTHETIC": "true"},
        {"ACSCG_ENV": "prod", "ACSCG_REMEDIATION_ENABLED": "true"},
    ],
)
def test_settings_invalid(overrides: dict[str, str]) -> None:
    with pytest.raises(SettingsError):
        Settings.from_env(env(**overrides))


def test_catalog_lookups(catalog: Catalog) -> None:
    assert catalog.control_for_rule("acscg-sec014-log-retention") == "SEC-014"
    assert catalog.control_for_rule("acscg-sec099-x") is None
    assert catalog.control_for_rule("other") is None
    assert catalog.control_for_securityhub("CloudWatch.16") == "SEC-014"
    assert "SEC-001" in catalog and "SEC-999" not in catalog
    with pytest.raises(KeyError):
        catalog.get("SEC-999")
    assert len(catalog.catalog_controls()) == 15
    assert "Owner" in catalog.required_tags


def test_packaged_catalog_matches_yaml(catalog: Catalog) -> None:
    packaged = Catalog.load_packaged()
    assert [c.control_id for c in packaged.catalog_controls()] == [c.control_id for c in catalog.catalog_controls()]


def test_actions_cover_remediable_controls(catalog: Catalog) -> None:
    for control in catalog.catalog_controls():
        assert (action_for(control.control_id) is not None) == control.remediable, control.control_id
    assert "acscg-RestrictSecurityGroupIngress" in document_names()
    assert "ec2:RevokeSecurityGroupIngress" in supported_actions()


def test_lifecycle_rules() -> None:
    lifecycle.check_transition(None, FindingState.OPEN)
    with pytest.raises(lifecycle.InvalidTransitionError):
        lifecycle.check_transition(FindingState.REPORTED, FindingState.REMEDIATING)
    with pytest.raises(lifecycle.InvalidTransitionError):
        lifecycle.check_transition(FindingState.PENDING_APPROVAL, FindingState.VERIFIED_RESOLVED)
    assert lifecycle.awaiting_owner(FindingState.REPORTED) and not lifecycle.awaiting_owner(FindingState.OPEN)
    assert not FindingState.VERIFIED_RESOLVED.is_open and FindingState.REPORTED.is_open


def test_processor_handler_summary_and_invalid(harness: Harness) -> None:
    assert processor_handle(config_event(), harness.processor)["processed"] == 1
    with pytest.raises(InvalidEventError):
        processor_handle({"id": "x"}, harness.processor)


# ------------------------------------------------------------------ DynamoDB adapter (moto)


@pytest.fixture
def dynamo_table():  # type: ignore[no-untyped-def]
    with mock_aws():
        resource = boto3.resource("dynamodb", region_name=REGION)
        table = resource.create_table(
            TableName="acscg-dev-findings",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "execution_id", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "by-execution",
                    "KeySchema": [{"AttributeName": "execution_id", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table


def test_dynamo_store_contract(dynamo_table) -> None:  # type: ignore[no-untyped-def]
    clock = iter(range(1_000, 10_000))
    store = DynamoStore(dynamo_table, now=lambda: next(clock))
    assert store.claim_event("e1") and not store.claim_event("e1")
    store.release_event("e1")
    assert store.claim_event("e1")
    item = {"finding_key": "k", "control_id": "SEC-005", "state": "OPEN", "details": {"a": "b"}}
    store.put_finding(item, None)
    with pytest.raises(ConflictError):
        store.put_finding(item, None)
    assert store.get_finding("k")["version"] == 1
    store.put_finding({**item, "state": "REPORTED"}, 1)
    with pytest.raises(ConflictError):
        store.put_finding(item, 1)
    assert store.get_finding("missing") is None
    store.add_history("k", {"at": "t1", "from": None, "to": "OPEN"})
    assert store.history("k")[0]["to"] == "OPEN"
    store.put_remediation("k", {"request_id": "r1", "execution_id": "x1", "status": "Started"})
    assert store.remediations("k")[0]["request_id"] == "r1"
    assert store.find_remediation("x1")[0] == "k"  # type: ignore[index]
    assert store.find_remediation("nope") is None
    assert store.acquire_lock("k", "r1") and not store.acquire_lock("k", "r2")
    store.release_lock("k", "r2")  # wrong owner: no effect
    assert not store.acquire_lock("k", "r3")
    store.release_lock("k", "r1")
    assert store.acquire_lock("k", "r3")
    assert store.claim_notification("k", "OPEN", 1) and not store.claim_notification("k", "OPEN", 1)
    assert [f["finding_key"] for f in store.all_findings()] == ["k"]
    dynamo_table.put_item(Item={"pk": "EXC#SEC-005", "sk": "arn:x", "expires_at": "2099-01-01T00:00:00Z"})
    assert store.get_exception("SEC-005", "arn:x")["expires_at"].startswith("2099")  # type: ignore[index]
    assert store.get_exception("SEC-005", "arn:y") is None


def test_dynamo_lock_expires(dynamo_table) -> None:  # type: ignore[no-untyped-def]
    now = {"t": 1_000}
    store = DynamoStore(dynamo_table, now=lambda: now["t"])
    assert store.acquire_lock("k", "r1")
    now["t"] += 6 * 3600
    assert store.acquire_lock("k", "r2")  # expired lock taken over


# ------------------------------------------------------------------ other adapters


class Recorder:
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.responses = responses or {}

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        def call(**kwargs: Any) -> Any:
            self.calls.append((name, kwargs))
            return self.responses.get(name, {})

        return call


def test_sns_and_lambda_adapters() -> None:
    sns = Recorder()
    SnsNotifier(sns, "arn:t").notify("x" * 150, {"a": 1})
    assert len(sns.calls[0][1]["Subject"]) == 100
    lam = Recorder()
    LambdaRequester(lam, "fn").request("k")
    assert lam.calls[0][1]["InvocationType"] == "Event"


def test_ssm_inspector_parses_approval() -> None:
    execution = {
        "AutomationExecution": {
            "AutomationExecutionStatus": "Success",
            "StepExecutions": [
                {"Action": "aws:executeAwsApi", "StepStatus": "Success"},
                {
                    "Action": "aws:approve",
                    "StepStatus": "Success",
                    "ExecutionEndTime": "2026-11-24T09:20:00Z",
                    "Outputs": {
                        "ApprovalStatus": ["Approved"],
                        "ApproverDecisions": [
                            json.dumps([{"approver": "security-approver", "comment": "CHG-1"}]),
                            "not-json",
                        ],
                    },
                },
            ],
        }
    }
    result = SsmInspector(Recorder({"get_automation_execution": execution})).inspect("e")
    assert result["approval_status"] == "Approved" and result["approver"] == "security-approver"
    assert result["approval_comment"] == "CHG-1"


def config_results(*items: tuple[str, str]) -> dict[str, Any]:
    return {
        "EvaluationResults": [
            {"EvaluationResultIdentifier": {"EvaluationResultQualifier": {"ConfigRuleName": rule}}, "ComplianceType": c}
            for rule, c in items
        ]
    }


def test_config_verifier() -> None:
    finding = {"control_id": "SEC-005", "resource_type": "AWS::EC2::SecurityGroup", "resource_id": SG_ID}
    verify = lambda resp: ConfigVerifier(Recorder({"get_compliance_details_by_resource": resp})).verify(finding)  # noqa: E731
    assert verify(config_results(("acscg-sec005-restricted-ssh", "COMPLIANT"))) == Compliance.COMPLIANT
    assert (
        verify(config_results(("acscg-sec005-a", "COMPLIANT"), ("acscg-sec005-b", "NON_COMPLIANT")))
        == Compliance.NON_COMPLIANT
    )
    assert verify(config_results(("other-rule", "NON_COMPLIANT"))) is None
    assert verify(config_results(("acscg-sec005-a", "INSUFFICIENT_DATA"))) is None


def test_config_verifier_ignores_results_recorded_before_the_remediation() -> None:
    from datetime import UTC, datetime

    finding = {"control_id": "SEC-001", "resource_type": "AWS::S3::Bucket", "resource_id": "b"}

    def result(c: str, hour: int, naive: bool = False) -> dict[str, Any]:
        when = datetime(2026, 11, 25, hour, 0, tzinfo=None if naive else UTC)
        return {
            "EvaluationResultIdentifier": {"EvaluationResultQualifier": {"ConfigRuleName": "acscg-sec001-x"}},
            "ComplianceType": c,
            "ResultRecordedTime": when,
        }

    def verify(*items: dict[str, Any]) -> Compliance | None:
        client = Recorder({"get_compliance_details_by_resource": {"EvaluationResults": list(items)}})
        return ConfigVerifier(client).verify(finding, since="2026-11-25T22:00:00Z")

    assert verify(result("NON_COMPLIANT", 21)) is None  # pre-remediation: not a verdict
    assert verify(result("NON_COMPLIANT", 21), result("COMPLIANT", 23)) == Compliance.COMPLIANT
    assert verify(result("NON_COMPLIANT", 23, naive=True)) == Compliance.NON_COMPLIANT
    assert verify({**result("COMPLIANT", 23), "ResultRecordedTime": "2026-11-25T23:00:00Z"}) == Compliance.COMPLIANT
    assert verify({**result("COMPLIANT", 23), "ResultRecordedTime": None}) is None


def test_ssm_policy_provider_caches() -> None:
    ssm = Recorder({"get_parameter": {"Parameter": {"Value": json.dumps(policy_document())}}})
    ticks = iter([0, 10, 100])
    provider = SsmPolicyProvider(ssm, "/acscg/dev/policy", ttl_seconds=60, clock=lambda: next(ticks))
    provider.get()
    provider.get()
    provider.get()
    assert len(ssm.calls) == 2
    assert ssm.calls[0][1] == {"Name": "/acscg/dev/policy", "WithDecryption": True}


# ------------------------------------------------------------------ live checks (moto)


class Clients:
    def client(self, service: str) -> Any:
        return boto3.client(service, region_name=REGION)


def finding_for(control: str, rtype: str, rid: str, arn: str) -> dict[str, Any]:
    return {
        "control_id": control,
        "resource_type": rtype,
        "resource_id": rid,
        "resource_identifier": arn,
        "account": ACCOUNT,
        "region": REGION,
    }


@mock_aws
def test_live_check_security_group() -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="fixture", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{sg}"
    live = live_checks.run_check(
        finding_for("SEC-005", "AWS::EC2::SecurityGroup", sg, arn), Clients(), required_tags=(), log_retention_days=30
    )
    assert live is not None and live.violation_present and live.needs_approval
    assert len(live.parameters["SecurityGroupRuleIds"]) == 1
    rdp = live_checks.run_check(
        finding_for("SEC-006", "AWS::EC2::SecurityGroup", sg, arn), Clients(), required_tags=(), log_retention_days=30
    )
    assert rdp is not None and not rdp.violation_present


@mock_aws
def test_live_check_bucket_tags_and_logs() -> None:
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
    bucket = finding_for("SEC-001", "AWS::S3::Bucket", BUCKET, f"arn:aws:s3:::{BUCKET}")
    assert live_checks.run_check(bucket, Clients(), required_tags=(), log_retention_days=30).violation_present  # type: ignore[union-attr]
    s3.put_public_access_block(
        Bucket=BUCKET,
        PublicAccessBlockConfiguration=dict.fromkeys(live_checks.BPA_FIELDS, True),
    )
    assert not live_checks.run_check(bucket, Clients(), required_tags=(), log_retention_days=30).violation_present  # type: ignore[union-attr]

    logs = boto3.client("logs", region_name=REGION)
    logs.create_log_group(logGroupName="/acscg/dev/fixture", tags={"Project": "acscg"})
    arn = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/acscg/dev/fixture"
    group = finding_for("SEC-014", "AWS::Logs::LogGroup", "/acscg/dev/fixture", arn)
    live = live_checks.run_check(group, Clients(), required_tags=(), log_retention_days=30)
    assert live is not None and live.violation_present and not live.needs_approval
    old = live_checks.check_log_retention(group, Clients(), 30, now=datetime.now(UTC) + timedelta(days=60))
    assert old.needs_approval
    missing = live_checks.check_log_retention({**group, "resource_id": "/nope"}, Clients(), 30)
    assert not missing.violation_present

    tags = live_checks.run_check(
        finding_for("SEC-013", "AWS::S3::Bucket", BUCKET, f"arn:aws:s3:::{BUCKET}"),
        Clients(),
        required_tags=("Project", "Owner"),
        log_retention_days=30,
    )
    assert tags is not None and tags.violation_present and "Owner" in tags.parameters["MissingTagKeys"]


@mock_aws
def test_live_check_imdsv2_and_errors() -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    instance = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "optional"})[
        "Instances"
    ][0]["InstanceId"]
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{instance}"
    live = live_checks.run_check(
        finding_for("SEC-008", "AWS::EC2::Instance", instance, arn), Clients(), required_tags=(), log_retention_days=30
    )
    assert live is not None and live.violation_present
    broken = live_checks.run_check(
        finding_for("SEC-005", "AWS::EC2::SecurityGroup", "sg-missing", "x"),
        _Broken(),
        required_tags=(),
        log_retention_days=30,
    )
    assert broken is None
    assert (
        live_checks.run_check(
            finding_for("SEC-009", "AWS::IAM::User", "u", "u"), Clients(), required_tags=(), log_retention_days=30
        )
        is None
    )


class _Broken:
    def client(self, service: str) -> Any:
        raise RuntimeError("no credentials")


# ------------------------------------------------------------------ evidence and reports


def sample_finding() -> dict[str, Any]:
    return {
        "finding_key": "f" * 64,
        "control_id": "SEC-005",
        "severity": "high",
        "resource_type": "AWS::EC2::SecurityGroup",
        "resource_id": SG_ID,
        "resource_identifier": f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{SG_ID}",
        "account": ACCOUNT,
        "region": REGION,
        "first_seen": "2026-11-24T09:00:00Z",
    }


def test_evidence_checksum_detects_tampering() -> None:
    doc = build_evidence(
        kind="transition-open",
        finding=sample_finding(),
        recorded_at="2026-11-24T09:00:01Z",
        previous_compliance_state="COMPLIANT",
        updated_compliance_state="NON_COMPLIANT",
        lifecycle_from=None,
        lifecycle_to="OPEN",
    )
    assert verify_checksum(doc)
    tampered = json.loads(json.dumps(doc))
    tampered["updated_compliance_state"] = "COMPLIANT"
    assert not verify_checksum(tampered)
    assert evidence_key(doc).startswith(f"evidence/SEC-005/{'f' * 64}/2026-11-24T09-00-01Z")
    manifest = build_manifest([("b", "2"), ("a", "1")], "2026-11-24T23:59:59Z")
    assert [o["key"] for o in manifest["objects"]] == ["a", "b"] and len(manifest["manifest_sha256"]) == 64


def test_evidence_sinks() -> None:
    doc = build_evidence(
        kind="k",
        finding=sample_finding(),
        recorded_at="t",
        previous_compliance_state=None,
        updated_compliance_state=None,
        lifecycle_from=None,
        lifecycle_to="OPEN",
    )
    sink = InMemoryEvidenceSink()
    sink.put(doc)
    with pytest.raises(FileExistsError):
        sink.put(doc)
    s3 = Recorder()
    S3EvidenceSink(s3, "bucket", "alias/k").put(doc)
    call = s3.calls[0][1]
    assert call["ServerSideEncryption"] == "aws:kms" and call["IfNoneMatch"] == "*"
    with pytest.raises(ValueError, match="KMS"):
        S3EvidenceSink(s3, "bucket", "")


def test_scenario_14_report_from_real_findings(catalog: Catalog) -> None:
    findings = [
        {**sample_finding(), "state": "VERIFIED_RESOLVED"},
        {
            **sample_finding(),
            "finding_key": "2",
            "control_id": "SEC-013",
            "state": "REPORTED",
            "severity": "low",
            "resource_type": "AWS::Logs::LogGroup",
            "resource_id": "/acscg/x",
        },
        {**sample_finding(), "finding_key": "3", "control_id": "SEC-004", "state": "COMPLIANT"},
        {**sample_finding(), "finding_key": "4", "control_id": "SEC-005", "state": "REPORTED", "synthetic": True},
        {**sample_finding(), "finding_key": "5", "control_id": "EXT-GUARDDUTY", "state": "REPORTED", "sample": True},
        {**sample_finding(), "finding_key": "6", "control_id": "SEC-001", "state": "bogus"},
    ]
    report = build_report(findings, catalog, environment="dev", generated_at="2026-11-24T12:00:00Z")
    summary = report["summary"]
    assert summary["resources_evaluated"] == 3
    assert summary["open_findings"] == 1 and summary["remediated_findings"] == 1
    assert summary["compliance_score"] == pytest.approx(66.7)
    assert summary["excluded_synthetic_or_sample"] == 2
    assert summary["open_by_severity"]["low"] == 1
    public = render_markdown(report, public=True)
    assert ACCOUNT not in public and "/acscg/x" not in public and "res-" in public
    assert "/acscg/x" in render_markdown(report, public=False)
    assert "Not a certification" in public
    empty = build_report([], catalog, environment="dev", generated_at="t")
    assert empty["summary"]["compliance_score"] is None and "None." in render_markdown(empty)


def test_report_handler_writes_three_objects(catalog: Catalog, harness: Harness) -> None:
    harness.processor.process(config_event())
    s3 = Recorder()
    result = generate(harness.store, catalog, make_settings(), s3, "2026-11-24T12:00:00Z")
    keys = [c[1]["Key"] for c in s3.calls]
    assert keys == [
        "reports/2026-11-24T12-00-00Z/report.json",
        "reports/2026-11-24T12-00-00Z/report.md",
        "reports/2026-11-24T12-00-00Z/report-public.md",
    ]
    assert all(c[1]["ServerSideEncryption"] == "aws:kms" for c in s3.calls)
    assert result["summary"]["open_findings"] == 1 and ACCOUNT not in result["public_markdown"]
    assert result["metric_records"] == 1 + len(result["summary"]["open_by_severity"])


def test_emf_records_equal_the_report_and_carry_no_identifiers(catalog: Catalog, harness: Harness, capsys) -> None:  # type: ignore[no-untyped-def]
    """Scenario 14 metrics: every value is the report's own number (Phase 7)."""
    import json as _json

    from acscg.report_generator.report import emf_records, metric_namespace

    harness.processor.process(config_event())
    generate(harness.store, catalog, make_settings(), Recorder(), "2026-11-24T12:00:00Z")
    lines = [_json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    main = next(x for x in lines if "OpenFindings" in x)
    meta = main["_aws"]["CloudWatchMetrics"][0]
    assert meta["Namespace"] == metric_namespace("dev") == "ACSCG/acscg-dev" and meta["Dimensions"] == [[]]
    assert main["_aws"]["Timestamp"] == 1795521600000  # 2026-11-24T12:00:00Z
    assert {m["Name"] for m in meta["Metrics"]} <= set(main)  # every declared metric has a value
    report = build_report(harness.store.all_findings(), catalog, environment="dev", generated_at="t")
    assert main["OpenFindings"] == report["summary"]["open_findings"] == 1
    assert main["ResourcesEvaluated"] == report["summary"]["resources_evaluated"]
    by_sev = {x["Severity"]: x["OpenFindingsBySeverity"] for x in lines if "Severity" in x}
    assert by_sev == report["summary"]["open_by_severity"]
    assert ACCOUNT not in _json.dumps(lines) and SG_ID not in _json.dumps(lines)
    empty = build_report([], catalog, environment="dev", generated_at="t")
    first = emf_records(empty, namespace="n", timestamp_ms=0, report_key="k")[0]
    assert "ComplianceScore" not in first and "ComplianceScore" not in {
        m["Name"] for m in first["_aws"]["CloudWatchMetrics"][0]["Metrics"]
    }


# ------------------------------------------------------------------ packaging


def test_lambda_package_is_reproducible(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import importlib.util

    from conftest import ROOT

    spec = importlib.util.spec_from_file_location("build_lambda", ROOT / "scripts" / "build_lambda.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    assert module.CATALOG_JSON.read_text("utf-8") == module.catalog_json(), "run scripts/build_lambda.py --catalog-only"
    first = module.build(tmp_path / "a.zip")
    second = module.build(tmp_path / "b.zip")
    assert first == second
    names = zipfile.ZipFile(tmp_path / "a.zip").namelist()
    assert "acscg/data/control-catalog.json" in names
    assert "acscg/findings_processor/handler.py" in names
    assert not any("__pycache__" in n or n.startswith("tests") for n in names)
