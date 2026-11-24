"""Event validation, normalisation per source, severity, and custom evaluators."""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import ACCOUNT, REGION, SG_ID, cloudtrail_event, config_event

from acscg.common.catalog import Catalog
from acscg.common.models import Compliance, Finding, RemediationStatus, Resource, Severity
from acscg.compliance_evaluator import config_rule
from acscg.compliance_evaluator.change_attribution import attribute, principal_of
from acscg.compliance_evaluator.security_groups import covers_port, open_permissions, open_rules
from acscg.compliance_evaluator.tags import evaluate_tags, normalise_tags
from acscg.findings_processor.normalizers import build_arn, guardduty_severity, normalise
from acscg.findings_processor.severity import classify
from acscg.findings_processor.validation import MAX_EVENT_BYTES, InvalidEventError, validate_event

# ------------------------------------------------------------------ validation


def test_valid_config_event() -> None:
    assert validate_event(config_event(), allow_synthetic=False) == ("aws.config", "Config Rules Compliance Change")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.pop("detail"),
        lambda e: e.update(source="custom.attacker"),
        lambda e: e.update({"detail-type": "Something Else"}),
        lambda e: e["detail"].pop("configRuleName"),
        lambda e: e["detail"].update(resourceId=""),
        lambda e: e["detail"]["newEvaluationResult"].update(complianceType=True),
        lambda e: e["detail"].update(padding="x" * (MAX_EVENT_BYTES + 1)),
        lambda e: e["detail"].update(newEvaluationResult="NON_COMPLIANT"),
    ],
)
def test_invalid_events_rejected(mutate) -> None:  # type: ignore[no-untyped-def]
    event = config_event()
    mutate(event)
    with pytest.raises(InvalidEventError):
        validate_event(event, allow_synthetic=False)


def test_non_object_rejected() -> None:
    with pytest.raises(InvalidEventError):
        validate_event("event", allow_synthetic=True)


# ------------------------------------------------------------------ normalisers


def test_config_normaliser(catalog: Catalog) -> None:
    [finding] = normalise(config_event(), catalog)
    assert isinstance(finding, Finding)
    assert finding.control_id == "SEC-005" and finding.compliance == Compliance.NON_COMPLIANT
    assert finding.resource.arn == f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{SG_ID}"
    assert finding.details["previous_compliance"] == "COMPLIANT"


def test_unknown_compliance_type_maps_to_insufficient_data(catalog: Catalog) -> None:
    event = config_event()
    event["detail"]["newEvaluationResult"]["complianceType"] = "WEIRD"
    assert normalise(event, catalog)[0].compliance == Compliance.INSUFFICIENT_DATA


def test_build_arn() -> None:
    assert build_arn("AWS::IAM::User", "AIDAEXAMPLE", ACCOUNT, REGION) is None
    assert build_arn("AWS::Lambda::Function", "fn", ACCOUNT, REGION) == f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:fn"
    assert build_arn("AWS::Other", "arn:aws:x:::y", ACCOUNT, REGION) == "arn:aws:x:::y"
    assert Resource("AWS::IAM::User", "AIDAEXAMPLE", ACCOUNT, REGION).identifier == "config:AWS::IAM::User:AIDAEXAMPLE"


def access_analyzer_event(
    resource_type: str = "AWS::S3::Bucket", status: str = "ACTIVE", public: bool = True
) -> dict[str, Any]:
    return {
        "id": "aa-1",
        "source": "aws.access-analyzer",
        "detail-type": "Access Analyzer Finding",
        "account": ACCOUNT,
        "region": REGION,
        "time": "2026-11-24T09:00:00Z",
        "detail": {
            "id": "f-1",
            "resource": "arn:aws:s3:::acscg-dev-fixture-bucket",
            "resourceType": resource_type,
            "status": status,
            "accountId": ACCOUNT,
            "isPublic": public,
        },
    }


def test_access_analyzer(catalog: Catalog) -> None:
    [finding] = normalise(access_analyzer_event(), catalog)
    assert finding.control_id == "SEC-001" and finding.details["is_public"]
    assert classify(finding, catalog) == Severity.CRITICAL
    archived = normalise(access_analyzer_event(status="ARCHIVED"), catalog)[0]
    assert archived.compliance == Compliance.COMPLIANT
    assert normalise(access_analyzer_event(resource_type="AWS::KMS::Key"), catalog) == []


def securityhub_event(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": "sh-1",
        "source": "aws.securityhub",
        "detail-type": "Security Hub Findings - Imported",
        "account": ACCOUNT,
        "region": REGION,
        "time": "2026-11-24T09:00:00Z",
        "detail": {"findings": findings},
    }


def asff(
    control: str = "EC2.13", product: str = "Security Hub", status: str = "FAILED", label: str = "HIGH", **extra: Any
) -> dict[str, Any]:
    item = {
        "Id": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:finding/1",
        "AwsAccountId": ACCOUNT,
        "Region": REGION,
        "ProductFields": {"aws/securityhub/ProductName": product},
        "Compliance": {"Status": status, "SecurityControlId": control},
        "Severity": {"Label": label},
        "Resources": [
            {
                "Type": "AwsEc2SecurityGroup",
                "Id": f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{SG_ID}",
                "Region": REGION,
            }
        ],
        "Title": "SG allows 22",
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
    }
    item.update(extra)
    return item


def test_security_hub_findings(catalog: Catalog) -> None:
    findings = normalise(
        securityhub_event(
            [
                asff(),
                asff(product="Config"),
                asff(RecordState="ARCHIVED"),
                asff("Unknown.1", status="PASSED", label="LOW"),
            ]
        ),
        catalog,
    )
    assert [f.control_id for f in findings] == ["SEC-005", "EXT-SECURITYHUB"]
    assert findings[0].compliance == Compliance.NON_COMPLIANT and findings[1].compliance == Compliance.COMPLIANT
    assert classify(findings[0], catalog) == Severity.HIGH
    assert classify(findings[1], catalog) == Severity.LOW


def guardduty_event(severity: float = 8.0, sample: bool = True) -> dict[str, Any]:
    return {
        "id": "gd-1",
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "account": ACCOUNT,
        "region": REGION,
        "time": "2026-11-24T09:00:00Z",
        "detail": {
            "id": "gdf-1",
            "type": "Recon:EC2/PortProbeUnprotectedPort",
            "severity": severity,
            "accountId": ACCOUNT,
            "region": REGION,
            "title": "Unprotected port probed",
            "resource": {"resourceType": "Instance"},
            "service": {"additionalInfo": {"sample": sample}},
        },
    }


def test_guardduty_sample_findings_scenario_16(catalog: Catalog) -> None:
    [finding] = normalise(guardduty_event(), catalog)
    assert finding.control_id == "EXT-GUARDDUTY" and finding.sample
    assert classify(finding, catalog) == Severity.HIGH
    assert [guardduty_severity(x) for x in (2, 5, 7.5, 9.5)] == [
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_guardduty_sample_is_reported_never_requested(report_only_harness, harness) -> None:  # type: ignore[no-untyped-def]
    harness.processor.process(guardduty_event())
    [item] = harness.store.all_findings()
    assert item["state"] == "REPORTED" and item["sample"] is True
    assert harness.requester.requested == []


def test_ssm_status_normaliser(catalog: Catalog) -> None:
    from conftest import ssm_status_event

    [status] = normalise(ssm_status_event("e-1", "Success"), catalog)
    assert isinstance(status, RemediationStatus) and status.execution_id == "e-1"


def test_severity_escalations(catalog: Catalog) -> None:
    trail = Finding(
        "SEC-015",
        "cloudtrail",
        "e",
        Resource("AWS::CloudTrail::Trail", "t", ACCOUNT, REGION),
        Compliance.NON_COMPLIANT,
        "t",
    )
    assert classify(trail, catalog) == Severity.CRITICAL
    bucket = Finding(
        "SEC-003", "config", "e", Resource("AWS::S3::Bucket", "b", ACCOUNT, REGION), Compliance.NON_COMPLIANT, "t"
    )
    assert classify(bucket, catalog) == Severity.LOW
    assert classify(bucket, catalog, data_classification="audit-evidence") == Severity.HIGH


# ------------------------------------------------------------------ evaluators


@pytest.mark.parametrize(
    ("protocol", "low", "high", "port", "expected"),
    [
        ("tcp", 22, 22, 22, True),
        ("tcp", 0, 1024, 22, True),
        ("tcp", 23, 3388, 22, False),
        ("-1", None, None, 3389, True),
        ("udp", 0, 65535, 22, False),
        ("6", None, None, 22, True),
        ("tcp", -1, -1, 3389, True),
    ],
)
def test_covers_port(protocol: str, low, high, port: int, expected: bool) -> None:  # type: ignore[no-untyped-def]
    assert covers_port(protocol, low, high, port) is expected


def test_open_permissions_all_shapes() -> None:
    api = [{"IpProtocol": "tcp", "FromPort": 20, "ToPort": 30, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    config = [
        {
            "ipProtocol": "tcp",
            "fromPort": 3389,
            "toPort": 3389,
            "ipv6Ranges": [{"cidrIpv6": "::/0"}],
            "ipRanges": ["0.0.0.0/0"],
        }
    ]
    private = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]
    assert [r.cidr for r in open_permissions(api, 22)] == ["0.0.0.0/0"]
    assert sorted(r.cidr for r in open_permissions(config, 3389)) == ["0.0.0.0/0", "::/0"]
    assert open_permissions(private, 22) == []


def test_open_rules_ignore_egress_and_private() -> None:
    rules = [
        {
            "SecurityGroupRuleId": "sgr-1",
            "IsEgress": False,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIpv4": "0.0.0.0/0",
        },
        {"SecurityGroupRuleId": "sgr-2", "IsEgress": True, "IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"},
        {
            "SecurityGroupRuleId": "sgr-3",
            "IsEgress": False,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIpv4": "10.0.0.0/8",
        },
        {
            "SecurityGroupRuleId": "sgr-4",
            "IsEgress": False,
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIpv6": "::/0",
        },
    ]
    assert [r.rule_id for r in open_rules(rules, 22)] == ["sgr-1"]


def test_tags() -> None:
    required = ("Project", "Environment", "Owner")
    assert evaluate_tags({"Project": "acscg", "Environment": "dev", "Owner": "me"}, required).compliant
    result = evaluate_tags([{"Key": "Project", "Value": "acscg"}, {"Key": "Environment", "Value": "qa"}], required)
    assert result.missing == ("Owner",) and result.invalid == {"Environment": "qa"}
    assert normalise_tags(None) == {} and normalise_tags([{"key": "a", "value": None}]) == {"a": ""}


def test_change_attribution() -> None:
    approved = frozenset({"arn:aws:iam::111122223333:role/acscg-github-apply"})
    unauth = attribute(cloudtrail_event()["detail"], approved)
    assert unauth is not None and not unauth.authorized and unauth.resource_id == SG_ID
    ok = attribute(cloudtrail_event(principal="arn:aws:iam::111122223333:role/acscg-github-apply")["detail"], approved)
    assert ok is not None and ok.authorized
    assert attribute(cloudtrail_event("DescribeSecurityGroups")["detail"], approved) is None
    modify = cloudtrail_event(
        "ModifySecurityGroupRules", params={"ModifySecurityGroupRulesRequest": {"GroupId": ["sg-9"]}}
    )
    assert attribute(modify["detail"], approved).resource_id == "sg-9"  # type: ignore[union-attr]
    unknown = cloudtrail_event("PutBucketPolicy", "s3.amazonaws.com", params={})
    assert attribute(unknown["detail"], approved).resource_id == "unknown"  # type: ignore[union-attr]
    assert principal_of({"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/alice"})[1] == "IAMUser"
    assert principal_of({"type": "AWSService", "invokedBy": "config.amazonaws.com"})[0] == "config.amazonaws.com"


# ------------------------------------------------------------------ custom Config rule handler


class FakeConfig:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def put_evaluations(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


def rule_event(
    item: dict[str, Any] | None,
    params: dict[str, Any],
    message_type: str = "ConfigurationItemChangeNotification",
    left: bool = False,
) -> dict[str, Any]:
    return {
        "invokingEvent": json.dumps({"configurationItem": item, "messageType": message_type}),
        "ruleParameters": json.dumps(params),
        "resultToken": "token",
        "eventLeftScope": left,
    }


def sg_item(permissions: list[dict[str, Any]], status: str = "OK") -> dict[str, Any]:
    return {
        "resourceType": "AWS::EC2::SecurityGroup",
        "resourceId": SG_ID,
        "configurationItemCaptureTime": "2026-11-24T09:00:00.000Z",
        "configurationItemStatus": status,
        "configuration": {"ipPermissions": permissions},
        "tags": {"Project": "acscg"},
    }


def test_config_rule_open_admin_port_ipv6() -> None:
    client = FakeConfig()
    item = sg_item([{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipv6Ranges": [{"cidrIpv6": "::/0"}]}])
    result = config_rule.handler(rule_event(item, {"check": "open_admin_port", "controlId": "SEC-005"}), None, client)
    assert result["evaluations"][0]["ComplianceType"] == "NON_COMPLIANT"
    assert client.calls[0]["ResultToken"] == "token"


def test_config_rule_variants() -> None:
    params = {"check": "open_admin_port", "controlId": "SEC-006"}
    assert config_rule.evaluate_item(sg_item([]), params)[0] == "COMPLIANT"
    assert config_rule.evaluate_item(sg_item([], status="ResourceDeleted"), params)[0] == "NOT_APPLICABLE"
    assert config_rule.evaluate_item({**sg_item([]), "resourceType": "AWS::S3::Bucket"}, params)[0] == "NOT_APPLICABLE"
    tags = {"check": "required_tags", "requiredTags": "Project, Owner"}
    compliance, note = config_rule.evaluate_item(sg_item([]), tags)
    assert compliance == "NON_COMPLIANT" and "Owner" in note
    assert config_rule.evaluate_item({**sg_item([]), "tags": {"Project": "a", "Owner": "b"}}, tags)[0] == "COMPLIANT"
    with pytest.raises(ValueError, match="unknown check"):
        config_rule.evaluate_item(sg_item([]), {"check": "nope"})
    client = FakeConfig()
    assert config_rule.handler(rule_event(None, params, "ScheduledNotification"), None, client) == {"evaluations": []}
    left = config_rule.handler(rule_event(sg_item([]), params, left=True), None, client)
    assert left["evaluations"][0]["ComplianceType"] == "NOT_APPLICABLE"


@pytest.mark.parametrize(
    ("configuration", "expected"),
    [
        ({}, "NON_COMPLIANT"),  # "Never expire": the managed rule would say COMPLIANT
        ({"retentionInDays": 7}, "NON_COMPLIANT"),
        ({"retentionInDays": 30}, "COMPLIANT"),
        ({"RetentionInDays": 365}, "COMPLIANT"),
    ],
)
def test_config_rule_log_retention_set(configuration: dict[str, Any], expected: str) -> None:
    item = {"resourceType": "AWS::Logs::LogGroup", "resourceId": "/acscg/test", "configuration": configuration}
    params = {"check": "log_retention_set", "minRetentionDays": "30"}
    assert config_rule.evaluate_item(item, params)[0] == expected
    assert config_rule.evaluate_item(sg_item([]), params)[0] == "NOT_APPLICABLE"


class FakeLogs:
    def __init__(self, groups: list[dict[str, Any]], page: int = 2) -> None:
        self.groups, self.page = groups, page

    def describe_log_groups(self, **kwargs: Any) -> dict[str, Any]:
        start = int(kwargs.get("nextToken", 0))
        chunk = self.groups[start : start + self.page]
        nxt = start + self.page
        return {"logGroups": chunk, **({"nextToken": str(nxt)} if nxt < len(self.groups) else {})}


def test_periodic_log_retention_lists_groups_itself_and_batches() -> None:
    groups = [
        {"logGroupName": "/never"},
        {"logGroupName": "/short", "retentionInDays": 7},
        {"logGroupName": "/ok", "retentionInDays": 30},
    ]
    groups += [{"logGroupName": f"/g{i}", "retentionInDays": 90} for i in range(150)]
    config = FakeConfig()
    event = {
        "invokingEvent": json.dumps(
            {"messageType": "ScheduledNotification", "notificationCreationTime": "2026-11-24T16:00:00.000Z"}
        ),
        "ruleParameters": json.dumps({"check": "log_retention_set", "minRetentionDays": "30"}),
        "resultToken": "token",
    }
    out = config_rule.handler(event, None, config, FakeLogs(groups, page=50))
    by_name = {e["ComplianceResourceId"]: e["ComplianceType"] for e in out["evaluations"]}
    assert (
        by_name["/never"] == "NON_COMPLIANT" and by_name["/short"] == "NON_COMPLIANT" and by_name["/ok"] == "COMPLIANT"
    )
    assert len(by_name) == 153
    assert [len(c["Evaluations"]) for c in config.calls] == [100, 53]  # PutEvaluations limit
    assert all(e["OrderingTimestamp"] == "2026-11-24T16:00:00.000Z" for e in out["evaluations"])


def test_scheduled_notification_for_other_checks_is_still_ignored() -> None:
    client = FakeConfig()
    assert config_rule.handler(
        rule_event(None, {"check": "open_admin_port"}, "ScheduledNotification"), None, client
    ) == {"evaluations": []}
    assert client.calls == []
