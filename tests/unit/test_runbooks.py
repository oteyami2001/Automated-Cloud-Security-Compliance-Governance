"""Static validation of SSM Automation runbooks and offline execution of their embedded scripts."""

from __future__ import annotations

import ast
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import ROOT

from acscg.remediation_engine.actions import ACTIONS

RUNBOOK_FILES = {
    "acscg-RestrictSecurityGroupIngress": "restrict-security-group.yaml",
    "acscg-EnableBucketPublicAccessBlock": "enable-s3-protection.yaml",
    "acscg-EnforceRequiredTags": "enforce-required-tags.yaml",
    "acscg-SetLogRetention": "set-log-retention.yaml",
    "acscg-EnforceImdsV2": "enforce-imdsv2.yaml",
}
# Parameters the gatekeeper passes per document (remediation_engine/service.py + live_checks.py)
GATEKEEPER_PARAMETERS = {
    "acscg-RestrictSecurityGroupIngress": {"SecurityGroupId", "SecurityGroupRuleIds"},
    "acscg-EnableBucketPublicAccessBlock": {"BucketName"},
    "acscg-EnforceRequiredTags": {"ResourceArn", "TagKeys", "TagValues"},
    "acscg-SetLogRetention": {"LogGroupName", "RetentionInDays"},
    "acscg-EnforceImdsV2": {"InstanceId", "PreviousHttpTokens"},
}
COMMON = {"AutomationAssumeRole", "FindingKey", "RequestId", "RequireApproval", "Approvers"}
READ_OR_REEVALUATE = {"StartConfigRulesEvaluation", "DescribeInstances"}


def load(name: str) -> dict[str, Any]:
    return yaml.safe_load((ROOT / "runbooks" / name).read_text("utf-8"))


def test_every_action_has_a_runbook() -> None:
    assert {a.document for a in ACTIONS} == set(RUNBOOK_FILES)
    assert {p.name for p in (ROOT / "runbooks").glob("*.yaml")} == set(RUNBOOK_FILES.values())


@pytest.mark.parametrize(("document", "filename"), sorted(RUNBOOK_FILES.items()))
def test_runbook_structure(document: str, filename: str) -> None:
    doc = load(filename)
    assert doc["schemaVersion"] == "0.3"
    assert doc["assumeRole"] == "{{ AutomationAssumeRole }}"
    params = set(doc["parameters"])
    assert COMMON | GATEKEEPER_PARAMETERS[document] <= params, params
    steps = doc["mainSteps"]
    names = [s["name"] for s in steps]
    assert names[0] == "AssertAndCapture", "first step must re-check the precondition"
    assert len(names) == len(set(names))
    # exactly one mutating API/script step besides re-evaluation, rollback and capture/verify
    mutating = [
        s
        for s in steps
        if (s["action"] == "aws:executeAwsApi" and s["inputs"]["Api"] not in READ_OR_REEVALUATE)
        or (s["action"] == "aws:executeScript" and s["name"] not in {"AssertAndCapture", "Verify", "Rollback"})
    ]
    assert len(mutating) == 1, [s["name"] for s in mutating]
    change = mutating[0]
    assert change["onFailure"] == "Abort"
    # approval gate: a branch on RequireApproval leads to aws:approve before the change
    approve = next(s for s in steps if s["action"] == "aws:approve")
    assert approve["inputs"]["Approvers"] == "{{ Approvers }}"
    assert approve["inputs"]["MinRequiredApprovals"] == 1
    assert approve["timeoutSeconds"] <= 4 * 3600
    assert approve["nextStep"] == change["name"]
    assert names.index("ApprovalRequired") < names.index("Approve") < names.index(change["name"])
    # verification and rollback
    verify = next(s for s in steps if s["name"] == "Verify")
    assert verify["onFailure"] == "step:Rollback" and verify["isEnd"] is True
    rollback = next(s for s in steps if s["name"] == "Rollback")
    assert rollback["isEnd"] is True
    reevaluate = next(s for s in steps if s["name"] == "Reevaluate")
    assert all(r.startswith("acscg-sec") for r in reevaluate["inputs"]["ConfigRuleNames"])
    for step in steps:
        if step["action"] == "aws:executeScript":
            assert step["inputs"]["Runtime"].startswith("python3")
            ast.parse(step["inputs"]["Script"])


def test_high_risk_runbooks_default_to_approval() -> None:
    assert load("restrict-security-group.yaml")["parameters"]["RequireApproval"]["default"] == "true"
    assert load("enforce-imdsv2.yaml")["parameters"]["RequireApproval"]["allowedValues"] == ["true"]


# ------------------------------------------------------------------ executing embedded scripts


class FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeEc2:
    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self.rules = rules
        self.authorized: list[dict[str, Any]] = []

    def describe_security_group_rules(self, **_: Any) -> dict[str, Any]:
        return {"SecurityGroupRules": list(self.rules)}

    def authorize_security_group_ingress(self, **kwargs: Any) -> None:
        self.authorized.append(kwargs)


def run_script(filename: str, step: str, payload: dict[str, Any], clients: dict[str, Any]) -> Any:
    doc = load(filename)
    code = next(s for s in doc["mainSteps"] if s["name"] == step)["inputs"]["Script"]
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = lambda service: clients[service]  # type: ignore[attr-defined]
    fake_exc = types.ModuleType("botocore.exceptions")
    fake_exc.ClientError = FakeClientError  # type: ignore[attr-defined]
    saved = {k: sys.modules.get(k) for k in ("boto3", "botocore", "botocore.exceptions")}
    sys.modules["boto3"] = fake_boto3
    sys.modules["botocore"] = types.ModuleType("botocore")
    sys.modules["botocore.exceptions"] = fake_exc
    try:
        namespace: dict[str, Any] = {}
        exec(compile(code, f"{filename}:{step}", "exec"), namespace)  # noqa: S102 - our own runbook code
        return namespace["handler"](payload, None)
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


OPEN_RULE = {
    "SecurityGroupRuleId": "sgr-0aaa1111",
    "IsEgress": False,
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "CidrIpv4": "0.0.0.0/0",
}
PRIVATE_RULE = {
    "SecurityGroupRuleId": "sgr-0bbb2222",
    "IsEgress": False,
    "IpProtocol": "tcp",
    "FromPort": 443,
    "ToPort": 443,
    "CidrIpv4": "10.0.0.0/8",
}
EGRESS = {"SecurityGroupRuleId": "sgr-0ccc3333", "IsEgress": True, "IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"}
F = "restrict-security-group.yaml"


def test_sg_assert_refuses_non_open_rules() -> None:
    ec2 = FakeEc2([OPEN_RULE, PRIVATE_RULE, EGRESS])
    out = run_script(F, "AssertAndCapture", {"GroupId": "sg-1", "RuleIds": ["sgr-0aaa1111"]}, {"ec2": ec2})
    assert len(json.loads(out["Before"])) == 3
    with pytest.raises(ValueError, match="not open"):
        run_script(F, "AssertAndCapture", {"GroupId": "sg-1", "RuleIds": ["sgr-0bbb2222"]}, {"ec2": ec2})
    with pytest.raises(ValueError, match="not found"):
        run_script(F, "AssertAndCapture", {"GroupId": "sg-1", "RuleIds": ["sgr-0ccc3333"]}, {"ec2": ec2})


def test_sg_verify_detects_collateral_changes() -> None:
    before = json.dumps([OPEN_RULE, PRIVATE_RULE, EGRESS])
    payload = {"GroupId": "sg-1", "RuleIds": ["sgr-0aaa1111"], "Before": before}
    assert run_script(F, "Verify", payload, {"ec2": FakeEc2([PRIVATE_RULE, EGRESS])})["Verified"]
    with pytest.raises(ValueError, match="still present"):
        run_script(F, "Verify", payload, {"ec2": FakeEc2([OPEN_RULE, PRIVATE_RULE, EGRESS])})
    with pytest.raises(ValueError, match="other than"):
        run_script(F, "Verify", payload, {"ec2": FakeEc2([EGRESS])})


def test_sg_rollback_restores_only_removed_rules() -> None:
    ipv6 = {**OPEN_RULE, "SecurityGroupRuleId": "sgr-0ddd4444", "CidrIpv4": None, "CidrIpv6": "::/0"}
    before = json.dumps([OPEN_RULE, ipv6, PRIVATE_RULE])
    ec2 = FakeEc2([ipv6, PRIVATE_RULE])  # only the IPv4 rule was removed
    with pytest.raises(RuntimeError, match="rolled back 1"):
        run_script(
            F,
            "Rollback",
            {"GroupId": "sg-1", "RuleIds": ["sgr-0aaa1111", "sgr-0ddd4444"], "Before": before},
            {"ec2": ec2},
        )
    assert ec2.authorized[0]["IpPermissions"][0]["IpRanges"][0]["CidrIp"] == "0.0.0.0/0"


class FakeS3:
    def __init__(self, config: dict[str, bool] | None) -> None:
        self.config = config
        self.deleted = False

    def get_public_access_block(self, **_: Any) -> dict[str, Any]:
        if self.config is None:
            raise FakeClientError("NoSuchPublicAccessBlockConfiguration")
        return {"PublicAccessBlockConfiguration": self.config}

    def put_public_access_block(self, **kwargs: Any) -> None:
        self.config = kwargs["PublicAccessBlockConfiguration"]

    def delete_public_access_block(self, **_: Any) -> None:
        self.deleted = True


def test_s3_scripts() -> None:
    f = "enable-s3-protection.yaml"
    out = run_script(f, "AssertAndCapture", {"Bucket": "b"}, {"s3": FakeS3(None)})
    assert out["HadConfig"] is False
    full = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)
    with pytest.raises(ValueError, match="already"):
        run_script(f, "AssertAndCapture", {"Bucket": "b"}, {"s3": FakeS3(full)})
    assert run_script(f, "Verify", {"Bucket": "b"}, {"s3": FakeS3(full)})["Verified"]
    s3 = FakeS3(full)
    with pytest.raises(RuntimeError):
        run_script(f, "Rollback", {"Bucket": "b", "Before": "{}", "HadConfig": False}, {"s3": s3})
    assert s3.deleted


class FakeTagging:
    def __init__(self, tags: dict[str, str]) -> None:
        self.tags = tags

    def get_resources(self, **_: Any) -> dict[str, Any]:
        return {"ResourceTagMappingList": [{"Tags": [{"Key": k, "Value": v} for k, v in self.tags.items()]}]}

    def tag_resources(self, **kwargs: Any) -> dict[str, Any]:
        self.tags.update(kwargs["Tags"])
        return {}

    def untag_resources(self, **kwargs: Any) -> None:
        for key in kwargs["TagKeys"]:
            self.tags.pop(key, None)


def test_tag_scripts_never_overwrite() -> None:
    f = "enforce-required-tags.yaml"
    tagging = FakeTagging({"Project": "acscg", "Owner": "existing"})
    out = run_script(
        f,
        "AssertAndCapture",
        {"Arn": "a", "Keys": ["Owner", "Environment"], "Values": ["x", "dev"]},
        {"resourcegroupstaggingapi": tagging},
    )
    assert json.loads(out["ToAdd"]) == {"Environment": "dev"}
    run_script(f, "AddTags", {"Arn": "a", "ToAdd": out["ToAdd"]}, {"resourcegroupstaggingapi": tagging})
    assert tagging.tags["Owner"] == "existing"
    assert run_script(f, "Verify", {"Arn": "a", "ToAdd": out["ToAdd"]}, {"resourcegroupstaggingapi": tagging})[
        "Verified"
    ]
    with pytest.raises(RuntimeError):
        run_script(f, "Rollback", {"Arn": "a", "AddedKeys": ["Environment"]}, {"resourcegroupstaggingapi": tagging})
    assert "Environment" not in tagging.tags
    with pytest.raises(ValueError, match="length"):
        run_script(
            f, "AssertAndCapture", {"Arn": "a", "Keys": ["Owner"], "Values": []}, {"resourcegroupstaggingapi": tagging}
        )


class FakeLogs:
    def __init__(self, groups: list[dict[str, Any]]) -> None:
        self.groups = groups

    def describe_log_groups(self, **_: Any) -> dict[str, Any]:
        return {"logGroups": self.groups}

    def delete_retention_policy(self, **_: Any) -> None:
        self.groups[0].pop("retentionInDays", None)


def test_log_retention_scripts_never_change_existing_retention() -> None:
    f = "set-log-retention.yaml"
    assert run_script(f, "AssertAndCapture", {"Name": "/g", "Days": 30}, {"logs": FakeLogs([{"logGroupName": "/g"}])})[
        "NeverExpired"
    ]
    with pytest.raises(ValueError, match="already set"):
        run_script(
            f,
            "AssertAndCapture",
            {"Name": "/g", "Days": 30},
            {"logs": FakeLogs([{"logGroupName": "/g", "retentionInDays": 7}])},
        )
    with pytest.raises(ValueError, match="not found"):
        run_script(f, "AssertAndCapture", {"Name": "/g", "Days": 30}, {"logs": FakeLogs([])})
    with pytest.raises(ValueError, match="30, 90 or 365"):
        run_script(f, "AssertAndCapture", {"Name": "/g", "Days": 7}, {"logs": FakeLogs([{"logGroupName": "/g"}])})
    assert run_script(
        f, "Verify", {"Name": "/g", "Days": "30"}, {"logs": FakeLogs([{"logGroupName": "/g", "retentionInDays": 30}])}
    )
    logs = FakeLogs([{"logGroupName": "/g", "retentionInDays": 30}])
    with pytest.raises(RuntimeError):
        run_script(f, "Rollback", {"Name": "/g"}, {"logs": logs})
    assert "retentionInDays" not in logs.groups[0]


def test_runbook_files_are_documented() -> None:
    readme = (ROOT / "runbooks" / "README.md").read_text("utf-8")
    for filename in RUNBOOK_FILES.values():
        assert filename in readme
    assert isinstance(Path(ROOT / "runbooks"), Path)


def _strings(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in _strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v)]
    return []


@pytest.mark.parametrize("filename", sorted(RUNBOOK_FILES.values()))
def test_list_parameters_are_never_embedded_in_a_longer_string(filename: str) -> None:
    """SSM rejects a non-String parameter used as a substring (StringList: P6-2; Integer: P6-9, found in AWS)."""
    doc = load(filename)
    lists = [
        n for n, p in doc["parameters"].items() if p.get("type") in {"StringList", "MapList", "Integer", "Boolean"}
    ]
    for text in _strings(doc["mainSteps"]):
        for name in lists:
            ref = "{{ " + name + " }}"
            if ref in text:
                assert text.strip() == ref, f"{filename}: {name} used inside {text[:80]!r}"


BOTO_TYPES = {"integer": "Integer", "long": "Integer", "boolean": "Boolean", "string": "String", "list": "StringList"}


@pytest.mark.parametrize("filename", sorted(RUNBOOK_FILES.values()))
def test_api_inputs_match_the_aws_api_types(filename: str) -> None:
    """Every "{{ Param }}" passed whole to an aws:executeAwsApi input has the type the API expects.

    Found in AWS (P6-8): a String RetentionInDays reached PutRetentionPolicy as "30" and was rejected.
    """
    import re

    import botocore.session

    session = botocore.session.get_session()
    doc = load(filename)
    for step in doc["mainSteps"]:
        if step["action"] != "aws:executeAwsApi":
            continue
        inputs = step["inputs"]
        model = session.get_service_model(inputs["Service"]).operation_model(inputs["Api"]).input_shape
        for key, value in inputs.items():
            if key in {"Service", "Api"}:
                continue
            assert key in model.members, f"{filename}:{step['name']}: {key} is not an input of {inputs['Api']}"
            match = re.fullmatch(r"\{\{ *(\w+) *\}\}", str(value)) if isinstance(value, str) else None
            if not match:
                continue
            expected = BOTO_TYPES.get(model.members[key].type_name)
            declared = doc["parameters"][match.group(1)]["type"]
            assert declared == expected, f"{filename}:{step['name']}: {key} needs {expected}, parameter is {declared}"
