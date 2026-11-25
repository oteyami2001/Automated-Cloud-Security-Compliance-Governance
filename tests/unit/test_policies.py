"""Policy source files: schema-valid, report-only by default, and parseable after Terraform-style rendering."""

from __future__ import annotations

import json
from string import Template
from typing import Any

import pytest
import yaml
from conftest import ACCOUNT, APPROVER, REGION, ROOT
from jsonschema import Draft202012Validator

from acscg.remediation_engine.policy import parse_policy

ENVS = ("dev", "staging", "prod")


def schema(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((ROOT / "policies" / "schemas" / name).read_text("utf-8")))


def source(env: str) -> dict[str, Any]:
    return yaml.safe_load((ROOT / "policies" / "remediation" / f"{env}.yaml").read_text("utf-8"))


def render(env: str, approvers: list[str]) -> dict[str, Any]:
    """Mirror of the Terraform rendering: substitute ${account_id}/${region} and add computed fields."""
    text = Template((ROOT / "policies" / "remediation" / f"{env}.yaml").read_text("utf-8")).substitute(
        account_id=ACCOUNT, region=REGION, fixture_sg_arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0fixture"
    )
    doc = yaml.safe_load(text)
    doc["approval"]["approvers"] = approvers
    doc.update(project_inventory=[], approved_change_principals=[], project_role_arns=[])
    return doc


@pytest.mark.parametrize("env", ENVS)
def test_policy_sources_are_valid_and_report_only(env: str) -> None:
    doc = source(env)
    assert list(schema("remediation-policy.schema.json").iter_errors(doc)) == []
    assert doc["environment"] == env
    policy = parse_policy(render(env, [APPROVER]))
    if env != "dev":
        assert doc["remediation_enabled"] is False and doc["remediation_mode"] == "report_only"
        assert not policy.remediation_enabled and policy.allowlist == ()
    elif policy.remediation_enabled:  # a dev window: fixtures only, every entry expires
        assert policy.allowlist
        for entry in policy.allowlist:
            assert "fixture" in entry.resource_arn and entry.expires_at, entry


def test_schema_forbids_prod_remediation_and_allowlists() -> None:
    validator = schema("remediation-policy.schema.json")
    prod = {**source("prod"), "remediation_enabled": True}
    assert list(validator.iter_errors(prod))
    staging = {
        **source("staging"),
        "allowlist": [
            {
                "id": "AL-001",
                "control_id": "SEC-005",
                "action": "ec2:RevokeSecurityGroupIngress",
                "account": "${account_id}",
                "region": REGION,
                "resource_arn": "arn:aws:ec2:us-east-2:${account_id}:security-group/sg-1",
                "expires_at": "2026-12-01T00:00:00Z",
                "reason": "test window",
            }
        ],
    }
    assert list(validator.iter_errors(staging))
    assert list(validator.iter_errors({**staging, "environment": "dev"})) == []


def test_schema_requires_templated_account() -> None:
    entry = {
        "id": "AL-001",
        "control_id": "SEC-005",
        "action": "ec2:RevokeSecurityGroupIngress",
        "account": ACCOUNT,  # a literal account ID must never be committed
        "region": REGION,
        "resource_arn": "arn:aws:ec2:us-east-2:${account_id}:security-group/sg-1",
        "expires_at": "2026-12-01T00:00:00Z",
        "reason": "test window",
    }
    assert list(schema("remediation-policy.schema.json").iter_errors({**source("dev"), "allowlist": [entry]}))


@pytest.mark.parametrize("env", ENVS)
def test_exception_registers_valid(env: str) -> None:
    doc = yaml.safe_load((ROOT / "policies" / "exceptions" / f"{env}.yaml").read_text("utf-8"))
    assert list(schema("exceptions.schema.json").iter_errors(doc)) == []


def test_scanner_register_valid() -> None:
    doc = yaml.safe_load((ROOT / "policies" / "exceptions" / "scanner-exceptions.yaml").read_text("utf-8"))
    assert list(schema("scanner-exceptions.schema.json").iter_errors(doc)) == []
