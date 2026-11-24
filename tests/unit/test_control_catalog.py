"""Offline tests for the control catalog and framework mappings."""

from __future__ import annotations

import copy
import importlib.util
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("validate_catalog", ROOT / "scripts" / "validate_catalog.py")
validate_catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate_catalog)

REQUIRED_CONTROLS = {f"SEC-{n:03d}" for n in range(1, 16)}


def load_catalog() -> dict:
    return yaml.safe_load((ROOT / "controls" / "control-catalog.yaml").read_text("utf-8"))


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A copy of controls/ that a test may mutate."""
    shutil.copytree(ROOT / "controls", tmp_path / "controls")
    return tmp_path


def write_catalog(root: Path, catalog: dict) -> None:
    (root / "controls" / "control-catalog.yaml").write_text(yaml.safe_dump(catalog, sort_keys=False), "utf-8")


def control(catalog: dict, control_id: str) -> dict:
    return next(c for c in catalog["controls"] if c["id"] == control_id)


def test_repository_catalog_is_valid() -> None:
    assert validate_catalog.validate() == []


def test_catalog_contains_the_fifteen_required_controls() -> None:
    assert {c["id"] for c in load_catalog()["controls"]} == REQUIRED_CONTROLS


def test_default_mode_is_report_only() -> None:
    assert load_catalog()["catalog"]["defaults"]["remediation_mode"] == "report_only"


def test_nothing_is_claimed_as_verified_in_aws() -> None:
    assert {c["implementation_status"] for c in load_catalog()["controls"]} == {"planned"}


@pytest.mark.parametrize("control_id", ["SEC-005", "SEC-006", "SEC-008"])
def test_high_risk_remediations_require_human_approval(control_id: str) -> None:
    c = control(load_catalog(), control_id)
    assert c["remediation"]["eligibility"] == "human_approval"
    assert c["approval"]["required"] is True


@pytest.mark.parametrize("control_id", ["SEC-009", "SEC-010", "SEC-011", "SEC-012"])
def test_identity_and_audit_controls_never_change_resources(control_id: str) -> None:
    assert control(load_catalog(), control_id)["remediation"]["eligibility"] in {"report_only", "escalate"}


def test_unknown_framework_requirement_is_rejected(workspace: Path) -> None:
    catalog = load_catalog()
    control(catalog, "SEC-001")["frameworks"]["nist_800_53_r5"].append("ZZ-99")
    write_catalog(workspace, catalog)
    errors = validate_catalog.validate(workspace)
    assert any("ZZ-99" in e for e in errors), errors


def test_stale_back_link_is_rejected(workspace: Path) -> None:
    catalog = load_catalog()
    control(catalog, "SEC-004")["frameworks"]["cis_aws_v5_0_0"] = []
    write_catalog(workspace, catalog)
    errors = validate_catalog.validate(workspace)
    assert any("2.1.1" in e for e in errors), errors


def test_auto_remediation_of_cloudtrail_is_rejected(workspace: Path) -> None:
    catalog = load_catalog()
    c = control(catalog, "SEC-012")
    c["remediation"] = copy.deepcopy(control(catalog, "SEC-001")["remediation"])
    c["approval"] = {"required": False}
    write_catalog(workspace, catalog)
    errors = validate_catalog.validate(workspace)
    assert any("audit services" in e for e in errors), errors


def test_human_approval_control_without_approvers_is_rejected(workspace: Path) -> None:
    catalog = load_catalog()
    control(catalog, "SEC-005")["approval"] = {"required": False}
    write_catalog(workspace, catalog)
    assert any(e.startswith("schema:") for e in validate_catalog.validate(workspace))


def test_non_report_only_default_is_rejected(workspace: Path) -> None:
    catalog = load_catalog()
    catalog["catalog"]["defaults"]["remediation_mode"] = "auto_low_risk"
    write_catalog(workspace, catalog)
    assert validate_catalog.validate(workspace)


def test_verified_in_aws_without_evidence_is_rejected(workspace: Path) -> None:
    catalog = load_catalog()
    control(catalog, "SEC-003")["implementation_status"] = "verified-in-aws"
    write_catalog(workspace, catalog)
    assert any("verified-in-aws" in e for e in validate_catalog.validate(workspace))


def test_every_framework_file_records_version_and_source() -> None:
    for filename in validate_catalog.FRAMEWORK_FILES.values():
        fw = yaml.safe_load((ROOT / "controls" / filename).read_text("utf-8"))["framework"]
        assert fw["version"] and fw["sources"], filename
        assert all(s.get("url") for s in fw["sources"]), filename
