"""Phase 3 operator scripts: valid bash, read-only where they claim to be, and safe by construction."""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest
from conftest import ROOT

SCRIPTS = ROOT / "scripts"
BASH = shutil.which("bash") or "/bin/bash"
READ_ONLY_VERB = re.compile(r"^(describe|list|get|head)-[a-z0-9-]+$")
AWS_CALL = re.compile(r"\baws\s+(?:--region\s+\S+\s+)?([a-z0-9-]+)\s+([a-z0-9-]+)")
Q_CALL = re.compile(r"\bq\s+([a-z0-9-]+)\s+([a-z0-9-]+)")


@pytest.mark.parametrize(
    "name",
    ["bootstrap.sh", "verify_bootstrap.sh", "install_terraform.sh", "configure_github.sh", "verify_github_settings.sh"],
)
def test_scripts_are_valid_bash(name: str) -> None:
    result = subprocess.run([BASH, "-n", str(SCRIPTS / name)], capture_output=True, text=True, check=False)  # noqa: S603 - fixed bash checking this repository's script
    assert result.returncode == 0, result.stderr


def test_verify_bootstrap_is_read_only() -> None:
    text = (SCRIPTS / "verify_bootstrap.sh").read_text("utf-8")
    calls = AWS_CALL.findall(text) + Q_CALL.findall(text)
    assert len(calls) > 10
    offending = sorted({f"{s} {o}" for s, o in calls if not READ_ONLY_VERB.match(o)})
    assert offending == []


def test_verify_github_settings_uses_get_only() -> None:
    text = (SCRIPTS / "verify_github_settings.sh").read_text("utf-8")
    assert "-X PUT" not in text and "-X PATCH" not in text and "-X POST" not in text and "-X DELETE" not in text


def test_bootstrap_applies_only_a_reviewed_saved_plan() -> None:
    text = (SCRIPTS / "bootstrap.sh").read_text("utf-8")
    assert 'plan_guard.py" verify "$JSON" --mode apply --no-boundary-check --expected "$DIGEST"' in text
    apply_lines = [line for line in text.splitlines() if "terraform -chdir" in line and " apply " in line]
    assert apply_lines and all('"$PLAN"' in line for line in apply_lines)  # never a fresh, unreviewed apply
    assert "-auto-approve" not in text
    assert 'CALLER" = "$TF_VAR_aws_account_id' in text  # refuses the wrong account


def test_install_terraform_verifies_checksum() -> None:
    text = (SCRIPTS / "install_terraform.sh").read_text("utf-8")
    assert "sha256sum -c" in text and "SHA256SUMS" in text


def test_ruleset_requires_pr_and_ci_ok() -> None:
    ruleset = json.loads((ROOT / ".github" / "rulesets" / "main.json").read_text("utf-8"))
    types = {r["type"] for r in ruleset["rules"]}
    assert {"deletion", "non_fast_forward", "pull_request", "required_status_checks"} <= types
    checks = next(r for r in ruleset["rules"] if r["type"] == "required_status_checks")
    assert checks["parameters"]["required_status_checks"] == [{"context": "ci-ok"}]
    assert ruleset["bypass_actors"] == []


def test_ci_ok_depends_on_every_job() -> None:
    import yaml

    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8"))
    jobs = set(workflow["jobs"]) - {"ci-ok"}
    assert set(workflow["jobs"]["ci-ok"]["needs"]) == jobs


def test_bootstrap_inputs_match_verification() -> None:
    tfvars = (ROOT / "terraform" / "bootstrap" / "terraform.tfvars").read_text("utf-8")
    verify = (SCRIPTS / "verify_bootstrap.sh").read_text("utf-8")
    owner_id = re.search(r'github_owner_id\s*=\s*"(\d+)"', tfvars)[1]  # type: ignore[index]
    repo_id = re.search(r'github_repo_id\s*=\s*"(\d+)"', tfvars)[1]  # type: ignore[index]
    assert f"oteyami2001@{owner_id}/Automated-Cloud-Security-Compliance-Governance@{repo_id}" in verify
    assert not re.search(r"(?<!\d)\d{12}(?!\d)", tfvars), "no account ID in committed tfvars"


def test_root_lock_files_cover_ci_and_cloudshell_platforms() -> None:
    for root in ("bootstrap", "stack"):
        lock = (ROOT / "terraform" / root / ".terraform.lock.hcl").read_text("utf-8")
        assert 'version     = "6.73.0"' in lock
        assert lock.count('"h1:') >= 5, root  # linux amd64/arm64, darwin amd64/arm64, windows amd64


def test_bootstrap_plan_reports_no_changes_instead_of_exiting_silently() -> None:
    script = (SCRIPTS / "bootstrap.sh").read_text("utf-8")
    assert script.index("^No changes") < script.index("grep -E '^Plan:'")
