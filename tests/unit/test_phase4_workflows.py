"""Static checks of the Terraform plan/apply workflows and tf_ci.sh (ADR 0008)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text("utf-8"))


@pytest.mark.parametrize(
    ("name", "environment", "role"),
    [
        ("terraform-plan.yml", "dev-plan", "acscg-github-dev-plan"),
        ("terraform-apply.yml", "dev", "acscg-github-dev-apply"),
    ],
)
def test_workflow_identity_and_permissions(name: str, environment: str, role: str) -> None:
    workflow = load(name)
    assert workflow["permissions"] == {}
    (job,) = workflow["jobs"].values()
    assert job["environment"] == environment  # OIDC subject …:environment:<env>, main only
    assert job["permissions"] == {"contents": "read", "id-token": "write"}
    steps = job["steps"]
    uses = [s["uses"] for s in steps if "uses" in s]
    assert all(SHA_PIN.match(u) for u in uses), uses
    creds = next(s for s in steps if s.get("uses", "").startswith("aws-actions/configure-aws-credentials@"))
    assert creds["with"]["role-to-assume"].endswith(f":role/{role}")
    assert creds["with"]["mask-aws-account-id"] is True
    for step in steps:
        assert "${{" not in step.get("run", ""), f"expressions go through env, not into run: {step}"
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False


def test_apply_needs_the_reviewed_digest() -> None:
    workflow = load("terraform-apply.yml")
    trigger = workflow[True]["workflow_dispatch"]  # YAML 1.1 reads the key "on" as True
    assert trigger["inputs"]["digest"]["required"] is True
    (job,) = workflow["jobs"].values()
    apply_step = job["steps"][-1]
    assert apply_step["env"]["EXPECTED_DIGEST"] == "${{ inputs.digest }}"
    assert apply_step["run"].startswith("bash scripts/tf_ci.sh apply ")


def test_plan_workflow_has_no_write_path() -> None:
    workflow = load("terraform-plan.yml")
    (job,) = workflow["jobs"].values()
    assert job["steps"][-1]["run"].split()[:3] == ["bash", "scripts/tf_ci.sh", "plan"]  # read-only role, plan only


def test_tf_ci_uses_the_bootstrap_state_backend() -> None:
    script = (ROOT / "scripts" / "tf_ci.sh").read_text("utf-8")
    for setting in (
        "bucket=acscg-tfstate-${TF_VAR_aws_account_id}-${REGION}",
        "key=stack/${ENV}/terraform.tfstate",
        "encrypt=true",
        "kms_key_id=alias/acscg-tfstate",
        "use_lockfile=true",
    ):
        assert setting in script
    assert 'plan_guard.py" verify' in script  # apply only after the digest matched


@pytest.mark.parametrize("name", ["terraform-plan.yml", "terraform-apply.yml"])
def test_missing_environment_secrets_fail_fast(name: str) -> None:
    (job,) = load(name)["jobs"].values()
    names = [s.get("name", s.get("uses", "")) for s in job["steps"]]
    check = names.index("Environment secrets present")
    login = next(i for i, n in enumerate(names) if n.startswith("aws-actions/configure-aws-credentials@"))
    assert check < login


def test_tf_ci_redaction_removes_ids_emails_and_auth_blobs() -> None:
    import shutil
    import subprocess

    script = (ROOT / "scripts" / "tf_ci.sh").read_text("utf-8")
    start = script.index("redact() {")
    func = script[start : script.index("\n}\n", start) + 3]
    sample = (
        "not authorized on resource: arn:aws:ec2:us-east-2:111122223333:vpc/vpc-0223b576a747a4747 "
        "sg-0123456789abcdef0 owner@example.com Encoded authorization failure message: l21_e11Ma9B7z-x\n"
        "Encoded authorization failure message:\n" + "7dQHrrpwzSEz-DNgzSbfmauz9px" * 6 + "\n"
    )
    bash = shutil.which("bash") or "/bin/bash"
    cmd = [bash, "-c", func + "redact"]
    out = subprocess.run(cmd, input=sample, capture_output=True, text=True, check=True).stdout  # noqa: S603 - fixed bash running this repository's own redact function
    assert "111122223333" not in out and "vpc-0223b576a747a4747" not in out and "sg-0123456789abcdef0" not in out
    assert "owner@example.com" not in out and "l21_e11Ma9B7z" not in out and "7dQHrrpwzSEz" not in out
    assert "vpc-<id>" in out and "<removed>" in out


def test_verify_workflow_is_read_only() -> None:
    workflow = load("verify-deployment.yml")
    assert workflow["permissions"] == {}
    assert True not in workflow or not (workflow[True]["workflow_dispatch"] or {}).get("inputs")
    (job,) = workflow["jobs"].values()
    assert job["environment"] == "dev-plan" and job["permissions"] == {"contents": "read", "id-token": "write"}
    steps = job["steps"]
    creds = next(s for s in steps if s.get("uses", "").startswith("aws-actions/configure-aws-credentials@"))
    assert creds["with"]["role-to-assume"].endswith(":role/acscg-github-dev-plan")  # never the apply role
    assert all(SHA_PIN.match(s["uses"]) for s in steps if "uses" in s)
    assert all("${{" not in s.get("run", "") for s in steps)
