"""The Phase 0 discovery script must stay read-only and must redact identifiers by default."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "discover_aws.sh"
READ_ONLY_VERB = re.compile(r"^(describe|list|get)-[a-z0-9-]+$")
# `run "<label>" <service> <operation>` and `$(aws <service> <operation> ...)`
CALL = re.compile(r"""(?:\brun\s+"[^"]*"\s+|\baws\s+)([a-z0-9-]+)\s+([a-z0-9-]+)""")
# ce:GetCostAndUsage is read-only although its verb is "get-cost-and-usage"; it is matched by the rule.


def aws_calls() -> list[tuple[str, str]]:
    calls = []
    for line in SCRIPT.read_text("utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        calls += CALL.findall(line)
    return calls


def test_script_makes_aws_calls() -> None:
    assert len(aws_calls()) > 40


def test_every_aws_call_is_read_only() -> None:
    offending = sorted({f"{svc} {op}" for svc, op in aws_calls() if not READ_ONLY_VERB.match(op)})
    assert offending == []


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_output_is_redacted_by_default(tmp_path: Path) -> None:
    stub = tmp_path / "aws"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in\n'
        '  *"get-caller-identity --query Account"*) echo 123456789012;;\n'
        '  *) echo \'{"Arn":"arn:aws:iam::123456789012:role/x","Email":"a.b@example.com","Cidr":"203.0.113.7/32"}\';;\n'
        "esac\n",
        "utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "SKIP_COST_EXPLORER": "1"}
    result = subprocess.run(  # noqa: S603 - fixed script path, stubbed aws binary
        [shutil.which("bash") or "/bin/bash", str(SCRIPT), "us-east-2"],
        capture_output=True,
        text=True,
        env=env,
        check=True,
        timeout=120,
    )
    out = result.stdout
    assert "<ACCOUNT_ID>" in out
    for secret in ("123456789012", "a.b@example.com", "203.0.113.7"):
        assert secret not in out
