"""Plan guard and digest (ADR 0008): every rejection rule, digest binding, and fail-closed input handling."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("plan_guard", ROOT / "scripts" / "plan_guard.py")
pg = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(pg)  # type: ignore[union-attr]


def rc(
    address: str,
    rtype: str,
    actions: list[str],
    after: dict[str, Any] | None = None,
    before: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "address": address,
        "mode": "managed",
        "type": rtype,
        "change": {"actions": actions, "before": before, "after": after or {}, "after_unknown": {}},
    }


def plan(*changes: dict[str, Any], **variables: str) -> dict[str, Any]:
    defaults = {
        "config_ownership_mode": "integrate",
        "cloudtrail_mode": "integrate",
        "security_hub_mode": "disabled",
        "guardduty_mode": "disabled",
    }
    defaults.update(variables)
    return {
        "format_version": "1.2",
        "variables": {k: {"value": v} for k, v in defaults.items()},
        "resource_changes": list(changes),
    }


ROLE = rc(
    "module.x.aws_iam_role.r",
    "aws_iam_role",
    ["create"],
    {"name": "acscg-dev-x", "permissions_boundary": "arn:aws:iam::1:policy/acscg-workload-boundary"},
)


def test_clean_plan_passes() -> None:
    assert (
        pg.guard(plan(ROLE, rc("aws_sqs_queue.q", "aws_sqs_queue", ["create"], {"name": "acscg-dev-q"})), "apply") == []
    )


@pytest.mark.parametrize(
    ("change", "variables", "message"),
    [
        (
            rc(
                "module.c.aws_config_configuration_recorder.this[0]",
                "aws_config_configuration_recorder",
                ["create"],
                {"name": "acscg-dev-recorder"},
            ),
            {},
            "config_ownership_mode",
        ),
        (
            rc("module.t.aws_cloudtrail.this[0]", "aws_cloudtrail", ["update"], {"name": "idp-management-events"}),
            {},
            "cloudtrail_mode",
        ),
        (
            rc("module.s.aws_securityhub_account.this[0]", "aws_securityhub_account", ["delete"]),
            {},
            "security_hub_mode",
        ),
        (rc("module.g.aws_guardduty_detector.this[0]", "aws_guardduty_detector", ["create"]), {}, "guardduty_mode"),
        (rc("aws_iam_openid_connect_provider.github[0]", "aws_iam_openid_connect_provider", ["create"]), {}, "shared"),
        (
            rc("aws_s3_bucket.x", "aws_s3_bucket", ["update"], {"bucket": "aiops-tfstate-1-us-east-2"}),
            {},
            "another project",
        ),
        (
            rc("aws_iam_role.y", "aws_iam_role", ["update"], {"name": "idp-github-apply", "permissions_boundary": "b"}),
            {},
            "another project",
        ),
        (
            rc(
                "module.e.aws_s3_bucket.evidence",
                "aws_s3_bucket",
                ["delete", "create"],
                {"bucket": "acscg-dev-evidence"},
            ),
            {},
            "protected resource",
        ),
        (rc("module.e.aws_kms_key.this", "aws_kms_key", ["delete"]), {}, "protected resource"),
        (rc("aws_iam_role.z", "aws_iam_role", ["create"], {"name": "acscg-dev-z"}), {}, "permissions boundary"),
    ],
)
def test_guard_rejects(change: dict[str, Any], variables: dict[str, str], message: str) -> None:
    violations = pg.guard(plan(change, **variables), "apply")
    assert violations and any(message in v for v in violations), violations


def test_owned_services_may_change_in_create_mode() -> None:
    change = rc(
        "module.c.aws_config_configuration_recorder.this[0]",
        "aws_config_configuration_recorder",
        ["create"],
        {"name": "acscg-dev-recorder"},
    )
    assert pg.guard(plan(change, config_ownership_mode="create"), "apply") == []


def test_destroy_mode_only_deletes() -> None:
    deleting = rc("module.e.aws_kms_key.this", "aws_kms_key", ["delete"])
    assert pg.guard(plan(deleting), "destroy") == []
    creating = rc("aws_sqs_queue.q", "aws_sqs_queue", ["create"], {"name": "acscg-dev-q"})
    assert any("only delete" in v for v in pg.guard(plan(deleting, creating), "destroy"))


def test_bootstrap_roles_skip_boundary_check() -> None:
    unbounded = rc("module.ci.aws_iam_role.this", "aws_iam_role", ["create"], {"name": "acscg-github-dev-apply"})
    assert pg.guard(plan(unbounded), "apply", require_boundary=False) == []


def test_unknown_boundary_at_plan_is_accepted() -> None:
    change = rc("aws_iam_role.r", "aws_iam_role", ["create"], {"name": "acscg-dev-r"})
    change["change"]["after_unknown"] = {"permissions_boundary": True}
    assert pg.guard(plan(change), "apply") == []


def test_digest_binds_mode_values_and_ignores_order() -> None:
    a = rc("aws_sqs_queue.a", "aws_sqs_queue", ["create"], {"name": "acscg-dev-a"})
    b = rc("aws_sqs_queue.b", "aws_sqs_queue", ["create"], {"name": "acscg-dev-b"})
    noop = rc("aws_sqs_queue.c", "aws_sqs_queue", ["no-op"], {"name": "acscg-dev-c"})
    base = pg.digest(plan(a, b), "apply")
    assert pg.digest(plan(b, a, noop), "apply") == base
    assert pg.digest(plan(a, b), "destroy") != base
    changed = rc("aws_sqs_queue.b", "aws_sqs_queue", ["create"], {"name": "acscg-dev-b2"})
    assert pg.digest(plan(a, changed), "apply") != base
    assert len(base) == 64


def test_summary_never_contains_values() -> None:
    secret = rc(
        "aws_sns_topic_subscription.email[0]",
        "aws_sns_topic_subscription",
        ["create"],
        {"endpoint": "owner@example.com"},
    )
    text = "\n".join(pg.summary(plan(secret)))
    assert "owner@example.com" not in text and "aws_sns_topic_subscription.email[0]" in text


def run_cli(tmp_path: Path, document: Any, *args: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(document) if not isinstance(document, str) else document, "utf-8")
    return subprocess.run(  # noqa: S603 - runs this repository's own script with fixed arguments
        [sys.executable, str(ROOT / "scripts" / "plan_guard.py"), *args[:1], str(path), *args[1:]],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_fail_closed_and_verify(tmp_path: Path) -> None:
    assert run_cli(tmp_path, "{}", "check", "--mode", "apply").returncode == 2
    assert run_cli(tmp_path, "not json", "check", "--mode", "apply").returncode == 2
    assert (
        run_cli(
            tmp_path, {"format_version": "1.2", "errored": True, "resource_changes": []}, "check", "--mode", "apply"
        ).returncode
        == 2
    )
    good = plan(ROLE)
    out = run_cli(tmp_path, good, "check", "--mode", "apply")
    assert out.returncode == 0
    value = out.stdout.split("digest=")[1].strip()
    assert run_cli(tmp_path, good, "verify", "--mode", "apply", "--expected", value).returncode == 0
    assert run_cli(tmp_path, good, "verify", "--mode", "destroy", "--expected", value).returncode == 1
    assert run_cli(tmp_path, good, "verify", "--mode", "apply", "--expected", "0" * 64).returncode == 1
    assert run_cli(tmp_path, good, "verify", "--mode", "apply", "--expected", "short").returncode == 2
    bad = plan(rc("aws_iam_openid_connect_provider.x", "aws_iam_openid_connect_provider", ["delete"]))
    assert run_cli(tmp_path, bad, "check", "--mode", "apply").returncode == 1


def test_tf_ci_script_syntax() -> None:
    command = ["/bin/bash", "-n", str(ROOT / "scripts" / "tf_ci.sh")]
    result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603 - fixed system bash checking this repository's script
    assert result.returncode == 0, result.stderr
