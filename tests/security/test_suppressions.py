"""The scanner-suppression register is enforced: unjustified, unregistered, expired or stale entries fail."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_suppressions", ROOT / "scripts" / "check_suppressions.py")
cs = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["check_suppressions"] = cs  # dataclasses resolve their module through sys.modules
spec.loader.exec_module(cs)  # type: ignore[union-attr]

TODAY = date(2026, 11, 24)


def workspace(tmp_path: Path, code: str, entries: list[dict]) -> Path:
    (tmp_path / "terraform").mkdir()
    (tmp_path / "terraform" / "main.tf").write_text(code, "utf-8")
    register = tmp_path / "policies" / "exceptions"
    register.mkdir(parents=True)
    (register / "scanner-exceptions.yaml").write_text(yaml.safe_dump({"suppressions": entries}), "utf-8")
    return tmp_path


def entry(**overrides: str) -> dict:
    data = {
        "tool": "checkov",
        "rule": "CKV_AWS_18",
        "path": "terraform/main.tf",
        "justification": "Access logging needs a further bucket",
        "owner": "x",
        "review_by": "2027-01-01",
    }
    data.update(overrides)
    return data


GOOD = "# checkov:skip=CKV_AWS_18:Access logging would need a further log bucket here\n"


def test_repository_register_is_complete() -> None:
    assert cs.check() == []


def test_registered_and_justified_passes(tmp_path: Path) -> None:
    assert cs.check(workspace(tmp_path, GOOD, [entry()]), TODAY) == []


def test_unregistered_suppression_fails(tmp_path: Path) -> None:
    errors = cs.check(workspace(tmp_path, GOOD, []), TODAY)
    assert any("not in" in e for e in errors)


def test_unjustified_suppression_fails(tmp_path: Path) -> None:
    errors = cs.check(workspace(tmp_path, "# checkov:skip=CKV_AWS_18:ok\n", [entry()]), TODAY)
    assert any("justification" in e for e in errors)


def test_expired_and_far_future_reviews_fail(tmp_path: Path) -> None:
    assert any("has passed" in e for e in cs.check(workspace(tmp_path, GOOD, [entry(review_by="2026-01-01")]), TODAY))
    shutil.rmtree(tmp_path / "terraform")
    shutil.rmtree(tmp_path / "policies")
    assert any("180 days" in e for e in cs.check(workspace(tmp_path, GOOD, [entry(review_by="2028-01-01")]), TODAY))


def test_stale_entries_fail(tmp_path: Path) -> None:
    errors = cs.check(workspace(tmp_path, GOOD, [entry(), entry(rule="CKV_AWS_144")]), TODAY)
    assert any("stale" in e for e in errors)
