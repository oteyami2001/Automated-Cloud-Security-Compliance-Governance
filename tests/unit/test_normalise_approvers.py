"""scripts/normalise_approvers.py: tolerant of pasting, strict on content, never echoes the secret."""

from __future__ import annotations

import importlib.util
import sys

import pytest
from conftest import ROOT

spec = importlib.util.spec_from_file_location("normalise_approvers", ROOT / "scripts" / "normalise_approvers.py")
assert spec and spec.loader
na = importlib.util.module_from_spec(spec)
sys.modules["normalise_approvers"] = na
spec.loader.exec_module(na)

ROLE = "arn:aws:iam::111122223333:role/AccountFullAccessRole"


@pytest.mark.parametrize(
    "raw",
    [
        f'["{ROLE}"]',
        f'  ["{ROLE}"]\n',
        f'[ "{ROLE} " ]\r\n',
        f'["{ROLE}", "arn:aws:iam::111122223333:user/alice"]',
        ROLE,  # plain ARN, as printed by `aws iam get-role ... --output text`
        f"{ROLE}\n",
        f'"{ROLE}"',
        f"\u201c{ROLE}\u201d",  # smart quotes from a word processor or chat
        f"\ufeff{ROLE}",  # byte-order mark
        f"{ROLE}, arn:aws:iam::111122223333:user/alice",
    ],
)
def test_valid_values_are_normalised(raw: str) -> None:
    out = na.normalise(raw)
    assert out.startswith(f'["{ROLE}"') and " " not in out and "\n" not in out


@pytest.mark.parametrize(
    ("raw", "fragment"),
    [
        ("", "empty"),
        (f'["{ROLE}"] extra', "not valid JSON"),
        (f"[{ROLE}]", "not valid JSON"),
        (f"APPROVERS={ROLE}", "starts with a letter"),
        (f"{{{ROLE}}}", "starts with the symbol U\\+007B"),
        ("[]", "non-empty JSON list"),
        ('["arn:aws:iam::111122223333:root"]', "item 1"),
        ('["arn:aws:sts::111122223333:assumed-role/AccountFullAccessRole/session"]', "item 1"),
    ],
)
def test_invalid_values_explain_without_echoing(raw: str, fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment) as err:
        na.normalise(raw)
    assert "111122223333" not in str(err.value)


def test_main_exit_codes(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("APPROVERS", f' ["{ROLE}"] ')
    assert na.main() == 0 and capsys.readouterr().out.strip() == f'["{ROLE}"]'
    monkeypatch.setenv("APPROVERS", "nope")
    assert na.main() == 1
    assert "nope" not in capsys.readouterr().err
