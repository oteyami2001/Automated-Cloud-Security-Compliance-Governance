#!/usr/bin/env python3
"""Validate the APPROVERS secret and print it as compact JSON for TF_VAR_approvers.

Accepted forms (surrounding whitespace, line breaks and stray quote marks are removed):
  arn:aws:iam::123456789012:role/Name                    one plain ARN (simplest to paste)
  arn:aws:iam::...:role/A, arn:aws:iam::...:user/b       several, comma- or space-separated
  ["arn:aws:iam::123456789012:role/Name"]                a JSON list On any problem the
script exits 1 with a message that never contains the value itself (it is a secret in CI logs).
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

ARN = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:(role|user)/[\w+=,.@/-]{1,512}$")


QUOTES = "\"'\u201c\u201d\u2018\u2019`"
INVISIBLE = "\ufeff\u200b\u200c\u200d\u00a0"


def _describe(ch: str) -> str:
    """Say what kind of character something starts with, without revealing the value."""
    if ch.isalpha():
        return "a letter"
    if ch.isdigit():
        return "a digit"
    return f"the symbol U+{ord(ch):04X}"


def normalise(raw: str) -> str:
    text = raw.translate({ord(c): None for c in INVISIBLE}).strip().strip(QUOTES).strip()
    if not text:
        raise ValueError("APPROVERS is empty")
    if text.startswith("arn:"):
        value: Any = [part.strip().strip(QUOTES) for part in text.replace(",", " ").split()]
        return _validated(value)
    if not text.startswith("["):
        raise ValueError(
            f"APPROVERS must be an IAM ARN or a JSON list; it starts with {_describe(text[0])} ({len(text)} characters)"
        )
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"APPROVERS is not valid JSON ({exc.msg} at character {exc.pos} of {len(text)})") from None
    return _validated(value)


def _validated(value: Any) -> str:
    if not isinstance(value, list) or not value:
        raise ValueError('APPROVERS must be a non-empty JSON list, e.g. ["arn:aws:iam::<account>:role/<name>"]')
    for i, item in enumerate(value, start=1):
        if not isinstance(item, str) or not ARN.fullmatch(item.strip()):
            raise ValueError(
                f"item {i} of APPROVERS is not an IAM role or user ARN (root and STS session ARNs are not allowed)"
            )
    return json.dumps([item.strip() for item in value], separators=(",", ":"))


def main() -> int:
    try:
        print(normalise(os.environ.get("APPROVERS", "")))
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
