#!/usr/bin/env python3
"""Every inline scanner suppression must be justified and registered (docs/cicd-design.md §5).

Finds Checkov skips, Trivy ignores, TFLint ignores, Bandit ``nosec`` and Ruff ``noqa`` for security
rules (S*, BLE*) and checks that each one:
  1. carries a justification of at least 20 characters on the same line;
  2. is listed in policies/exceptions/scanner-exceptions.yaml (tool, rule, path) with an owner and a
     review_by date that is not in the past and at most 180 days ahead;
and that the register lists nothing that no longer exists in the code (no stale entries).

    scripts/check_suppressions.py            # check (CI)
    scripts/check_suppressions.py --list     # print the suppressions found
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "policies" / "exceptions" / "scanner-exceptions.yaml"
SCAN_GLOBS = ("terraform/**/*.tf", "src/**/*.py", "scripts/*.py", "tests/**/*.py", ".github/workflows/*.yml")
PATTERNS = [
    ("checkov", re.compile(r"checkov:skip=(?P<rule>[A-Z0-9_]+):?(?P<why>.*)")),
    ("trivy", re.compile(r"trivy:ignore:(?P<rule>[A-Z0-9-]+)\s*(?P<why>.*)")),
    ("tflint", re.compile(r"tflint-ignore:\s*(?P<rule>[a-z0-9_,]+)\s*(?P<why>.*)")),
    ("bandit", re.compile(r"#\s*nosec\s*(?P<rule>B\d+)?\s*(?P<why>.*)")),
    ("ruff", re.compile(r"noqa:\s*(?P<rule>(?:S|BLE)\d+)[^-]*-?\s*(?P<why>.*)")),
]
MIN_JUSTIFICATION = 20
MAX_REVIEW_DAYS = 180


@dataclass(frozen=True)
class Suppression:
    tool: str
    rule: str
    path: str
    line: int
    why: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.tool, self.rule, self.path)


def find(root: Path = ROOT) -> list[Suppression]:
    found = []
    for pattern in SCAN_GLOBS:
        for path in sorted(root.glob(pattern)):
            if "/.terraform/" in str(path) or path.name == "check_suppressions.py":
                continue
            for number, text in enumerate(path.read_text("utf-8").splitlines(), start=1):
                for tool, regex in PATTERNS:
                    match = regex.search(text)
                    if match:
                        found.append(
                            Suppression(
                                tool,
                                match["rule"] or "all",
                                str(path.relative_to(root)),
                                number,
                                _why(tool, text, match),
                            )
                        )
    return found


def _why(tool: str, text: str, match: re.Match[str]) -> str:
    why = match["why"].split("#", 1)[0].strip()
    if tool == "bandit" and not why:
        # Bandit reads words after "nosec" as test IDs, so the reason is written before the marker.
        before = text[: match.start()]
        why = before.split(" - ", 1)[1].strip(" #") if " - " in before else ""
    return why


def check(root: Path = ROOT, today: date | None = None) -> list[str]:
    today = today or date.today()
    register = yaml.safe_load((root / REGISTER.relative_to(ROOT)).read_text("utf-8")) or {}
    entries = {(e["tool"], e["rule"], e["path"]): e for e in register.get("suppressions", [])}
    errors = []
    found = find(root)
    for s in found:
        if len(s.why) < MIN_JUSTIFICATION:
            errors.append(
                f"{s.path}:{s.line}: {s.tool} {s.rule} needs an inline justification (>= {MIN_JUSTIFICATION} chars)"
            )
        entry = entries.get(s.key)
        if entry is None:
            errors.append(f"{s.path}:{s.line}: {s.tool} {s.rule} is not in {REGISTER.relative_to(ROOT)}")
            continue
        review = date.fromisoformat(str(entry["review_by"]))
        if review < today:
            errors.append(f"{s.path}: {s.tool} {s.rule} review date {review} has passed")
        if review > today + timedelta(days=MAX_REVIEW_DAYS):
            errors.append(f"{s.path}: {s.tool} {s.rule} review date is more than {MAX_REVIEW_DAYS} days ahead")
    used = {s.key for s in found}
    errors += [f"stale register entry {k} (suppression no longer in code)" for k in sorted(set(entries) - used)]
    return errors


def main() -> int:
    if "--list" in sys.argv:
        for s in find():
            print(f"{s.tool}\t{s.rule}\t{s.path}:{s.line}\t{s.why}")
        return 0
    errors = check()
    for e in errors:
        print(f"::error::{e}")
    print(f"{len(find())} suppressions checked, {len(errors)} problem(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
