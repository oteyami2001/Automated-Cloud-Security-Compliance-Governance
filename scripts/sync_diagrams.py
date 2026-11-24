#!/usr/bin/env python3
"""Embed diagrams/<name>.mmd into Markdown files between diagram markers.

    <!-- diagram:<name> -->
    ```mermaid
    ...contents of diagrams/<name>.mmd...
    ```
    <!-- /diagram -->

Usage:
    scripts/sync_diagrams.py          # rewrite docs in place
    scripts/sync_diagrams.py --check  # exit 1 if any embedded diagram is stale (used by CI and tests)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BLOCK = re.compile(r"(<!-- diagram:(?P<name>[a-z0-9-]+) -->\n)(?P<body>.*?)(<!-- /diagram -->)", re.DOTALL)


def render(text: str, diagrams: Path) -> str:
    def replace(match: re.Match[str]) -> str:
        source = (diagrams / f"{match['name']}.mmd").read_text("utf-8").rstrip("\n")
        return f"{match.group(1)}```mermaid\n{source}\n```\n{match.group(4)}"

    return BLOCK.sub(replace, text)


def sync(root: Path = ROOT, check: bool = False) -> list[Path]:
    stale = []
    for doc in sorted([root / "README.md", *(root / "docs").rglob("*.md")]):
        if not doc.exists():
            continue
        text = doc.read_text("utf-8")
        new = render(text, root / "diagrams")
        if new != text:
            stale.append(doc)
            if not check:
                doc.write_text(new, "utf-8")
    return stale


def main() -> int:
    check = "--check" in sys.argv[1:]
    stale = sync(check=check)
    for path in stale:
        print(f"{'stale' if check else 'updated'}: {path.relative_to(ROOT)}")
    return 1 if check and stale else 0


if __name__ == "__main__":
    sys.exit(main())
