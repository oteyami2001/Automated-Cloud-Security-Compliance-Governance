"""Generated documentation sections must match their sources."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_embedded_diagrams_are_current() -> None:
    assert load("sync_diagrams").sync(check=True) == []


def test_generated_control_tables_are_current() -> None:
    assert load("render_control_tables").sync(check=True) == []


def test_every_diagram_is_embedded_somewhere() -> None:
    docs = "".join(p.read_text("utf-8") for p in [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")])
    for diagram in (ROOT / "diagrams").glob("*.mmd"):
        assert f"<!-- diagram:{diagram.stem} -->" in docs, diagram.name


def test_docs_do_not_contain_account_ids() -> None:
    """Public repository: no 12-digit AWS account IDs in documentation (prompt section 10)."""
    pattern = re.compile(r"(?<![\d.])\d{12}(?![\d.])")
    for path in [ROOT / "README.md", *(ROOT / "docs").rglob("*.md"), *(ROOT / "controls").rglob("*.yaml")]:
        assert not pattern.search(path.read_text("utf-8")), path
