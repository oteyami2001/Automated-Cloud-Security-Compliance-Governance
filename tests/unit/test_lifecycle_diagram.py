"""The lifecycle diagram must show exactly the transitions the code allows."""

from __future__ import annotations

import re

from conftest import ROOT

from acscg.findings_processor.lifecycle import TRANSITIONS

EDGE = re.compile(r"^\s*(\[\*\]|[A-Z_]+)\s*-->\s*(\[\*\]|[A-Z_]+)")


def test_diagram_matches_transition_table() -> None:
    text = (ROOT / "diagrams" / "remediation-flow.mmd").read_text("utf-8")
    edges = {m.groups() for line in text.splitlines() if (m := EDGE.match(line))}
    drawn = {(None if a == "[*]" else a, b) for a, b in edges if b != "[*]"}
    allowed = {(None if a is None else str(a), str(b)) for a, targets in TRANSITIONS.items() for b in targets}
    assert drawn == allowed
