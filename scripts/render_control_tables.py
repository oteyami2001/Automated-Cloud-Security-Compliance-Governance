#!/usr/bin/env python3
"""Render Markdown tables from controls/control-catalog.yaml into docs between markers.

    <!-- generated:control-summary --> ... <!-- /generated -->
    <!-- generated:framework-matrix --> ... <!-- /generated -->

Usage: scripts/render_control_tables.py [--check]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BLOCK = re.compile(r"(<!-- generated:(?P<name>[a-z-]+) -->\n)(?P<body>.*?)(<!-- /generated -->)", re.DOTALL)
ELIGIBILITY = {
    "report_only": "Report only",
    "auto_low_risk": "Mode 2 (auto, allowlisted)",
    "human_approval": "Mode 3 (human approval)",
    "escalate": "Escalate (never remediated)",
}


def cell(values: list[str]) -> str:
    return ", ".join(values) if values else "—"


def control_summary(controls: list[dict]) -> str:
    rows = [
        "| ID | Control | Severity | Detection | Remediation | Approval | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in controls:
        detection = c["detection"]
        how = cell(detection.get("config_managed_rules", [])) if detection.get("config_managed_rules") else ""
        if detection["method"] in {"hybrid", "cloudtrail_eventbridge"}:
            how = (how + " + " if how else "") + "CloudTrail→EventBridge"
        rows.append(
            f"| {c['id']} | {c['title']} | {c['severity']} | {detection['method']}: {how} | "
            f"{ELIGIBILITY[c['remediation']['eligibility']]} | {'required' if c['approval']['required'] else 'no'} | "
            f"{c['implementation_status']} |"
        )
    return "\n".join(rows) + "\n"


def framework_matrix(controls: list[dict]) -> str:
    rows = [
        "| ID | NIST SP 800-53 r5 | CIS v5.0.0 | CIS v6.0.0 | PCI DSS v4.0.1 | SOC 2 TSC | Relationship |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in controls:
        f = c["frameworks"]
        rows.append(
            f"| {c['id']} | {cell(f['nist_800_53_r5'])} | {cell(f['cis_aws_v5_0_0'])} | {cell(f['cis_aws_v6_0_0'])} | "
            f"{cell(f['pci_dss_v4_0_1'])} | {cell(f['soc2_tsc_2017'])} | {c['mapping_relationship']} |"
        )
    return "\n".join(rows) + "\n"


RENDERERS = {"control-summary": control_summary, "framework-matrix": framework_matrix}


def render(text: str, controls: list[dict]) -> str:
    return BLOCK.sub(lambda m: f"{m.group(1)}{RENDERERS[m['name']](controls)}{m.group(4)}", text)


def sync(root: Path = ROOT, check: bool = False) -> list[Path]:
    controls = yaml.safe_load((root / "controls" / "control-catalog.yaml").read_text("utf-8"))["controls"]
    stale = []
    for doc in sorted([root / "README.md", *(root / "docs").rglob("*.md")]):
        if not doc.exists():
            continue
        text = doc.read_text("utf-8")
        new = render(text, controls)
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
