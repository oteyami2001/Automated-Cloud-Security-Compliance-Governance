"""Build posture reports from findings. Every number is computed from stored findings; nothing is illustrative.

Synthetic and sample findings are excluded from posture metrics and counted separately, so a
demonstration never inflates or deflates the score.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Any

from acscg import __version__
from acscg.common.catalog import Catalog
from acscg.common.log import mask
from acscg.common.models import FindingState, Severity

S = FindingState
REMEDIATED = {S.VERIFIED_RESOLVED}
DISCLAIMER = (
    "Framework-aligned technical control results. Not a certification, attestation or statement of "
    "compliance with NIST SP 800-53, CIS, PCI DSS or SOC 2."
)


def _state(item: dict[str, Any]) -> S | None:
    try:
        return S(item.get("state"))
    except ValueError:
        return None


def build_report(
    findings: list[dict[str, Any]], catalog: Catalog, *, environment: str, generated_at: str
) -> dict[str, Any]:
    real = [f for f in findings if not f.get("synthetic") and not f.get("sample")]
    excluded = len(findings) - len(real)
    per_control: dict[str, Counter[str]] = defaultdict(Counter)
    open_by_severity: Counter[str] = Counter()
    open_items = []
    for item in real:
        state = _state(item)
        if state is None:
            continue
        counter = per_control[item["control_id"]]
        counter["evaluated"] += 1
        if state.is_open:
            counter["open"] += 1
            open_by_severity[item.get("severity", "medium")] += 1
            open_items.append(item)
        else:
            counter["passing"] += 1
        if state in REMEDIATED:
            counter["remediated"] += 1
        if state == S.SUPPRESSED_EXCEPTION:
            counter["excepted"] += 1

    controls = []
    domains: dict[str, Counter[str]] = defaultdict(Counter)
    for control in catalog.catalog_controls():
        counts = per_control.get(control.control_id, Counter())
        evaluated = counts["evaluated"]
        score = round(100 * counts["passing"] / evaluated, 1) if evaluated else None
        controls.append(
            {
                "control_id": control.control_id,
                "title": control.title,
                "domain": control.domain,
                "severity": control.severity.label,
                "evaluated": evaluated,
                "passing": counts["passing"],
                "open": counts["open"],
                "remediated": counts["remediated"],
                "excepted": counts["excepted"],
                "score": score,
                "frameworks": control.raw.get("frameworks", {}),
            }
        )
        domains[control.domain]["evaluated"] += evaluated
        domains[control.domain]["passing"] += counts["passing"]

    total_evaluated = sum(c["evaluated"] for c in controls)
    total_passing = sum(c["passing"] for c in controls)
    severity_order = [s.label for s in sorted(Severity, reverse=True)]
    return {
        "report_version": "1.0",
        "generator": f"acscg {__version__}",
        "environment": environment,
        "generated_at": generated_at,
        "disclaimer": DISCLAIMER,
        "summary": {
            "compliance_score": round(100 * total_passing / total_evaluated, 1) if total_evaluated else None,
            "resources_evaluated": total_evaluated,
            "open_findings": len(open_items),
            "remediated_findings": sum(c["remediated"] for c in controls),
            "open_by_severity": {s: open_by_severity.get(s, 0) for s in severity_order},
            "external_open_findings": sum(1 for f in open_items if not str(f["control_id"]).startswith("SEC-")),
            "excluded_synthetic_or_sample": excluded,
        },
        "domains": {
            d: {
                "evaluated": c["evaluated"],
                "score": round(100 * c["passing"] / c["evaluated"], 1) if c["evaluated"] else None,
            }
            for d, c in sorted(domains.items())
        },
        "controls": controls,
        "open_findings": [
            {
                "finding_key": f["finding_key"],
                "control_id": f["control_id"],
                "severity": f.get("severity"),
                "state": f.get("state"),
                "resource_type": f.get("resource_type"),
                "resource_id": f.get("resource_id"),
                "first_seen": f.get("first_seen"),
            }
            for f in sorted(
                open_items, key=lambda x: (-Severity.parse(x.get("severity", "medium")).value, x["control_id"])
            )
        ],
    }


def _short(value: str) -> str:
    return "res-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def render_markdown(report: dict[str, Any], *, public: bool = True) -> str:
    """Human-readable report. ``public=True`` hides resource IDs and masks identifiers."""
    summary = report["summary"]
    score = summary["compliance_score"]
    lines = [
        f"# ACSCG compliance report ({report['environment']})",
        "",
        f"Generated {report['generated_at']} by {report['generator']}.",
        "",
        f"> {report['disclaimer']}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Compliance score | {'n/a' if score is None else f'{score}%'} |",
        f"| Resources evaluated | {summary['resources_evaluated']} |",
        f"| Open findings | {summary['open_findings']} |",
        f"| Remediated (verified) | {summary['remediated_findings']} |",
        f"| Excluded synthetic/sample findings | {summary['excluded_synthetic_or_sample']} |",
        "",
        "## Open findings by severity",
        "",
        "| " + " | ".join(summary["open_by_severity"]) + " |",
        "|" + "---|" * len(summary["open_by_severity"]),
        "| " + " | ".join(str(v) for v in summary["open_by_severity"].values()) + " |",
        "",
        "## Controls",
        "",
        "| Control | Title | Evaluated | Passing | Open | Remediated | Score |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in report["controls"]:
        score_text = "n/a" if c["score"] is None else f"{c['score']}%"
        lines.append(
            f"| {c['control_id']} | {c['title']} | {c['evaluated']} | {c['passing']} | {c['open']} | "
            f"{c['remediated']} | {score_text} |"
        )
    lines += ["", "## Open findings", ""]
    if not report["open_findings"]:
        lines.append("None.")
    else:
        lines += ["| Control | Severity | State | Resource type | Resource |", "|---|---|---|---|---|"]
        for f in report["open_findings"]:
            resource = _short(f"{f['resource_type']}/{f['resource_id']}") if public else f["resource_id"]
            lines.append(f"| {f['control_id']} | {f['severity']} | {f['state']} | {f['resource_type']} | {resource} |")
    text = "\n".join(lines) + "\n"
    return mask(text) if public else text
