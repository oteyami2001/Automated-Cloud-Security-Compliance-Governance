"""Evidence documents with every field required by the project brief (section 12).

Integrity: ``checksum.sha256`` is computed over the canonical JSON of the document *without* the
checksum block. The same value is stored as S3 object metadata and in DynamoDB, and listed in the
daily manifest, so later modification is detectable (tamper-evident, ADR 0007).
"""

from __future__ import annotations

import re
from typing import Any

from acscg.common.canonical import canonical_json, sha256_hex

SCHEMA_VERSION = "1.0"

REQUIRED_FIELDS = (
    "finding_id",
    "control_id",
    "resource",
    "detection_timestamp",
    "previous_compliance_state",
    "proposed_remediation",
    "approval",
    "execution_result",
    "updated_compliance_state",
    "verification_timestamp",
    "checksum",
)

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def build_evidence(  # noqa: PLR0913 - keyword-only, one argument per required evidence field
    *,
    kind: str,
    finding: dict[str, Any],
    recorded_at: str,
    previous_compliance_state: str | None,
    updated_compliance_state: str | None,
    lifecycle_from: str | None,
    lifecycle_to: str,
    proposed_remediation: dict[str, Any] | None = None,
    approval: dict[str, Any] | None = None,
    execution_result: dict[str, Any] | None = None,
    verification_timestamp: str | None = None,
    decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "recorded_at": recorded_at,
        "finding_id": finding["finding_key"],
        "control_id": finding["control_id"],
        "severity": finding.get("severity"),
        "source": finding.get("source"),
        "source_event_id": finding.get("last_event_id"),
        "resource": {
            "type": finding["resource_type"],
            "id": finding["resource_id"],
            "identifier": finding["resource_identifier"],
            "account": finding["account"],
            "region": finding["region"],
        },
        "detection_timestamp": finding.get("first_seen"),
        "previous_compliance_state": previous_compliance_state,
        "lifecycle": {"from": lifecycle_from, "to": lifecycle_to},
        "proposed_remediation": proposed_remediation,
        "approval": approval or {"required": False, "identity": None, "decision": None, "timestamp": None},
        "execution_result": execution_result,
        "updated_compliance_state": updated_compliance_state,
        "verification_timestamp": verification_timestamp,
        "decision": decision,
        "synthetic": bool(finding.get("synthetic")),
    }
    body["checksum"] = {"algorithm": "SHA-256", "sha256": sha256_hex(canonical_json(body))}
    return body


def verify_checksum(document: dict[str, Any]) -> bool:
    body = {k: v for k, v in document.items() if k != "checksum"}
    expected = document.get("checksum", {}).get("sha256")
    return bool(expected) and sha256_hex(canonical_json(body)) == expected


def evidence_key(document: dict[str, Any]) -> str:
    stamp = _SAFE.sub("-", document["recorded_at"])
    return f"evidence/{document['control_id']}/{document['finding_id']}/{stamp}-{_SAFE.sub('-', document['kind'])}.json"


def build_manifest(entries: list[tuple[str, str]], generated_at: str) -> dict[str, Any]:
    """Daily manifest of (key, sha256) pairs; its own digest is published in the report."""
    items = [{"key": k, "sha256": h} for k, h in sorted(entries)]
    body = {"generated_at": generated_at, "count": len(items), "objects": items}
    body["manifest_sha256"] = sha256_hex(canonical_json({"objects": items}))
    return body
