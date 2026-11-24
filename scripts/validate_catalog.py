#!/usr/bin/env python3
"""Validate the control catalog and its framework mappings (offline, no AWS access).

Checks:
  1. controls/control-catalog.yaml matches controls/schema/control-catalog.schema.json.
  2. Control IDs are unique and contiguous (SEC-001..SEC-NNN).
  3. Every mapped framework requirement ID exists in the matching framework reference file,
     and every requirement in a reference file is used by at least one control.
  4. Each reference file's `mapped_by` list matches the catalog exactly (no stale back-links).
  5. Safety invariants that the schema cannot express:
     - the catalog default remediation mode is report_only;
     - controls on audit services (CloudTrail, Config) are never auto-remediated;
     - no control is marked verified-in-aws (nothing is deployed in Phase 1).

Exit code 0 when valid; 1 with a list of errors otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
CONTROLS = ROOT / "controls"

FRAMEWORK_FILES = {
    "nist_800_53_r5": "nist-800-53.yaml",
    "cis_aws_v5_0_0": "cis-aws-v5.yaml",
    "cis_aws_v6_0_0": "cis-aws-v6.yaml",
    "pci_dss_v4_0_1": "pci-dss.yaml",
    "soc2_tsc_2017": "soc2.yaml",
}

AUDIT_RESOURCE_TYPES = {"AWS::CloudTrail::Trail", "AWS::Config::ConfigurationRecorder"}


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def check_schema(catalog: dict, schema: dict) -> list[str]:
    errors = []
    for err in sorted(Draft202012Validator(schema).iter_errors(catalog), key=lambda e: list(e.path)):
        location = "/".join(str(p) for p in err.path) or "<root>"
        errors.append(f"schema: {location}: {err.message}")
    return errors


def check_ids(controls: list[dict]) -> list[str]:
    errors = []
    ids = [c["id"] for c in controls]
    if len(ids) != len(set(ids)):
        errors.append(f"duplicate control IDs: {sorted({i for i in ids if ids.count(i) > 1})}")
    if ids != [f"SEC-{n:03d}" for n in range(1, len(ids) + 1)]:
        errors.append(f"control IDs must be contiguous and ordered: got {ids}")
    return errors


def mapped_requirements(controls: list[dict]) -> dict[str, dict[str, set[str]]]:
    used: dict[str, dict[str, set[str]]] = {key: {} for key in FRAMEWORK_FILES}
    for control in controls:
        for key, req_ids in control["frameworks"].items():
            for req_id in req_ids:
                used[key].setdefault(req_id, set()).add(control["id"])
    return used


def check_framework_file(path: Path, key: str, used: dict[str, set[str]]) -> list[str]:
    filename = path.name
    if not path.exists():
        return [f"{filename}: missing framework reference file"]
    errors = []
    ref = load_yaml(path)
    fw = ref.get("framework", {})
    if fw.get("key") != key:
        errors.append(f"{filename}: framework.key is {fw.get('key')!r}, expected {key!r}")
    errors += [
        f"{filename}: framework.{field} is required (record version and source)"
        for field in ("name", "version", "sources")
        if not fw.get(field)
    ]
    known: dict[str, dict] = {}
    for req in ref.get("requirements", []):
        if req["id"] in known:
            errors.append(f"{filename}: duplicate requirement {req['id']}")
        known[req["id"]] = req
        errors += [
            f"{filename}: {req['id']} has no {field}" for field in ("title", "verification") if not req.get(field)
        ]
    for req_id, by in sorted(used.items()):
        if req_id not in known:
            errors.append(f"{filename}: {req_id} is mapped by {sorted(by)} but not defined")
        elif set(known[req_id].get("mapped_by", [])) != by:
            errors.append(
                f"{filename}: {req_id}.mapped_by is {known[req_id].get('mapped_by')}, catalog says {sorted(by)}"
            )
    errors += [
        f"{filename}: {req_id} is defined but no control maps to it" for req_id in sorted(set(known) - set(used))
    ]
    return errors


def check_safety_invariants(catalog: dict) -> list[str]:
    errors = []
    if catalog["catalog"]["defaults"]["remediation_mode"] != "report_only":
        errors.append("catalog default remediation_mode must be report_only")
    for control in catalog["controls"]:
        eligibility = control["remediation"]["eligibility"]
        if AUDIT_RESOURCE_TYPES & set(control["resource_types"]) and eligibility in {"auto_low_risk", "human_approval"}:
            errors.append(f"{control['id']}: audit services must never be remediated by the platform")
        if control["implementation_status"] == "verified-in-aws":
            errors.append(f"{control['id']}: verified-in-aws requires recorded AWS evidence (none exists yet)")
    return errors


def validate(root: Path = ROOT) -> list[str]:
    controls_dir = root / "controls"
    catalog = load_yaml(controls_dir / "control-catalog.yaml")
    schema = json.loads((controls_dir / "schema" / "control-catalog.schema.json").read_text("utf-8"))
    errors = check_schema(catalog, schema)
    if errors:
        return errors  # later checks assume a structurally valid catalog
    errors += check_ids(catalog["controls"])
    used = mapped_requirements(catalog["controls"])
    for key, filename in FRAMEWORK_FILES.items():
        errors += check_framework_file(controls_dir / filename, key, used[key])
    return errors + check_safety_invariants(catalog)


def main() -> int:
    errors = validate()
    if errors:
        print(f"Control catalog INVALID ({len(errors)} error(s)):")
        for line in errors:
            print(f"  - {line}")
        return 1
    catalog = load_yaml(CONTROLS / "control-catalog.yaml")
    print(f"Control catalog valid: {len(catalog['controls'])} controls, {len(FRAMEWORK_FILES)} framework files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
