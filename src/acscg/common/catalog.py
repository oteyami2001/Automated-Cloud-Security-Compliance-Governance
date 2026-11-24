"""Read-only access to the control catalog.

At runtime the catalog is packaged as JSON (``acscg/data/control-catalog.json``, generated from
``controls/control-catalog.yaml`` by ``scripts/build_lambda.py``) because PyYAML is not part of the
Lambda runtime. Tests may pass the parsed YAML directly.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from acscg.common.models import Severity

RULE_NAME = re.compile(r"^acscg-(?P<control>sec\d{3})-[a-z0-9-]+$")

# Controls that do not come from the catalog but from optional threat-detection sources.
EXTERNAL_CONTROLS = {
    "EXT-GUARDDUTY": {"title": "GuardDuty threat finding", "severity": "medium"},
    "EXT-SECURITYHUB": {"title": "Security Hub CSPM finding", "severity": "medium"},
}


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    severity: Severity
    eligibility: str
    approval_required: bool
    resource_types: tuple[str, ...]
    securityhub_controls: tuple[str, ...]
    domain: str
    raw: dict[str, Any]

    @property
    def remediable(self) -> bool:
        return self.eligibility in {"auto_low_risk", "human_approval"}


class Catalog:
    def __init__(self, data: dict[str, Any]) -> None:
        self._controls: dict[str, Control] = {}
        for item in data["controls"]:
            detection = item.get("detection", {})
            self._controls[item["id"]] = Control(
                control_id=item["id"],
                title=item["title"],
                severity=Severity.parse(item["severity"]),
                eligibility=item["remediation"]["eligibility"],
                approval_required=bool(item["approval"]["required"]),
                resource_types=tuple(item["resource_types"]),
                securityhub_controls=tuple(detection.get("securityhub_controls", [])),
                domain=item["domain"],
                raw=item,
            )
        for control_id, meta in EXTERNAL_CONTROLS.items():
            self._controls[control_id] = Control(
                control_id=control_id,
                title=meta["title"],
                severity=Severity.parse(meta["severity"]),
                eligibility="report_only",
                approval_required=False,
                resource_types=(),
                securityhub_controls=(),
                domain="threat-detection",
                raw={},
            )
        self.default_mode: str = data.get("catalog", {}).get("defaults", {}).get("remediation_mode", "report_only")
        self.required_tags: tuple[str, ...] = tuple(
            data.get("catalog", {}).get("defaults", {}).get("required_tags", [])
        )

    @classmethod
    def load_packaged(cls) -> Catalog:
        text = resources.files("acscg.data").joinpath("control-catalog.json").read_text("utf-8")
        return cls(json.loads(text))

    @classmethod
    def load_file(cls, path: Path) -> Catalog:
        text = path.read_text("utf-8")
        if path.suffix in {".yaml", ".yml"}:
            import yaml  # noqa: PLC0415 - dev/test only dependency

            return cls(yaml.safe_load(text))
        return cls(json.loads(text))

    def get(self, control_id: str) -> Control:
        try:
            return self._controls[control_id]
        except KeyError as exc:
            raise KeyError(f"unknown control {control_id}") from exc

    def __contains__(self, control_id: object) -> bool:
        return control_id in self._controls

    def catalog_controls(self) -> list[Control]:
        return [c for c in self._controls.values() if c.control_id.startswith("SEC-")]

    def control_for_rule(self, rule_name: str) -> str | None:
        """Map ``acscg-sec005-restricted-ssh`` to ``SEC-005``. Other rules are not ours."""
        match = RULE_NAME.match(rule_name)
        if not match:
            return None
        control_id = match["control"].upper().replace("SEC", "SEC-")
        return control_id if control_id in self._controls else None

    def control_for_securityhub(self, security_control_id: str) -> str | None:
        for control in self.catalog_controls():
            if security_control_id in control.securityhub_controls:
                return control.control_id
        return None
