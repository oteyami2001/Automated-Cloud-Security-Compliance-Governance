"""Lambda entry point for the remediation gatekeeper (invoked asynchronously with a finding key)."""

from __future__ import annotations

import re
from typing import Any

from acscg.common.settings import Settings
from acscg.remediation_engine.service import Gatekeeper, build_gatekeeper

KEY = re.compile(r"^[0-9a-f]{64}$")
_GATEKEEPER: Gatekeeper | None = None


def handle(event: dict[str, Any], gatekeeper: Gatekeeper) -> dict[str, Any]:
    key = event.get("finding_key") if isinstance(event, dict) else None
    if not isinstance(key, str) or not KEY.match(key):
        return {"allowed": False, "reasons": ["invalid request"]}
    return gatekeeper.handle(key)


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:  # pragma: no cover - thin wrapper
    global _GATEKEEPER  # noqa: PLW0603
    if _GATEKEEPER is None:
        _GATEKEEPER = build_gatekeeper(Settings.from_env())
    return handle(event, _GATEKEEPER)
