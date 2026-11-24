"""Platform policy: remediation mode, approvers, exact-ARN allowlist, inventory and protected resources.

Terraform renders this document (from ``policies/remediation/*.yaml`` and module outputs) into an
SSM parameter that only the Terraform apply role can write. Both Lambdas read it; neither trusts
event content for authorization (ADR 0006). Parsing is strict: any invalid field raises
:class:`PolicyError`, and callers treat that as "deny everything".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from acscg.common.canonical import parse_time
from acscg.remediation_engine.actions import ACTIONS, action_for

MODES = ("report_only", "auto_low_risk", "human_approval")
ARN = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:[^*?]+$")
ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:(role|user)/[\w+=,.@/-]+$")
MAX_TIMEOUT_MINUTES = 24 * 60


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class AllowlistEntry:
    entry_id: str
    control_id: str
    action: str
    account: str
    region: str
    resource_arn: str
    expires_at: datetime
    reason: str
    parameters: tuple[tuple[str, str], ...] = ()  # e.g. tag values to add for SEC-013

    def matches(self, *, control_id: str, action: str, account: str, region: str, resource_arn: str) -> bool:
        return (
            self.control_id == control_id
            and self.action == action
            and self.account == account
            and self.region == region
            and self.resource_arn == resource_arn
        )


@dataclass(frozen=True)
class PlatformPolicy:
    environment: str
    remediation_enabled: bool = False
    remediation_mode: str = "report_only"
    approvers: tuple[str, ...] = ()
    timeout_minutes: int = 240
    max_attempts_per_finding: int = 2
    allowlist: tuple[AllowlistEntry, ...] = ()
    protected_resources: frozenset[str] = frozenset()
    project_inventory: frozenset[str] = frozenset()
    approved_change_principals: frozenset[str] = frozenset()
    project_role_arns: frozenset[str] = frozenset()
    extra: dict[str, Any] = field(default_factory=dict)

    def find_entry(self, **kwargs: str) -> AllowlistEntry | None:
        for entry in self.allowlist:
            if entry.matches(**kwargs):
                return entry
        return None


def _require(data: dict[str, Any], name: str, kind: type) -> Any:
    if name not in data:
        raise PolicyError(f"missing {name}")
    value = data[name]
    if kind is int and isinstance(value, bool):
        raise PolicyError(f"{name} must be {kind.__name__}")
    if not isinstance(value, kind):
        raise PolicyError(f"{name} must be {kind.__name__}")
    return value


def _entry(raw: dict[str, Any]) -> AllowlistEntry:
    for key in ("id", "control_id", "action", "account", "region", "resource_arn", "expires_at", "reason"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise PolicyError(f"allowlist entry field {key} is required")
    if not re.fullmatch(r"\d{12}", raw["account"]):
        raise PolicyError(f"allowlist {raw['id']}: account must be 12 digits")
    if not ARN.match(raw["resource_arn"]):
        raise PolicyError(f"allowlist {raw['id']}: resource_arn must be an exact ARN without wildcards")
    action = action_for(raw["control_id"])
    if action is None or action.action != raw["action"]:
        raise PolicyError(f"allowlist {raw['id']}: action {raw['action']} is not permitted for {raw['control_id']}")
    try:
        expires = parse_time(raw["expires_at"])
    except ValueError as exc:
        raise PolicyError(f"allowlist {raw['id']}: invalid expires_at") from exc
    return AllowlistEntry(
        raw["id"],
        raw["control_id"],
        raw["action"],
        raw["account"],
        raw["region"],
        raw["resource_arn"],
        expires,
        raw["reason"],
        _parameters(raw),
    )


def _parameters(raw: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    params = raw.get("parameters", {}) or {}
    if not isinstance(params, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in params.items()):
        raise PolicyError(f"allowlist {raw['id']}: parameters must map strings to strings")
    return tuple(sorted(params.items()))


def parse_policy(document: str | dict[str, Any]) -> PlatformPolicy:
    data = json.loads(document) if isinstance(document, str) else document
    if not isinstance(data, dict):
        raise PolicyError("policy must be an object")
    environment = _require(data, "environment", str)
    enabled = _require(data, "remediation_enabled", bool)
    mode = _require(data, "remediation_mode", str)
    if mode not in MODES:
        raise PolicyError(f"remediation_mode must be one of {MODES}")
    if environment == "prod" and enabled:
        raise PolicyError("remediation cannot be enabled in prod")
    approval = data.get("approval", {})
    approvers = tuple(approval.get("approvers", []))
    for arn in approvers:
        if not ROLE_ARN.match(arn):
            raise PolicyError(f"approver {arn!r} is not an IAM role/user ARN")
    project_roles = frozenset(data.get("project_role_arns", []))
    if set(approvers) & project_roles:
        raise PolicyError("an automation or CI role cannot be an approver (separation of duties)")
    timeout = int(approval.get("timeout_minutes", 240))
    if not 1 <= timeout <= MAX_TIMEOUT_MINUTES:
        raise PolicyError("approval timeout must be between 1 and 1440 minutes")
    attempts = int(data.get("limits", {}).get("max_attempts_per_finding", 2))
    if not 1 <= attempts <= 3:
        raise PolicyError("max_attempts_per_finding must be 1..3")
    entries = tuple(_entry(e) for e in data.get("allowlist", []))
    ids = [e.entry_id for e in entries]
    if len(ids) != len(set(ids)):
        raise PolicyError("duplicate allowlist ids")
    if enabled and mode == "human_approval" and not approvers:
        raise PolicyError("human_approval mode needs at least one approver")
    return PlatformPolicy(
        environment=environment,
        remediation_enabled=enabled,
        remediation_mode=mode,
        approvers=approvers,
        timeout_minutes=timeout,
        max_attempts_per_finding=attempts,
        allowlist=entries,
        protected_resources=frozenset(data.get("protected_resources", [])),
        project_inventory=frozenset(data.get("project_inventory", [])),
        approved_change_principals=frozenset(data.get("approved_change_principals", [])),
        project_role_arns=project_roles,
    )


def supported_actions() -> list[str]:
    return sorted({a.action for a in ACTIONS})
