"""Remediation authorization decision (docs/security-model.md §4).

:func:`decide` is a pure function: given the finding, catalog control, platform policy, runtime
settings, live check and lock/attempt facts, it returns a :class:`Decision` with every reason it
denied. Anything unexpected denies (fail closed). Tags are never an input.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from acscg.common.catalog import Control
from acscg.common.models import FindingState, Ownership
from acscg.common.settings import Settings
from acscg.remediation_engine.actions import RemediationAction, action_for
from acscg.remediation_engine.policy import AllowlistEntry, PlatformPolicy

ELIGIBLE_STATES = {
    FindingState.OPEN,
    FindingState.REJECTED_POLICY,
    FindingState.APPROVAL_EXPIRED,
    FindingState.REMEDIATION_FAILED,
}


@dataclass(frozen=True)
class LiveCheck:
    """Result of re-reading the resource right now (never the event payload)."""

    violation_present: bool
    account: str
    region: str
    resource_arn: str
    parameters: dict[str, Any] = field(default_factory=dict)  # e.g. the exact rule id to revoke
    needs_approval: bool = False  # e.g. log retention would delete existing data
    note: str = ""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    mode: str | None  # "auto_low_risk" | "human_approval"
    reasons: tuple[str, ...]
    action: RemediationAction | None = None
    entry: AllowlistEntry | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "mode": self.mode,
            "reasons": list(self.reasons),
            "action": self.action.action if self.action else None,
            "document": self.action.document if self.action else None,
            "allowlist_entry": self.entry.entry_id if self.entry else None,
        }


def _mode(control: Control, action: RemediationAction, policy: PlatformPolicy, live: LiveCheck | None) -> str:
    """Mode 2 only for auto-eligible controls in auto mode without an approval trigger; else Mode 3."""
    needs_approval = (
        control.eligibility == "human_approval"
        or action.always_requires_approval
        or policy.remediation_mode == "human_approval"
        or (live is not None and live.needs_approval)
    )
    return "human_approval" if needs_approval else "auto_low_risk"


def _environment_reasons(settings: Settings, policy: PlatformPolicy) -> list[str]:
    reasons = []
    if not settings.remediation_enabled or not policy.remediation_enabled:
        reasons.append("remediation is disabled for this environment")
    if settings.remediation_mode == "report_only" or policy.remediation_mode == "report_only":
        reasons.append("environment is in report-only mode")
    return reasons


def _finding_reasons(
    finding: dict[str, Any], control: Control, policy: PlatformPolicy, attempts: int, lock_available: bool
) -> list[str]:
    reasons = []
    if not control.remediable or action_for(control.control_id) is None:
        reasons.append(f"control {control.control_id} is not eligible for remediation ({control.eligibility})")
    if finding.get("synthetic") or finding.get("sample"):
        reasons.append("synthetic or sample findings are never remediated")
    try:
        state: FindingState | None = FindingState(finding.get("state"))
    except ValueError:
        state = None
    if state not in ELIGIBLE_STATES:
        reasons.append(f"finding state {state} is not eligible")
    if finding.get("ownership") != str(Ownership.PROJECT_OWNED):
        reasons.append(f"resource is not project-owned ({finding.get('ownership')})")
    if finding.get("resource_identifier") in policy.protected_resources:
        reasons.append("resource is on the protected list")
    if attempts >= policy.max_attempts_per_finding:
        reasons.append(f"attempt limit reached ({attempts}/{policy.max_attempts_per_finding})")
    if not lock_available:
        reasons.append("another remediation for this finding is active")
    return reasons


def _allowlist_reasons(
    finding: dict[str, Any], action: RemediationAction | None, policy: PlatformPolicy, settings: Settings, now: datetime
) -> tuple[list[str], AllowlistEntry | None]:
    if action is None:
        return [], None
    entry = policy.find_entry(
        control_id=action_control(finding, action),
        action=action.action,
        account=str(finding.get("account")),
        region=str(finding.get("region")),
        resource_arn=str(finding.get("resource_identifier")),
    )
    if entry is None:
        return ["no allowlist entry matches account, region, resource ARN, control and action"], None
    reasons = []
    if entry.expires_at <= now:
        reasons.append(f"allowlist entry {entry.entry_id} expired")
    if entry.account != settings.account_id or entry.region != settings.region:
        reasons.append("allowlist entry is for a different account or region than this deployment")
    return reasons, entry


def action_control(finding: dict[str, Any], action: RemediationAction) -> str:
    control_id = str(finding.get("control_id"))
    return control_id if control_id in action.control_ids else action.control_ids[0]


def _live_reasons(finding: dict[str, Any], live: LiveCheck | None, settings: Settings) -> list[str]:
    if live is None:
        return ["live check unavailable"]
    reasons = []
    if not live.violation_present:
        reasons.append("live re-check shows the violation is no longer present")
    expected = (finding.get("account"), finding.get("region"), finding.get("resource_identifier"))
    if (live.account, live.region, live.resource_arn) != expected:
        reasons.append("live resource identity does not match the finding")
    if live.account != settings.account_id or live.region != settings.region:
        reasons.append("live resource is outside this deployment's account or region")
    return reasons


def decide(  # noqa: PLR0913 - every input is an explicit authorization fact
    *,
    finding: dict[str, Any] | None,
    control: Control | None,
    policy: PlatformPolicy | None,
    settings: Settings,
    live: LiveCheck | None,
    attempts: int,
    lock_available: bool,
    now: datetime,
) -> Decision:
    if finding is None or control is None or policy is None:
        return Decision(False, None, ("missing finding, control or policy",))
    action = action_for(control.control_id)
    allow_reasons, entry = _allowlist_reasons(finding, action, policy, settings, now)
    reasons = [
        *_environment_reasons(settings, policy),
        *_finding_reasons(finding, control, policy, attempts, lock_available),
        *allow_reasons,
        *_live_reasons(finding, live, settings),
    ]
    if reasons or action is None:
        return Decision(False, None, tuple(reasons or ["no action"]), action, entry)
    mode = _mode(control, action, policy, live)
    if mode == "human_approval" and not policy.approvers:
        return Decision(False, None, ("approval required but no approvers configured",), action, entry)
    return Decision(True, mode, ("authorized",), action, entry)
