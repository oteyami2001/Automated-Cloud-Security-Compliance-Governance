"""Shared persistence of lifecycle transitions: state, history, evidence and notifications.

Used by the findings processor and the remediation gatekeeper so both apply exactly the same
transition rules (lifecycle.check_transition) and evidence format.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acscg.common.canonical import utc_now
from acscg.common.log import get_logger, log_event
from acscg.common.models import FindingState, Severity
from acscg.common.settings import Settings
from acscg.evidence_collector.builder import build_evidence
from acscg.evidence_collector.sink import EvidenceSink
from acscg.findings_processor import lifecycle
from acscg.findings_processor.ports import Notifier
from acscg.findings_processor.store import Store

LOG = get_logger("acscg.recorder")
S = FindingState
Step = tuple[S | None, S, str]


@dataclass
class Recorder:
    settings: Settings
    store: Store
    evidence: EvidenceSink
    notifier: Notifier
    clock: Callable[[], str] = utc_now
    transitions: list[tuple[str, str | None, str]] = field(default_factory=list)

    def save(
        self,
        item: dict[str, Any],
        version: int | None,
        steps: list[Step],
        execution: dict[str, Any] | None = None,
    ) -> None:
        for before, after, _ in steps:
            lifecycle.check_transition(before, after)
        if steps:
            item["state"] = str(steps[-1][1])
            item["state_changed_at"] = self.clock()
        self.store.put_finding(item, version)
        new_version = (version or 0) + 1
        for before, after, reason in steps:
            now = self.clock()
            self.store.add_history(item["finding_key"], {"at": now, "from": before, "to": str(after), "reason": reason})
            self.transitions.append((item["finding_key"], str(before) if before else None, str(after)))
            self._record_evidence(item, before, after, reason, execution)
        if steps:
            final = steps[-1][1]
            # Notify once per save if any transition in it is notifiable (OPEN → REPORTED must notify).
            if any(after in lifecycle.NOTIFY_STATES for _, after, _ in steps) or item.get("escalate"):
                self._notify(item, final, new_version)
            log_event(
                LOG, "finding state", finding_key=item["finding_key"], control_id=item["control_id"], state=str(final)
            )

    def _record_evidence(
        self, item: dict[str, Any], before: S | None, after: S, reason: str, execution: dict[str, Any] | None
    ) -> None:
        exec_result = None
        approval = None
        proposed = None
        if execution:
            approval = execution.get("approval")
            exec_result = {
                "execution_id": execution.get("execution_id"),
                "document": execution.get("document"),
                "status": execution.get("status"),
                "completed_at": execution.get("completed_at"),
            }
            proposed = {"action": execution.get("action"), "mode": execution.get("mode")}
        verified = item.get("verified_at") if after in {S.VERIFIED_RESOLVED, S.VERIFICATION_FAILED} else None
        document = build_evidence(
            kind=f"transition-{str(after).lower()}",
            finding=item,
            recorded_at=self.clock(),
            previous_compliance_state=item.get("previous_compliance"),
            updated_compliance_state=item.get("compliance"),
            lifecycle_from=str(before) if before else None,
            lifecycle_to=str(after),
            proposed_remediation=proposed,
            approval=approval,
            execution_result=exec_result,
            verification_timestamp=verified,
            decision={"reason": reason},
        )
        # A retry may record the same transition in the same second: it is already stored.
        with contextlib.suppress(FileExistsError):
            self.evidence.put(document)

    def _notify(self, item: dict[str, Any], state: S, version: int) -> None:
        if not self.store.claim_notification(item["finding_key"], str(state), version):
            return
        severity = Severity.parse(item["severity"])
        prefix = "ESCALATION" if item.get("escalate") else severity.label.upper()
        subject = f"[ACSCG {self.settings.environment}] {prefix} {item['control_id']} {state}"
        message = {
            "finding_key": item["finding_key"],
            "control_id": item["control_id"],
            "title": item.get("title"),
            "severity": item["severity"],
            "state": str(state),
            "resource_type": item["resource_type"],
            "resource_id": item["resource_id"],
            "ownership": item.get("ownership"),
            "synthetic": item.get("synthetic", False),
            "annotation": item.get("annotation", "")[:200],
        }
        self.notifier.notify(subject, message)
