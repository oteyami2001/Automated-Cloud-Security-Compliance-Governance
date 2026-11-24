"""Findings processing pipeline (docs/architecture.md §4.1)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acscg.common.canonical import parse_time, utc_now
from acscg.common.catalog import Catalog
from acscg.common.log import get_logger, log_event
from acscg.common.models import Compliance, Finding, FindingState, Ownership, RemediationStatus
from acscg.common.settings import Settings
from acscg.evidence_collector.sink import EvidenceSink
from acscg.findings_processor import lifecycle
from acscg.findings_processor.normalizers import normalise
from acscg.findings_processor.ownership import resolve
from acscg.findings_processor.ports import (
    ExecutionInspector,
    Notifier,
    PolicyProvider,
    RemediationRequester,
    Verifier,
)
from acscg.findings_processor.recorder import Recorder
from acscg.findings_processor.severity import classify
from acscg.findings_processor.store import ConflictError, Store
from acscg.findings_processor.validation import validate_event
from acscg.remediation_engine.actions import action_for
from acscg.remediation_engine.policy import PlatformPolicy

LOG = get_logger("acscg.findings_processor")
MAX_CONFLICT_RETRIES = 3
S = FindingState
RETRYABLE_STATES = {S.REJECTED_POLICY, S.APPROVAL_EXPIRED, S.REMEDIATION_FAILED}
SUCCESS_STATUSES = {"Success", "CompletedWithSuccess"}
FAILURE_STATUSES = {"Failed", "Cancelled", "TimedOut", "Rejected", "CompletedWithFailure", "Exited"}


def aggregate_compliance(results: dict[str, dict[str, Any]]) -> Compliance:
    """Worst result wins: any NON_COMPLIANT rule makes the control non-compliant for the resource."""
    values = {Compliance(str(r.get("compliance") or Compliance.INSUFFICIENT_DATA)) for r in results.values()}
    if Compliance.NON_COMPLIANT in values:
        return Compliance.NON_COMPLIANT
    if Compliance.COMPLIANT in values:
        return Compliance.COMPLIANT
    if values == {Compliance.NOT_APPLICABLE}:
        return Compliance.NOT_APPLICABLE
    return Compliance.INSUFFICIENT_DATA


@dataclass
class Outcome:
    processed: int = 0
    duplicates: int = 0
    ignored: int = 0
    transitions: list[tuple[str, str | None, str]] = field(default_factory=list)


@dataclass
class Processor:
    settings: Settings
    catalog: Catalog
    store: Store
    evidence: EvidenceSink
    notifier: Notifier
    requester: RemediationRequester
    policy_provider: PolicyProvider
    inspector: ExecutionInspector
    verifier: Verifier
    clock: Callable[[], str] = utc_now
    recorder: Recorder = field(init=False)

    def __post_init__(self) -> None:
        self.recorder = Recorder(self.settings, self.store, self.evidence, self.notifier, self.clock)

    # ------------------------------------------------------------------ entry point
    def process(self, event: dict[str, Any]) -> Outcome:
        validate_event(event, allow_synthetic=self.settings.allow_synthetic_events)
        policy = self.policy_provider.get()
        outcome = Outcome()
        self.recorder.transitions = outcome.transitions
        items = normalise(event, self.catalog, approved_principals=policy.approved_change_principals)
        if not items:
            outcome.ignored += 1
            log_event(LOG, "event ignored", event_id=event["id"], detail_type=event["detail-type"])
        for item in items:
            claim = f"{event['id']}#{getattr(item, 'source_event_id', '')}#{self._item_key(item)}"
            if not self.store.claim_event(claim):
                outcome.duplicates += 1
                log_event(LOG, "duplicate event", claim=claim)
                continue
            try:
                if isinstance(item, Finding):
                    self._with_retry(lambda f=item: self._handle_finding(f, policy, outcome))
                else:
                    self._with_retry(lambda s=item: self._handle_status(s, outcome))
            except Exception:
                # Let the EventBridge retry reprocess this item instead of dropping it as a duplicate.
                self.store.release_event(claim)
                raise
            outcome.processed += 1
        return outcome

    @staticmethod
    def _item_key(item: Finding | RemediationStatus) -> str:
        return item.key if isinstance(item, Finding) else f"{item.execution_id}#{item.status}"

    @staticmethod
    def _with_retry(action: Callable[[], None]) -> None:
        for attempt in range(MAX_CONFLICT_RETRIES):
            try:
                action()
                return
            except ConflictError:
                if attempt == MAX_CONFLICT_RETRIES - 1:
                    raise

    # ------------------------------------------------------------------ findings
    def _handle_finding(self, finding: Finding, policy: PlatformPolicy, outcome: Outcome) -> None:
        finding.severity = classify(finding, self.catalog)
        ownership = resolve(finding.resource, policy)
        current = self.store.get_finding(finding.key)
        version = current["version"] if current else None
        state = S(current["state"]) if current else None
        item = self._merge(current, finding, ownership)
        compliance = self._aggregate(item, current, finding)

        if compliance in {Compliance.INSUFFICIENT_DATA}:
            self.recorder.save(item, version, [])
            return

        if compliance in {Compliance.COMPLIANT, Compliance.NOT_APPLICABLE}:
            if state is None:
                self.recorder.save(item, version, [(None, S.COMPLIANT, "first evaluation compliant")])
            elif state == S.VERIFYING:
                item["verified_at"] = finding.observed_at
                self.recorder.save(item, version, [(state, S.VERIFIED_RESOLVED, "re-evaluation compliant")])
            elif state in {S.PENDING_APPROVAL, S.REMEDIATING} or lifecycle.is_resolved(state):
                self.recorder.save(item, version, [])
            else:
                self.recorder.save(item, version, [(state, S.RESOLVED_EXTERNALLY, "compliant without platform action")])
            return

        # NON_COMPLIANT
        steps: list[tuple[S | None, S, str]] = []
        if state is None or lifecycle.is_resolved(state):
            item["first_seen"] = finding.observed_at
            steps.append((state, S.OPEN, "violation detected"))
        elif state == S.SUPPRESSED_EXCEPTION and not self._exception_active(item):
            steps.append((state, S.OPEN, "exception expired"))
        if steps:
            routed = self._route(item, finding, policy, ownership)
            if routed:
                steps.append((S.OPEN, routed[0], routed[1]))
        self.recorder.save(item, version, steps)
        reached_open = bool(steps) and steps[-1][1] == S.OPEN
        retry = not steps and state in RETRYABLE_STATES
        if (reached_open or retry) and self._remediation_candidate(item, finding, policy, ownership)[0]:
            self.requester.request(finding.key)
            log_event(LOG, "remediation requested", finding_key=finding.key, control_id=finding.control_id)

    @staticmethod
    def _aggregate(item: dict[str, Any], current: dict[str, Any] | None, finding: Finding) -> Compliance:
        """One finding per control and resource, several rules per control (e.g. four for SEC-001).

        Each rule's latest result is kept; the finding is NON_COMPLIANT while any rule says so, and
        resolves only when every rule that reported is compliant. Without this, the last rule to
        report decided alone and a compliant result from one rule could close a violation another
        rule still sees (found in AWS during Phase 5, evidence P5-10).
        """
        rules = dict((current or {}).get("rule_results") or {})
        if current and not rules:  # finding stored before per-rule tracking: keep what it knew
            legacy = str((current.get("details") or {}).get("rule") or current.get("source") or "unknown")
            rules[legacy] = {"compliance": current.get("compliance"), "annotation": current.get("annotation", "")}
        rule = str(finding.details.get("rule") or finding.source)
        rules[rule] = {
            "compliance": str(finding.compliance),
            "annotation": finding.annotation,
            "observed_at": finding.observed_at,
        }
        effective = aggregate_compliance(rules)
        item["rule_results"] = rules
        item["compliance"] = str(effective)
        notes = [
            f"{r}: {v['annotation']}"
            for r, v in sorted(rules.items())
            if v.get("annotation") and v.get("compliance") == str(effective)
        ]
        item["annotation"] = "; ".join(notes)[:512] if notes else finding.annotation
        return effective

    def _merge(self, current: dict[str, Any] | None, finding: Finding, ownership: Ownership) -> dict[str, Any]:
        item = dict(current or {})
        item.update(
            {
                "finding_key": finding.key,
                "control_id": finding.control_id,
                "title": finding.title,
                "severity": finding.severity.label,
                "source": finding.source,
                "resource_type": finding.resource.resource_type,
                "resource_id": finding.resource.resource_id,
                "resource_identifier": finding.resource.identifier,
                "account": finding.resource.account,
                "region": finding.resource.region,
                "ownership": str(ownership),
                "compliance": str(finding.compliance),
                "previous_compliance": (current or {}).get("compliance", "NONE"),
                "annotation": finding.annotation,
                "last_seen": finding.observed_at,
                "last_event_id": finding.source_event_id,
                "synthetic": finding.synthetic or bool((current or {}).get("synthetic")),
                "sample": finding.sample,
                "details": {k: v for k, v in finding.details.items() if not isinstance(v, float)},
            }
        )
        item.setdefault("first_seen", finding.observed_at)
        item.setdefault("state", None)
        return item

    def _exception_active(self, item: dict[str, Any]) -> bool:
        exception = self.store.get_exception(item["control_id"], item["resource_identifier"])
        if not exception:
            return False
        try:
            return parse_time(exception["expires_at"]) > parse_time(self.clock())
        except (KeyError, ValueError):
            return False  # malformed exception never suppresses

    def _remediation_candidate(
        self, item: dict[str, Any], finding: Finding, policy: PlatformPolicy, ownership: Ownership
    ) -> tuple[bool, str]:
        control = self.catalog.get(finding.control_id)
        checks = [
            (control.remediable, f"control eligibility is {control.eligibility}"),
            (action_for(finding.control_id) is not None, "no remediation action exists"),
            (not finding.synthetic and not item.get("synthetic"), "synthetic events are never remediated"),
            (not finding.sample, "sample findings are never remediated"),
            (self.settings.remediation_enabled and policy.remediation_enabled, "remediation is disabled"),
            (
                self.settings.remediation_mode != "report_only" and policy.remediation_mode != "report_only",
                "report-only mode",
            ),
            (ownership == Ownership.PROJECT_OWNED, f"resource ownership is {ownership}"),
        ]
        for ok, reason in checks:
            if not ok:
                return False, reason
        return True, "candidate"

    def _route(
        self, item: dict[str, Any], finding: Finding, policy: PlatformPolicy, ownership: Ownership
    ) -> tuple[S, str] | None:
        if self._exception_active(item):
            return S.SUPPRESSED_EXCEPTION, "approved exception"
        candidate, reason = self._remediation_candidate(item, finding, policy, ownership)
        if candidate:
            return None  # stays OPEN; the gatekeeper decides
        if self.catalog.get(finding.control_id).eligibility == "escalate":
            item["escalate"] = True
        return S.REPORTED, reason

    # ------------------------------------------------------------------ remediation status
    def _handle_status(self, status: RemediationStatus, outcome: Outcome) -> None:
        found = self.store.find_remediation(status.execution_id)
        if found is None:
            log_event(LOG, "status for unknown execution", logging.WARNING, execution_id=status.execution_id)
            return
        key, request = found
        if status.status not in SUCCESS_STATUSES | FAILURE_STATUSES:
            return  # non-terminal; the finding already shows PENDING_APPROVAL / REMEDIATING
        current = self.store.get_finding(key)
        if current is None:
            return
        state = S(current["state"])
        if state not in {S.PENDING_APPROVAL, S.REMEDIATING}:
            return  # already finalised (duplicate or late event)
        details = self.inspector.inspect(status.execution_id)
        approval = {
            "required": request.get("mode") == "human_approval",
            "identity": details.get("approver"),
            "decision": details.get("approval_status"),
            "comment": details.get("approval_comment"),
            "timestamp": details.get("approval_time"),
        }
        request.update({"status": status.status, "completed_at": status.observed_at, "approval": approval})
        item = dict(current)
        steps: list[tuple[S | None, S, str]] = []
        if status.status in SUCCESS_STATUSES:
            if state == S.PENDING_APPROVAL:
                steps.append((state, S.REMEDIATING, "approved"))
            steps.append((S.REMEDIATING, S.VERIFYING, "runbook succeeded"))
            verdict = self.verifier.verify(item)
            if verdict == Compliance.COMPLIANT:
                item["verified_at"] = self.clock()
                item["compliance"] = str(Compliance.COMPLIANT)
                steps.append((S.VERIFYING, S.VERIFIED_RESOLVED, "re-evaluation compliant"))
            elif verdict == Compliance.NON_COMPLIANT:
                item["verified_at"] = self.clock()
                steps.append((S.VERIFYING, S.VERIFICATION_FAILED, "still non-compliant after remediation"))
                item["escalate"] = True
        elif details.get("approval_status") == "Rejected":
            steps.append((state, S.REMEDIATION_REJECTED, "approver rejected"))
        elif state == S.PENDING_APPROVAL and (
            status.status == "TimedOut" or details.get("approval_step_status") == "TimedOut"
        ):
            steps.append((state, S.APPROVAL_EXPIRED, "approval timed out"))
        else:
            steps.append((state, S.REMEDIATION_FAILED, details.get("failure_message") or status.status))
            item["escalate"] = True
        self.store.put_remediation(key, request)
        self.recorder.save(item, current["version"], steps, execution=request)
        self.store.release_lock(key, request["request_id"])
