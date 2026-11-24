"""Gatekeeper service: load facts, decide, record, and (only if authorized) start the runbook."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from acscg.common.canonical import parse_time, utc_now
from acscg.common.catalog import Catalog
from acscg.common.log import get_logger, log_event
from acscg.common.models import FindingState
from acscg.common.settings import Settings
from acscg.findings_processor.ports import PolicyProvider
from acscg.findings_processor.recorder import Recorder
from acscg.findings_processor.store import Store
from acscg.remediation_engine.gatekeeper import Decision, LiveCheck, decide
from acscg.remediation_engine.policy import PlatformPolicy, PolicyError

LOG = get_logger("acscg.gatekeeper")
S = FindingState
LOG_RETENTION_DAYS = {"dev": 30, "staging": 90, "prod": 365}


@dataclass
class Gatekeeper:
    settings: Settings
    catalog: Catalog
    store: Store
    recorder: Recorder
    policy_provider: PolicyProvider
    live_check: Callable[[dict[str, Any]], LiveCheck | None]
    ssm: Any
    clock: Callable[[], str] = utc_now
    id_factory: Callable[[], str] = lambda: uuid.uuid4().hex

    def handle(self, finding_key: str) -> dict[str, Any]:
        request_id = self.id_factory()
        finding = self.store.get_finding(finding_key)
        if finding is None:
            log_event(LOG, "unknown finding", logging.WARNING, finding_key=finding_key)
            return {"allowed": False, "reasons": ["unknown finding"]}
        try:
            policy: PlatformPolicy | None = self.policy_provider.get()
        except (PolicyError, KeyError, ValueError) as exc:
            log_event(LOG, "policy unavailable", logging.ERROR, error=str(exc))
            policy = None
        control = self.catalog.get(finding["control_id"]) if finding["control_id"] in self.catalog else None

        lock_available = self.store.acquire_lock(finding_key, request_id)
        if not lock_available:
            log_event(LOG, "remediation already active", finding_key=finding_key)
            return {"allowed": False, "reasons": ["another remediation for this finding is active"]}
        attempts = sum(1 for r in self.store.remediations(finding_key) if r.get("execution_id"))
        live = self.live_check(finding) if policy is not None else None
        decision = decide(
            finding=finding,
            control=control,
            policy=policy,
            settings=self.settings,
            live=live,
            attempts=attempts,
            lock_available=True,
            now=self._now(),
        )
        request = {
            "request_id": request_id,
            "requested_at": self.clock(),
            "decision": decision.as_dict(),
            "mode": decision.mode,
            "action": decision.action.action if decision.action else None,
            "document": decision.action.document if decision.action else None,
            "live_check": {"violation_present": live.violation_present, "note": live.note} if live else None,
        }
        if not decision.allowed:
            self._deny(finding, request, decision)
            self.store.release_lock(finding_key, request_id)
            return decision.as_dict()
        if policy is None or live is None:  # unreachable: decide() denies without them; fail closed anyway
            raise RuntimeError("authorization facts missing after an allow decision")
        try:
            execution_id = self._start(finding, decision, live, policy, request_id)
        except Exception as exc:  # noqa: BLE001 - any start failure is recorded as REMEDIATION_FAILED, then the lock is released
            request["status"] = "StartFailed"
            request["error"] = type(exc).__name__
            self.store.put_remediation(finding_key, request)
            self.recorder.save(
                finding,
                finding["version"],
                [(S(finding["state"]), S.REMEDIATION_FAILED, "runbook could not start")],
                execution=request,
            )
            self.store.release_lock(finding_key, request_id)
            return {**decision.as_dict(), "started": False}
        request.update(
            {"execution_id": execution_id, "status": "Started", "parameters": _public_parameters(live.parameters)}
        )
        self.store.put_remediation(finding_key, request)
        new_state = S.PENDING_APPROVAL if decision.mode == "human_approval" else S.REMEDIATING
        reason = (
            "awaiting human approval" if new_state == S.PENDING_APPROVAL else "automatic low-risk remediation started"
        )
        self.recorder.save(finding, finding["version"], [(S(finding["state"]), new_state, reason)], execution=request)
        log_event(LOG, "remediation started", finding_key=finding_key, execution_id=execution_id, mode=decision.mode)
        return {**decision.as_dict(), "started": True, "execution_id": execution_id}

    def _now(self) -> datetime:
        return parse_time(self.clock())

    def _deny(self, finding: dict[str, Any], request: dict[str, Any], decision: Decision) -> None:
        request["status"] = "Denied"
        self.store.put_remediation(finding["finding_key"], request)
        state = S(finding["state"]) if finding.get("state") else None
        steps = (
            []
            if state == S.REJECTED_POLICY or state not in {S.OPEN, S.APPROVAL_EXPIRED, S.REMEDIATION_FAILED}
            else [(state, S.REJECTED_POLICY, "; ".join(decision.reasons))]
        )
        finding["rejection_reasons"] = list(decision.reasons)
        self.recorder.save(finding, finding["version"], steps, execution=request)
        log_event(LOG, "remediation denied", finding_key=finding["finding_key"], reasons=list(decision.reasons))

    def _start(
        self, finding: dict[str, Any], decision: Decision, live: LiveCheck, policy: PlatformPolicy, request_id: str
    ) -> str:
        if decision.action is None:
            raise RuntimeError("no remediation action")
        params: dict[str, list[str]] = {
            "FindingKey": [finding["finding_key"]],
            "RequestId": [request_id],
            "RequireApproval": ["true" if decision.mode == "human_approval" else "false"],
            "Approvers": list(policy.approvers) or ["none"],
        }
        for key, value in live.parameters.items():
            if key == "Previous":
                continue
            params[key] = value if isinstance(value, list) else [str(value)]
        if finding["control_id"] == "SEC-013" and decision.entry is not None:
            values = dict(decision.entry.parameters)
            missing = live.parameters.get("MissingTagKeys", [])
            params["TagKeys"] = [k for k in missing if k in values]
            params["TagValues"] = [values[k] for k in missing if k in values]
            params.pop("MissingTagKeys", None)
            if not params["TagKeys"]:
                raise ValueError("allowlist entry provides no values for the missing tags")
        response = self.ssm.start_automation_execution(
            DocumentName=decision.action.document,
            Parameters=params,
            ClientToken=request_id,
            Tags=[{"Key": "Project", "Value": "acscg"}, {"Key": "FindingKey", "Value": finding["finding_key"][:64]}],
        )
        return str(response["AutomationExecutionId"])


def _public_parameters(parameters: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in parameters.items() if k not in {"Approvers"}}


def build_gatekeeper(settings: Settings) -> Gatekeeper:  # pragma: no cover - real AWS wiring
    import boto3  # noqa: PLC0415

    from acscg.evidence_collector.sink import S3EvidenceSink  # noqa: PLC0415
    from acscg.findings_processor.ports import SnsNotifier, SsmPolicyProvider  # noqa: PLC0415
    from acscg.findings_processor.store import DynamoStore  # noqa: PLC0415
    from acscg.remediation_engine.live_checks import run_check  # noqa: PLC0415

    catalog = Catalog.load_packaged()
    store = DynamoStore(boto3.resource("dynamodb").Table(settings.table_name))
    recorder = Recorder(
        settings,
        store,
        S3EvidenceSink(boto3.client("s3"), settings.evidence_bucket, settings.kms_key_id),
        SnsNotifier(boto3.client("sns"), settings.topic_arn),
    )
    return Gatekeeper(
        settings=settings,
        catalog=catalog,
        store=store,
        recorder=recorder,
        policy_provider=SsmPolicyProvider(boto3.client("ssm"), settings.policy_parameter),
        live_check=lambda f: run_check(
            f, boto3, required_tags=catalog.required_tags, log_retention_days=LOG_RETENTION_DAYS[settings.environment]
        ),
        ssm=boto3.client("ssm"),
    )
