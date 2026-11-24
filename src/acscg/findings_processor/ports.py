"""Ports (interfaces) the processor depends on, with AWS adapters and test doubles.

Every AWS call is behind one of these, so the processor's logic is tested offline.
"""

from __future__ import annotations

import json
import time
from typing import Any, Protocol

from acscg.common.models import Compliance
from acscg.remediation_engine.policy import PlatformPolicy, parse_policy

# ---------------------------------------------------------------- notifications


class Notifier(Protocol):
    def notify(self, subject: str, message: dict[str, Any]) -> None: ...


class RecordingNotifier:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def notify(self, subject: str, message: dict[str, Any]) -> None:
        self.sent.append((subject, message))


class SnsNotifier:
    def __init__(self, client: Any, topic_arn: str) -> None:
        self.client = client
        self.topic_arn = topic_arn

    def notify(self, subject: str, message: dict[str, Any]) -> None:
        self.client.publish(TopicArn=self.topic_arn, Subject=subject[:100], Message=json.dumps(message, indent=2))


# ---------------------------------------------------------------- remediation requests


class RemediationRequester(Protocol):
    def request(self, finding_key: str) -> None: ...


class RecordingRequester:
    def __init__(self) -> None:
        self.requested: list[str] = []

    def request(self, finding_key: str) -> None:
        self.requested.append(finding_key)


class LambdaRequester:
    """Asynchronous invocation of the gatekeeper with the finding key only (it re-reads everything)."""

    def __init__(self, client: Any, function_name: str) -> None:
        self.client = client
        self.function_name = function_name

    def request(self, finding_key: str) -> None:
        self.client.invoke(
            FunctionName=self.function_name,
            InvocationType="Event",
            Payload=json.dumps({"finding_key": finding_key}).encode("utf-8"),
        )


# ---------------------------------------------------------------- execution inspection


class ExecutionInspector(Protocol):
    def inspect(self, execution_id: str) -> dict[str, Any]: ...


class StaticInspector:
    def __init__(self, results: dict[str, dict[str, Any]] | None = None) -> None:
        self.results = results or {}

    def inspect(self, execution_id: str) -> dict[str, Any]:
        return self.results.get(execution_id, {})


class SsmInspector:
    """Reads the approval step and outputs of an Automation execution.

    The aws:approve step reports ``ApprovalStatus`` and ``ApproverDecisions`` outputs. Their exact
    shape is re-verified against a real execution in Phase 6; parsing here is defensive.
    """

    def __init__(self, client: Any) -> None:
        self.client = client

    def inspect(self, execution_id: str) -> dict[str, Any]:
        execution = self.client.get_automation_execution(AutomationExecutionId=execution_id)["AutomationExecution"]
        result: dict[str, Any] = {
            "status": execution.get("AutomationExecutionStatus"),
            "failure_message": execution.get("FailureMessage"),
            "outputs": execution.get("Outputs", {}),
            "approval_status": None,
            "approver": None,
            "approval_comment": None,
            "approval_time": None,
            "approval_step_status": None,
        }
        for step in execution.get("StepExecutions", []):
            if step.get("Action") != "aws:approve":
                continue
            outputs = step.get("Outputs", {}) or {}
            result["approval_step_status"] = step.get("StepStatus")
            result["approval_status"] = (outputs.get("ApprovalStatus") or [None])[0]
            result["approval_time"] = str(step.get("ExecutionEndTime") or "") or None
            for raw in outputs.get("ApproverDecisions", []) or []:
                try:
                    decisions = json.loads(raw) if isinstance(raw, str) else raw
                except json.JSONDecodeError:
                    continue
                for decision in decisions if isinstance(decisions, list) else [decisions]:
                    result["approver"] = decision.get("approver") or decision.get("Approver")
                    result["approval_comment"] = decision.get("comment") or decision.get("Comment")
        return result


# ---------------------------------------------------------------- verification


class Verifier(Protocol):
    def verify(self, finding: dict[str, Any]) -> Compliance | None: ...


class StaticVerifier:
    def __init__(self, result: Compliance | None = Compliance.COMPLIANT) -> None:
        self.result = result

    def verify(self, finding: dict[str, Any]) -> Compliance | None:
        return self.result


class ConfigVerifier:
    """Reads this project's Config rule results for the resource. None = not yet evaluated."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def verify(self, finding: dict[str, Any]) -> Compliance | None:
        prefix = "acscg-" + finding["control_id"].lower().replace("-", "")
        results = self.client.get_compliance_details_by_resource(
            ResourceType=finding["resource_type"], ResourceId=finding["resource_id"]
        ).get("EvaluationResults", [])
        ours = [
            r
            for r in results
            if r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ConfigRuleName"].startswith(prefix)
        ]
        if not ours:
            return None
        types = {r["ComplianceType"] for r in ours}
        if "NON_COMPLIANT" in types:
            return Compliance.NON_COMPLIANT
        return Compliance.COMPLIANT if types <= {"COMPLIANT", "NOT_APPLICABLE"} else None


# ---------------------------------------------------------------- policy


class PolicyProvider(Protocol):
    def get(self) -> PlatformPolicy: ...


class StaticPolicyProvider:
    def __init__(self, policy: PlatformPolicy) -> None:
        self.policy = policy

    def get(self) -> PlatformPolicy:
        return self.policy


class SsmPolicyProvider:
    """Reads the Terraform-rendered policy parameter, caching it briefly. Parse errors propagate (deny)."""

    def __init__(self, client: Any, name: str, ttl_seconds: int = 60, clock: Any = time.monotonic) -> None:
        self.client = client
        self.name = name
        self.ttl = ttl_seconds
        self.clock = clock
        self._cached: tuple[float, PlatformPolicy] | None = None

    def get(self) -> PlatformPolicy:
        now = self.clock()
        if self._cached and now - self._cached[0] < self.ttl:
            return self._cached[1]
        value = self.client.get_parameter(Name=self.name, WithDecryption=True)["Parameter"]["Value"]
        policy = parse_policy(value)
        self._cached = (now, policy)
        return policy
