"""Event schema validation without third-party dependencies.

Each supported (source, detail-type) pair has a specification of required paths and their types.
Anything else is rejected. Validation never trusts an event enough to act on it alone: the
remediation gatekeeper re-reads the live resource (ADR 0006).
"""

from __future__ import annotations

import json
from typing import Any

MAX_EVENT_BYTES = 256 * 1024  # EventBridge maximum entry size

SYNTHETIC_SOURCE = "acscg.synthetic"

ENVELOPE: dict[str, type | tuple[type, ...]] = {
    "id": str,
    "source": str,
    "detail-type": str,
    "account": str,
    "region": str,
    "time": str,
    "detail": dict,
}

_CONFIG = {
    "detail.configRuleName": str,
    "detail.resourceId": str,
    "detail.resourceType": str,
    "detail.awsAccountId": str,
    "detail.awsRegion": str,
    "detail.newEvaluationResult": dict,
    "detail.newEvaluationResult.complianceType": str,
}

SPECS: dict[tuple[str, str], dict[str, type | tuple[type, ...]]] = {
    ("aws.config", "Config Rules Compliance Change"): _CONFIG,
    (SYNTHETIC_SOURCE, "Config Rules Compliance Change"): _CONFIG,
    ("aws.ec2", "AWS API Call via CloudTrail"): {},
    ("aws.s3", "AWS API Call via CloudTrail"): {},
    ("aws.cloudtrail", "AWS API Call via CloudTrail"): {},
    ("aws.config", "AWS API Call via CloudTrail"): {},
    ("aws.iam", "AWS API Call via CloudTrail"): {},
    (SYNTHETIC_SOURCE, "AWS API Call via CloudTrail"): {},
    ("aws.access-analyzer", "Access Analyzer Finding"): {
        "detail.id": str,
        "detail.resource": str,
        "detail.resourceType": str,
        "detail.status": str,
        "detail.accountId": str,
    },
    ("aws.securityhub", "Security Hub Findings - Imported"): {"detail.findings": list},
    ("aws.guardduty", "GuardDuty Finding"): {
        "detail.id": str,
        "detail.type": str,
        "detail.severity": (int, float),
        "detail.accountId": str,
        "detail.region": str,
    },
    ("aws.ssm", "EC2 Automation Execution Status-change Notification"): {
        "detail.ExecutionId": str,
        "detail.Definition": str,
        "detail.Status": str,
    },
}

_CLOUDTRAIL = {
    "detail.eventSource": str,
    "detail.eventName": str,
    "detail.eventID": str,
    "detail.eventTime": str,
    "detail.userIdentity": dict,
}
for _key, _spec in SPECS.items():
    if _key[1] == "AWS API Call via CloudTrail":
        _spec.update(_CLOUDTRAIL)


class InvalidEventError(ValueError):
    """The event does not match any supported schema. It is dead-lettered, never retried."""


def get_path(data: dict[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(dotted)
        current = current[part]
    return current


def _check(event: dict[str, Any], spec: dict[str, type | tuple[type, ...]]) -> list[str]:
    errors = []
    for path, expected in spec.items():
        try:
            value = get_path(event, path)
        except KeyError:
            errors.append(f"missing {path}")
            continue
        if isinstance(value, bool) or not isinstance(value, expected):
            errors.append(f"{path} has type {type(value).__name__}")
        elif isinstance(value, str) and not value.strip():
            errors.append(f"{path} is empty")
    return errors


def validate_event(event: Any, *, allow_synthetic: bool) -> tuple[str, str]:
    """Return ``(source, detail_type)`` or raise :class:`InvalidEventError`."""
    if not isinstance(event, dict):
        raise InvalidEventError("event is not an object")
    if len(json.dumps(event, default=str).encode("utf-8")) > MAX_EVENT_BYTES:
        raise InvalidEventError("event exceeds the maximum size")
    errors = _check(event, ENVELOPE)
    if errors:
        raise InvalidEventError("; ".join(errors))
    key = (event["source"], event["detail-type"])
    if key not in SPECS:
        raise InvalidEventError(f"unsupported event {key}")
    if event["source"] == SYNTHETIC_SOURCE and not allow_synthetic:
        raise InvalidEventError("synthetic events are disabled in this environment")
    errors = _check(event, SPECS[key])
    if errors:
        raise InvalidEventError("; ".join(errors))
    return key
