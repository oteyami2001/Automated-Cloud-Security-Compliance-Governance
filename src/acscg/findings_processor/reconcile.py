"""Reconcile the findings table with AWS Config's current results (Phase 5, evidence P4-13).

EventBridge only carries compliance *changes*. Results that existed before the event routing
did, or events that were lost, never reach the processor, and Config does not resend unchanged
results. This job reads every current result of the project's rules and feeds each one through
the normal processor as a Config compliance-change event, so the same validation, lifecycle,
idempotency and notification rules apply.

The event ID is derived from (rule, resource type, resource ID, result time). Re-running the job
for an unchanged result is therefore a duplicate and changes nothing; a newer result is processed
once. Read-only towards AWS Config; it writes only to the findings table, evidence and SNS (the
processor's own permissions).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from acscg.common.log import get_logger, log_event
from acscg.findings_processor.processor import Processor

LOG = get_logger("acscg.findings_processor.reconcile")
RULE_PREFIX = "acscg-"
RESULT_TYPES = ["COMPLIANT", "NON_COMPLIANT"]
PAGE_LIMIT = 100  # GetComplianceDetailsByConfigRule maximum


@dataclass
class Summary:
    rules: int = 0
    results: int = 0
    processed: int = 0
    duplicates: int = 0
    ignored: int = 0
    transitions: int = 0
    failed: int = 0


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=UTC)
        return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def project_rules(config: Any, prefix: str = RULE_PREFIX) -> list[str]:
    names: list[str] = []
    token: str | None = None
    while True:
        page = config.describe_config_rules(**({"NextToken": token} if token else {}))
        names.extend(r["ConfigRuleName"] for r in page.get("ConfigRules", []) if r["ConfigRuleName"].startswith(prefix))
        token = page.get("NextToken")
        if not token:
            return sorted(names)


def rule_results(config: Any, rule: str) -> Iterator[dict[str, Any]]:
    token: str | None = None
    while True:
        args: dict[str, Any] = {"ConfigRuleName": rule, "ComplianceTypes": RESULT_TYPES, "Limit": PAGE_LIMIT}
        if token:
            args["NextToken"] = token
        page = config.get_compliance_details_by_config_rule(**args)
        yield from page.get("EvaluationResults", [])
        token = page.get("NextToken")
        if not token:
            return


def to_event(result: dict[str, Any], account: str, region: str) -> dict[str, Any]:
    """Shape one EvaluationResult like the EventBridge "Config Rules Compliance Change" event."""
    qualifier = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
    rule, resource_type, resource_id = qualifier["ConfigRuleName"], qualifier["ResourceType"], qualifier["ResourceId"]
    recorded = _iso(result.get("ResultRecordedTime") or result["EvaluationResultIdentifier"].get("OrderingTimestamp"))
    material = "|".join([rule, resource_type, resource_id, recorded, str(result["ComplianceType"])])
    new_result: dict[str, Any] = {"complianceType": result["ComplianceType"], "resultRecordedTime": recorded}
    if result.get("Annotation"):
        new_result["annotation"] = result["Annotation"]
    return {
        "version": "0",
        "id": "reconcile-" + hashlib.sha256(material.encode()).hexdigest()[:32],
        "detail-type": "Config Rules Compliance Change",
        "source": "aws.config",
        "account": account,
        "time": recorded,
        "region": region,
        "resources": [],
        "detail": {
            "resourceId": resource_id,
            "awsRegion": region,
            "awsAccountId": account,
            "configRuleName": rule,
            "messageType": "ComplianceChangeNotification",
            "resourceType": resource_type,
            "newEvaluationResult": new_result,
            "reconciled": True,
        },
    }


def reconcile(config: Any, processor: Processor, account: str, region: str) -> Summary:
    summary = Summary()
    for rule in project_rules(config):
        summary.rules += 1
        for result in rule_results(config, rule):
            summary.results += 1
            try:
                outcome = processor.process(to_event(result, account, region))
            except Exception as exc:  # noqa: BLE001 - one bad result must not stop the whole run
                summary.failed += 1
                log_event(LOG, "reconcile item failed", logging.ERROR, rule=rule, error=type(exc).__name__)
                continue
            summary.processed += outcome.processed
            summary.duplicates += outcome.duplicates
            summary.ignored += outcome.ignored
            summary.transitions += len(outcome.transitions)
    log_event(LOG, "reconcile complete", **summary.__dict__)
    return summary


def lambda_handler(_event: dict[str, Any], _context: Any) -> dict[str, Any]:  # pragma: no cover - AWS wiring
    import boto3  # noqa: PLC0415

    from acscg.common.settings import Settings  # noqa: PLC0415
    from acscg.findings_processor.handler import build_processor  # noqa: PLC0415

    settings = Settings.from_env()
    summary = reconcile(boto3.client("config"), build_processor(settings), settings.account_id, settings.region)
    if summary.failed:
        raise RuntimeError(f"{summary.failed} results failed; see the log")  # alarm on function errors
    return summary.__dict__
