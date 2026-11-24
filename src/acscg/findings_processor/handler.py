"""Lambda entry point for the findings processor."""

from __future__ import annotations

import logging
from typing import Any

from acscg.common.catalog import Catalog
from acscg.common.log import get_logger, log_event
from acscg.common.settings import Settings
from acscg.findings_processor.processor import Processor
from acscg.findings_processor.validation import InvalidEventError

LOG = get_logger("acscg.findings_processor.handler")
_PROCESSOR: Processor | None = None


def build_processor(settings: Settings) -> Processor:  # pragma: no cover - wiring of real AWS clients
    import boto3  # noqa: PLC0415

    from acscg.evidence_collector.sink import S3EvidenceSink  # noqa: PLC0415
    from acscg.findings_processor.ports import (  # noqa: PLC0415
        ConfigVerifier,
        LambdaRequester,
        SnsNotifier,
        SsmInspector,
        SsmPolicyProvider,
    )
    from acscg.findings_processor.store import DynamoStore  # noqa: PLC0415

    return Processor(
        settings=settings,
        catalog=Catalog.load_packaged(),
        store=DynamoStore(boto3.resource("dynamodb").Table(settings.table_name)),
        evidence=S3EvidenceSink(boto3.client("s3"), settings.evidence_bucket, settings.kms_key_id),
        notifier=SnsNotifier(boto3.client("sns"), settings.topic_arn),
        requester=LambdaRequester(boto3.client("lambda"), settings.gatekeeper_function),
        policy_provider=SsmPolicyProvider(boto3.client("ssm"), settings.policy_parameter),
        inspector=SsmInspector(boto3.client("ssm")),
        verifier=ConfigVerifier(boto3.client("config")),
    )


def handle(event: dict[str, Any], processor: Processor) -> dict[str, Any]:
    try:
        outcome = processor.process(event)
    except InvalidEventError as exc:
        # Not retryable: log without the payload and fail so the event lands in the DLQ.
        log_event(LOG, "invalid event", logging.ERROR, reason=str(exc), event_id=str(event.get("id", "?")))
        raise
    return {
        "processed": outcome.processed,
        "duplicates": outcome.duplicates,
        "ignored": outcome.ignored,
        "transitions": len(outcome.transitions),
    }


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:  # pragma: no cover - thin wrapper
    global _PROCESSOR  # noqa: PLW0603 - reuse clients across warm invocations
    if _PROCESSOR is None:
        _PROCESSOR = build_processor(Settings.from_env())
    return handle(event, _PROCESSOR)
