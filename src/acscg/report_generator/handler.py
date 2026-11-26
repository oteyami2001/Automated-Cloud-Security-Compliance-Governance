"""Lambda entry point: build the report from DynamoDB and store JSON + Markdown in the evidence bucket."""

from __future__ import annotations

import json
from typing import Any

from acscg.common.canonical import canonical_json, parse_time, sha256_hex, utc_now
from acscg.common.catalog import Catalog
from acscg.common.settings import Settings
from acscg.findings_processor.store import Store
from acscg.report_generator.report import build_report, emf_records, metric_namespace, render_markdown


def generate(store: Store, catalog: Catalog, settings: Settings, s3: Any, generated_at: str) -> dict[str, Any]:
    report = build_report(store.all_findings(), catalog, environment=settings.environment, generated_at=generated_at)
    stamp = generated_at.replace(":", "-")
    body = canonical_json(report)
    digest = sha256_hex(body)
    public_md = render_markdown(report, public=True)
    for key, content, ctype in (
        (f"reports/{stamp}/report.json", body, "application/json"),
        (f"reports/{stamp}/report.md", render_markdown(report, public=False), "text/markdown"),
        (f"reports/{stamp}/report-public.md", public_md, "text/markdown"),
    ):
        s3.put_object(
            Bucket=settings.evidence_bucket,
            Key=key,
            Body=content.encode("utf-8"),
            ContentType=ctype,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=settings.kms_key_id,
            Metadata={"acscg-sha256": sha256_hex(content)},
        )
    key = f"reports/{stamp}/report.json"
    metrics = emf_records(
        report,
        namespace=metric_namespace(settings.environment),
        timestamp_ms=int(parse_time(generated_at).timestamp() * 1000),
        report_key=key,
    )
    for record in metrics:
        print(json.dumps(record, sort_keys=True))
    return {
        "report_key": key,
        "sha256": digest,
        "summary": report["summary"],
        "public_markdown": public_md,
        "metric_records": len(metrics),
    }


def lambda_handler(_event: dict[str, Any], _context: Any) -> dict[str, Any]:  # pragma: no cover - AWS wiring
    import boto3  # noqa: PLC0415

    from acscg.findings_processor.store import DynamoStore  # noqa: PLC0415

    settings = Settings.from_env()
    store = DynamoStore(boto3.resource("dynamodb").Table(settings.table_name))
    result = generate(store, Catalog.load_packaged(), settings, boto3.client("s3"), utc_now())
    return json.loads(json.dumps(result, default=str))
