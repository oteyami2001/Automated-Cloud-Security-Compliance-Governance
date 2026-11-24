# Python packages (Python 3.13)

🧱 Implemented, ✅ tested offline (Phase 2). Runtime dependencies: standard library + boto3 (ADR 0013).

| Package | Entry point | Purpose |
|---|---|---|
| `acscg.common` | — | models, catalog, settings (fail closed), masked JSON logging, canonical JSON |
| `acscg.findings_processor` | `handler.lambda_handler` | validate → normalise → classify → dedupe → lifecycle → evidence → notify |
| `acscg.compliance_evaluator` | `config_rule.handler` | custom Config rules (IPv6/port ranges, tag values), change attribution |
| `acscg.remediation_engine` | `handler.lambda_handler` | policy, pure authorization decision, live checks, runbook start |
| `acscg.evidence_collector` | — | evidence documents (all §12 fields) with SHA-256, S3 sink, manifests |
| `acscg.report_generator` | `handler.lambda_handler` | JSON + Markdown reports (public variant redacted) |

Build: `scripts/build_lambda.py` (deterministic zip, packaged catalog JSON).
