"""AWS Config custom rule handler (Lambda) for checks managed rules do not cover.

Rule parameters (JSON string ``ruleParameters``):
    {"check": "open_admin_port", "controlId": "SEC-005"}           # IPv4 + IPv6 + port ranges
    {"check": "required_tags", "requiredTags": "Project,Owner,..."}  # keys + allowed values
    {"check": "log_retention_set", "minRetentionDays": "30"}          # SEC-014: "never expire" is NON_COMPLIANT

The managed rule CW_LOGGROUP_RETENTION_PERIOD_CHECK treats "Never expire" as COMPLIANT (AWS Config
developer guide), so SEC-014's main case needs this custom check.

The handler only reads the configuration item delivered by Config and calls
``config:PutEvaluations`` with the result token. It never changes resources.
"""

from __future__ import annotations

import json
from typing import Any

from acscg.common.log import get_logger, log_event
from acscg.compliance_evaluator.security_groups import ADMIN_PORTS, open_permissions
from acscg.compliance_evaluator.tags import evaluate_tags

LOG = get_logger("acscg.config_rule")
MAX_ANNOTATION = 256


def _open_admin_port(item: dict[str, Any], params: dict[str, Any]) -> tuple[str, str]:
    if item.get("resourceType") != "AWS::EC2::SecurityGroup":
        return "NOT_APPLICABLE", "not a security group"
    port = ADMIN_PORTS[params.get("controlId", "SEC-005")]
    permissions = (item.get("configuration") or {}).get("ipPermissions", [])
    offending = open_permissions(permissions, port)
    if offending:
        cidrs = sorted({o.cidr for o in offending})
        return "NON_COMPLIANT", f"ingress to port {port} open to {', '.join(cidrs)}"
    return "COMPLIANT", f"no ingress to port {port} from 0.0.0.0/0 or ::/0"


def _required_tags(item: dict[str, Any], params: dict[str, Any]) -> tuple[str, str]:
    required = [t.strip() for t in str(params.get("requiredTags", "")).split(",") if t.strip()]
    result = evaluate_tags(item.get("tags"), required)
    if result.compliant:
        return "COMPLIANT", "all required tags present with allowed values"
    parts = []
    if result.missing:
        parts.append("missing: " + ",".join(result.missing))
    if result.invalid:
        parts.append("invalid: " + ",".join(sorted(result.invalid)))
    return "NON_COMPLIANT", "; ".join(parts)[:MAX_ANNOTATION]


def _log_retention_set(item: dict[str, Any], params: dict[str, Any]) -> tuple[str, str]:
    if item.get("resourceType") != "AWS::Logs::LogGroup":
        return "NOT_APPLICABLE", "not a log group"
    configuration = item.get("configuration") or {}
    days = configuration.get("retentionInDays", configuration.get("RetentionInDays"))
    minimum = int(params.get("minRetentionDays", 30))
    if days in (None, "", 0):
        return "NON_COMPLIANT", "retention is 'Never expire'"
    if int(days) < minimum:
        return "NON_COMPLIANT", f"retention {days} days is below {minimum}"
    return "COMPLIANT", f"retention {days} days"


CHECKS = {
    "open_admin_port": _open_admin_port,
    "required_tags": _required_tags,
    "log_retention_set": _log_retention_set,
}


def evaluate_item(item: dict[str, Any], params: dict[str, Any]) -> tuple[str, str]:
    """Return (complianceType, annotation) for one configuration item."""
    status = item.get("configurationItemStatus", "OK")
    if status in {"ResourceDeleted", "ResourceDeletedNotRecorded", "ResourceNotRecorded"}:
        return "NOT_APPLICABLE", "resource deleted or not recorded"
    check = CHECKS.get(params.get("check", ""))
    if check is None:
        raise ValueError(f"unknown check {params.get('check')!r}")
    return check(item, params)


def handler(event: dict[str, Any], _context: Any = None, config_client: Any = None) -> dict[str, Any]:
    invoking = json.loads(event["invokingEvent"])
    params = json.loads(event.get("ruleParameters") or "{}")
    item = invoking.get("configurationItem")
    if invoking.get("messageType") != "ConfigurationItemChangeNotification" or not item:
        # Oversized/scheduled notifications are not used by these rules.
        log_event(LOG, "ignored notification", message_type=invoking.get("messageType"))
        return {"evaluations": []}
    if event.get("eventLeftScope"):
        compliance, annotation = "NOT_APPLICABLE", "resource left the rule scope"
    else:
        compliance, annotation = evaluate_item(item, params)
    evaluation = {
        "ComplianceResourceType": item["resourceType"],
        "ComplianceResourceId": item["resourceId"],
        "ComplianceType": compliance,
        "Annotation": annotation[:MAX_ANNOTATION],
        "OrderingTimestamp": item["configurationItemCaptureTime"],
    }
    if config_client is None:  # pragma: no cover - real AWS client only in Lambda
        import boto3  # noqa: PLC0415

        config_client = boto3.client("config")
    config_client.put_evaluations(Evaluations=[evaluation], ResultToken=event["resultToken"])
    log_event(LOG, "evaluation", resource_type=item["resourceType"], compliance=compliance)
    return {"evaluations": [evaluation]}
