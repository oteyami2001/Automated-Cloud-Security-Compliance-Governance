"""Translate validated events from each source into :class:`Finding` / :class:`RemediationStatus`."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from acscg.common.catalog import Catalog
from acscg.common.models import Compliance, Finding, RemediationStatus, Resource, Severity
from acscg.compliance_evaluator.change_attribution import attribute
from acscg.findings_processor.validation import SYNTHETIC_SOURCE

Normalised = list[Finding | RemediationStatus]


def build_arn(resource_type: str, resource_id: str, account: str, region: str) -> str | None:
    """ARN for resource types whose Config resourceId is enough to build one."""
    templates = {
        "AWS::EC2::SecurityGroup": "arn:aws:ec2:{r}:{a}:security-group/{i}",
        "AWS::EC2::Volume": "arn:aws:ec2:{r}:{a}:volume/{i}",
        "AWS::EC2::Instance": "arn:aws:ec2:{r}:{a}:instance/{i}",
        "AWS::S3::Bucket": "arn:aws:s3:::{i}",
        "AWS::Logs::LogGroup": "arn:aws:logs:{r}:{a}:log-group:{i}",
        "AWS::Lambda::Function": "arn:aws:lambda:{r}:{a}:function:{i}",
        "AWS::DynamoDB::Table": "arn:aws:dynamodb:{r}:{a}:table/{i}",
        "AWS::CloudTrail::Trail": "arn:aws:cloudtrail:{r}:{a}:trail/{i}",
    }
    if resource_id.startswith("arn:"):
        return resource_id
    template = templates.get(resource_type)
    return template.format(r=region, a=account, i=resource_id) if template else None


def _resource(resource_type: str, resource_id: str, account: str, region: str) -> Resource:
    return Resource(resource_type, resource_id, account, region, build_arn(resource_type, resource_id, account, region))


def _compliance(value: str) -> Compliance:
    try:
        return Compliance(value)
    except ValueError:
        return Compliance.INSUFFICIENT_DATA


def config_change(event: dict[str, Any], catalog: Catalog, **_: Any) -> Normalised:
    detail = event["detail"]
    control_id = catalog.control_for_rule(detail["configRuleName"])
    if control_id is None:
        return []  # not one of this project's rules
    result = detail["newEvaluationResult"]
    finding = Finding(
        control_id=control_id,
        source="config",
        source_event_id=event["id"],
        resource=_resource(detail["resourceType"], detail["resourceId"], detail["awsAccountId"], detail["awsRegion"]),
        compliance=_compliance(result["complianceType"]),
        observed_at=result.get("resultRecordedTime", event["time"]),
        title=catalog.get(control_id).title,
        annotation=str(result.get("annotation", ""))[:256],
        synthetic=event["source"] == SYNTHETIC_SOURCE,
        details={
            "rule": detail["configRuleName"],
            "previous_compliance": (detail.get("oldEvaluationResult") or {}).get("complianceType", "NONE"),
        },
    )
    return [finding]


def cloudtrail_change(
    event: dict[str, Any], catalog: Catalog, approved_principals: frozenset[str] = frozenset(), **_: Any
) -> Normalised:
    detail = event["detail"]
    result = attribute(detail, approved_principals)
    if result is None:
        return []
    account = str(detail.get("recipientAccountId", event["account"]))
    region = str(detail.get("awsRegion", event["region"]))
    return [
        Finding(
            control_id=result.control_id,
            source="cloudtrail",
            source_event_id=str(detail["eventID"]),
            resource=_resource(result.resource_type, result.resource_id, account, region),
            compliance=Compliance.COMPLIANT if result.authorized else Compliance.NON_COMPLIANT,
            observed_at=str(detail["eventTime"]),
            title=catalog.get(result.control_id).title,
            annotation=f"{result.event_name}: {result.reason}",
            synthetic=event["source"] == SYNTHETIC_SOURCE,
            details={
                "event_name": result.event_name,
                "principal_arn": result.principal_arn,
                "principal_type": result.principal_type,
                "authorized": result.authorized,
            },
        )
    ]


def access_analyzer(event: dict[str, Any], catalog: Catalog, **_: Any) -> Normalised:
    detail = event["detail"]
    control_id = {"AWS::S3::Bucket": "SEC-001", "AWS::IAM::Role": "SEC-010"}.get(detail["resourceType"])
    if control_id is None:
        return []
    active = detail["status"] == "ACTIVE"
    return [
        Finding(
            control_id=control_id,
            source="access-analyzer",
            source_event_id=event["id"],
            resource=_resource(detail["resourceType"], detail["resource"], detail["accountId"], event["region"]),
            compliance=Compliance.NON_COMPLIANT if active else Compliance.COMPLIANT,
            observed_at=str(detail.get("updatedAt", event["time"])),
            title=catalog.get(control_id).title,
            annotation="external access" + (" (public)" if detail.get("isPublic") else ""),
            details={"analyzer_finding_id": detail["id"], "is_public": bool(detail.get("isPublic"))},
        )
    ]


_ASFF_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFORMATIONAL,
}


def security_hub(event: dict[str, Any], catalog: Catalog, **_: Any) -> Normalised:
    out: Normalised = []
    for item in event["detail"]["findings"]:
        product = str((item.get("ProductFields") or {}).get("aws/securityhub/ProductName", ""))
        if product == "Config":
            continue  # Config evaluations are ingested directly (ADR 0004)
        if item.get("RecordState") == "ARCHIVED":
            continue
        compliance_block = item.get("Compliance") or {}
        security_control = compliance_block.get("SecurityControlId", "")
        control_id = catalog.control_for_securityhub(security_control) or "EXT-SECURITYHUB"
        status = compliance_block.get("Status")
        compliance = (
            Compliance.COMPLIANT
            if status == "PASSED" or (item.get("Workflow") or {}).get("Status") == "RESOLVED"
            else Compliance.NON_COMPLIANT
        )
        resource = (item.get("Resources") or [{}])[0]
        out.append(
            Finding(
                control_id=control_id,
                source="securityhub",
                source_event_id=str(item.get("Id", event["id"])),
                resource=_resource(
                    str(resource.get("Type", "Other")),
                    str(resource.get("Id", "unknown")),
                    str(item.get("AwsAccountId", event["account"])),
                    str(resource.get("Region", item.get("Region", event["region"]))),
                ),
                compliance=compliance,
                observed_at=str(item.get("UpdatedAt", event["time"])),
                severity=_ASFF_SEVERITY.get(str((item.get("Severity") or {}).get("Label", "MEDIUM")), Severity.MEDIUM),
                title=str(item.get("Title", ""))[:200],
                sample=bool((item.get("ProductFields") or {}).get("sample")),
                details={"security_control_id": security_control, "product": product},
            )
        )
    return out


def guardduty_severity(score: float) -> Severity:
    """GuardDuty numeric severity bands: 1-3.9 low, 4-6.9 medium, 7-8.9 high, 9-10 critical."""
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def guardduty(event: dict[str, Any], catalog: Catalog, **_: Any) -> Normalised:
    detail = event["detail"]
    resource = detail.get("resource") or {}
    resource_type = str(resource.get("resourceType", "Unknown"))
    sample = bool(((detail.get("service") or {}).get("additionalInfo") or {}).get("sample"))
    return [
        Finding(
            control_id="EXT-GUARDDUTY",
            source="guardduty",
            source_event_id=str(detail["id"]),
            resource=Resource(f"GuardDuty::{resource_type}", str(detail["id"]), detail["accountId"], detail["region"]),
            compliance=Compliance.NON_COMPLIANT,
            observed_at=str(detail.get("updatedAt", event["time"])),
            severity=guardduty_severity(float(detail["severity"])),
            title=str(detail.get("title", detail["type"]))[:200],
            sample=sample,
            details={"type": detail["type"]},
        )
    ]


def ssm_status(event: dict[str, Any], catalog: Catalog, **_: Any) -> Normalised:
    detail = event["detail"]
    if not str(detail["Definition"]).startswith("acscg-"):
        return []
    return [
        RemediationStatus(
            execution_id=detail["ExecutionId"],
            document_name=detail["Definition"],
            status=detail["Status"],
            source_event_id=event["id"],
            observed_at=str(detail.get("EndTime") or event["time"]),
        )
    ]


NORMALISERS: dict[str, Callable[..., Normalised]] = {
    "Config Rules Compliance Change": config_change,
    "AWS API Call via CloudTrail": cloudtrail_change,
    "Access Analyzer Finding": access_analyzer,
    "Security Hub Findings - Imported": security_hub,
    "GuardDuty Finding": guardduty,
    "EC2 Automation Execution Status-change Notification": ssm_status,
}


def normalise(event: dict[str, Any], catalog: Catalog, approved_principals: frozenset[str] = frozenset()) -> Normalised:
    return NORMALISERS[event["detail-type"]](event, catalog, approved_principals=approved_principals)
