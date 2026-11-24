"""SEC-012 / SEC-015: attribute CloudTrail change events to approved or unapproved principals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# eventSource -> eventName -> control
MONITORED: dict[str, dict[str, str]] = {
    "cloudtrail.amazonaws.com": {
        "StopLogging": "SEC-012",
        "DeleteTrail": "SEC-012",
        "UpdateTrail": "SEC-012",
        "PutEventSelectors": "SEC-012",
    },
    "ec2.amazonaws.com": {
        name: "SEC-015"
        for name in (
            "AuthorizeSecurityGroupIngress",
            "RevokeSecurityGroupIngress",
            "AuthorizeSecurityGroupEgress",
            "RevokeSecurityGroupEgress",
            "ModifySecurityGroupRules",
        )
    },
    "s3.amazonaws.com": {
        name: "SEC-015"
        for name in (
            "PutBucketPolicy",
            "DeleteBucketPolicy",
            "PutBucketPublicAccessBlock",
            "DeleteBucketPublicAccessBlock",
            "PutBucketAcl",
        )
    },
    "config.amazonaws.com": {
        name: "SEC-015"
        for name in (
            "StopConfigurationRecorder",
            "DeleteConfigurationRecorder",
            "PutConfigurationRecorder",
            "DeleteDeliveryChannel",
            "DeleteConfigRule",
        )
    },
    "iam.amazonaws.com": {
        name: "SEC-015"
        for name in (
            "CreatePolicyVersion",
            "SetDefaultPolicyVersion",
            "PutRolePolicy",
            "AttachRolePolicy",
            "PutUserPolicy",
            "AttachUserPolicy",
            "UpdateAssumeRolePolicy",
        )
    },
}

# (resource type, requestParameters key) per event source
RESOURCE_KEYS: dict[str, tuple[str, tuple[str, ...]]] = {
    "cloudtrail.amazonaws.com": ("AWS::CloudTrail::Trail", ("name", "trailName")),
    "ec2.amazonaws.com": ("AWS::EC2::SecurityGroup", ("groupId",)),
    "s3.amazonaws.com": ("AWS::S3::Bucket", ("bucketName",)),
    "config.amazonaws.com": (
        "AWS::Config::ConfigurationRecorder",
        ("configurationRecorderName", "configRuleName", "deliveryChannelName"),
    ),
    "iam.amazonaws.com": ("AWS::IAM::Policy", ("policyArn", "roleName", "userName")),
}


@dataclass(frozen=True)
class ChangeAttribution:
    control_id: str
    event_name: str
    resource_type: str
    resource_id: str
    principal_arn: str
    principal_type: str
    authorized: bool
    reason: str


def principal_of(user_identity: dict[str, Any]) -> tuple[str, str]:
    """Return (principal ARN, identity type). Assumed roles resolve to the role (session issuer) ARN."""
    identity_type = str(user_identity.get("type", "Unknown"))
    issuer = user_identity.get("sessionContext", {}).get("sessionIssuer", {})
    if identity_type == "AssumedRole" and issuer.get("arn"):
        return str(issuer["arn"]), identity_type
    return str(user_identity.get("arn", user_identity.get("invokedBy", "unknown"))), identity_type


def _resource_id(event_source: str, params: dict[str, Any]) -> str:
    _, keys = RESOURCE_KEYS[event_source]
    for key in keys:
        if params.get(key):
            return str(params[key])
    if event_source == "ec2.amazonaws.com":
        for item in params.get("ModifySecurityGroupRulesRequest", {}).get("GroupId", []) or []:
            return str(item)
        if params.get("GroupId"):
            return str(params["GroupId"])
    return "unknown"


def attribute(detail: dict[str, Any], approved_principals: set[str] | frozenset[str]) -> ChangeAttribution | None:
    """Classify a CloudTrail ``detail``. Returns None for events that are not monitored or failed."""
    source = detail.get("eventSource", "")
    name = detail.get("eventName", "")
    control = MONITORED.get(source, {}).get(name)
    if control is None:
        return None
    if detail.get("errorCode"):
        return None  # the call failed; nothing changed
    principal, identity_type = principal_of(detail.get("userIdentity", {}))
    resource_type, _ = RESOURCE_KEYS[source]
    resource_id = _resource_id(source, detail.get("requestParameters") or {})
    authorized = principal in approved_principals
    reason = (
        "approved change principal" if authorized else f"{identity_type} principal is not an approved change principal"
    )
    return ChangeAttribution(control, name, resource_type, resource_id, principal, identity_type, authorized, reason)
