"""The only remediation actions the platform can request, one SSM document each."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RemediationAction:
    control_ids: tuple[str, ...]
    action: str  # IAM action the runbook performs
    document: str  # SSM Automation document name (created by Terraform)
    always_requires_approval: bool


ACTIONS: tuple[RemediationAction, ...] = (
    RemediationAction(("SEC-001",), "s3:PutBucketPublicAccessBlock", "acscg-EnableBucketPublicAccessBlock", False),
    RemediationAction(
        ("SEC-005", "SEC-006"), "ec2:RevokeSecurityGroupIngress", "acscg-RestrictSecurityGroupIngress", True
    ),
    RemediationAction(("SEC-008",), "ec2:ModifyInstanceMetadataOptions", "acscg-EnforceImdsV2", True),
    RemediationAction(("SEC-013",), "tag:TagResources", "acscg-EnforceRequiredTags", False),
    RemediationAction(("SEC-014",), "logs:PutRetentionPolicy", "acscg-SetLogRetention", False),
)


def action_for(control_id: str) -> RemediationAction | None:
    for action in ACTIONS:
        if control_id in action.control_ids:
            return action
    return None


def document_names() -> set[str]:
    return {a.document for a in ACTIONS}
