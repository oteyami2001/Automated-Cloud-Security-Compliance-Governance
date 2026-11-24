"""Shared fixtures: an offline processor wired to in-memory fakes, and event builders.

Account 111122223333 and the 203.0.113.0/24 range are documentation values, not real identifiers.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from acscg.common.catalog import Catalog  # noqa: E402
from acscg.common.settings import Settings  # noqa: E402
from acscg.evidence_collector.sink import InMemoryEvidenceSink  # noqa: E402
from acscg.findings_processor.ports import (  # noqa: E402
    RecordingNotifier,
    RecordingRequester,
    StaticInspector,
    StaticPolicyProvider,
    StaticVerifier,
)
from acscg.findings_processor.processor import Processor  # noqa: E402
from acscg.findings_processor.store import InMemoryStore  # noqa: E402
from acscg.remediation_engine.policy import PlatformPolicy, parse_policy  # noqa: E402

ACCOUNT = "111122223333"
REGION = "us-east-2"
SG_ID = "sg-0123456789abcdef0"
SG_ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/{SG_ID}"
BUCKET = "acscg-dev-fixture-bucket"
BUCKET_ARN = f"arn:aws:s3:::{BUCKET}"
APPLY_ROLE = f"arn:aws:iam::{ACCOUNT}:role/acscg-github-apply"
APPROVER = f"arn:aws:iam::{ACCOUNT}:role/security-approver"


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    return Catalog.load_file(ROOT / "controls" / "control-catalog.yaml")


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "dev",
        "account_id": ACCOUNT,
        "region": REGION,
        "table_name": "acscg-dev-findings",
        "evidence_bucket": "acscg-dev-evidence",
        "topic_arn": f"arn:aws:sns:{REGION}:{ACCOUNT}:acscg-dev-security-alerts",
        "allow_synthetic_events": True,
        "kms_key_id": "alias/acscg-dev-evidence",
    }
    values.update(overrides)
    return Settings(**values)


def policy_document(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "environment": "dev",
        "remediation_enabled": True,
        "remediation_mode": "human_approval",
        "approval": {"approvers": [APPROVER], "timeout_minutes": 240},
        "limits": {"max_attempts_per_finding": 2},
        "allowlist": [
            {
                "id": "AL-001",
                "control_id": "SEC-005",
                "action": "ec2:RevokeSecurityGroupIngress",
                "account": ACCOUNT,
                "region": REGION,
                "resource_arn": SG_ARN,
                "expires_at": "2099-01-01T00:00:00Z",
                "reason": "scenario 9-11",
            },
            {
                "id": "AL-002",
                "control_id": "SEC-001",
                "action": "s3:PutBucketPublicAccessBlock",
                "account": ACCOUNT,
                "region": REGION,
                "resource_arn": BUCKET_ARN,
                "expires_at": "2099-01-01T00:00:00Z",
                "reason": "scenario 8",
            },
        ],
        "protected_resources": [],
        "project_inventory": [SG_ARN, BUCKET_ARN],
        "approved_change_principals": [APPLY_ROLE],
        "project_role_arns": [APPLY_ROLE],
    }
    doc.update(overrides)
    return doc


def make_policy(**overrides: Any) -> PlatformPolicy:
    return parse_policy(policy_document(**overrides))


class Clock:
    """Deterministic, strictly increasing timestamps."""

    def __init__(self) -> None:
        self._ticks = itertools.count()

    def __call__(self) -> str:
        n = next(self._ticks)
        return f"2026-11-24T10:{n // 60:02d}:{n % 60:02d}Z"


class Harness:
    def __init__(self, catalog: Catalog, settings: Settings, policy: PlatformPolicy) -> None:
        self.store = InMemoryStore()
        self.evidence = InMemoryEvidenceSink()
        self.notifier = RecordingNotifier()
        self.requester = RecordingRequester()
        self.inspector = StaticInspector()
        self.verifier = StaticVerifier()
        self.clock = Clock()
        self.processor = Processor(
            settings=settings,
            catalog=catalog,
            store=self.store,
            evidence=self.evidence,
            notifier=self.notifier,
            requester=self.requester,
            policy_provider=StaticPolicyProvider(policy),
            inspector=self.inspector,
            verifier=self.verifier,
            clock=self.clock,
        )

    def finding(self, key: str) -> dict[str, Any]:
        item = self.store.get_finding(key)
        assert item is not None
        return item


@pytest.fixture
def harness(catalog: Catalog) -> Harness:
    return Harness(catalog, make_settings(remediation_enabled=True, remediation_mode="human_approval"), make_policy())


@pytest.fixture
def report_only_harness(catalog: Catalog) -> Harness:
    return Harness(catalog, make_settings(), make_policy(remediation_enabled=False, remediation_mode="report_only"))


_ids = itertools.count(1)


def config_event(
    rule: str = "acscg-sec005-restricted-ssh",
    resource_type: str = "AWS::EC2::SecurityGroup",
    resource_id: str = SG_ID,
    compliance: str = "NON_COMPLIANT",
    event_id: str | None = None,
    source: str = "aws.config",
    previous: str = "COMPLIANT",
) -> dict[str, Any]:
    return {
        "version": "0",
        "id": event_id or f"evt-{next(_ids)}",
        "detail-type": "Config Rules Compliance Change",
        "source": source,
        "account": ACCOUNT,
        "time": "2026-11-24T09:00:00Z",
        "region": REGION,
        "resources": [],
        "detail": {
            "resourceId": resource_id,
            "awsRegion": REGION,
            "awsAccountId": ACCOUNT,
            "configRuleName": rule,
            "recordVersion": "1.0",
            "messageType": "ComplianceChangeNotification",
            "resourceType": resource_type,
            "newEvaluationResult": {
                "evaluationResultIdentifier": {
                    "evaluationResultQualifier": {
                        "configRuleName": rule,
                        "resourceType": resource_type,
                        "resourceId": resource_id,
                    },
                    "orderingTimestamp": "2026-11-24T08:59:00Z",
                },
                "complianceType": compliance,
                "resultRecordedTime": "2026-11-24T09:00:00Z",
                "annotation": "test",
            },
            "oldEvaluationResult": {"complianceType": previous},
        },
    }


def cloudtrail_event(
    event_name: str = "AuthorizeSecurityGroupIngress",
    event_source: str = "ec2.amazonaws.com",
    principal: str = f"arn:aws:iam::{ACCOUNT}:role/ConsoleAdmin",
    params: dict[str, Any] | None = None,
    error: str | None = None,
    event_id: str | None = None,
    source: str = "aws.ec2",
) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "eventVersion": "1.09",
        "eventSource": event_source,
        "eventName": event_name,
        "eventTime": "2026-11-24T09:05:00Z",
        "eventID": event_id or f"ct-{next(_ids)}",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": principal.replace(":role/", ":assumed-role/") + "/session",
            "sessionContext": {"sessionIssuer": {"type": "Role", "arn": principal}},
        },
        "requestParameters": params if params is not None else {"groupId": SG_ID},
    }
    if error:
        detail["errorCode"] = error
    return {
        "version": "0",
        "id": f"eb-{next(_ids)}",
        "detail-type": "AWS API Call via CloudTrail",
        "source": source,
        "account": ACCOUNT,
        "time": "2026-11-24T09:05:00Z",
        "region": REGION,
        "resources": [],
        "detail": detail,
    }


def ssm_status_event(
    execution_id: str, status: str, definition: str = "acscg-RestrictSecurityGroupIngress"
) -> dict[str, Any]:
    return {
        "version": "0",
        "id": f"ssm-{next(_ids)}",
        "detail-type": "EC2 Automation Execution Status-change Notification",
        "source": "aws.ssm",
        "account": ACCOUNT,
        "time": "2026-11-24T09:30:00Z",
        "region": REGION,
        "resources": [],
        "detail": {
            "ExecutionId": execution_id,
            "Definition": definition,
            "Status": status,
            "EndTime": "2026-11-24T09:30:00Z",
        },
    }
