"""Core domain model: severities, compliance, lifecycle states, resources and findings."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum, StrEnum
from typing import Any


class Severity(Enum):
    """Ordered severity levels (comparison uses the rank)."""

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}") from exc

    def __lt__(self, other: Severity) -> bool:
        return self.value < other.value

    def __le__(self, other: Severity) -> bool:
        return self.value <= other.value

    def __gt__(self, other: Severity) -> bool:
        return self.value > other.value

    def __ge__(self, other: Severity) -> bool:
        return self.value >= other.value

    @property
    def label(self) -> str:
        return self.name.lower()


class Compliance(StrEnum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class FindingState(StrEnum):
    """Finding lifecycle states (diagrams/remediation-flow.mmd)."""

    COMPLIANT = "COMPLIANT"
    OPEN = "OPEN"
    SUPPRESSED_EXCEPTION = "SUPPRESSED_EXCEPTION"
    REPORTED = "REPORTED"
    REJECTED_POLICY = "REJECTED_POLICY"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    REMEDIATING = "REMEDIATING"
    REMEDIATION_REJECTED = "REMEDIATION_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    VERIFYING = "VERIFYING"
    VERIFIED_RESOLVED = "VERIFIED_RESOLVED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    RESOLVED_EXTERNALLY = "RESOLVED_EXTERNALLY"

    @property
    def is_open(self) -> bool:
        """True while the underlying violation is believed to exist."""
        return self not in {
            FindingState.COMPLIANT,
            FindingState.VERIFIED_RESOLVED,
            FindingState.RESOLVED_EXTERNALLY,
        }


class Ownership(StrEnum):
    PROJECT_OWNED = "project-owned"
    PRE_EXISTING = "pre-existing"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Resource:
    """A cloud resource. ``identifier`` is the ARN when derivable, otherwise ``config:<type>:<id>``."""

    resource_type: str
    resource_id: str
    account: str
    region: str
    arn: str | None = None

    @property
    def identifier(self) -> str:
        return self.arn or f"config:{self.resource_type}:{self.resource_id}"


def finding_key(control_id: str, resource: Resource) -> str:
    """Canonical key: one violation of one control on one resource is one finding (ADR 0009)."""
    material = "|".join([control_id, resource.account, resource.region, resource.identifier])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    """A normalised observation produced from any source."""

    control_id: str
    source: str
    source_event_id: str
    resource: Resource
    compliance: Compliance
    observed_at: str
    severity: Severity = Severity.MEDIUM
    title: str = ""
    annotation: str = ""
    synthetic: bool = False
    sample: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return finding_key(self.control_id, self.resource)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        data["compliance"] = str(self.compliance)
        data["finding_key"] = self.key
        data["resource"]["identifier"] = self.resource.identifier
        return data


@dataclass(frozen=True)
class RemediationStatus:
    """A status change of a remediation execution (SSM Automation)."""

    execution_id: str
    document_name: str
    status: str
    source_event_id: str
    observed_at: str
