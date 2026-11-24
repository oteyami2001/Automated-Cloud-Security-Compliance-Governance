"""Severity classification: catalog base severity plus deterministic escalation rules."""

from __future__ import annotations

from acscg.common.catalog import Catalog
from acscg.common.models import Finding, Severity

EXTERNAL_SOURCES = {"guardduty", "securityhub"}


def classify(finding: Finding, catalog: Catalog, data_classification: str | None = None) -> Severity:
    """Return the severity for a finding.

    * GuardDuty / Security Hub keep their source severity (already mapped) unless the finding maps
      to a catalog control with a higher base severity.
    * SEC-001 escalates to critical when public access is confirmed (Access Analyzer ``isPublic``).
    * SEC-003 escalates to high for buckets classified ``audit-evidence``.
    * SEC-015 changes to audit services (CloudTrail, Config) escalate to critical.
    """
    control = catalog.get(finding.control_id)
    severity = control.severity
    if finding.source in EXTERNAL_SOURCES:
        severity = max(severity, finding.severity) if finding.control_id.startswith("SEC-") else finding.severity
    if finding.control_id == "SEC-001" and finding.details.get("is_public"):
        severity = Severity.CRITICAL
    if finding.control_id == "SEC-003" and data_classification == "audit-evidence":
        severity = max(severity, Severity.HIGH)
    if finding.control_id == "SEC-015" and finding.resource.resource_type in {
        "AWS::CloudTrail::Trail",
        "AWS::Config::ConfigurationRecorder",
    }:
        severity = Severity.CRITICAL
    return severity
