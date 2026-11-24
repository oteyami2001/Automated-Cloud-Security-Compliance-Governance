"""Resource ownership: project-owned resources are the only ones that can ever be remediated."""

from __future__ import annotations

from acscg.common.models import Ownership, Resource
from acscg.remediation_engine.policy import PlatformPolicy


def resolve(resource: Resource, policy: PlatformPolicy) -> Ownership:
    """Protected (pre-existing) wins over everything; inventory comes from Terraform state, not tags."""
    identifier = resource.identifier
    if identifier in policy.protected_resources:
        return Ownership.PRE_EXISTING
    if identifier in policy.project_inventory:
        return Ownership.PROJECT_OWNED
    return Ownership.UNKNOWN
