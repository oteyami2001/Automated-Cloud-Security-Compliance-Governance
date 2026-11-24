"""SEC-013: required tag keys and allowed values."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DEFAULT_ALLOWED_VALUES: dict[str, set[str]] = {
    "Environment": {"dev", "staging", "prod"},
    "ManagedBy": {"terraform", "manual", "aws"},
    "DataClassification": {"public", "internal", "confidential", "restricted", "audit-evidence"},
}


@dataclass(frozen=True)
class TagResult:
    missing: tuple[str, ...] = ()
    invalid: dict[str, str] = field(default_factory=dict)

    @property
    def compliant(self) -> bool:
        return not self.missing and not self.invalid


def normalise_tags(tags: Any) -> dict[str, str]:
    """Accept {"k": "v"}, [{"Key": k, "Value": v}] and [{"key": k, "value": v}]."""
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): "" if v is None else str(v) for k, v in tags.items()}
    result = {}
    for item in tags:
        key = item.get("Key", item.get("key"))
        value = item.get("Value", item.get("value", ""))
        if key is not None:
            result[str(key)] = "" if value is None else str(value)
    return result


def evaluate_tags(
    tags: Any,
    required: tuple[str, ...] | list[str],
    allowed_values: dict[str, set[str]] | None = None,
) -> TagResult:
    present = normalise_tags(tags)
    allowed = DEFAULT_ALLOWED_VALUES if allowed_values is None else allowed_values
    missing = tuple(k for k in required if not present.get(k, "").strip())
    invalid = {
        k: present[k]
        for k in required
        if k in present and present[k].strip() and k in allowed and present[k] not in allowed[k]
    }
    return TagResult(missing=missing, invalid=invalid)
