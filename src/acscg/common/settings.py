"""Runtime settings from environment variables. Missing or invalid values fail closed."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass

REMEDIATION_MODES = ("report_only", "auto_low_risk", "human_approval")
ENVIRONMENTS = ("dev", "staging", "prod")


class SettingsError(ValueError):
    """Raised when configuration is missing or invalid. The function must not continue."""


def _flag(value: str | None) -> bool:
    if value is None:
        return False
    normalised = value.strip().lower()
    if normalised in {"true", "1", "yes"}:
        return True
    if normalised in {"false", "0", "no", ""}:
        return False
    raise SettingsError(f"invalid boolean {value!r}")


@dataclass(frozen=True)
class Settings:
    environment: str
    account_id: str
    region: str
    table_name: str
    evidence_bucket: str
    topic_arn: str
    remediation_mode: str = "report_only"
    remediation_enabled: bool = False
    allow_synthetic_events: bool = False
    gatekeeper_function: str = ""
    policy_parameter: str = ""
    kms_key_id: str = ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        required = {
            "environment": "ACSCG_ENV",
            "account_id": "ACSCG_ACCOUNT_ID",
            "region": "ACSCG_REGION",
            "table_name": "ACSCG_TABLE",
            "evidence_bucket": "ACSCG_EVIDENCE_BUCKET",
            "topic_arn": "ACSCG_TOPIC_ARN",
        }
        values: dict[str, object] = {}
        missing = [var for var in required.values() if not env.get(var)]
        if missing:
            raise SettingsError(f"missing required settings: {', '.join(sorted(missing))}")
        for attr, var in required.items():
            values[attr] = env[var]
        values["remediation_mode"] = env.get("ACSCG_REMEDIATION_MODE", "report_only")
        values["remediation_enabled"] = _flag(env.get("ACSCG_REMEDIATION_ENABLED"))
        values["allow_synthetic_events"] = _flag(env.get("ACSCG_ALLOW_SYNTHETIC"))
        values["gatekeeper_function"] = env.get("ACSCG_GATEKEEPER_FUNCTION", "")
        values["policy_parameter"] = env.get("ACSCG_POLICY_PARAMETER", "")
        values["kms_key_id"] = env.get("ACSCG_KMS_KEY_ID", "")
        settings = cls(**values)  # type: ignore[arg-type]
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.environment not in ENVIRONMENTS:
            raise SettingsError(f"environment must be one of {ENVIRONMENTS}")
        if not re.fullmatch(r"\d{12}", self.account_id):
            raise SettingsError("account id must be 12 digits")
        if not re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-\d", self.region):
            raise SettingsError("invalid region")
        if self.remediation_mode not in REMEDIATION_MODES:
            raise SettingsError(f"remediation mode must be one of {REMEDIATION_MODES}")
        if self.allow_synthetic_events and self.environment != "dev":
            raise SettingsError("synthetic events are allowed only in dev")
        if self.remediation_enabled and self.environment == "prod":
            raise SettingsError("remediation cannot be enabled in prod without an ADR change")
