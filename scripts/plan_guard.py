#!/usr/bin/env python3
"""Fail-closed plan guard and plan digest (ADR 0008).

    plan_guard.py check  <plan.json> --mode apply|destroy     # guard + print digest
    plan_guard.py verify <plan.json> --mode apply|destroy --expected <digest>

``plan.json`` is the output of ``terraform show -json tfplan``. The guard rejects plans that:
  * are not a plan document (fail closed);
  * change an account-level security service the stack does not own (ADR 0003) - those types may
    only change when the matching *_mode variable is "create";
  * touch the shared GitHub OIDC provider or anything belonging to other projects (aiops-, idp-);
  * delete evidence, keys or the findings table outside destroy mode;
  * create or update an IAM role without a permissions boundary (stack plans);
  * contain anything but deletes in destroy mode.

The digest is SHA-256 over the mode plus every planned change (address, actions, after-values),
canonically serialised. It is printed; the plan file and the values are never printed or uploaded.
Exit codes: 0 ok, 1 guard violation or digest mismatch, 2 invalid input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

# resource type -> plan variable that must be "create" for the stack to change it
OWNED_ONLY_WHEN_CREATED = {
    "aws_config_configuration_recorder": "config_ownership_mode",
    "aws_config_configuration_recorder_status": "config_ownership_mode",
    "aws_config_delivery_channel": "config_ownership_mode",
    "aws_cloudtrail": "cloudtrail_mode",
    "aws_securityhub_account": "security_hub_mode",
    "aws_securityhub_standards_subscription": "security_hub_mode",
    "aws_guardduty_detector": "guardduty_mode",
    "aws_guardduty_detector_feature": "guardduty_mode",
}
NEVER_TOUCH_TYPES = {
    "aws_iam_openid_connect_provider",
    "aws_organizations_policy",
    "aws_organizations_policy_attachment",
}
FOREIGN = re.compile(r"(^|[:/])(aiops|idp)-")
NAME_FIELDS = ("name", "bucket", "function_name", "role", "table_name", "alarm_name", "dashboard_name", "arn")
PROTECTED_FROM_DELETE = {"aws_kms_key", "aws_dynamodb_table"}
PROTECTED_ADDRESS = re.compile(r"(evidence|state)")
CHANGE = {"create", "update", "delete"}


class PlanError(ValueError):
    pass


def load_plan(path: Path) -> dict[str, Any]:
    try:
        plan = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PlanError(f"cannot read plan JSON: {exc}") from exc
    if (
        not isinstance(plan, dict)
        or "format_version" not in plan
        or ("resource_changes" not in plan and "planned_values" not in plan)
    ):
        raise PlanError("document is not a terraform plan (terraform show -json output expected)")
    if plan.get("errored"):
        raise PlanError("plan errored")
    return plan


def changes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        rc
        for rc in plan.get("resource_changes", [])
        if rc.get("mode", "managed") == "managed" and set(rc["change"]["actions"]) & CHANGE
    ]


def variable(plan: dict[str, Any], name: str, default: str = "") -> str:
    return str(plan.get("variables", {}).get(name, {}).get("value", default))


def _names(rc: dict[str, Any]) -> list[str]:
    values = []
    for side in ("before", "after"):
        data = rc["change"].get(side) or {}
        values += [str(data[f]) for f in NAME_FIELDS if isinstance(data.get(f), str)]
    return values


def guard(plan: dict[str, Any], mode: str, *, require_boundary: bool = True) -> list[str]:
    violations = []
    for rc in changes(plan):
        address, rtype, actions = rc["address"], rc["type"], set(rc["change"]["actions"])
        if mode == "destroy" and actions != {"delete"}:
            violations.append(f"{address}: destroy plans may only delete ({sorted(actions)})")
        if rtype in NEVER_TOUCH_TYPES:
            violations.append(f"{address}: {rtype} is shared or organisation-level and is never managed here")
        mode_var = OWNED_ONLY_WHEN_CREATED.get(rtype)
        if mode_var and variable(plan, mode_var, "create") != "create":
            violations.append(f"{address}: {rtype} may change only when {mode_var} = create (ADR 0003)")
        if any(FOREIGN.search(n) for n in _names(rc)):
            violations.append(f"{address}: touches a resource of another project")
        protected = rtype in PROTECTED_FROM_DELETE or (
            rtype.startswith("aws_s3_bucket") and PROTECTED_ADDRESS.search(address) is not None
        )
        if mode != "destroy" and "delete" in actions and protected:
            violations.append(f"{address}: protected resource would be deleted or replaced outside destroy mode")
        if require_boundary and rtype == "aws_iam_role" and actions & {"create", "update"}:
            after = rc["change"].get("after") or {}
            if not after.get("permissions_boundary") and "permissions_boundary" not in (
                rc["change"].get("after_unknown") or {}
            ):
                violations.append(f"{address}: IAM role without permissions boundary")
    return violations


def digest(plan: dict[str, Any], mode: str) -> str:
    material = {
        "mode": mode,
        "changes": sorted(
            (
                {
                    "address": rc["address"],
                    "actions": rc["change"]["actions"],
                    "after": rc["change"].get("after"),
                    "after_unknown": rc["change"].get("after_unknown"),
                }
                for rc in changes(plan)
            ),
            key=lambda c: c["address"],
        ),
    }
    text = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def summary(plan: dict[str, Any]) -> list[str]:
    """Addresses and actions only: never values (public CI logs)."""
    return [
        f"{'/'.join(rc['change']['actions'])}: {rc['address']}"
        for rc in sorted(changes(plan), key=lambda r: r["address"])
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["check", "verify"])
    parser.add_argument("plan", type=Path)
    parser.add_argument("--mode", choices=["apply", "destroy"], required=True)
    parser.add_argument("--expected")
    parser.add_argument(
        "--no-boundary-check", action="store_true", help="bootstrap plans (CI roles have no workload boundary)"
    )
    args = parser.parse_args(argv)
    try:
        plan = load_plan(args.plan)
    except PlanError as exc:
        print(f"::error::{exc}")
        return 2
    violations = guard(plan, args.mode, require_boundary=not args.no_boundary_check)
    for line in summary(plan):
        print(line)
    print(f"Planned changes: {len(changes(plan))}")
    if violations:
        for v in violations:
            print(f"::error::plan guard: {v}")
        return 1
    value = digest(plan, args.mode)
    if args.command == "check":
        print(f"digest={value}")
        return 0
    if not args.expected or not re.fullmatch(r"[0-9a-f]{64}", args.expected):
        print("::error::--expected must be 64 lowercase hex characters")
        return 2
    if value != args.expected:
        print("::error::plan digest does not match the reviewed plan; refusing to apply")
        return 1
    print("Plan digest matches the reviewed plan.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
