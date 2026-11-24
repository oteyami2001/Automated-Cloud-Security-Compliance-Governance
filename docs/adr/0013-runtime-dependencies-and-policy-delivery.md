# ADR 0013: Standard-library runtime and a Terraform-rendered policy parameter

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The Lambdas must stay small and reproducible, and must avoid compiled third-party dependencies
(arm64 builds). The remediation policy (mode, allowlist, approvers, inventory) must be changeable
only through the reviewed Terraform pipeline, and readable by two Lambdas.

## Decision

1. **Runtime dependencies:** the standard library plus `boto3`, which the Lambda Python 3.13
   runtime provides. No PyYAML or jsonschema at runtime: event validation is a small declarative
   type check (`findings_processor/validation.py`), and the catalog ships as generated JSON
   (`scripts/build_lambda.py`, checked in CI). The package is a deterministic zip with fixed
   timestamps and sorted entries. The same commit always gives the same SHA-256.
2. **Policy delivery:** Terraform renders `policies/remediation/<env>.yaml`. It adds approvers
   (sensitive TF_VAR), the remediable inventory (fixture ARNs from state), approved change
   principals and project roles, and stores the result as an **SSM SecureString** (project KMS
   key, Standard tier, ≤ 4 KB enforced by a precondition). Only the apply role can write it. The
   Lambdas read it with a 60-second cache and parse it strictly. A parse error denies everything.
3. **Logging:** functions use Lambda's `Text` log format because the code writes its own masked
   JSON lines. The dashboard's metric filter and Logs Insights query rely on that format.

## Consequences

- Dev and test dependencies (PyYAML, jsonschema, moto) are pinned and hash-locked, but never deployed.
- Changing the allowlist always shows up in a plan diff of `aws_ssm_parameter.policy`.

## Alternatives considered

Lambda layers with PyYAML/jsonschema (rpds-py is compiled, so it needs a per-architecture build).
AppConfig for the policy (more moving parts, no gain at this size). Environment variables (4 KB
limit shared with the other settings, and visible to anyone who can read the function configuration).
