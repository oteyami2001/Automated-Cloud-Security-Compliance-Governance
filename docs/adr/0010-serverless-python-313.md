# ADR 0010: Serverless runtime: Python 3.13 Lambda (arm64), zip packages, no persistent compute

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The prompt requires Python 3.13 and avoiding unnecessary persistent compute. Project 2 standardised on Python 3.13 (its ADR 0006).

## Decision

- Lambda Python 3.13, arm64, zip deployment built reproducibly in CI. Runtime dependencies limited to boto3 from the runtime where possible.
- No EC2, ECS, EKS, RDS, ALB or NAT Gateway. Lambdas run outside a VPC (they call only AWS APIs), so there is no NAT cost.
- Reserved concurrency caps per function.

## Consequences

- Idle cost near zero. Cold starts are acceptable for security events.
- Out-of-VPC Lambdas rely on IAM, not network controls, for protection. That is acceptable because they expose no inbound endpoint.

## Alternatives considered

Container images: an ECR repository and image scanning add cost and process with no benefit at this size.
