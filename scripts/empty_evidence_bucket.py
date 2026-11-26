#!/usr/bin/env python3
"""Empty the project's Object Lock evidence bucket before a verified destroy (scenario 17, Phase 9).

Called only by ``tf_ci.sh apply <env> destroy`` after the reviewed destroy digest matched, with the
cleanup role (the only principal the bucket policy lets bypass GOVERNANCE retention). Deletes every
object version and delete marker of exactly one bucket, ``acscg-<env>-evidence-<account>-<region>``,
then checks that nothing is left. Prints counts only: no keys, no account ID.

    python scripts/empty_evidence_bucket.py --env dev --region us-east-2 --confirm destroy-dev
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Iterator
from typing import Any

BATCH = 1000  # DeleteObjects limit
BUCKET = re.compile(r"^acscg-(dev|staging|prod)-evidence-\d{12}-[a-z]{2}-[a-z]+-\d$")


def bucket_name(env: str, account: str, region: str) -> str:
    name = f"acscg-{env}-evidence-{account}-{region}"
    if not BUCKET.match(name):
        raise ValueError("refusing: not a project evidence bucket name")
    return name


def versions(s3: Any, bucket: str) -> Iterator[dict[str, str]]:
    kwargs: dict[str, Any] = {"Bucket": bucket}
    while True:
        page = s3.list_object_versions(**kwargs)
        for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
            yield {"Key": item["Key"], "VersionId": item["VersionId"]}
        if not page.get("IsTruncated"):
            return
        kwargs["KeyMarker"] = page["NextKeyMarker"]
        kwargs["VersionIdMarker"] = page["NextVersionIdMarker"]


def empty(s3: Any, bucket: str) -> tuple[int, int]:
    """Delete all versions and markers; return (deleted, errors)."""
    deleted = errors = 0
    batch: list[dict[str, str]] = []

    def flush() -> None:
        nonlocal deleted, errors
        if not batch:
            return
        result = s3.delete_objects(
            Bucket=bucket, BypassGovernanceRetention=True, Delete={"Objects": list(batch), "Quiet": True}
        )
        failed = len(result.get("Errors", []))
        errors += failed
        deleted += len(batch) - failed
        batch.clear()

    for version in list(versions(s3, bucket)):  # list first: deleting while paging skips entries
        batch.append(version)
        if len(batch) == BATCH:
            flush()
    flush()
    return deleted, errors


def default_factory(region: str) -> tuple[Any, Any]:  # pragma: no cover - real AWS wiring
    import boto3  # noqa: PLC0415

    session = boto3.Session(region_name=region)
    return session.client("s3"), session.client("sts")


def main(argv: list[str] | None = None, factory: Callable[[str], tuple[Any, Any]] = default_factory) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env", required=True, choices=["dev", "staging", "prod"])
    parser.add_argument("--region", required=True)
    parser.add_argument("--confirm", required=True, help="must be destroy-<env>")
    args = parser.parse_args(argv)
    if args.confirm != f"destroy-{args.env}":
        print(f"refusing: --confirm must be destroy-{args.env}")
        return 2
    s3, sts = factory(args.region)
    bucket = bucket_name(args.env, sts.get_caller_identity()["Account"], args.region)
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:  # noqa: BLE001 - a missing bucket means there is nothing to empty
        print("evidence bucket not found: nothing to empty")
        return 0
    deleted, errors = empty(s3, bucket)
    left = sum(1 for _ in versions(s3, bucket))
    print(f"evidence bucket emptied: {deleted} versions/markers deleted, {errors} errors, {left} left")
    return 0 if errors == 0 and left == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
