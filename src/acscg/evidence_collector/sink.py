"""Evidence sinks: S3 (SSE-KMS, checksum metadata, Object Lock defaults from the bucket) and in-memory."""

from __future__ import annotations

from typing import Any, Protocol

from acscg.common.canonical import canonical_json
from acscg.evidence_collector.builder import evidence_key


class EvidenceSink(Protocol):
    def put(self, document: dict[str, Any]) -> str: ...


class InMemoryEvidenceSink:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}

    def put(self, document: dict[str, Any]) -> str:
        key = evidence_key(document)
        if key in self.objects:
            raise FileExistsError(key)  # evidence is write-once
        self.objects[key] = document
        return key


class S3EvidenceSink:
    def __init__(self, client: Any, bucket: str, kms_key_id: str) -> None:
        if not kms_key_id:
            raise ValueError("evidence requires a KMS key")
        self.client = client
        self.bucket = bucket
        self.kms_key_id = kms_key_id

    def put(self, document: dict[str, Any]) -> str:
        key = evidence_key(document)
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=canonical_json(document).encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms_key_id,
            ChecksumAlgorithm="SHA256",
            Metadata={"acscg-sha256": document["checksum"]["sha256"]},
            IfNoneMatch="*",  # never overwrite an existing evidence object
        )
        return key
