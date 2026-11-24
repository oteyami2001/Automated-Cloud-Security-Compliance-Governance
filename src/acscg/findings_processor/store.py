"""Persistence for findings, idempotency keys, history, remediation requests and locks.

Single-table design (docs/architecture.md §4.2). :class:`InMemoryStore` implements the same
contract for offline tests; :class:`DynamoStore` uses conditional writes for idempotency and
optimistic locking.
"""

from __future__ import annotations

import time
from copy import deepcopy
from typing import Any, Protocol

IDEMPOTENCY_TTL_SECONDS = 7 * 24 * 3600
LOCK_TTL_SECONDS = 5 * 3600


class ConflictError(RuntimeError):
    """Optimistic-lock or conditional-write conflict."""


class Store(Protocol):
    def claim_event(self, event_id: str) -> bool: ...
    def release_event(self, event_id: str) -> None: ...
    def get_finding(self, key: str) -> dict[str, Any] | None: ...
    def put_finding(self, item: dict[str, Any], expected_version: int | None) -> None: ...
    def add_history(self, key: str, entry: dict[str, Any]) -> None: ...
    def history(self, key: str) -> list[dict[str, Any]]: ...
    def put_remediation(self, key: str, request: dict[str, Any]) -> None: ...
    def remediations(self, key: str) -> list[dict[str, Any]]: ...
    def find_remediation(self, execution_id: str) -> tuple[str, dict[str, Any]] | None: ...
    def acquire_lock(self, key: str, owner: str) -> bool: ...
    def release_lock(self, key: str, owner: str) -> None: ...
    def claim_notification(self, key: str, state: str, version: int) -> bool: ...
    def all_findings(self) -> list[dict[str, Any]]: ...
    def get_exception(self, control_id: str, resource_id: str) -> dict[str, Any] | None: ...


class InMemoryStore:
    def __init__(self) -> None:
        self.events: set[str] = set()
        self.findings: dict[str, dict[str, Any]] = {}
        self.hist: dict[str, list[dict[str, Any]]] = {}
        self.rems: dict[str, list[dict[str, Any]]] = {}
        self.locks: dict[str, str] = {}
        self.notifications: set[tuple[str, str, int]] = set()
        self.exceptions: dict[tuple[str, str], dict[str, Any]] = {}

    def claim_event(self, event_id: str) -> bool:
        if event_id in self.events:
            return False
        self.events.add(event_id)
        return True

    def release_event(self, event_id: str) -> None:
        self.events.discard(event_id)

    def get_finding(self, key: str) -> dict[str, Any] | None:
        item = self.findings.get(key)
        return deepcopy(item) if item else None

    def put_finding(self, item: dict[str, Any], expected_version: int | None) -> None:
        current = self.findings.get(item["finding_key"])
        current_version = current["version"] if current else None
        if current_version != expected_version:
            raise ConflictError(f"version {current_version} != expected {expected_version}")
        stored = deepcopy(item)
        stored["version"] = (expected_version or 0) + 1
        self.findings[item["finding_key"]] = stored

    def add_history(self, key: str, entry: dict[str, Any]) -> None:
        self.hist.setdefault(key, []).append(deepcopy(entry))

    def history(self, key: str) -> list[dict[str, Any]]:
        return deepcopy(self.hist.get(key, []))

    def put_remediation(self, key: str, request: dict[str, Any]) -> None:
        items = self.rems.setdefault(key, [])
        for index, existing in enumerate(items):
            if existing["request_id"] == request["request_id"]:
                items[index] = deepcopy(request)
                return
        items.append(deepcopy(request))

    def remediations(self, key: str) -> list[dict[str, Any]]:
        return deepcopy(self.rems.get(key, []))

    def find_remediation(self, execution_id: str) -> tuple[str, dict[str, Any]] | None:
        for key, items in self.rems.items():
            for item in items:
                if item.get("execution_id") == execution_id:
                    return key, deepcopy(item)
        return None

    def acquire_lock(self, key: str, owner: str) -> bool:
        if key in self.locks:
            return False
        self.locks[key] = owner
        return True

    def release_lock(self, key: str, owner: str) -> None:
        if self.locks.get(key) == owner:
            del self.locks[key]

    def claim_notification(self, key: str, state: str, version: int) -> bool:
        marker = (key, state, version)
        if marker in self.notifications:
            return False
        self.notifications.add(marker)
        return True

    def all_findings(self) -> list[dict[str, Any]]:
        return [deepcopy(v) for v in self.findings.values()]

    def get_exception(self, control_id: str, resource_id: str) -> dict[str, Any] | None:
        item = self.exceptions.get((control_id, resource_id))
        return deepcopy(item) if item else None


class DynamoStore:
    """DynamoDB adapter. Table: pk (S), sk (S); TTL attribute ``ttl``; GSI ``by-execution`` on ``execution_id``."""

    def __init__(self, table: Any, now: Any = time.time) -> None:
        self.table = table
        self.now = now
        from boto3.dynamodb.conditions import Key  # noqa: PLC0415

        self._key = Key

    def _conditional_put(self, item: dict[str, Any], condition: str, values: dict[str, Any] | None = None) -> bool:
        from botocore.exceptions import ClientError  # noqa: PLC0415

        kwargs: dict[str, Any] = {"Item": item, "ConditionExpression": condition}
        if values:
            kwargs["ExpressionAttributeValues"] = values
        try:
            self.table.put_item(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def claim_event(self, event_id: str) -> bool:
        item = {"pk": f"EVENT#{event_id}", "sk": "EVENT", "ttl": int(self.now()) + IDEMPOTENCY_TTL_SECONDS}
        return self._conditional_put(item, "attribute_not_exists(pk)")

    def release_event(self, event_id: str) -> None:
        self.table.delete_item(Key={"pk": f"EVENT#{event_id}", "sk": "EVENT"})

    def get_finding(self, key: str) -> dict[str, Any] | None:
        item = self.table.get_item(Key={"pk": f"FINDING#{key}", "sk": "STATE"}, ConsistentRead=True).get("Item")
        if not item:
            return None
        data = {k: v for k, v in item.items() if k not in {"pk", "sk"}}
        data["version"] = int(data["version"])
        return data

    def put_finding(self, item: dict[str, Any], expected_version: int | None) -> None:
        stored = {**item, "pk": f"FINDING#{item['finding_key']}", "sk": "STATE", "version": (expected_version or 0) + 1}
        if expected_version is None:
            ok = self._conditional_put(stored, "attribute_not_exists(pk)")
        else:
            ok = self._conditional_put(stored, "version = :v", {":v": expected_version})
        if not ok:
            raise ConflictError(f"finding {item['finding_key']} changed concurrently")

    def add_history(self, key: str, entry: dict[str, Any]) -> None:
        sk = f"HIST#{entry['at']}#{entry['to']}#{int(self.now() * 1000)}"
        self.table.put_item(Item={**entry, "pk": f"FINDING#{key}", "sk": sk})

    def _query(self, key: str, prefix: str) -> list[dict[str, Any]]:
        condition = self._key("pk").eq(f"FINDING#{key}") & self._key("sk").begins_with(prefix)
        items = self.table.query(KeyConditionExpression=condition).get("Items", [])
        return [{k: v for k, v in i.items() if k not in {"pk", "sk"}} for i in items]

    def history(self, key: str) -> list[dict[str, Any]]:
        return self._query(key, "HIST#")

    def put_remediation(self, key: str, request: dict[str, Any]) -> None:
        self.table.put_item(
            Item={**request, "pk": f"FINDING#{key}", "sk": f"REM#{request['request_id']}", "finding_key": key}
        )

    def remediations(self, key: str) -> list[dict[str, Any]]:
        return self._query(key, "REM#")

    def find_remediation(self, execution_id: str) -> tuple[str, dict[str, Any]] | None:
        items = self.table.query(
            IndexName="by-execution", KeyConditionExpression=self._key("execution_id").eq(execution_id)
        ).get("Items", [])
        if not items:
            return None
        item = items[0]
        return str(item["finding_key"]), {k: v for k, v in item.items() if k not in {"pk", "sk"}}

    def acquire_lock(self, key: str, owner: str) -> bool:
        now = int(self.now())
        item = {"pk": f"LOCK#{key}", "sk": "LOCK", "owner": owner, "ttl": now + LOCK_TTL_SECONDS}
        # An expired lock (DynamoDB TTL deletion is lazy) may be taken over.
        from botocore.exceptions import ClientError  # noqa: PLC0415

        try:
            self.table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk) OR #t < :now",
                ExpressionAttributeNames={"#t": "ttl"},
                ExpressionAttributeValues={":now": now},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def release_lock(self, key: str, owner: str) -> None:
        from botocore.exceptions import ClientError  # noqa: PLC0415

        try:
            self.table.delete_item(
                Key={"pk": f"LOCK#{key}", "sk": "LOCK"},
                ConditionExpression="#o = :o",
                ExpressionAttributeNames={"#o": "owner"},
                ExpressionAttributeValues={":o": owner},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise

    def claim_notification(self, key: str, state: str, version: int) -> bool:
        item = {
            "pk": f"NOTIFY#{key}#{state}#{version}",
            "sk": "NOTIFY",
            "ttl": int(self.now()) + IDEMPOTENCY_TTL_SECONDS,
        }
        return self._conditional_put(item, "attribute_not_exists(pk)")

    def all_findings(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "FilterExpression": "sk = :s AND begins_with(pk, :p)",
            "ExpressionAttributeValues": {":s": "STATE", ":p": "FINDING#"},
        }
        while True:
            page = self.table.scan(**kwargs)
            items.extend({k: v for k, v in i.items() if k not in {"pk", "sk"}} for i in page.get("Items", []))
            if "LastEvaluatedKey" not in page:
                return items
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def get_exception(self, control_id: str, resource_id: str) -> dict[str, Any] | None:
        item = self.table.get_item(Key={"pk": f"EXC#{control_id}", "sk": resource_id}).get("Item")
        return {k: v for k, v in item.items() if k not in {"pk", "sk"}} if item else None
