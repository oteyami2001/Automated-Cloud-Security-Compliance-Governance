"""Structured JSON logging with masking of identifiers (account IDs, e-mail, IPv4).

Logs from this project may surface in public places (GitHub Actions output, screenshots), so every
message and field passes through :func:`mask` before it is written.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

_PATTERNS = [
    (re.compile(r"(?<![\d.])\d{12}(?![\d.])"), "<ACCOUNT_ID>"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<EMAIL>"),
    (re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), "<IPV4>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<ACCESS_KEY_ID>"),
]
# CIDRs that are part of the security semantics (0.0.0.0/0) stay readable.
_KEEP = {"0.0.0.0"}  # noqa: S104 - a CIDR literal kept readable in logs, not a bind address  # nosec B104


def mask(value: Any) -> Any:
    """Recursively mask identifiers in strings, lists and dicts."""
    if isinstance(value, str):
        text = value
        for pattern, replacement in _PATTERNS:
            if replacement == "<IPV4>":
                text = pattern.sub(lambda m: m.group(0) if m.group(0) in _KEEP else "<IPV4>", text)
            else:
                text = pattern.sub(replacement, text)
        return text
    if isinstance(value, dict):
        return {k: mask(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [mask(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(getattr(record, "fields", {}))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(mask(payload), default=str, sort_keys=True)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(logging.INFO)
    return logger


def log_event(logger: logging.Logger, message: str, level: int = logging.INFO, **fields: Any) -> None:
    logger.log(level, message, extra={"fields": fields})
