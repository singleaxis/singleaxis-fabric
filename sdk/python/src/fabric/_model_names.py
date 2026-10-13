# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Model-name exposure rule shared by capture and ``fabric.reconstruct`` (spec 043 §7).

A provider ``model`` value is emitted as is only when it matches the 042 pattern, has
no ``://`` and is allowlisted; any other string becomes ``m-`` + 16 hex of its SHA-256.
Imports neither ``fabric.wire`` nor ``fabric.reconstruct``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence

MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")  # plus: no "://"
HASHED_MODEL_RE = re.compile(r"^m-[0-9a-f]{16}$")
DEFAULT_MODEL_ALLOWLIST: tuple[str, ...] = (
    "gpt-*", "o1*", "o3*", "o4*", "chatgpt-*", "claude-*", "gemini-*", "text-embedding-*",
    "llama*", "meta-llama/*", "mistral*", "mixtral*", "codestral*", "command*", "deepseek*",
    "qwen*", "grok*", "anthropic/*", "openai/*", "google/*",
)  # fmt: skip


def _valid_name(value: str) -> bool:
    return bool(MODEL_PATTERN.fullmatch(value)) and "://" not in value


def parse_model_allowlist(text: str | None) -> tuple[str, ...]:
    """``FABRIC_WIRE_MODEL_ALLOWLIST``: exact names or ``prefix*``; errors never echo entries."""
    entries = tuple(e.strip() for e in (text or "").split(",") if e.strip())
    for entry in entries:
        if not _valid_name(entry[:-1] if entry.endswith("*") else entry):
            raise ValueError("FABRIC_WIRE_MODEL_ALLOWLIST entries must be model names or prefix*")
    return entries


def model_allowed(value: str, allowlist: Sequence[str] = ()) -> bool:
    if not isinstance(value, str) or not _valid_name(value):
        return False
    for entry in (*DEFAULT_MODEL_ALLOWLIST, *allowlist):
        if value == entry or (entry.endswith("*") and value.startswith(entry[:-1])):
            return True
    return False


def hashed_model(value: str) -> str:
    return "m-" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def expose_model(value: object, allowlist: Sequence[str] = ()) -> str | None:
    """The telemetry form of a model value; ``None`` (omitted) unless a non-empty string."""
    if not isinstance(value, str) or not value:
        return None
    return value if model_allowed(value, allowlist) else hashed_model(value)
