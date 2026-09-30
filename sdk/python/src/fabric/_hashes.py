# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validation for caller-supplied digest metadata.

Hash-labelled telemetry fields are a privacy boundary. Accepting arbitrary
strings under a ``*_hash`` key would let raw content bypass the Collector's
exact-key allowlist, so recorder APIs require lowercase SHA-256 hex.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(value: str) -> str:
    """SHA-256 hex digest of ``value``'s UTF-8 bytes.

    ``surrogatepass`` keeps hashing total on lone UTF-16 surrogates
    (malformed but reachable via arbitrary file paths / tool / memory
    content), where plain ``str.encode("utf-8")`` would raise
    ``UnicodeEncodeError``. Byte-identical to plain UTF-8 for all
    well-formed text.
    """
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def require_sha256_hex(field_name: str, value: str) -> str:
    """Return ``value`` when it is lowercase SHA-256 hex; otherwise fail."""
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be str, got {type(value).__name__}")
    if _SHA256_HEX.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be exactly 64 lowercase SHA-256 hex characters")
    return value


def require_sha256_hex_values(field_name: str, values: Iterable[str]) -> tuple[str, ...]:
    """Validate and freeze a sequence of SHA-256 hex values."""
    return tuple(require_sha256_hex(field_name, value) for value in values)
