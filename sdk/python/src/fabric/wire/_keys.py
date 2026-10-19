# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Customer key material from the environment or a file (spec 049 §7.7, §7.8).

``<NAME>`` holds standard base64 of the key; ``<NAME>_FILE`` names a file holding either
the raw key bytes or their standard base64 (one optional trailing newline). Setting both
is an error. Every error is fixed text: a key, a path or a file's bytes never appear in
an exception or a log line. Keys are never stored by Fabric.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping

SPOOL_KEY_BYTES = 32  # AES-256-GCM
TOKEN_KEY_MIN_BYTES = 32
_MAX_KEY_FILE_BYTES = 4096


def _decode(text: bytes) -> bytes | None:
    try:
        return base64.b64decode(text.removesuffix(b"\n"), validate=True)
    except (binascii.Error, ValueError):
        return None


def _accept(key: bytes | None, *, exact: int | None, minimum: int) -> bool:
    return key is not None and (len(key) == exact if exact is not None else len(key) >= minimum)


def key_from_env(
    environ: Mapping[str, str], name: str, *, exact: int | None = None, minimum: int = 1
) -> bytes | None:
    """The key named ``name`` (``None`` when neither variable is set), or ``ValueError``."""
    value, path = environ.get(name) or "", environ.get(f"{name}_FILE") or ""
    if value and path:
        raise ValueError(f"set {name} or {name}_FILE, not both")
    if value:
        key = _decode(value.strip().encode("ascii", "replace"))
        if not _accept(key, exact=exact, minimum=minimum):
            raise ValueError(f"{name} must be base64 of a {_size(exact, minimum)} key")
        return key
    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_KEY_FILE_BYTES + 1)
    except OSError:
        raise ValueError(f"{name}_FILE is not readable") from None
    decoded = _decode(raw)
    for candidate in (decoded, raw):  # base64 text first, else the raw bytes
        if _accept(candidate, exact=exact, minimum=minimum) and len(raw) <= _MAX_KEY_FILE_BYTES:
            return candidate
    raise ValueError(f"{name}_FILE must hold a {_size(exact, minimum)} key (raw or base64)")


def _size(exact: int | None, minimum: int) -> str:
    return f"{exact}-byte" if exact is not None else f"{minimum}-byte or longer"


def envelope_key_id(key: bytes) -> str:
    """A public id of an envelope key (``kid-`` + 8 hex): which key sealed a record,
    never the key. Domain-separated from the id key's ``key_id``."""
    return "kid-" + hmac.new(key, b"fabric-spool/v1/kid", hashlib.sha256).hexdigest()[:8]
