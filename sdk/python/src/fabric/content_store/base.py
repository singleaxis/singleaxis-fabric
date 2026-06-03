# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""ContentStore protocol + ContentRef value type."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ContentRef:
    """A reference to stored content.

    ``uri`` is the tenant-resolvable locator (e.g.
    ``file:///var/fabric/content/<hash>`` or
    ``s3://bucket/prefix/<hash>``). ``content_hash`` is the SHA-256
    of the stored bytes so an auditor can verify integrity after
    resolving the uri.
    """

    uri: str
    content_hash: str


@runtime_checkable
class ContentStore(Protocol):
    """Writes raw content to tenant-controlled storage, returns a
    ContentRef. The SDK stamps the ref's ``uri`` onto events; it
    never reads content back.
    """

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef: ...

    def close(self) -> None: ...


def content_hash(content: str) -> str:
    """SHA-256 hex of the content's UTF-8 bytes. Shared key strategy
    so the same content lands at the same address (content-addressed).
    """
    return hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()
