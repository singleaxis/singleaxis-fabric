# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local-filesystem content store for the dual-pipeline architecture."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fabric.content_store.base import ContentRef, content_hash


@dataclass(slots=True)
class LocalFilesystemContentStore:
    """Content-addressed store on the local filesystem.

    Writes content to ``{root}/{hash[:2]}/{hash}`` and returns a
    ``file://`` ref. Content-addressed: identical content is written
    once (idempotent). For single-node dev or a shared PVC.
    """

    root: str

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        """Write ``content`` to its content-addressed path and return a
        ``file://`` ref. Idempotent: if the target already exists (same
        content → same path), the write is skipped. ``key_hint`` is
        accepted for protocol parity but ignored — the address is the
        content hash, not the hint.
        """
        digest = content_hash(content)
        shard = Path(self.root) / digest[:2]
        shard.mkdir(parents=True, exist_ok=True)
        target = shard / digest
        if not target.exists():
            target.write_text(content, encoding="utf-8")
        return ContentRef(uri=f"file://{target.resolve()}", content_hash=digest)

    def close(self) -> None:
        """No-op: the filesystem store holds no resources to release."""
