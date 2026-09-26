# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local-filesystem content store for the dual-pipeline architecture."""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from fabric.content_store.base import (
    ContentRef,
    CorruptedObjectError,
    check_safe_identifier,
    content_hash,
    content_hash_bytes,
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    """Write ``data`` to ``target`` atomically: tmp + fsync + rename +
    directory fsync. Never leaves a partially written object."""
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # mkdir honours the process umask only for newly-created components;
    # tighten an existing directory as well so governed roots never remain
    # group/world-readable after first use.
    os.chmod(target.parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, target)
        # fsync the directory so the rename is durable.
        dir_fd = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


@dataclass(slots=True)
class LocalFilesystemContentStore:
    """Content-addressed store on the local filesystem.

    Without ``tenant_id`` (legacy), writes content to
    ``{root}/{hash[:2]}/{hash}`` and returns a ``file://`` ref —
    byte-identical to the original adapter.

    With ``tenant_id`` (governed mode, spec 033), objects live at
    ``{root}/{tenant_id}/{digest}`` with descriptor sidecars under
    ``{root}/{tenant_id}/meta/{digest}.json`` and manifests under
    ``{root}/{tenant_id}/manifests/``. All writes are atomic
    (tmp + fsync + rename), files are mode ``0600``, and pre-existing
    objects are re-verified — a digest mismatch raises
    :class:`CorruptedObjectError` rather than silently trusting a
    hash-named file.
    """

    root: str
    tenant_id: str | None = None

    def __post_init__(self) -> None:
        if self.tenant_id is None:
            return
        check_safe_identifier("tenant_id", self.tenant_id)
        # Filesystem-level containment: the resolved tenant root must be
        # strictly inside the resolved configured root.
        resolved_root = self._root_path()
        tenant_root = (resolved_root / self.tenant_id).resolve()
        if not tenant_root.is_relative_to(resolved_root) or tenant_root == resolved_root:
            raise ValueError(
                f"tenant root {tenant_root} escapes the configured root {resolved_root}"
            )

    # -- legacy contract -------------------------------------------------

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        """Write ``content`` to its content-addressed path and return a
        ``file://`` ref. Idempotent: if the target already exists (same
        content → same path), the write is skipped. ``key_hint`` is
        accepted for protocol parity but ignored — the address is the
        content hash, not the hint.
        """
        digest = content_hash(content)
        target = self._object_path(digest)
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return ContentRef(uri=f"file://{target.resolve()}", content_hash=digest)

    def close(self) -> None:
        """No-op: the filesystem store holds no resources to release."""

    # -- governed contract -------------------------------------------------

    def _root_path(self) -> Path:
        return Path(self.root).resolve()

    def _tenant_root(self) -> Path:
        if self.tenant_id is None:
            raise RuntimeError(
                "governed content requires LocalFilesystemContentStore(tenant_id=...)"
            )
        return self._root_path() / self.tenant_id

    def _object_path(self, digest: str) -> Path:
        if self.tenant_id is None:
            return self._root_path() / digest[:2] / digest
        return self._tenant_root() / digest

    def ref_for(self, digest: str) -> str:
        return f"file://{self._object_path(digest)}"

    def put_object(self, descriptor: Mapping[str, Any], content: str) -> ContentRef:
        digest = descriptor["digest"].split(":", 1)[1]
        if not _DIGEST_RE.match(digest):
            raise ValueError(f"descriptor digest is not sha256 hex: {digest!r}")
        data = content.encode("utf-8", "surrogatepass")
        if content_hash_bytes(data) != digest:
            raise ValueError("content bytes do not match descriptor digest")
        target = self._tenant_root() / digest
        if target.exists():
            if content_hash_bytes(target.read_bytes()) != digest:
                raise CorruptedObjectError(
                    f"pre-existing object {target} fails digest verification"
                )
        else:
            _atomic_write_bytes(target, data)
        meta = self._tenant_root() / "meta" / f"{digest}.json"
        if not meta.exists():
            _atomic_write_bytes(
                meta,
                (json.dumps(descriptor, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
            )
        return ContentRef(uri=f"file://{target}", content_hash=digest)

    def evidence_ref_for(self, object_id: str) -> str:
        """Prospective v2 reference, scoped to one observation."""
        check_safe_identifier("object_id", object_id)
        return f"file://{self._tenant_root() / 'evidence' / object_id}"

    def put_bytes_object(self, descriptor: Mapping[str, Any], content: bytes) -> ContentRef:
        """Persist exact v2 bytes and an observation-specific descriptor."""
        if descriptor.get("schema_version") != "fabric.content-object/v2":
            raise ValueError("put_bytes_object requires a content-object/v2 descriptor")
        if descriptor.get("tenant_id") != self.tenant_id:
            raise ValueError("descriptor tenant_id does not match store tenant_id")
        object_id = check_safe_identifier("object_id", descriptor["object_id"])
        digest = content_hash_bytes(content)
        if descriptor.get("stored_sha256") != f"sha256:{digest}":
            raise ValueError("content bytes do not match stored_sha256")
        if descriptor.get("stored_byte_length") != len(content):
            raise ValueError("content bytes do not match stored_byte_length")
        target = self._tenant_root() / "evidence" / object_id
        ref = f"file://{target}"
        if descriptor.get("ref") != ref:
            raise ValueError("descriptor ref does not match store namespace")
        meta = target.parent / "meta" / f"{object_id}.json"
        body = (json.dumps(descriptor, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        if target.exists():
            if target.read_bytes() != content:
                raise CorruptedObjectError(f"pre-existing evidence object {target} differs")
        else:
            _atomic_write_bytes(target, content)
        if meta.exists():
            if meta.read_bytes() != body:
                raise CorruptedObjectError(f"pre-existing evidence descriptor {meta} differs")
        else:
            _atomic_write_bytes(meta, body)
        return ContentRef(uri=ref, content_hash=digest)

    def write_manifest(
        self, manifest: Mapping[str, Any], *, decision_id: str, manifest_id: str
    ) -> str:
        root = self._tenant_root() / "manifests"
        target = root / f"{manifest_id}.json"
        body = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        _atomic_write_bytes(target, body)
        alias_dir = root / "by-decision"
        _atomic_write_bytes(
            alias_dir / f"{self._safe_name(decision_id)}.json",
            (json.dumps({"manifest_uri": f"file://{target}"}) + "\n").encode("utf-8"),
        )
        return f"file://{target}"

    @staticmethod
    def _safe_name(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", value)

    def manifest_uri_for(self, manifest_id: str) -> str:
        return f"file://{self._tenant_root() / 'manifests' / f'{manifest_id}.json'}"

    def manifest_uri_for_decision(self, decision_id: str) -> str:
        target = (
            self._tenant_root()
            / "manifests"
            / "by-decision"
            / f"{self._safe_name(decision_id)}.json"
        )
        return f"file://{target}"

    def _resolve_uri(self, uri: str) -> Path:
        parsed = urlparse(uri)
        if parsed.scheme != "file":
            raise ValueError(f"unsupported uri scheme {parsed.scheme!r}")
        candidate = Path(unquote(parsed.path)).resolve()
        # Governed mode confines reads to the tenant namespace — a
        # configured store must never reach a sibling tenant's directory.
        boundary = self._tenant_root() if self.tenant_id else self._root_path()
        if not candidate.is_relative_to(boundary):
            raise ValueError(f"uri escapes the configured store root: {uri!r}")
        return candidate

    def owns_uri(self, uri: str) -> bool:
        try:
            self._resolve_uri(uri)
        except ValueError:
            return False
        return True

    def exists(self, uri: str) -> bool:
        return self._resolve_uri(uri).is_file()

    def read(self, uri: str) -> bytes:
        path = self._resolve_uri(uri)
        if not path.is_file():
            raise FileNotFoundError(uri)
        return path.read_bytes()

    def read_descriptor(self, uri: str) -> Mapping[str, Any]:
        path = self._resolve_uri(uri)
        meta = path.parent / "meta" / f"{path.name}.json"
        if not meta.is_file():
            raise FileNotFoundError(f"no descriptor sidecar for {uri!r}")
        value = json.loads(meta.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"descriptor sidecar at {uri!r} is not an object")
        return value

    def read_manifest(self, uri: str) -> dict[str, Any]:
        path = self._resolve_uri(uri)
        if not path.is_file():
            raise FileNotFoundError(uri)
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"manifest is not a JSON object: {uri!r}")
        return value

    def list_object_uris(self) -> list[str]:
        if self.tenant_id is None:
            return []
        root = self._tenant_root()
        if not root.is_dir():
            return []
        uris = []
        for path in sorted(root.iterdir()):
            if path.is_file() and _DIGEST_RE.match(path.name):
                uris.append(f"file://{path}")
        return uris
