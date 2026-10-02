# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local-filesystem content store for the dual-pipeline architecture."""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import uuid
from collections.abc import Iterator, Mapping
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


@contextlib.contextmanager
def _directory(path: Path, *, create: bool = False) -> Iterator[int]:
    """Pin each directory before use; never follow a replaced namespace."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass  # The no-follow directory open below validates it.
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _read_bytes(path: Path) -> bytes:
    with _directory(path.parent) as directory:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise CorruptedObjectError("unsafe local content file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read()
        finally:
            os.close(fd)


def _exists(path: Path) -> bool:
    try:
        with _directory(path.parent) as directory:
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise CorruptedObjectError("unsafe local content file")
            return True
    except FileNotFoundError:
        return False


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    """Write and fsync through pinned directory descriptors, without symlinks."""
    with _directory(target.parent, create=True) as directory:
        os.fchmod(directory, 0o700)
        if stat.S_IMODE(os.fstat(directory).st_mode) != stat.S_IRWXU:
            raise PermissionError("content directory must enforce owner-only permissions")
        temporary = ".pending-" + uuid.uuid4().hex
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)


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
        # Resolve only the explicitly configured root, once. Descendants are
        # traversed through no-follow directory descriptors on every operation.
        self.root = str(Path(self.root).resolve())
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
        if not _exists(target):
            _atomic_write_bytes(target, content.encode("utf-8"))
        return ContentRef(uri=f"file://{target}", content_hash=digest)

    def close(self) -> None:
        """No-op: the filesystem store holds no resources to release."""

    # -- governed contract -------------------------------------------------

    def _root_path(self) -> Path:
        return Path(self.root)

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
        if _exists(target):
            if content_hash_bytes(_read_bytes(target)) != digest:
                raise CorruptedObjectError(
                    f"pre-existing object {target} fails digest verification"
                )
        else:
            _atomic_write_bytes(target, data)
        meta = self._tenant_root() / "meta" / f"{digest}.json"
        if not _exists(meta):
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
        if _exists(target):
            if _read_bytes(target) != content:
                raise CorruptedObjectError(f"pre-existing evidence object {target} differs")
        else:
            _atomic_write_bytes(target, content)
        if _exists(meta):
            if _read_bytes(meta) != body:
                raise CorruptedObjectError(f"pre-existing evidence descriptor {meta} differs")
        else:
            _atomic_write_bytes(meta, body)
        return ContentRef(uri=ref, content_hash=digest)

    def write_manifest(
        self, manifest: Mapping[str, Any], *, decision_id: str, manifest_id: str
    ) -> str:
        check_safe_identifier("manifest_id", manifest_id)
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
        check_safe_identifier("manifest_id", manifest_id)
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
        candidate = Path(os.path.abspath(unquote(parsed.path)))
        # Governed mode confines reads to the tenant namespace — a
        # configured store must never reach a sibling tenant's directory.
        boundary = self._tenant_root() if self.tenant_id else self._root_path()
        if not candidate.is_relative_to(boundary) or not candidate.resolve().is_relative_to(
            boundary
        ):
            raise ValueError(f"uri escapes the configured store root: {uri!r}")
        return candidate

    def owns_uri(self, uri: str) -> bool:
        try:
            self._resolve_uri(uri)
        except ValueError:
            return False
        return True

    def exists(self, uri: str) -> bool:
        return _exists(self._resolve_uri(uri))

    def read(self, uri: str) -> bytes:
        path = self._resolve_uri(uri)
        if not _exists(path):
            raise FileNotFoundError(uri)
        return _read_bytes(path)

    def read_descriptor(self, uri: str) -> Mapping[str, Any]:
        path = self._resolve_uri(uri)
        meta = path.parent / "meta" / f"{path.name}.json"
        if not _exists(meta):
            raise FileNotFoundError(f"no descriptor sidecar for {uri!r}")
        value = json.loads(_read_bytes(meta).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"descriptor sidecar at {uri!r} is not an object")
        return value

    def read_manifest(self, uri: str) -> dict[str, Any]:
        path = self._resolve_uri(uri)
        if not _exists(path):
            raise FileNotFoundError(uri)
        value = json.loads(_read_bytes(path).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"manifest is not a JSON object: {uri!r}")
        return value

    def list_object_uris(self) -> list[str]:
        if self.tenant_id is None:
            return []
        root = self._tenant_root()
        uris = []
        try:
            with _directory(root) as directory:
                for name in sorted(os.listdir(directory)):
                    if not _DIGEST_RE.fullmatch(name):
                        continue
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise CorruptedObjectError("unsafe local content file")
                    uris.append(f"file://{root / name}")
        except FileNotFoundError:
            return []
        return uris
