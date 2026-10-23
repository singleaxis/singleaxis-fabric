# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local-filesystem content store for the dual-pipeline architecture."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from fabric.content_store.base import (
    ContentRef,
    CorruptedObjectError,
    check_descriptor_only,
    check_safe_identifier,
    content_hash,
    content_hash_bytes,
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
# The Fabric Node's directory-backend envelope (spec 049 §7.8; contracts/content/v2/
# fixtures/node-envelope-v1.json): magic | 12-byte nonce | AES-256-GCM(plaintext), with the
# object's location below the content root bound as AAD.
NODE_ENVELOPE_MAGIC = b"FABRIC-NODE-CONTENT-1\n"
_NODE_ENVELOPE_AAD = "fabric.node-content-envelope/v1"


def open_node_envelope(data: bytes, relative: str, key: bytes | None) -> bytes:
    """A Node-written body or descriptor, as stored: opened with ``key`` (the magic is then
    required and the envelope must authenticate), else returned as is unless it is an
    envelope (which a reader without the key refuses: fail closed). Fixed-text errors."""
    sealed = data.startswith(NODE_ENVELOPE_MAGIC)
    if key is None:
        if sealed:
            raise CorruptedObjectError("enveloped Node content needs the Node content key")
        return data
    if not sealed:
        raise CorruptedObjectError("Node content is not enveloped under the configured key")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    head = len(NODE_ENVELOPE_MAGIC)
    aad = json.dumps([_NODE_ENVELOPE_AAD, relative], separators=(",", ":")).encode()
    try:
        opened: bytes = AESGCM(key).decrypt(data[head : head + 12], data[head + 12 :], aad)
    except Exception:  # InvalidTag, short input: never the bytes
        raise CorruptedObjectError("Node content envelope does not authenticate") from None
    return opened


def node_shard(object_id: str) -> tuple[str, str]:
    """The Fabric Node directory backend's two shard directories for ``object_id``: the
    first and second pairs of lowercase hex of SHA-256(object_id). The Node stores
    ``<tenant>/evidence/<id>`` at ``<tenant>/evidence/<s1>/<s2>/<id>`` and
    ``<tenant>/evidence/meta/<id>.json`` at ``<tenant>/evidence/meta/<s1>/<s2>/<id>.json``;
    refs and envelope AADs keep the flat (logical) key."""
    digest = hashlib.sha256(object_id.encode("utf-8")).hexdigest()
    return digest[:2], digest[2:4]


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


@contextlib.contextmanager
def _subdirectory(parent: int, name: str, *, create: bool = False) -> Iterator[int]:
    """``name`` under the pinned ``parent`` (created, durably, when asked), pinned."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass  # The no-follow directory open below validates it.
    fd = os.open(name, flags, dir_fd=parent)
    try:
        yield fd
    finally:
        os.close(fd)


def _read_bytes(path: Path) -> bytes:
    with _directory(path.parent) as directory:
        return _read_at(directory, path.name)


def _read_at(directory: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
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
            return _exists_at(directory, path.name)
    except FileNotFoundError:
        return False


def _exists_at(directory: int, name: str) -> bool:
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CorruptedObjectError("unsafe local content file")
    return True


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    """Write and fsync through pinned directory descriptors, without symlinks."""
    with _directory(target.parent, create=True) as directory:
        _atomic_write_at(directory, target.name, data)


def _atomic_write_at(directory: int, name: str, data: bytes) -> None:
    os.fchmod(directory, stat.S_IRWXU)  # owner-only directory (0o700)
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
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
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
    # Reader side of the Node directory envelope (spec 049 §7.8): a secret, never in repr.
    envelope_key: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.envelope_key is not None and (
            not isinstance(self.envelope_key, bytes) or len(self.envelope_key) != 32  # noqa: PLR2004
        ):  # fmt: skip
            raise ValueError("envelope_key must be a 32-byte AES-256-GCM key")
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
        # One pinned walk for both files (each step of a walk is a system call: on the
        # capture worker every one may wait for the host's thread to yield the GIL).
        with _directory(target.parent, create=True) as evidence:
            if _exists_at(evidence, target.name):
                if _read_at(evidence, target.name) != content:
                    raise CorruptedObjectError(f"pre-existing evidence object {target} differs")
            else:
                _atomic_write_at(evidence, target.name, content)
            with _subdirectory(evidence, "meta", create=True) as directory:
                if _exists_at(directory, meta.name):
                    if _read_at(directory, meta.name) != body:
                        raise CorruptedObjectError(
                            f"pre-existing evidence descriptor {meta} differs"
                        )
                else:
                    _atomic_write_at(directory, meta.name, body)
        return ContentRef(uri=ref, content_hash=digest)

    def put_descriptor_only(self, descriptor: Mapping[str, Any]) -> str:
        """Persist a descriptor-only object's descriptor sidecar, no bytes (as the Node does
        for one, so a reader finds it ``not_stored``); create-only, idempotent. Returns its
        reference."""
        object_id = check_descriptor_only(descriptor, self.tenant_id)
        target = self._tenant_root() / "evidence" / object_id
        body = (json.dumps(descriptor, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        name = f"{object_id}.json"
        with (
            _directory(target.parent, create=True) as evidence,
            _subdirectory(evidence, "meta", create=True) as directory,
        ):
            if _exists_at(directory, name):
                if _read_at(directory, name) != body:
                    raise CorruptedObjectError(f"pre-existing evidence descriptor {name} differs")
            else:
                _atomic_write_at(directory, name, body)
        return f"file://{target}"

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

    def _located(self, path: Path) -> Path:
        """Where the evidence object or descriptor at logical ``path`` is stored: the Fabric
        Node's sharded location (:func:`node_shard`) when present, else ``path`` itself (the
        flat layout of this SDK's writer and of Nodes before sharding)."""
        if self.tenant_id is None:
            return path
        evidence = self._tenant_root() / "evidence"
        if path.parent == evidence:
            object_id = path.name
        elif path.parent == evidence / "meta" and path.name.endswith(".json"):
            object_id = path.name.removesuffix(".json")
        else:
            return path
        sharded = path.parent.joinpath(*node_shard(object_id), path.name)
        return sharded if _exists(sharded) else path

    def exists(self, uri: str) -> bool:
        return _exists(self._located(self._resolve_uri(uri)))

    def read(self, uri: str) -> bytes:
        path = self._resolve_uri(uri)
        stored = self._located(path)
        if not _exists(stored):
            raise FileNotFoundError(uri)
        return self._opened(stored, path)

    def _opened(self, path: Path, logical: Path | None = None) -> bytes:
        """The file's bytes, through the Node envelope rule (:func:`open_node_envelope`). The
        AAD is the ``logical`` (flat) location when the file is stored in a Node shard."""
        data = _read_bytes(path)
        if self.envelope_key is None and not data.startswith(NODE_ENVELOPE_MAGIC):
            return data
        bound = path if logical is None else logical
        relative = bound.resolve().relative_to(self._root_path()).as_posix()
        return open_node_envelope(data, relative, self.envelope_key)

    def read_descriptor(self, uri: str) -> Mapping[str, Any]:
        path = self._resolve_uri(uri)
        meta = path.parent / "meta" / f"{path.name}.json"
        stored = self._located(meta)
        if not _exists(stored):
            raise FileNotFoundError(f"no descriptor sidecar for {uri!r}")
        value = json.loads(self._opened(stored, meta).decode("utf-8"))
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
