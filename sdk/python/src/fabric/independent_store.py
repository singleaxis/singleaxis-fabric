# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Read-only, owner-authorized local native-witness objects (spec 046).

Namespace isolation is a local permission check, not remote IAM, independence,
retention or encryption qualification. No telemetry-supplied URI is opened.
"""

from __future__ import annotations

import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_OBJECT = 16 << 20


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _private(info: os.stat_result, *, directory: bool) -> None:
    mode_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (
        not mode_ok
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or (not directory and info.st_nlink != 1)
    ):
        raise ValueError("unsafe witness namespace")


class LocalIndependentFeedResolver:
    """Resolve only opaque objects under one approved tenant/issuer namespace."""

    def __init__(
        self,
        root: str | Path,
        *,
        tenant_id: str,
        issuer_id: str,
        max_object_bytes: int = _MAX_OBJECT,
    ) -> None:
        if (
            not _identifier(tenant_id)
            or not _identifier(issuer_id)
            or not isinstance(max_object_bytes, int)
            or isinstance(max_object_bytes, bool)
            or not 0 < max_object_bytes <= _MAX_OBJECT
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
        ):
            raise ValueError("invalid local witness resolver configuration")
        # abspath deliberately does not resolve symlinks: every component is
        # checked with O_NOFOLLOW during each read, including configured root.
        self._root = Path(os.path.abspath(root))
        if self._root == Path(self._root.anchor):
            raise ValueError("invalid local witness resolver configuration")
        self.tenant_id = tenant_id
        self.issuer_id = issuer_id
        self.max_object_bytes = max_object_bytes

    def resolve(self, byte_object_id: str, max_bytes: int) -> bytes:
        if (
            not _identifier(byte_object_id)
            or not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 0 <= max_bytes <= _MAX_OBJECT
        ):
            raise ValueError("invalid local witness read request")
        try:
            return self._read(byte_object_id, min(max_bytes, self.max_object_bytes))
        except Exception:
            raise ValueError("authorized witness read unavailable") from None

    def _read(self, identifier: str, limit: int) -> bytes:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
        with ExitStack() as opened:
            fd = os.open(self._root.anchor, flags)
            opened.callback(os.close, fd)
            for index, component in enumerate(
                (*self._root.parts[1:], self.tenant_id, self.issuer_id)
            ):
                fd = os.open(component, flags, dir_fd=fd)
                opened.callback(os.close, fd)
                # Public ancestors such as /private/tmp are not owned stores.
                # The configured root and both namespace directories are.
                if index >= len(self._root.parts) - 2:
                    _private(os.fstat(fd), directory=True)
            object_fd = os.open(identifier, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            opened.callback(os.close, object_fd)
            before = os.fstat(object_fd)
            _private(before, directory=False)
            if before.st_size > limit:
                raise ValueError("witness exceeds limit")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(object_fd, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(object_fd)
            _private(after, directory=False)
            if remaining == 0 or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("witness changed while reading")
            data = b"".join(chunks)
            if len(data) != after.st_size:
                raise ValueError("witness length changed")
            return data
