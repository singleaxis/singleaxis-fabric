# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local witness read authorization and path safety."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fabric.independent_store import LocalIndependentFeedResolver


@pytest.fixture
def witness(tmp_path: Path) -> tuple[Path, LocalIndependentFeedResolver]:
    root = tmp_path / "witness"
    namespace = root / "tenant" / "issuer"
    namespace.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    namespace.parent.chmod(0o700)
    obj = namespace / "object"
    obj.write_bytes(b"\x00\xffsecret-canary")
    obj.chmod(0o600)
    return root, LocalIndependentFeedResolver(root, tenant_id="tenant", issuer_id="issuer")


def test_binary_and_empty_reads(witness: tuple[Path, LocalIndependentFeedResolver]) -> None:
    root, resolver = witness
    assert resolver.resolve("object", 100) == b"\x00\xffsecret-canary"
    empty = root / "tenant" / "issuer" / "empty"
    empty.touch(mode=0o600)
    assert resolver.resolve("empty", 0) == b""


@pytest.mark.parametrize("identifier", ["../object", "/object", "file:////object", "", "a/b", ".."])
def test_unsafe_ids_rejected(
    witness: tuple[Path, LocalIndependentFeedResolver], identifier: str
) -> None:
    _, resolver = witness
    with pytest.raises(ValueError, match="invalid local witness read request"):
        resolver.resolve(identifier, 100)


@pytest.mark.parametrize("component", ["root", "tenant", "issuer", "object"])
def test_permissions_are_checked_each_read(
    witness: tuple[Path, LocalIndependentFeedResolver], component: str
) -> None:
    root, resolver = witness
    parts = {"root": root, "tenant": root / "tenant", "issuer": root / "tenant" / "issuer"}
    path = parts.get(component, root / "tenant" / "issuer" / "object")
    path.chmod(0o755 if path.is_dir() else 0o644)
    with pytest.raises(ValueError, match="authorized witness read unavailable") as error:
        resolver.resolve("object", 100)
    assert "secret-canary" not in str(error.value)
    assert str(root) not in str(error.value)


@pytest.mark.parametrize("component", ["root", "tenant", "issuer", "object"])
def test_symlinks_are_rejected(
    witness: tuple[Path, LocalIndependentFeedResolver], component: str
) -> None:
    root, resolver = witness
    paths = {"root": root, "tenant": root / "tenant", "issuer": root / "tenant" / "issuer"}
    path = paths.get(component, root / "tenant" / "issuer" / "object")
    relocated = path.with_name(path.name + "-moved")
    path.rename(relocated)
    path.symlink_to(relocated, target_is_directory=relocated.is_dir())
    with pytest.raises(ValueError, match="authorized witness read unavailable"):
        resolver.resolve("object", 100)


def test_hardlink_oversize_and_other_tenant(
    witness: tuple[Path, LocalIndependentFeedResolver],
) -> None:
    root, resolver = witness
    obj = root / "tenant" / "issuer" / "object"
    with pytest.raises(ValueError):
        resolver.resolve("object", 1)
    os.link(obj, obj.with_name("linked"))
    with pytest.raises(ValueError):
        resolver.resolve("object", 100)
    other = LocalIndependentFeedResolver(root, tenant_id="other", issuer_id="issuer")
    with pytest.raises(ValueError):
        other.resolve("object", 100)


@pytest.mark.parametrize("limit", [True, -1, 1 << 25])
def test_invalid_limits(witness: tuple[Path, LocalIndependentFeedResolver], limit: int) -> None:
    root, resolver = witness
    with pytest.raises(ValueError):
        LocalIndependentFeedResolver(
            root, tenant_id="tenant", issuer_id="issuer", max_object_bytes=limit
        )
    with pytest.raises(ValueError):
        resolver.resolve("object", limit)


def test_changed_during_read_is_unavailable(
    witness: tuple[Path, LocalIndependentFeedResolver], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, resolver = witness
    original = os.read
    mutated = False

    def changing_read(fd: int, count: int) -> bytes:
        nonlocal mutated
        data = original(fd, count)
        if not mutated:
            mutated = True
            (root / "tenant" / "issuer" / "object").write_bytes(b"other-secret-canary")
        return data

    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(ValueError, match="authorized witness read unavailable"):
        resolver.resolve("object", 100)


def test_shared_ancestor_symlink_and_broad_root_are_rejected(
    witness: tuple[Path, LocalIndependentFeedResolver],
) -> None:
    root, _ = witness
    alias = root.parent / "ancestor-alias"
    alias.symlink_to(root.parent, target_is_directory=True)
    resolver = LocalIndependentFeedResolver(
        alias / root.name, tenant_id="tenant", issuer_id="issuer"
    )
    with pytest.raises(ValueError, match="authorized witness read unavailable"):
        resolver.resolve("object", 100)
    with pytest.raises(ValueError, match="invalid local witness resolver configuration"):
        LocalIndependentFeedResolver("/", tenant_id="tenant", issuer_id="issuer")
