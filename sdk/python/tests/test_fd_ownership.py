# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Exercise descriptor ownership on successful and interrupted namespace traversal."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric.byte_resolver import ByteEvidenceResolver
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.deployment_policy import DeploymentPolicy
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority
from fabric.independent_store import LocalIndependentFeedResolver


@pytest.fixture(params=["byte", "byte_metadata", "witness", "governed"])
def read_action(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Callable[[], object]]:
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    if request.param in {"byte", "byte_metadata"}:
        directory = root / "tenant" / "evidence"
        directory.mkdir(parents=True, mode=0o700)
        (directory / "meta").mkdir(mode=0o700)
        (directory / "object").write_bytes(b"synthetic bytes")
        (directory / "meta" / "object.json").write_bytes(b"{}")
        store = LocalFilesystemContentStore(str(root), tenant_id="tenant")
        resolver = ByteEvidenceResolver(store, tenant_id="tenant")
        yield lambda: resolver._read("object", metadata=request.param == "byte_metadata")
        store.close()
    elif request.param == "witness":
        directory = root / "tenant" / "issuer"
        directory.mkdir(parents=True, mode=0o700)
        directory.parent.chmod(0o700)
        obj = directory / "object"
        obj.write_bytes(b"synthetic bytes")
        obj.chmod(0o600)
        witness = LocalIndependentFeedResolver(root, tenant_id="tenant", issuer_id="issuer")
        yield lambda: witness._read("object", 100)
    else:
        policy = DeploymentPolicy.from_dict(
            {
                "schema_version": "fabric.deployment-policy/v1",
                "policy_id": "test",
                "policy_version": 1,
                "tenant_id": "tenant",
                "workload_id": "workload",
                "privacy": {"tool.call.result": "retain_original"},
                "storage": {"backend": "local", "region": "local", "key_id": "test"},
                "retention": {"days": 1},
                "required_integrations": [],
                "deployment": {
                    "profile": "local",
                    "image_digest": "local",
                    "tls_required": False,
                    "encrypted_store_required": False,
                },
            }
        )
        authority = LocalCapabilityAuthority(b"synthetic-test-secret-32-bytes!!!!")
        capability = authority.issue(
            policy=policy, subject_id="test", permissions={"write_original"}, ttl_seconds=300
        )
        governed = GovernedLocalContentStore(
            root, policy=policy, authority=authority, capability=capability
        )

        def enter_directory() -> object:
            with governed._directory(create=True) as descriptor:
                return os.fstat(descriptor)

        yield enter_directory


def test_every_acquired_descriptor_closes_on_success_and_each_open_failure(
    read_action: Callable[[], object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_open, real_close = os.open, os.close

    def exercise(fail_at: int | None) -> int:
        acquired: list[int] = []
        closed: list[int] = []
        attempts = 0

        def tracked_open(*args: Any, **kwargs: Any) -> int:
            nonlocal attempts
            attempts += 1
            if attempts == fail_at:
                raise OSError("synthetic traversal failure")
            descriptor = real_open(*args, **kwargs)
            acquired.append(descriptor)
            return descriptor

        def tracked_close(descriptor: int) -> None:
            real_close(descriptor)
            closed.append(descriptor)

        with monkeypatch.context() as patch:
            patch.setattr(os, "open", tracked_open)
            patch.setattr(os, "close", tracked_close)
            if fail_at is None:
                read_action()
            else:
                with pytest.raises(OSError, match="synthetic traversal failure"):
                    read_action()
        assert closed == list(reversed(acquired))
        for descriptor in acquired:
            with pytest.raises(OSError):
                os.fstat(descriptor)
        return attempts

    total = exercise(None)
    assert total >= 3
    for fail_at in range(1, total + 1):
        exercise(fail_at)


def test_descriptors_close_when_read_or_validation_fails(
    read_action: Callable[[], object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_open, real_close = os.open, os.close
    acquired: list[int] = []
    closed: list[int] = []

    def tracked_open(*args: Any, **kwargs: Any) -> int:
        descriptor = real_open(*args, **kwargs)
        acquired.append(descriptor)
        return descriptor

    def tracked_close(descriptor: int) -> None:
        real_close(descriptor)
        closed.append(descriptor)

    def failed_stat(_descriptor: int) -> os.stat_result:
        raise OSError("synthetic metadata failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", tracked_open)
        patch.setattr(os, "close", tracked_close)
        patch.setattr(os, "fstat", failed_stat)
        with pytest.raises(OSError, match="synthetic metadata failure"):
            read_action()
    assert acquired
    assert closed == list(reversed(acquired))
    for descriptor in acquired:
        with pytest.raises(OSError):
            os.fstat(descriptor)
