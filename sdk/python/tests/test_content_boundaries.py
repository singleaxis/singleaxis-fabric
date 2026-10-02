# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Regression coverage for content namespace and UTF-8 boundaries."""

from pathlib import Path

import pytest

from fabric._content import truncate_bytes
from fabric.content_store import LocalFilesystemContentStore, S3ContentStore
from fabric.content_store.base import check_safe_identifier


@pytest.mark.parametrize("text", ["éx", "€x", "😀x", "aé€😀z"])
def test_truncation_preserves_every_complete_utf8_prefix(text: str) -> None:
    data = text.encode("utf-8")
    for limit in range(len(data) + 1):
        expected = data[:limit].decode("utf-8", errors="ignore").encode("utf-8")
        assert truncate_bytes(data, limit) == expected


@pytest.mark.parametrize("field", ["tenant_id", "object_id", "manifest_id"])
def test_namespace_identifier_rejects_trailing_newline(field: str) -> None:
    with pytest.raises(ValueError, match="safe namespace"):
        check_safe_identifier(field, "valid\n")


@pytest.mark.parametrize(
    "manifest_id", ["../../outside", "/absolute", "a/b", "a\\b", "ok\n", "", ".", ".."]
)
@pytest.mark.parametrize("backend", ["local", "s3"])
def test_manifest_id_rejected_before_storage(
    tmp_path: Path, manifest_id: str, backend: str
) -> None:
    store = (
        LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant")
        if backend == "local"
        else S3ContentStore(bucket="test-content", tenant_id="tenant")
    )
    with pytest.raises(ValueError, match="manifest_id"):
        store.manifest_uri_for(manifest_id)
    with pytest.raises(ValueError, match="manifest_id"):
        store.write_manifest({}, decision_id="decision", manifest_id=manifest_id)
    assert not (tmp_path / "store").exists()


def test_local_manifest_stays_in_namespace(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(str(tmp_path), tenant_id="tenant")
    uri = store.write_manifest({"ok": True}, decision_id="decision", manifest_id="manifest-1")
    assert uri == store.manifest_uri_for("manifest-1")
    assert store.owns_uri(uri)
    assert store.read_manifest(uri) == {"ok": True}
