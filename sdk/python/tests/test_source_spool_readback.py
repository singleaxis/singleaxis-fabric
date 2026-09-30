# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh sealed readback must notice changes after a successful cached seal."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from fabric.source_spool import SyntheticSourceSpool


def _sealed(tmp_path: Path) -> tuple[SyntheticSourceSpool, dict[str, Any]]:
    root = tmp_path / "journal"
    root.mkdir(mode=0o700)
    spool = SyntheticSourceSpool(str(root), tenant_id="tenant-a", run_id="run-a")
    event = {
        "record_id": "record-a",
        "tenant_id": "tenant-a",
        "run_id": "run-a",
        "source_id": "source-a",
        "source_epoch": 0,
        "source_sequence": 0,
        "operation_id": "op-a",
        "attempt_id": "try-a",
        "boundary": "terminal",
        "role": "terminal.stdout",
        "status": "pending",
        "observed_at": "2026-09-30T00:00:00Z",
    }
    admission = spool.append(event)
    assert admission == "pending"
    assert spool.seal_epoch({"source-a": 0})["status"] == "sealed"
    return spool, event


def test_fresh_readback_is_exact_deep_copy_and_does_not_advance(tmp_path: Path) -> None:
    spool, event = _sealed(tmp_path)
    try:
        readback = spool.readback_sealed_epoch(0)
        assert readback["records"] == [event]
        assert readback["seal"] == spool.current_seal()
        readback["records"][0]["record_id"] = "changed"
        assert spool.readback_sealed_epoch(0)["records"] == [event]
        assert spool.epoch == 0
    finally:
        spool.close()


@pytest.mark.parametrize(
    "mutation",
    [
        "delete",
        "corrupt",
        "permissions",
        "root_permissions",
        "symlink",
        "intent",
        "hardlink",
        "fifo",
        "duplicate_json_field",
    ],
)
def test_changes_after_seal_do_not_use_cached_result(tmp_path: Path, mutation: str) -> None:
    spool, _ = _sealed(tmp_path)
    try:
        path = spool.root / "event-record-a.json"
        if mutation == "delete":
            path.unlink()
        elif mutation == "corrupt":
            path.write_bytes(b"CANARY-DO-NOT-LEAK")
        elif mutation == "permissions":
            path.chmod(0o644)
        elif mutation == "root_permissions":
            spool.root.chmod(0o755)
        elif mutation == "symlink":
            path.unlink()
            path.symlink_to(spool.root / "seal-0.json")
        elif mutation == "hardlink":
            os.link(path, spool.root / "extra-link")
        elif mutation == "fifo":
            path.unlink()
            os.mkfifo(path, 0o600)
        elif mutation == "duplicate_json_field":
            data = path.read_bytes()
            path.write_bytes(b'{"sha256":"CANARY-DO-NOT-LEAK",' + data[1:])
        else:
            intent = spool.root / "intent-0.json"
            intent.write_text(
                json.dumps(
                    {
                        "schema_version": "fabric.source-epoch-seal/v1",
                        "tenant_id": "tenant-a",
                        "run_id": "run-a",
                        "source_epoch": 0,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            intent.chmod(0o600)
        assert spool.current_seal() is not None
        with pytest.raises(ValueError, match=r"^source readback unavailable or invalid$"):
            spool.readback_sealed_epoch(0)
    finally:
        spool.close()


@pytest.mark.parametrize("epoch", [-1, True, "0", 1])
def test_invalid_or_unsealed_epoch_fails(tmp_path: Path, epoch: Any) -> None:
    spool, _ = _sealed(tmp_path)
    try:
        with pytest.raises(ValueError, match="source readback"):
            spool.readback_sealed_epoch(epoch)
    finally:
        spool.close()


def test_ancestor_symlink_is_not_an_authorized_source_root(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    spool, _ = _sealed(parent)
    moved = tmp_path / "parent-moved"
    try:
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        with pytest.raises(ValueError, match="source readback unavailable or invalid"):
            spool.readback_sealed_epoch(0)
    finally:
        spool.close()
