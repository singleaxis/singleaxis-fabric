# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Large bounded snapshots have exact-set projection without a false receipt."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from fabric.call_otlp import call_batch_manifest, project_call_snapshot_batches


def snapshot(count: int) -> dict[str, Any]:
    return {
        "schema_version": "fabric.call-recording/v1",
        "tenant_id": "tenant",
        "run_id": "run",
        "starts": [],
        "events": [],
        "operations": [
            {
                "record_id": f"record-{i}",
                "tenant_id": "tenant",
                "run_id": "run",
                "source_id": "source",
                "source_epoch": 0,
                "source_sequence": i,
                "observed_at": "2026-10-02T00:00:00Z",
                "call_id": f"call-{i}",
                "agent_id": "agent",
                "operation_id": f"op-{i}",
                "attempt_id": "try-1",
                "boundary": "tool",
                "role": "operation.outcome",
                "status": "recorded",
                "kind": "tool",
                "outcome": {"result_status": "ok"},
            }
            for i in range(count)
        ],
    }


def test_more_than_one_projection_batch_preserves_exact_set() -> None:
    value = snapshot(4100)
    batches = project_call_snapshot_batches(value)
    assert [len(ids) for _, ids in batches] == [4096, 4]
    ids = [identity for _, group in batches for identity in group]
    assert len(set(ids)) == 4100
    assert ids == [f"record-{i}" for i in range(4100)]
    manifest = call_batch_manifest(value)
    assert manifest["record_count"] == 4100
    assert manifest["durability_status"] == "unverified"
    assert manifest == call_batch_manifest(copy.deepcopy(value))
    value["operations"][0]["outcome"]["result_status"] = "error"
    assert manifest["snapshot_digest"] != call_batch_manifest(value)["snapshot_digest"]


@pytest.mark.parametrize("field", ["record_id", "source_sequence"])
def test_cross_batch_duplicate_rejected_before_output(field: str) -> None:
    value = snapshot(3)
    value["operations"][2][field] = value["operations"][0][field]
    with pytest.raises(ValueError, match="duplicate"):
        project_call_snapshot_batches(value, batch_size=2)


@pytest.mark.parametrize("size", [True, 0, -1, 4097, 1.5])
def test_invalid_batch_bounds(size: Any) -> None:
    with pytest.raises(ValueError):
        project_call_snapshot_batches(snapshot(0), batch_size=size)


def test_later_invalid_record_never_returns_partial_result() -> None:
    value = snapshot(3)
    value["operations"][2]["outcome"] = {"result_status": "secret-error"}
    with pytest.raises(ValueError):
        project_call_snapshot_batches(value, batch_size=2)


def test_empty_snapshot_has_valid_zero_record_manifest() -> None:
    manifest = call_batch_manifest(snapshot(0))
    assert manifest["record_count"] == 0
    assert len(manifest["batches"]) == 1
