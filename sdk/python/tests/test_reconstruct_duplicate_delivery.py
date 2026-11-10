# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Duplicate deliveries (field finding F5): delivery is at-least-once, so a Node retry
after a slow destination reply can store one export batch twice. The reader counts the
records whose ``fabric.event_id`` it already saw, per source, and changes nothing else:
no gap, no verdict, no extra exchange."""

from __future__ import annotations

import copy
import uuid
from pathlib import Path

from .test_reconstruct_verifier import Capture, only_run, react_run


def _with_event_ids(capture: Capture) -> None:
    for number, row in enumerate(capture.rows):
        row["attributes"]["fabric.event_id"] = str(uuid.UUID(int=number + 1, version=4))


def test_a_batch_delivered_twice_is_counted_and_changes_no_verdict(tmp_path: Path) -> None:
    once = Capture(tmp_path / "once")
    react_run(once)
    _with_event_ids(once)
    twice = Capture(tmp_path / "twice")
    react_run(twice)
    _with_event_ids(twice)
    # The whole batch again, byte-identical, as the Node's retry re-sent it.
    resent = copy.deepcopy(twice.rows)
    twice.rows.extend(resent)

    clean, duplicated = once.reconstruct(), twice.reconstruct()
    (source,) = duplicated["sources"]
    assert source["duplicate_records"] == len(resent)
    assert "duplicate_records" not in clean["sources"][0]
    assert source["exchanges"] == clean["sources"][0]["exchanges"] == 3
    run, baseline = only_run(duplicated), only_run(clean)
    assert run["verdict"] == baseline["verdict"] == "complete_for_declared_scope"
    assert run["gaps"] == baseline["gaps"] == []
    assert run["checks"] == baseline["checks"]
    assert [e["exchange_id"] for e in run["exchanges"]] == ["ex-0", "ex-1", "ex-2"]


def test_records_without_event_ids_are_not_counted(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    capture.rows.extend(copy.deepcopy(capture.rows))  # identical retries, no event ids
    (source,) = capture.reconstruct()["sources"]
    assert "duplicate_records" not in source
