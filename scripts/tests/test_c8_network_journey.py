# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Real loopback C8 semantics, protected storage and read-only recovery."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "qualification/run_c8_network_journey.py"
spec = importlib.util.spec_from_file_location("c8_journey", PATH)
journey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journey)


def test_network_semantics_independent_commit_and_fresh_readback(tmp_path):
    root = tmp_path / "evidence"
    report = journey.run(root)
    assert len(report["service_requests"]) == 4
    assert [row["status"] for row in report["service_requests"]] == [503, 200, 400, 200]
    assert sum(row["effect"] for row in report["service_requests"]) == 1
    assert report["fresh_readback"]["objects"] == 7
    lost = report["scenarios"][-1]["observed_result"]
    assert lost["caller_effect_state"] == "unknown"
    assert lost["independent_effect_state"] == "committed"
    assert lost["remote_effect"]["acknowledged"] is False
    assert report["production_verdict"] == "NO_GO"
    # Tampering with persisted metadata cannot authorize recovered bytes.
    metadata = json.loads((root / "metadata.json").read_text())
    next(row for row in metadata if "content_object_id" in row)["tenant_id"] = "other"
    (root / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(RuntimeError, match="authorized derivative read failed"):
        journey.readback(root)
    with sqlite3.connect(root / "service.sqlite") as db:
        assert db.execute("SELECT COUNT(*), SUM(effect) FROM requests").fetchone() == (
            4,
            1,
        )


def test_refuses_to_reuse_evidence_directory(tmp_path):
    with pytest.raises(FileExistsError):
        journey.run(tmp_path)
