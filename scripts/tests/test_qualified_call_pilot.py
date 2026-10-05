# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual provider/subprocess fixture, independently recorded byte evidence."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "qualification"
    / "run_qualified_call_pilot.py"
)


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("qualified_pilot_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_pilot_and_loss_matrix(tmp_path: Path) -> None:
    module = _load()
    output = tmp_path / "new-evidence"
    report = module.run_pilot(output)
    assert report["verdict"] == "verified_complete_for_declared_scope"
    assert report["fixture_only"] is True
    assert report["production_status"] == "NO_GO"
    assert report["operations"] == 4
    assert report["byte_objects"] == 15
    negative = json.loads((output / "negative-tests.json").read_bytes())
    assert len(negative) >= 18
    assert all(
        item["verdict"] != "verified_complete_for_declared_scope"
        for item in negative.values()
    )
    assert (
        output / "agent-workspace" / "result.bin"
    ).read_bytes() == b"\x00\xffrecorded-artifact\n"
    for filename in (
        "summary.json",
        "positive.json",
        "negative-tests.json",
        "projection.json",
    ):
        assert module.CANARY not in (output / filename).read_bytes()
    assert (
        report["receipt_authority"] == "fixture_only_not_live_node_or_storage_issuance"
    )


def test_pilot_preserves_existing_evidence(tmp_path: Path) -> None:
    module = _load()
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "keep"
    sentinel.write_bytes(b"user-owned")
    with pytest.raises(FileExistsError):
        module.run_pilot(output)
    assert sentinel.read_bytes() == b"user-owned"


def test_cli_requires_explicit_fixture_scope(tmp_path: Path) -> None:
    output = tmp_path / "not-created"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--evidence-dir", str(output)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 2
    assert b"requires --fixture-only" in result.stderr
    assert not output.exists()
