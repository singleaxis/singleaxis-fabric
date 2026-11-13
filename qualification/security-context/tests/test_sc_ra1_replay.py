# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SC-RA-1 end to end in replay mode: every session, capture off and on, every check, the
B4 gates skipped (they run as their own CI step and in sdk/python CI). CI runs
``run_sc_ra1.py`` itself, which also runs the gates; this test is the same run for a local
``pytest``."""

from __future__ import annotations

import json
from pathlib import Path

import run_sc_ra1


def test_sc_ra1_replay(tmp_path: Path) -> None:
    code = run_sc_ra1.main(["--mode", "replay", "--out", str(tmp_path), "--no-latency-gate"])
    result = json.loads((tmp_path / "sc-ra1-result.json").read_text())
    failed = [c for c in result["checks"] if not c["ok"]]
    assert code == 0 and not failed, failed
