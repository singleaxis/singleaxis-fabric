# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Regenerating the spec 049 P0 derived artifacts produces no diff."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.generate_p0_contracts import generate  # noqa: E402


def test_regenerating_derived_contract_artifacts_is_a_no_op() -> None:
    assert generate(REPO_ROOT, check=True) == []
