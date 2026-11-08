# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The records vocabularies and ``ControlObservation`` enums equal the registry's
(``contracts/coverage/v1/registry``), and the phase x decision matrix equals the one the
contract fixtures are generated from (``scripts/contracts/security_context.py``)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fabric import control_evidence
from fabric.reconstruct import _controls
from fabric.records import _vocab

from ._records_harness import _load

REPO = Path(__file__).resolve().parents[3]
REGISTRY = REPO / "contracts/coverage/v1/registry"


def _vocabulary(name: str) -> set[str]:
    doc: dict[str, Any] = json.loads((REGISTRY / "vocabularies-v1.json").read_text())
    return {row["value"] for row in doc[name]}


def _field_enum(field_id: str) -> set[str]:
    doc: dict[str, Any] = json.loads((REGISTRY / "field-registry-v1.json").read_text())
    (row,) = [f for f in doc["fields"] if f["id"] == field_id]
    return set(re.findall(r"enum ([a-z0-9_/]+)", row["type"])[0].split("/"))


def test_vocabularies_equal_the_registry() -> None:
    assert _vocab.CONTROL_KINDS == _vocabulary("control_kind") == _field_enum("D02")
    assert _vocab.CONTROL_DECISIONS == _vocabulary("control_decision") == _field_enum("D04")
    assert _field_enum("D03") == _vocab.CONTROL_PHASES
    assert _vocabulary("actor_type") == _vocab.ACTOR_TYPES
    assert _field_enum("C30") == _vocab.EXECUTION_MODES
    assert _field_enum("C31") == _vocab.APPROVAL_POLICIES
    assert _vocabulary("link_type") - {"parent"} == _vocab.LINK_TYPES


def test_control_observation_enums_equal_the_registry() -> None:
    ce = control_evidence
    assert _vocabulary("control_kind") == ce.KINDS
    assert _vocabulary("control_decision") == ce.DECISIONS
    assert _vocabulary("control_stage") == ce.STAGES
    assert _vocabulary("gated_kind") == ce.GATED_KINDS
    assert _vocabulary("control_mode") == ce.MODES
    assert _vocabulary("control_error_class") == ce.ERROR_CLASSES
    assert _vocabulary("control_signal") == ce.SIGNALS
    assert _vocabulary("control_derivation") == ce.DERIVATIONS
    assert _vocabulary("actor_type") == ce.ACTOR_TYPES


def test_the_matrix_is_the_contract_matrix() -> None:
    reference = _load("_security_context", REPO / "scripts/contracts/security_context.py")
    expected = {phase: frozenset(values) for phase, values in reference.MATRIX.items()}
    assert dict(_vocab.PHASE_DECISIONS) == expected
    assert dict(control_evidence.PHASE_DECISIONS) == expected
    assert dict(_controls.PHASE_DECISIONS) == expected
