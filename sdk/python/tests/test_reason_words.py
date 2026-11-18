# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-18 (F10): every reason a reader verdict can carry is put in plain words with
its fix, and ``fabric verify`` prints those words instead of a bare reason name.

The reasons are every value of the run-reconstruction schema's ``chainReason`` (gap types
and the 049/056 reasons), the controls chain's reasons (057) and the unattributed host
event reasons (056 M2). The catalogue is ``contracts/diagnostics/v1/reasons-v1.json``."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from fabric.cli import _coverage, _read, _reasons_data

REPO = Path(__file__).resolve().parents[3]
CONTRACT = REPO / "contracts" / "diagnostics" / "v1"
RUN_SCHEMA = REPO / "contracts" / "capture" / "v1" / "schema" / "run-reconstruction-v1.schema.json"


def _document() -> dict[str, Any]:
    document: dict[str, Any] = json.loads((CONTRACT / "reasons-v1.json").read_text("utf-8"))
    return document


def _schema_reasons() -> set[str]:
    """Every reason value the run-reconstruction schema allows on a verdict."""
    schema = json.loads(RUN_SCHEMA.read_text("utf-8"))
    defs = schema["$defs"]
    found = set(defs["chainReason"]["enum"]) | set(defs["gapType"]["enum"])
    found |= set(defs["controlsChainVerdict"]["properties"]["reasons"]["items"]["enum"])
    host = schema["properties"]["unattributed_host_events"]["properties"]["events"]["items"]
    found |= set(host["properties"]["reason"]["enum"])
    return found


def test_packaged_words_are_the_contract() -> None:
    """The wheel ships code only (057 B8): a generated module equal to the contract."""
    assert _document() == _reasons_data.REASONS


def test_words_match_their_schema_with_one_entry_per_reason() -> None:
    document = _document()
    schema = json.loads((CONTRACT / "schema" / "reasons-v1.schema.json").read_text("utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)
    reasons = [entry["reason"] for entry in document["reasons"]]
    assert len(reasons) == len(set(reasons))


def test_every_reader_reason_has_words_and_a_fix_and_no_other_reason_is_listed() -> None:
    """F10: no verdict reason reaches the user as a bare name."""
    catalogued = _coverage.known_reasons()
    assert _schema_reasons() - catalogued == set(), "reader reasons without words"
    assert catalogued - _schema_reasons() == set(), "words for a reason no reader emits"
    for reason in sorted(_schema_reasons()):
        line = _read.words(reason)
        assert line.startswith(f"{reason}: ") and "; fix: " in line, line
        text, fix = _coverage.reason_words(reason) or ("", "")
        assert text.strip() and fix.strip(), reason


def test_every_reason_the_reader_code_emits_is_a_schema_reason() -> None:
    """The reader's own reason literals (chain(...) arguments and appended reasons) are
    all in the schema, so the completeness test above covers what the code emits."""
    source = REPO / "sdk" / "python" / "src" / "fabric" / "reconstruct"
    emitted: set[str] = set()
    pattern = re.compile(r'reasons\.append\("([a-z_]+)"\)|"reasons": \["([a-z_]+)"\]')
    for path in source.glob("*.py"):
        for match in pattern.finditer(path.read_text("utf-8")):
            emitted.add(match[1] or match[2])
    assert emitted, "the pattern found no reason literal"
    assert emitted <= _schema_reasons()


def test_words_carry_no_interpolated_value() -> None:
    for entry in _document()["reasons"]:
        texts = [entry["text"], entry["fix"]]
        texts += [w for words in (entry.get("chains") or {}).values() for w in words.values()]
        for text in texts:
            assert "%s" not in text and "{" not in text, entry["reason"]


def test_a_chain_can_give_a_reason_its_own_meaning() -> None:
    effects = _coverage.reason_words("ambiguous_attribution", "effects")
    controls = _coverage.reason_words("ambiguous_attribution", "controls")
    assert effects and controls and effects != controls
    assert "terminal.argv" in effects[1]  # §12.4's example: the redact policy fix
    assert "pending" in controls[0]
    assert _coverage.reason_words("no_such_reason") is None
    assert _read.words("no_such_reason").startswith("no_such_reason (see")


@pytest.mark.parametrize(
    ("reason", "needle"),
    [
        # §12.4's three worked examples.
        ("unattributed_effect", "no tool call explains"),
        ("ambiguous_attribution", "withheld"),
        ("tail_unverified", "FABRIC_WIRE_DRAIN_ON_EXIT_S"),
        ("uninstrumented_client", "httpx or aiohttp"),
        ("anchor_missing", "fabric run"),
    ],
)
def test_the_words_name_the_cause_and_the_fix(reason: str, needle: str) -> None:
    assert needle in _read.words(reason)


def test_explain_run_words_gaps_chains_and_startup_effects() -> None:
    """A partial run: its gap, each chain's reasons as that chain means them (a reason two
    chains share in one meaning is said once), and its startup effects as a fact."""
    run = {
        "verdict": "partial",
        "gaps": [
            {"gap_type": "sequence_gap", "effect": "partial"},
            {"gap_type": "run_open", "effect": "info"},
        ],
        "chains": {
            "decisions": {"verdict": "partial", "reasons": ["sequence_gap"]},
            "effects": {"verdict": "partial", "reasons": ["ambiguous_attribution"]},
            "controls": {
                "verdict": "partial",
                "reasons": ["ambiguous_attribution", "sequence_gap"],
            },
            "corroboration": {"verdict": "not_observed", "reasons": ["not_configured"]},
        },
        "attribution": {"startup_effects": [{"attempt_uid": "a1"}]},
    }
    lines = _read.explain_run(run)
    assert lines[0].startswith("sequence_gap: records are missing")
    assert any(line.startswith("effects: ambiguous_attribution: an effect falls") for line in lines)
    assert any(
        line.startswith("controls: ambiguous_attribution: a control decision") for line in lines
    )
    assert any(line.startswith("controls: sequence_gap: records of a control") for line in lines)
    assert not any("run_open" in line or "not_configured" in line for line in lines)
    assert lines[-1].startswith("startup effects: commands ran before")
    assert _read.run_reasons(run) == ["sequence_gap", "ambiguous_attribution"]


def test_docs_page_lists_every_reason() -> None:
    page = (REPO / "docs" / "diagnostics.md").read_text("utf-8")
    for reason in _coverage.known_reasons():
        assert f"\n### {reason}\n" in page
