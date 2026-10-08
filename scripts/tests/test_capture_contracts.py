# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the draft LLM wire-capture contracts (spec 042 rev 3)."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_capture_contracts import (  # noqa: E402
    SCHEMAS,
    CaptureContractError,
    validate_capture_contracts,
    validate_digest_fixture,
    validate_document,
)

FAMILY = REPO_ROOT / "contracts" / "capture" / "v1"


def _json(relative: str) -> dict[str, Any]:
    value = json.loads((FAMILY / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schemas() -> dict[str, Any]:
    return {relative: _json(relative) for relative in SCHEMAS.values()}


def _assert_error(document: dict[str, Any], code: str) -> None:
    with pytest.raises(CaptureContractError) as caught:
        validate_document(document, _schemas())
    assert caught.value.code == code


def test_all_pinned_capture_artifacts_validate() -> None:
    validated = validate_capture_contracts(REPO_ROOT)
    assert len(validated) == 11
    assert "capture/fixtures/digests/stitch-v1-messages.json" in validated


def test_exchange_record_carries_no_content_or_stitching_keys() -> None:
    schema = _json("schema/llm-exchange-v1.schema.json")
    fields = set(schema["properties"])
    for forbidden in (
        "messages", "content", "prompt", "input", "output", "arguments",
        "message_digests", "tool_calls", "tool_call_ids_consumed", "previous_response_id",
    ):
        assert forbidden not in fields
    assert set(schema["$defs"]["body"]["properties"]) == {"sha256", "ref"}


def test_exchange_store_status_rollup() -> None:
    document = _json("fixtures/valid/llm-exchange-chat.json")
    document["response"].pop("ref")
    _assert_error(document, "capture.exchange.store_status")
    document["store_status"] = "partial"
    validate_document(document, _schemas())
    document["request"].pop("ref")
    document["store_status"] = "failed"
    validate_document(document, _schemas())
    document["store_status"] = "disabled"
    validate_document(document, _schemas())


def test_exchange_ref_must_not_traverse() -> None:
    document = _json("fixtures/valid/llm-exchange-chat.json")
    document["request"]["ref"] = "file:///var/lib/fabric/content/tenant-a/../tenant-b/x"
    _assert_error(document, "capture.exchange.ref")


def test_exchange_error_state_needs_error_type() -> None:
    document = _json("fixtures/valid/llm-exchange-chat.json")
    document["response_state"] = "error"
    _assert_error(document, "capture.schema")
    document["error_type"] = "ReadTimeout"
    validate_document(document, _schemas())
    document["response_state"] = "closed_early"
    _assert_error(document, "capture.exchange.error_type")


def test_complete_exchange_needs_a_response() -> None:
    document = _json("fixtures/valid/llm-exchange-chat.json")
    document.pop("response")
    _assert_error(document, "capture.schema")


def test_loss_record_shapes_are_closed_per_kind() -> None:
    heartbeat = _json("fixtures/valid/loss-record-heartbeat.json")
    heartbeat["reason"] = "queue_full"
    _assert_error(heartbeat, "capture.schema")
    loss = _json("fixtures/valid/loss-record-queue-full.json")
    loss["run_id"] = "run-travel-42"
    _assert_error(loss, "capture.schema")
    loss.pop("run_id")
    loss["reason"] = "buffer_overflow"
    _assert_error(loss, "capture.schema")


def test_heartbeat_allows_no_exchanges_yet() -> None:
    heartbeat = _json("fixtures/valid/loss-record-heartbeat.json")
    heartbeat["last_sequence"] = -1
    heartbeat.pop("run_id")
    validate_document(heartbeat, _schemas())


def test_reconstruction_skipped_check_is_unverified() -> None:
    document = _json("fixtures/valid/run-reconstruction-partial-loss.json")
    document["sources"][0]["missing_sequences"] = []
    document["sources"][0]["loss_ranges"] = []
    run = document["runs"][0]
    run["gaps"] = []
    run["counts"]["gaps_by_type"] = {}
    run["checks"] = dict.fromkeys(run["checks"], "passed")
    run["checks"]["bytes"] = "skipped"
    run["verdict"] = "complete_for_declared_scope"
    _assert_error(document, "capture.reconstruction.verdict")
    run["verdict"] = "unverified"
    validate_document(document, _schemas())


def test_reconstruction_info_gaps_do_not_downgrade() -> None:
    document = _json("fixtures/valid/run-reconstruction-partial-loss.json")
    document["sources"][0]["missing_sequences"] = []
    document["sources"][0]["loss_ranges"] = []
    run = document["runs"][0]
    run["gaps"] = [
        {
            "gap_type": "prefix_break",
            "effect": "info",
            "exchange_id": "ex-4",
            "reason": "history_rewritten",
        }
    ]
    run["counts"]["gaps_by_type"] = {"prefix_break": 1}
    run["checks"] = dict.fromkeys(run["checks"], "passed")
    run["verdict"] = "complete_for_declared_scope"
    validate_document(document, _schemas())


def test_complete_run_needs_heartbeat_through_its_window() -> None:
    document = _json("fixtures/valid/run-reconstruction-partial-loss.json")
    document["sources"][0]["missing_sequences"] = []
    document["sources"][0]["loss_ranges"] = []
    run = document["runs"][0]
    run["gaps"] = []
    run["counts"]["gaps_by_type"] = {}
    run["checks"] = dict.fromkeys(run["checks"], "passed")
    run["verdict"] = "complete_for_declared_scope"
    validate_document(document, _schemas())
    run["declared_scope"]["windows"][0]["heartbeat_sequence"] = 3
    _assert_error(document, "capture.reconstruction.verdict")


def test_adjacent_missing_sequence_blocks_complete() -> None:
    document = _json("fixtures/valid/run-reconstruction-partial-loss.json")
    document["sources"][0]["missing_sequences"] = [[5, 5]]
    document["sources"][0]["loss_ranges"] = []
    run = document["runs"][0]
    run["gaps"] = []
    run["counts"]["gaps_by_type"] = {}
    run["checks"] = dict.fromkeys(run["checks"], "passed")
    run["verdict"] = "complete_for_declared_scope"
    _assert_error(document, "capture.reconstruction.verdict")
    document["sources"][0]["missing_sequences"] = [[6, 6]]
    validate_document(document, _schemas())


def test_exchanges_must_lie_inside_declared_windows() -> None:
    document = _json("fixtures/valid/run-reconstruction-partial-loss.json")
    document["runs"][0]["declared_scope"]["windows"][0]["last_sequence"] = 3
    _assert_error(document, "capture.reconstruction.scope")


def test_digest_fixture_rejects_drift(tmp_path: Path) -> None:
    fixture = _json("fixtures/digests/stitch-v1-messages.json")
    validate_digest_fixture(fixture, tmp_path / "ok.json")
    broken = copy.deepcopy(fixture)
    broken["cases"][0]["projected"]["role"] = "user"
    with pytest.raises(CaptureContractError) as caught:
        validate_digest_fixture(broken, tmp_path / "broken.json")
    assert caught.value.code == "capture.digests.canonical"


def test_digest_fixture_pins_cross_call_equality() -> None:
    fixture = _json("fixtures/digests/stitch-v1-messages.json")
    pairs = [case for case in fixture["cases"] if "same_digest_as" in case]
    assert len(pairs) >= 3
    apis = {case["api"] for case in pairs}
    assert apis == {"openai.chat_completions", "anthropic.messages", "openai.responses"}
