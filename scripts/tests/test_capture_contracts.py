# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the draft LLM wire-capture contracts (spec 042 rev 4)."""

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
    assert len(validated) == 12
    assert "capture/fixtures/digests/stitch-v1-messages.json" in validated


def test_exchange_record_carries_no_content_or_stitching_keys() -> None:
    schema = _json("schema/llm-exchange-v1.schema.json")
    fields = set(schema["properties"])
    for forbidden in (
        "messages", "content", "prompt", "input", "output", "arguments",
        "message_digests", "tool_calls", "tool_call_ids_consumed", "previous_response_id",
        "response_id", "ref",
    ):
        assert forbidden not in fields
    assert set(schema["$defs"]["body"]["properties"]) == {"sha256", "object_id"}


def test_exchange_store_status_rollup() -> None:
    document = _json("fixtures/valid/llm-exchange-chat.json")
    document["response"].pop("object_id")
    _assert_error(document, "capture.exchange.store_status")
    document["store_status"] = "partial"
    validate_document(document, _schemas())
    document["request"].pop("object_id")
    document["store_status"] = "failed"
    validate_document(document, _schemas())
    document["store_status"] = "disabled"
    validate_document(document, _schemas())


@pytest.mark.parametrize(
    "value",
    [
        "file:///var/lib/fabric/content/tenant-a/evidence/0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01",
        "s3://bucket/fabric/content/tenant-a/evidence/0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01",
        "tenant-a/evidence/0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01",
        "0B8E1C52-1F0A-4D7E-8F3B-5C9A2E7D1A01",
        "0b8e1c52-1f0a-1d7e-8f3b-5c9a2e7d1a01",
        "patient-123-45-6789",
    ],
)
def test_exchange_object_id_is_a_bare_uuid4(value: str) -> None:
    document = _json("fixtures/valid/llm-exchange-chat.json")
    document["request"]["object_id"] = value
    _assert_error(document, "capture.schema")


def test_exchange_carries_no_response_id() -> None:
    document = _json("fixtures/valid/llm-exchange-chat.json")
    document["response_id"] = "chatcmpl-B9x2kQ"
    _assert_error(document, "capture.schema")


@pytest.mark.parametrize(
    ("reason", "valid"),
    [("stop", True), ("end_turn", True), ("other", True), ("secret_password", False)],
)
def test_exchange_finish_reasons_are_a_closed_vocabulary(reason: str, valid: bool) -> None:
    document = _json("fixtures/valid/llm-exchange-chat.json")
    document["finish_reasons"] = [reason]
    if valid:
        validate_document(document, _schemas())
    else:
        _assert_error(document, "capture.schema")


def test_reconstruction_model_uses_the_capture_pattern() -> None:
    document = _json("fixtures/valid/run-reconstruction-partial-loss.json")
    document["runs"][0]["exchanges"][0]["model"] = "Prompt: patient Alice has HIV"
    _assert_error(document, "capture.schema")


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
    run["declared_scope"]["windows"][0]["closed_by"] = "run_markers"
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
    run["declared_scope"]["windows"][0]["closed_by"] = "run_markers"
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
    run["declared_scope"]["windows"][0]["closed_by"] = "run_markers"
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
    run["declared_scope"]["windows"][0]["closed_by"] = "run_markers"
    _assert_error(document, "capture.reconstruction.verdict")
    document["sources"][0]["missing_sequences"] = [[6, 6]]
    validate_document(document, _schemas())


def test_complete_run_needs_a_proven_window_end() -> None:
    document = _json("fixtures/valid/run-reconstruction-partial-loss.json")
    document["sources"][0]["missing_sequences"] = []
    document["sources"][0]["loss_ranges"] = []
    run = document["runs"][0]
    run["gaps"] = []
    run["counts"]["gaps_by_type"] = {}
    run["checks"] = dict.fromkeys(run["checks"], "passed")
    run["verdict"] = "complete_for_declared_scope"
    window = run["declared_scope"]["windows"][0]
    window.pop("closed_by", None)
    _assert_error(document, "capture.reconstruction.verdict")  # no end evidence
    window["closed_by"] = "final_heartbeat"
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
