# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the draft LLM wire-capture contracts (spec 042)."""

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


def test_exchange_record_carries_no_content_fields() -> None:
    schema = _json("schema/llm-exchange-v1.schema.json")
    request_fields = set(schema["properties"]["request"]["properties"])
    response_fields = set(schema["properties"]["response"]["properties"])
    for forbidden in ("messages", "content", "prompt", "input", "output", "arguments"):
        assert forbidden not in request_fields | response_fields


def test_exchange_digest_count_must_match() -> None:
    document = _json("fixtures/valid/llm-exchange-chat-tool-result.json")
    document["request"]["message_count"] = 3
    _assert_error(document, "capture.exchange.count")


def test_exchange_truncation_flag_must_match_bodies() -> None:
    document = _json("fixtures/valid/llm-exchange-chat-tool-result.json")
    document["capture"]["truncated"] = True
    _assert_error(document, "capture.exchange.truncation")


def test_exchange_ref_must_be_tenant_bound() -> None:
    document = _json("fixtures/valid/llm-exchange-chat-tool-result.json")
    document["request"]["body"]["ref"] = "file:///var/lib/fabric/content/tenant-b/evidence/x"
    _assert_error(document, "capture.exchange.ref")


def test_exchange_store_status_rollup() -> None:
    document = _json("fixtures/valid/llm-exchange-chat-tool-result.json")
    body = document["response"]["body"]
    for key in ("ref", "stored_sha256", "stored_byte_length"):
        body.pop(key)
    body.update(status="failed", representation="unavailable")
    body.pop("source_sha256")
    _assert_error(document, "capture.exchange.store_status")
    document["capture"]["store_status"] = "partial"
    validate_document(document, _schemas())


def test_loss_record_cannot_report_future_sequences() -> None:
    document = _json("fixtures/valid/loss-record-queue-full.json")
    document["affected"][0]["source_sequence"] = 9
    _assert_error(document, "capture.loss.affected")


def test_watermark_cannot_carry_a_reason() -> None:
    document = _json("fixtures/valid/loss-record-run-close-watermark.json")
    document["reason"] = "queue_full"
    _assert_error(document, "capture.schema")


def test_reconstruction_skipped_check_is_unverified() -> None:
    document = _json("fixtures/valid/run-reconstruction-partial-loss.json")
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
    run = document["runs"][0]
    run["gaps"] = [gap for gap in run["gaps"] if gap["effect"] == "info"]
    run["counts"]["gaps_by_type"] = {"unmatched_tool_call": 1}
    run["checks"] = dict.fromkeys(run["checks"], "passed")
    run["verdict"] = "complete_for_declared_scope"
    validate_document(document, _schemas())


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
