# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the draft LLM wire-capture contracts (specs 042 and 043)."""

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
    validate_golden_fixture,
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
    assert len(validated) == 28
    assert "capture/fixtures/digests/stitch-v1-messages.json" in validated
    assert "capture/fixtures/golden/content-descriptor-s3.json" in validated


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


# --- spec 043: spool records, content log records, goldens, run scopes -------

CONTENT_ATTRIBUTES = {
    "event_class", "schema_version", "object_id", "tenant_id", "role", "media_type",
    "content_encoding", "representation", "transformations", "provenance", "boundary",
    "status", "stored_byte_length", "stored_sha256", "source_byte_length", "source_sha256",
    "source_id", "source_epoch", "source_sequence", "run_id", "operation_id", "captured_at",
}


def test_spool_and_content_share_one_descriptor_definition() -> None:
    spool = _json("schema/spool-record-v1.schema.json")["$defs"]["descriptor"]
    content = _json("schema/content-log-record-v1.schema.json")["$defs"]["descriptor"]
    assert spool == content
    assert set(content["properties"]) | {"event_class"} == CONTENT_ATTRIBUTES
    assert "ref" not in content["properties"] and "encoding" not in content["properties"]


def test_content_log_record_attribute_set_is_closed() -> None:
    document = _json("fixtures/valid/content-log-record-request.json")
    assert set(document["attributes"]) == CONTENT_ATTRIBUTES
    for key in ("ref", "content", "path", "bucket"):
        broken = copy.deepcopy(document)
        broken["attributes"][key] = "x"
        _assert_error(broken, "capture.schema")
    broken = copy.deepcopy(document)
    broken["attributes"]["event_class"] = "audit"
    _assert_error(broken, "capture.schema")


@pytest.mark.parametrize("tenant", ["../tenant-b", "tenant/b", ".", "..", ""])
def test_content_log_record_rejects_unsafe_tenants(tenant: str) -> None:
    document = _json("fixtures/valid/content-log-record-request.json")
    document["attributes"]["tenant_id"] = tenant
    _assert_error(document, "capture.schema")


def test_content_representation_must_agree() -> None:
    truncated = _json("fixtures/valid/content-log-record-truncated.json")
    validate_document(truncated, _schemas())
    broken = copy.deepcopy(truncated)
    broken["attributes"]["source_sha256"] = broken["attributes"]["stored_sha256"]
    _assert_error(broken, "capture.content.representation")
    request = _json("fixtures/valid/content-log-record-request.json")
    request["attributes"]["representation"] = "partial"
    _assert_error(request, "capture.content.representation")


def test_spool_header_carries_no_content_or_locations() -> None:
    schema = _json("schema/spool-record-v1.schema.json")
    exchange = schema["oneOf"][0]["properties"]
    attributes = set(exchange["span"]["properties"]["attributes"]["properties"])
    assert "fabric.run.scope_id" in attributes
    for forbidden in ("messages", "content", "prompt", "gen_ai.response.id", "ref", "uri"):
        assert forbidden not in attributes and forbidden not in exchange


def test_spool_body_must_be_named_by_the_span() -> None:
    document = _json("fixtures/valid/spool-record-exchange.json")
    validate_document(document, _schemas())
    document["span"]["attributes"]["fabric.content.result_ref"] = (
        "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a09"
    )
    _assert_error(document, "capture.spool.consistency")


def test_spool_final_marker_carries_no_run_or_scope() -> None:
    document = _json("fixtures/valid/spool-record-marker.json")
    document["marker"]["kind"] = "final"
    _assert_error(document, "capture.schema")
    document["marker"].pop("run_id")
    document["marker"].pop("scope_id")
    validate_document(document, _schemas())


def test_spool_loss_range_is_checked() -> None:
    document = _json("fixtures/valid/spool-record-loss.json")
    document["loss"]["count"] = 3
    _assert_error(document, "capture.loss.range")


def test_scope_id_is_a_uuid4_on_exchanges_and_markers() -> None:
    exchange = _json("fixtures/valid/llm-exchange-chat.json")
    exchange["scope_id"] = "3d7e1f2a-9b4c-4e5d-8a6f-1b2c3d4e5f60"
    validate_document(exchange, _schemas())
    exchange["scope_id"] = "run-travel-42"
    _assert_error(exchange, "capture.schema")
    heartbeat = _json("fixtures/valid/loss-record-heartbeat.json")
    heartbeat["heartbeat_kind"] = "periodic"
    _assert_error(heartbeat, "capture.heartbeat.scope")


def test_golden_descriptor_bytes_are_pinned(tmp_path: Path) -> None:
    golden = _json("fixtures/golden/content-descriptor-file.json")
    validate_golden_fixture(golden, _schemas(), tmp_path / "ok.json")
    assert golden["descriptor_json"].endswith("\n")
    assert '"encoding": "binary"' in golden["descriptor_json"]
    drift = copy.deepcopy(golden)
    compact = json.dumps(json.loads(golden["descriptor_json"]), separators=(",", ":"))
    drift["descriptor_json"] = compact + "\n"  # Go's json.Marshal default: wrong bytes
    with pytest.raises(CaptureContractError) as caught:
        validate_golden_fixture(drift, _schemas(), tmp_path / "drift.json")
    assert caught.value.code == "capture.golden.descriptor"
    moved = copy.deepcopy(_json("fixtures/golden/content-descriptor-s3.json"))
    moved["object_key"] = "fabric/content/tenant-a/" + moved["object_key"].rsplit("/", 1)[1]
    with pytest.raises(CaptureContractError) as caught:
        validate_golden_fixture(moved, _schemas(), tmp_path / "moved.json")
    assert caught.value.code == "capture.golden.layout"


def test_scope_window_must_match_its_markers() -> None:
    document = _json("fixtures/valid/run-reconstruction-nested-scopes.json")
    validate_document(document, _schemas())
    document["runs"][0]["declared_scope"]["windows"][1]["last_sequence"] = 2
    _assert_error(document, "capture.reconstruction.scope")


def test_scope_window_ignores_neighbouring_gaps_but_not_inner_ones() -> None:
    document = _json("fixtures/valid/run-reconstruction-nested-scopes.json")
    document["sources"][0]["missing_sequences"] = [[3, 3]]
    document["sources"][0]["heartbeat_sequence"] = 3
    validate_document(document, _schemas())  # outside every scope window
    run = document["runs"][0]
    run["exchanges"].pop(1)
    run["exchanges"][1]["continues_exchange_id"] = run["exchanges"][0]["exchange_id"]
    run["threads"][0]["exchange_ids"].pop(1)
    run["counts"]["exchanges"] = 2
    run["scopes"][1]["exchanges"] = 0
    document["sources"][0]["missing_sequences"] = [[1, 1], [3, 3]]
    _assert_error(document, "capture.reconstruction.verdict")


def test_scoped_exchange_must_lie_in_its_scope_window() -> None:
    document = _json("fixtures/valid/run-reconstruction-nested-scopes.json")
    document["runs"][0]["exchanges"][0]["scope_id"] = "8c1f0e2d-4a5b-4c6d-9e7f-2a3b4c5d6e7f"
    _assert_error(document, "capture.reconstruction.scope")
