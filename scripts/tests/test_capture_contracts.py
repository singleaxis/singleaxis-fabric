# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the draft LLM wire-capture contracts (specs 047 and 048)."""

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
    _check_marker_definitions,
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
    assert len(validated) == 105
    assert "capture/fixtures/digests/stitch-v1-messages.json" in validated
    assert "capture/fixtures/golden/content-descriptor-s3.json" in validated


def test_report_records_telemetry_origin_and_source_authentication() -> None:
    """Spec 049 §7.9, decision 20: the report says where its telemetry came from and
    names an unauthenticated production record as its own gap type."""
    schema = _json("schema/run-reconstruction-v1.schema.json")
    inputs = schema["properties"]["inputs"]["properties"]
    assert inputs["telemetry_origin"]["enum"] == ["trusted_readback", "imported"]
    assert inputs["profile"]["enum"] == ["local", "production"]
    assert "source_unauthenticated" in schema["$defs"]["gapType"]["enum"]
    report = _json("fixtures/valid/run-reconstruction-production-imported.json")
    (gap,) = [
        g
        for g in report["runs"][0]["gaps"]
        if g["gap_type"] == "source_unauthenticated"
    ]
    assert gap["effect"] == "unverified" and gap["reason"] == "imported_telemetry"


def test_exchange_record_carries_no_content_or_stitching_keys() -> None:
    schema = _json("schema/llm-exchange-v1.schema.json")
    fields = set(schema["properties"])
    for forbidden in (
        "messages",
        "content",
        "prompt",
        "input",
        "output",
        "arguments",
        "message_digests",
        "tool_calls",
        "tool_call_ids_consumed",
        "previous_response_id",
        "response_id",
        "ref",
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
def test_exchange_finish_reasons_are_a_closed_vocabulary(
    reason: str, valid: bool
) -> None:
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


# --- spec 048: spool records, content log records, goldens, run scopes -------

CONTENT_ATTRIBUTES = {
    "event_class",
    "schema_version",
    "object_id",
    "tenant_id",
    "role",
    "media_type",
    "content_encoding",
    "representation",
    "transformations",
    "provenance",
    "boundary",
    "status",
    "stored_byte_length",
    "stored_sha256",
    "source_byte_length",
    "source_sha256",
    "source_id",
    "source_epoch",
    "source_sequence",
    "run_id",
    "operation_id",
    "captured_at",
    # spec 049 §4.3 rule 6 (P0-A)
    "status_reason",
    "observed_at",
    "workload_id",
    "attempt_id",
    "stream_id",
    "chunk_index",
    "privacy_mode",
    "policy_id",
    "policy_version",
    "policy_digest",
    "protection_status",
    "transformation_id",
    "transformation_version",
    "links",
}


def test_spool_and_content_share_one_descriptor_definition() -> None:
    spool = _json("schema/spool-record-v1.schema.json")["$defs"]["descriptor"]
    content = _json("schema/content-log-record-v1.schema.json")["$defs"]["descriptor"]
    assert spool == content
    assert set(content["properties"]) | {"event_class"} == CONTENT_ATTRIBUTES
    assert (
        "ref" not in content["properties"] and "encoding" not in content["properties"]
    )
    # Receiver-owned: never part of what an agent sends (spec 049 §4.3 rule 6).
    assert "source_authenticated" not in content["properties"]


def test_content_log_record_attribute_set_is_closed() -> None:
    document = _json("fixtures/valid/content-log-record-request.json")
    assert set(document["attributes"]) <= CONTENT_ATTRIBUTES
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
    for forbidden in (
        "messages",
        "content",
        "prompt",
        "gen_ai.response.id",
        "ref",
        "uri",
    ):
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
    moved["object_key"] = (
        "fabric/content/tenant-a/" + moved["object_key"].rsplit("/", 1)[1]
    )
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
    document["runs"][0]["exchanges"][0]["scope_id"] = (
        "8c1f0e2d-4a5b-4c6d-9e7f-2a3b4c5d6e7f"
    )
    _assert_error(document, "capture.reconstruction.scope")


# ---------------------------------------------------------------- spec 049 P0 (capture/v1 1.1.0)
def test_shared_allocator_spool_kinds_and_inputs() -> None:
    schema = _json("schema/spool-record-v1.schema.json")
    assert schema["properties"]["record_kind"]["enum"] == [
        "exchange",
        "record",
        "loss",
        "marker",
    ]
    record = _json("fixtures/valid/spool-record-record.json")
    attributes = record["span"]["attributes"]
    assert attributes["fabric.capture.input"] == "records"
    exchange = _json("fixtures/valid/spool-record-exchange-shared-allocator.json")
    # One allocator per (source, epoch): both inputs take positions from one counter.
    assert exchange["source"] == record["source"]
    assert (
        attributes["fabric.source.sequence"]
        == exchange["span"]["attributes"]["fabric.source.sequence"] + 1
    )
    for key in ("fabric.source.sequence", "fabric.event_id", "fabric.attempt.uid"):
        broken = copy.deepcopy(record)
        del broken["span"]["attributes"][key]
        _assert_error(broken, "capture.schema")


def test_records_input_span_never_carries_content_or_the_node_stamp() -> None:
    record = _json("fixtures/valid/spool-record-record.json")
    for key, value in (
        ("fabric.source.authenticated", True),
        ("fabric.tool.arguments", {"query": "Jane Doe"}),
    ):
        broken = copy.deepcopy(record)
        broken["span"]["attributes"][key] = value
        _assert_error(broken, "capture.schema")


def test_segment_seal_is_a_heartbeat_kind_with_its_own_keys() -> None:
    seal = _json("fixtures/valid/loss-record-segment-seal.json")
    assert seal["heartbeat_kind"] == "segment_seal"
    validate_document(seal, _schemas())
    for key in ("segment_id", "terminal", "seal", "run_id"):
        broken = copy.deepcopy(seal)
        del broken[key]
        _assert_error(broken, "capture.schema")
    for key, value in (
        ("predecessors", ["none"]),
        ("scope_status", "ok"),
        ("open_deadline_s", 600),
    ):
        broken = copy.deepcopy(seal)
        broken[key] = value
        _assert_error(broken, "capture.schema")


def test_run_marker_keys_stay_on_their_kinds() -> None:
    start = _json("fixtures/valid/loss-record-run-start-continuation.json")
    for kind in ("periodic", "final"):
        broken = copy.deepcopy(start)
        broken["heartbeat_kind"] = kind
        broken.pop("scope_id")
        _assert_error(broken, "capture.schema")
    end = copy.deepcopy(start)
    end["heartbeat_kind"] = "run_end"
    _assert_error(end, "capture.schema")
    root = _json("fixtures/valid/spool-record-run-start-root.json")
    assert root["marker"]["predecessors"] == ["none"]
    root["marker"]["terminal"] = True
    _assert_error(root, "capture.schema")


def test_predecessor_entries_are_exact() -> None:
    start = _json("fixtures/valid/loss-record-run-start-continuation.json")
    entry = start["predecessors"][0]
    start["predecessors"] = [entry, entry]
    _assert_error(start, "capture.marker.predecessors")
    segment, source, _epoch, last, digest = entry.split("/")
    start["predecessors"] = [f"{segment}/{source}/9223372036854775808/{last}/{digest}"]
    _assert_error(start, "capture.marker.predecessors")
    start["predecessors"] = [f"{segment}/{source}/0/{last}/{digest}"]
    _assert_error(start, "capture.schema")


def test_run_marker_keys_are_defined_identically_on_both_forms() -> None:
    schemas = _schemas()
    _check_marker_definitions(schemas)
    tampered = copy.deepcopy(schemas)
    heartbeat = tampered["schema/loss-record-v1.schema.json"]["oneOf"][1]["properties"]
    heartbeat["open_deadline_s"]["maximum"] = 10**12
    with pytest.raises(CaptureContractError) as caught:
        _check_marker_definitions(tampered)
    assert caught.value.code == "capture.marker.definition"


def test_manifest_record_is_the_generated_span_form() -> None:
    from contracts.validate_coverage_contracts import (
        load_registries,
        render_manifest_record_schema,
    )

    manifest_schema = json.loads(
        (
            REPO_ROOT / "contracts/coverage/v1/schema/capture-manifest-v1.schema.json"
        ).read_text()
    )
    rendered = render_manifest_record_schema(
        load_registries(REPO_ROOT), manifest_schema
    )
    assert _json("schema/capture-manifest-record-v1.schema.json") == rendered
    record = _json("fixtures/valid/capture-manifest-record-local.json")
    for marker in (
        "fabric.wire.exchange_id",
        "fabric.heartbeat.last_sequence",
        "fabric.loss.reason",
    ):
        assert marker not in rendered["properties"]["attributes"]["properties"]
        broken = copy.deepcopy(record)
        broken["attributes"][marker] = "x"
        _assert_error(broken, "capture.schema")


def test_manifest_is_spooled_as_a_marker_without_a_position() -> None:
    marker = _json("fixtures/valid/spool-record-manifest.json")
    attributes = marker["marker"]["manifest"]
    assert marker["marker"]["kind"] == "manifest"
    assert (
        marker["marker"]["last_sequence"]
        == attributes["fabric.manifest.after_source_sequence"]
    )
    assert "fabric.capture.input" not in attributes
    broken = copy.deepcopy(marker)
    broken["marker"]["manifest"]["fabric.capture.input"] = "wire"
    _assert_error(broken, "capture.marker.manifest")
    broken = copy.deepcopy(marker)
    broken["marker"]["manifest_seq"] = 0
    _assert_error(broken, "capture.schema")


@pytest.mark.parametrize(
    ("pseudonym", "valid"),
    [
        ("p-0123456789abcdef", True),
        ("p-0123456789abcdef0123456789abcdef", True),
        ("p-0123456789abcdef0", False),
        ("p-0123456789ABCDEF", False),
        ("resp_abc123", False),
    ],
)
def test_provider_pseudonyms_keyed_or_legacy(pseudonym: str, valid: bool) -> None:
    """Spec 049 §2.9 rule 4: keyed p- + 32 hex, legacy p- + 16 hex stays readable."""
    import re  # noqa: PLC0415

    pattern = _json("schema/run-reconstruction-v1.schema.json")["$defs"]["pseudonym"][
        "pattern"
    ]
    assert (re.fullmatch(pattern, pseudonym) is not None) is valid


# ------------------------------------------------------------------ capture/v1 1.3.0 (spec 050 §4.2)
def test_capture_family_is_version_1_3_0() -> None:
    assert _json("manifest.json")["version"] == "1.3.0"


def test_exchange_bodies_bound_is_260_and_record_bodies_8() -> None:
    schema = _json("schema/spool-record-v1.schema.json")
    exchange, record = schema["oneOf"][0], schema["oneOf"][1]
    assert exchange["properties"]["bodies"]["maxItems"] == 260
    assert record["properties"]["bodies"]["maxItems"] == 8
    assert (
        exchange["properties"]["bodies"]["items"]
        == record["properties"]["bodies"]["items"]
    )
    validate_document(
        _json("fixtures/valid/spool-record-exchange-260.json"), _schemas()
    )
    assert len(_json("fixtures/valid/spool-record-exchange-260.json")["bodies"]) == 260
    _assert_error(
        _json("fixtures/invalid/spool-record-exchange-261.json"), "capture.schema"
    )


def test_record_bodies_are_the_object_ids_in_order() -> None:
    record = _json("fixtures/valid/spool-record-record-bodies.json")
    validate_document(record, _schemas())
    bodies = record["bodies"]
    assert [b["descriptor"]["object_id"] for b in bodies] == record["span"][
        "attributes"
    ]["fabric.content.object_ids"]
    # A descriptor-only body (R5) occupies no blob bytes and names a producer reason.
    only = [b for b in bodies if b["descriptor"]["status"] == "not_captured"]
    assert only and only[0]["length"] == 0
    assert only[0]["descriptor"]["status_reason"] == "payload_too_large"
    assert sum(b["descriptor"]["role"] == "record.evidence" for b in bodies) == 1
    swapped = copy.deepcopy(record)
    ids = swapped["span"]["attributes"]["fabric.content.object_ids"]
    ids[0], ids[1] = ids[1], ids[0]
    _assert_error(swapped, "capture.spool.consistency")
    shifted = copy.deepcopy(record)
    shifted["bodies"][2]["offset"] += 1
    _assert_error(shifted, "capture.spool.consistency")


def test_unsupported_descriptor_only_body() -> None:
    record = _json("fixtures/valid/spool-record-record-bodies.json")
    body = record["bodies"][1]["descriptor"]
    body.update(status="unsupported", status_reason="not_exact_bytes")
    validate_document(record, _schemas())
    body.update(stored_byte_length=0)
    _assert_error(record, "capture.schema")


def test_loss_segment_range_is_exact() -> None:
    loss = _json("fixtures/valid/loss-record-segment.json")
    validate_document(loss, _schemas())
    unattributed = copy.deepcopy(loss)
    del unattributed["segment_id"]
    unattributed["last_sequence"] += 3  # an unattributed range may hold other positions
    validate_document(unattributed, _schemas())
    loose = copy.deepcopy(loss)
    loose["last_sequence"] += 1
    _assert_error(loose, "capture.loss.segment")


def test_marker_additions_are_placed_by_kind() -> None:
    root = _json("fixtures/valid/spool-record-run-start-root-identity.json")
    validate_document(root, _schemas())
    run_end = _json("fixtures/valid/spool-record-marker-run-end-outcome.json")
    validate_document(run_end, _schemas())
    for key, value in (("outcome", "completed"), ("stop_reason", "goal_reached")):
        broken = copy.deepcopy(root)
        broken["marker"][key] = value
        _assert_error(broken, "capture.schema")
    for key in (
        "session_id",
        "user_id",
        "links",
        "id_basis",
        "identity",
        "parent_run_id",
    ):
        broken = copy.deepcopy(run_end)
        broken["marker"][key] = root["marker"][key]
        _assert_error(broken, "capture.schema")
    final = {
        "kind": "final",
        "last_sequence": 9,
        "event_id": run_end["marker"]["event_id"],
    }
    validate_document(dict(run_end, marker=final), _schemas())
    bad = dict(final, event_id=final["event_id"].upper())
    _assert_error(dict(run_end, marker=bad), "capture.schema")


def test_root_only_run_fields_and_id_basis() -> None:
    continuation = _json("fixtures/valid/loss-record-run-start-continuation.json")
    assert continuation["id_basis"] == "token"
    broken = copy.deepcopy(continuation)
    broken["links"] = []
    _assert_error(broken, "capture.marker.root")
    no_basis = copy.deepcopy(continuation)
    del no_basis["id_basis"]
    _assert_error(no_basis, "capture.marker.id_basis")
    # A pre-P1 run_start (no segment, no event id) stays readable.
    legacy = {
        k: v
        for k, v in continuation.items()
        if k
        not in {
            "segment_id",
            "id_basis",
            "event_id",
            "predecessors",
            "branch_ids",
            "declared_branches",
        }
    }
    validate_document(legacy, _schemas())


def test_manifest_marker_event_id_is_the_manifests() -> None:
    marker = _json("fixtures/valid/spool-record-manifest.json")
    assert (
        marker["marker"]["event_id"] == marker["marker"]["manifest"]["fabric.event_id"]
    )
    _assert_error(
        _json("fixtures/invalid/spool-record-manifest-event-id-mismatch.json"),
        "capture.marker.manifest",
    )


def test_reconstruction_run_states() -> None:
    report = _json("fixtures/valid/run-reconstruction-segments.json")
    validate_document(report, _schemas())
    run = report["runs"][0]
    assert run["run_state"] == "terminated" and run["segments"][0]["state"] == "sealed"
    opened = copy.deepcopy(report)
    opened["runs"][0].update(run_state="open", deadline_at="2026-10-25T00:00:00Z")
    opened["runs"][0]["gaps"].append({"gap_type": "run_open", "effect": "info"})
    opened["runs"][0]["counts"]["gaps_by_type"]["run_open"] = 1
    validate_document(opened, _schemas())  # run_open never counts in the verdict
    partial_open = copy.deepcopy(opened)
    partial_open["runs"][0]["gaps"][-1]["effect"] = "partial"
    with pytest.raises(CaptureContractError):
        validate_document(partial_open, _schemas())
    alias = copy.deepcopy(report)
    alias["runs"][0]["run_aliases"] = [run["run_id"]]
    _assert_error(alias, "capture.reconstruction.segments")
    schema = _json("schema/run-reconstruction-v1.schema.json")
    for gap in (
        "segment_missing",
        "segment_conflict",
        "post_terminal_activity",
        "run_unterminated",
        "run_open",
        "seal_mismatch",
        "unsealed_segment",
        "unsealed_epoch",
        "manifest_gap",
        "clock_uncertain",
    ):
        assert gap in schema["$defs"]["gapType"]["enum"]


def test_content_descriptor_rules_are_shared_with_the_prevalidate_vector() -> None:
    from contracts.validate_capture_contracts import content_descriptor_ok  # noqa: PLC0415

    record = _json("fixtures/valid/spool-record-record-bodies.json")
    for body in record["bodies"]:
        attrs = dict(body["descriptor"], event_class="content")
        assert content_descriptor_ok(attrs)
    attrs = dict(
        record["bodies"][2]["descriptor"],
        event_class="content",
        media_type="text/plain",
    )
    assert not content_descriptor_ok(attrs)
