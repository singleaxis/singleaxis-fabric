# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Span-file readers for the reconstruction verifier (sink JSONL and OTLP/JSON)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct import ReconstructInputError, SpanRecord, read_span_file, reconstruct
from fabric.reconstruct._ids import report_tenant_id
from fabric.reconstruct._inputs import HeartbeatObs, MalformedMarkerObs, observe
from tests.test_reconstruct_verifier import (
    GENERATED_AT,
    Capture,
    only_run,
    react_run,
    react_turns,
    validate,
)


def _any_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, list):
        return {"arrayValue": {"values": [_any_value(item) for item in value]}}
    return {"stringValue": value}


def _kv(mapping: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"key": key, "value": _any_value(value)} for key, value in mapping.items()]


def to_otlp(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Re-encode sink rows as one OTLP/JSON ExportTraceServiceRequest."""

    spans = []
    for row in rows:
        span: dict[str, Any] = {
            "traceId": row["trace_id"],
            "spanId": row["span_id"],
            "name": row["name"],
            "kind": 3,
            "startTimeUnixNano": str(row["start_ns"]),
            "endTimeUnixNano": str(row["end_ns"]),
            "attributes": _kv(row["attributes"]),
        }
        if row.get("parent_span_id"):
            span["parentSpanId"] = row["parent_span_id"]
        spans.append(span)
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": _kv({"service.name": "react-agent"})},
                "scopeSpans": [{"scope": {"name": "fabric.wire"}, "spans": spans}],
            }
        ]
    }


def test_sink_jsonl_ignores_log_rows(tmp_path: Path) -> None:
    path = tmp_path / "records.jsonl"
    rows = [
        {"kind": "log", "body": "x"},
        {
            "kind": "span",
            "trace_id": "AB" * 16,
            "span_id": "cd" * 8,
            "parent_span_id": None,
            "name": "fabric.model_call",
            "start_ns": 5,
            "end_ns": 9,
            "attributes": {"fabric.source.sequence": 3},
            "resource": {"service.name": "svc"},
        },
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n\n")
    fmt, spans = read_span_file(path)
    assert fmt == "sink_jsonl"
    assert len(spans) == 1
    span = spans[0]
    assert span.trace_id == "ab" * 16
    assert span.parent_span_id is None
    assert span.attributes == {"fabric.source.sequence": 3}
    assert (span.start_ns, span.end_ns) == (5, 9)


def test_otlp_whole_file_and_per_line(tmp_path: Path) -> None:
    rows = [
        {
            "trace_id": "ab" * 16,
            "span_id": "cd" * 8,
            "parent_span_id": "ef" * 8,
            "name": "fabric.capture_loss",
            "start_ns": 10,
            "end_ns": 10,
            "attributes": {
                "fabric.loss.first_sequence": 1,
                "fabric.loss.last_sequence": 2,
                "fabric.loss.reason": "queue_full",
            },
        }
    ]
    export = to_otlp(rows)
    whole = tmp_path / "whole.json"
    whole.write_text(json.dumps(export, indent=2))
    per_line = tmp_path / "lines.jsonl"
    per_line.write_text(json.dumps(export) + "\n" + json.dumps(export) + "\n")

    fmt, spans = read_span_file(whole)
    assert fmt == "otlp_json"
    assert spans[0].attributes == {
        "fabric.loss.first_sequence": 1,
        "fabric.loss.last_sequence": 2,
        "fabric.loss.reason": "queue_full",
    }
    assert spans[0].parent_span_id == "ef" * 8
    assert spans[0].resource == {"service.name": "react-agent"}
    fmt, spans = read_span_file(per_line)
    assert fmt == "otlp_json"
    assert len(spans) == 2


def test_otlp_base64_ids_are_converted(tmp_path: Path) -> None:
    trace = bytes(range(16))
    span_id = bytes(range(8))
    export = {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": base64.b64encode(trace).decode(),
                                "spanId": base64.b64encode(span_id).decode(),
                                "name": "x",
                                "startTimeUnixNano": 1,
                                "endTimeUnixNano": 2,
                            }
                        ]
                    }
                ]
            }
        ]
    }
    path = tmp_path / "b64.json"
    path.write_text(json.dumps(export))
    _, spans = read_span_file(path)
    assert spans[0].trace_id == trace.hex()
    assert spans[0].span_id == span_id.hex()


def test_empty_file_is_an_empty_sink(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    assert read_span_file(path) == ("sink_jsonl", [])


@pytest.mark.parametrize(
    "content",
    [
        "not json\n",
        "[1, 2]\n",
        '{"neither": true}\n',
        '{"kind": "span", "trace_id": 7}\n',
        '{"kind": "span", "start_ns": "soon"}\n',
        '{"kind": "span", "attributes": []}\n',
        '{"kind": "span"}\n{"resourceSpans": []}\n',
        '{"resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": [{"value": {}}]}]}]}]}',
        '{"resourceSpans": [{"scopeSpans": [{"spans": [{"traceId": "zz!"}]}]}]}',
        '{"resourceSpans": {"oops": 1}}',
    ],
)
def test_malformed_input_raises(tmp_path: Path, content: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(ReconstructInputError):
        read_span_file(path)


def test_unreadable_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ReconstructInputError):
        read_span_file(tmp_path / "missing.jsonl")
    binary = tmp_path / "binary.jsonl"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ReconstructInputError):
        read_span_file(binary)


def test_otlp_capture_reconstructs_like_sink(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    sink_document = capture.reconstruct()
    otlp = tmp_path / "export.json"
    otlp.write_text(json.dumps(to_otlp(capture.rows)))
    otlp_document = reconstruct([otlp], store=capture.store, generated_at=GENERATED_AT)
    validate(otlp_document)
    assert otlp_document["inputs"]["span_files"][0]["format"] == "otlp_json"
    assert otlp_document["runs"] == sink_document["runs"]
    assert otlp_document["sources"] == sink_document["sources"]
    assert only_run(otlp_document)["verdict"] == "complete_for_declared_scope"


def test_multiple_span_files_are_listed(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    first = tmp_path / "a.jsonl"
    second = tmp_path / "b.jsonl"
    first.write_text("".join(json.dumps(row) + "\n" for row in capture.rows[:2]))
    second.write_text("".join(json.dumps(row) + "\n" for row in capture.rows[2:]))
    document = reconstruct([first, second], store=capture.store, generated_at=GENERATED_AT)
    validate(document)
    assert [entry["records"] for entry in document["inputs"]["span_files"]] == [2, 2]
    assert only_run(document)["verdict"] == "complete_for_declared_scope"


@pytest.mark.parametrize(
    ("attributes", "name"),
    [
        ({"fabric.heartbeat.last_sequence": -2}, "fabric.capture_heartbeat"),
        ({"fabric.heartbeat.last_sequence": "3"}, "fabric.capture_heartbeat"),
        (
            {
                "fabric.loss.reason": "buffer_overflow",
                "fabric.loss.count": 1,
                "fabric.loss.first_sequence": 3,
                "fabric.loss.last_sequence": 3,
            },
            "fabric.capture_loss",
        ),
        (
            {
                "fabric.loss.reason": "queue_full",
                "fabric.loss.count": 3,
                "fabric.loss.first_sequence": 3,
                "fabric.loss.last_sequence": 4,
            },
            "fabric.capture_loss",
        ),
    ],
)
def test_invalid_loss_and_heartbeat_spans_are_ignored(
    tmp_path: Path, attributes: dict[str, Any], name: str
) -> None:
    capture = Capture(tmp_path)
    react_run(capture, heartbeat=False)
    capture.skip()
    capture._record(name, attributes)  # inject a malformed record
    capture.exchange(*react_turns()[0])
    capture.heartbeat()
    document = capture.reconstruct()
    (source,) = document["sources"]
    assert source["loss_ranges"] == []
    assert source["heartbeat_sequence"] == 4
    assert "sequence_gap" in {gap["gap_type"] for gap in only_run(document)["gaps"]}


SCOPE_KEY = "fabric.run.scope_id"
_UUID1_SCOPE = "3d7e1f2a-9b4c-1e5d-8a6f-1b2c3d4e5f60"
SCOPE = "3d7e1f2a-9b4c-4e5d-8a6f-1b2c3d4e5f60"
OTHER_SCOPE = "8c1f0e2d-4a5b-4c6d-9e7f-2a3b4c5d6e7f"


def _heartbeat_span(span_id: str, attributes: dict[str, Any]) -> SpanRecord:
    return SpanRecord(
        trace_id="a" * 32,
        span_id=span_id,
        parent_span_id=None,
        name="fabric.capture_heartbeat",
        start_ns=1,
        end_ns=1,
        attributes={
            "fabric.source_id": "wire-1",
            "fabric.source.epoch": 7,
            "fabric.heartbeat.last_sequence": 3,
            **attributes,
        },
        resource={},
    )


@pytest.mark.parametrize(
    ("attributes", "kind", "run_id"),
    [
        ({"fabric.heartbeat.kind": "periodic"}, "periodic", None),
        ({"fabric.heartbeat.kind": "final"}, "final", None),
        (
            {"fabric.heartbeat.kind": "run_start", "fabric.run.id": "r-1", SCOPE_KEY: SCOPE},
            "run_start",
            "r-1",
        ),
        (
            {"fabric.heartbeat.kind": "run_end", "fabric.run.id": "r-1", SCOPE_KEY: SCOPE},
            "run_end",
            "r-1",
        ),
        # A marker that names no valid scope (047 capture) bounds nothing.
        ({"fabric.heartbeat.kind": "run_end", "fabric.run.id": "r-1"}, None, None),
        (
            {"fabric.heartbeat.kind": "run_end", "fabric.run.id": "r-1", SCOPE_KEY: SCOPE.upper()},
            None,
            None,
        ),
        (
            {"fabric.heartbeat.kind": "run_end", "fabric.run.id": "r-1", SCOPE_KEY: "not-a-uuid"},
            None,
            None,
        ),
        (
            {
                "fabric.heartbeat.kind": "run_start",
                "fabric.run.id": "r-1",
                SCOPE_KEY: _UUID1_SCOPE,  # uuid1, not uuid4
            },
            None,
            None,
        ),
        # A run id or scope id on a non-marker kind is ignored.
        (
            {"fabric.heartbeat.kind": "final", "fabric.run.id": "r-1", SCOPE_KEY: SCOPE},
            "final",
            None,
        ),
        ({"fabric.heartbeat.kind": "periodic", SCOPE_KEY: SCOPE}, "periodic", None),
        # Outside the closed vocabulary, or absent (pre-rev-5 capture).
        ({"fabric.heartbeat.kind": "shutdown"}, None, None),
        ({"fabric.run.id": "r-1"}, None, None),
    ],
)
def test_heartbeat_kind_is_a_closed_vocabulary(
    attributes: dict[str, Any], kind: str | None, run_id: str | None
) -> None:
    observed = observe(_heartbeat_span("b" * 16, attributes))
    scope = SCOPE if run_id is not None else None
    assert observed == HeartbeatObs("wire-1", 7, kind, run_id, 3, scope)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "attributes",
    [
        {"fabric.heartbeat.kind": "run_end", SCOPE_KEY: SCOPE},
        {"fabric.heartbeat.kind": "run_end", "fabric.run.id": "bad id", SCOPE_KEY: SCOPE},
        {"fabric.heartbeat.kind": "run_start", "fabric.run.id": "r-1", SCOPE_KEY: SCOPE,
         "fabric.heartbeat.last_sequence": "x"},
    ],
)  # fmt: skip
def test_a_marker_naming_a_valid_scope_with_malformed_fields_flags_that_scope(
    attributes: dict[str, Any],
) -> None:
    """It bounds nothing, but the scope it names can never be closed (sol2 #5)."""
    observed = observe(_heartbeat_span("b" * 16, attributes))
    assert isinstance(observed, MalformedMarkerObs) and observed.scope_id == SCOPE
    if attributes.get("fabric.heartbeat.last_sequence") != "x":
        assert observed.heartbeat == HeartbeatObs("wire-1", 7, None, None, 3)


def test_heartbeat_identity_ignores_the_span_id() -> None:
    """A retried export re-sends the same record under a new span id (spec 047 E1)."""
    attributes = {"fabric.heartbeat.kind": "run_start", "fabric.run.id": "r-1", SCOPE_KEY: SCOPE}
    first = observe(_heartbeat_span("b" * 16, attributes))
    retry = observe(_heartbeat_span("c" * 16, attributes))
    assert first == retry
    assert len({first, retry}) == 1


def test_heartbeat_identity_includes_the_scope_id() -> None:
    """Two blocks of one run entered at the same sequence are two markers (spec 048 §6)."""
    base = {"fabric.heartbeat.kind": "run_start", "fabric.run.id": "r-1"}
    first = observe(_heartbeat_span("b" * 16, {**base, SCOPE_KEY: SCOPE}))
    other = observe(_heartbeat_span("c" * 16, {**base, SCOPE_KEY: OTHER_SCOPE}))
    assert first != other
    assert len({first, other}) == 2


@pytest.mark.parametrize(
    ("value", "expected"),
    [(SCOPE, SCOPE), (SCOPE.upper(), None), ("", None), (7, None), ("x" * 36, None)],
)
def test_exchange_scope_id_must_be_a_lowercase_uuid4(
    tmp_path: Path, value: Any, expected: str | None
) -> None:
    """A scope id is identity: a malformed one refuses the input (sol2 #5), never "absent"."""
    capture = Capture(tmp_path)
    exchange = capture.exchange(*react_turns()[0], scope_id=value)
    record = SpanRecord(
        trace_id=exchange.span["trace_id"],
        span_id=exchange.span["span_id"],
        parent_span_id=None,
        name="fabric.model_call",
        start_ns=exchange.span["start_ns"],
        end_ns=exchange.span["end_ns"],
        attributes=exchange.span["attributes"],
        resource={},
    )
    if expected is None:
        with pytest.raises(ReconstructInputError, match="malformed identity"):
            observe(record)
        return
    observed = observe(record)
    assert observed is not None
    assert getattr(observed, "scope_id") == expected  # noqa: B009


def test_otlp_json_negative_int_values_are_read(tmp_path: Path) -> None:
    """OTLP/JSON writes int64 as a string; a run_start before any call carries "-1"."""
    span = {
        "traceId": "a" * 32,
        "spanId": "b" * 16,
        "name": "fabric.capture_heartbeat",
        "startTimeUnixNano": "1",
        "endTimeUnixNano": "1",
        "attributes": [
            {"key": "fabric.source_id", "value": {"stringValue": "wire-1"}},
            {"key": "fabric.source.epoch", "value": {"intValue": "7"}},
            {"key": "fabric.heartbeat.last_sequence", "value": {"intValue": "-1"}},
            {"key": "fabric.heartbeat.kind", "value": {"stringValue": "run_start"}},
            {"key": "fabric.run.id", "value": {"stringValue": "r-1"}},
            {"key": SCOPE_KEY, "value": {"stringValue": SCOPE}},
        ],
    }
    path = tmp_path / "spans.json"
    path.write_text(
        json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]}), encoding="utf-8"
    )
    _, (record,) = read_span_file(path)
    assert observe(record) == HeartbeatObs("wire-1", 7, "run_start", "r-1", -1, SCOPE)
    span["startTimeUnixNano"] = "-1"  # timestamps stay unsigned
    path.write_text(
        json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]}), encoding="utf-8"
    )
    with pytest.raises(ReconstructInputError):
        read_span_file(path)


def test_report_names_no_input_paths(tmp_path: Path) -> None:
    """Codex r2 #2: span file and store root paths (which can name a user's home directory)
    never reach the report; span files are identified by digest, format and count."""
    from fabric.reconstruct.__main__ import main  # noqa: PLC0415

    home = tmp_path / "home" / "jane.doe-patient-0042"
    capture = Capture(home)
    react_run(capture)
    spans = capture.write()
    out = tmp_path / "report.json"
    argv = ["--spans", str(spans), "--store-root", str(home / "store"), "--tenant", "tenant-a"]
    assert main([*argv, "--out", str(out)]) == 0
    text = out.read_text("utf-8")
    assert "jane.doe" not in text and str(tmp_path) not in text
    document = json.loads(text)
    validate(document)
    (entry,) = document["inputs"]["span_files"]
    assert set(entry) == {"sha256", "format", "records"}
    assert document["inputs"]["store"] == {
        "kind": "local",
        "tenant_id": report_tenant_id("tenant-a"),
    }
