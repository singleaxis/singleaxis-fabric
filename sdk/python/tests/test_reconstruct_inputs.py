# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Span-file readers for the reconstruction verifier (sink JSONL and OTLP/JSON)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct import ReconstructInputError, read_span_file, reconstruct
from tests.test_reconstruct_verifier import (
    GENERATED_AT,
    Capture,
    only_run,
    react_run,
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
            "attributes": {"fabric.run.sequence": 3},
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
    assert span.attributes == {"fabric.run.sequence": 3}
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
                "fabric.loss.affected_sequences": [1, 2],
                "fabric.loss.affected_truncated": False,
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
        "fabric.loss.affected_sequences": [1, 2],
        "fabric.loss.affected_truncated": False,
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
    assert only_run(otlp_document)["verdict"] == "complete_for_declared_scope"


def test_invalid_attribute_values_unplace_the_exchange(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    exchanges = react_run(capture)
    # A value the Node would have stripped: the exchange cannot be placed and
    # its sequence is reported missing instead of being trusted.
    exchanges[1].span["attributes"]["fabric.run.sequence"] = -4
    exchanges[1].span["attributes"]["fabric.wire.exchange_ref"] = "file:///x/not a valid id"
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert [ex["exchange_id"] for ex in run["exchanges"]] == ["ex-0", "ex-2"]


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


def test_reconstruct_rejects_bad_options(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    path = capture.write()
    with pytest.raises(ReconstructInputError):
        reconstruct([])
    with pytest.raises(ReconstructInputError):
        reconstruct([path], scope="everything")  # type: ignore[arg-type]
    with pytest.raises(ReconstructInputError):
        reconstruct([path], scan_store=True)
    with pytest.raises(ReconstructInputError):
        reconstruct([path], store=capture.store, tenant_id="other-tenant")
    with pytest.raises(ReconstructInputError):
        reconstruct([path], store=object(), tenant_id="tenant-a")
