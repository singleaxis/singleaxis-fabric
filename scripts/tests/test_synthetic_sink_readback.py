"""Controlled sink parser must bind each record ID to the expected metadata."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)

verify = runpy.run_path(
    str(
        Path(__file__).resolve().parents[1]
        / "qualification"
        / "verify_synthetic_sink_readback.py"
    )
)["verify"]


def _fixture(
    tmp_path: Path, *, duplicate: bool = False, wrong_role: bool = False
) -> tuple[dict, Path]:
    request = ExportLogsServiceRequest()
    scope = request.resource_logs.add().scope_logs.add()
    for _ in range(2 if duplicate else 1):
        record = scope.log_records.add()
        record.event_name = "agent.evidence.content"
        for key, value in (
            ("record_id", "evt-example"),
            ("role", "terminal.stdout" if wrong_role else "model.request.messages"),
            ("status", "stored"),
            ("content_sha256", "sha256:" + "a" * 64),
            ("source_sequence", "1"),
        ):
            attr = record.attributes.add()
            attr.key = key
            attr.value.string_value = value
    sink_dir = tmp_path / "sink"
    sink_dir.mkdir()
    (sink_dir / "one.otlp").write_bytes(request.SerializeToString())
    report = {
        "cases": [
            {
                "fault": "clean",
                "expected_sink_records": [
                    {
                        "event_name": "agent.evidence.content",
                        "attributes": {
                            "record_id": "evt-example",
                            "role": "model.request.messages",
                            "status": "stored",
                            "content_sha256": "sha256:" + "a" * 64,
                            "source_sequence": "1",
                        },
                    }
                ],
            }
        ]
    }
    item = report["cases"][0]["expected_sink_records"][0]
    item["attribute_types"] = {key: "string_value" for key in item["attributes"]}
    return report, sink_dir


def test_exact_parsed_sink_record(tmp_path: Path) -> None:
    report, sink_dir = _fixture(tmp_path)
    assert verify(report, sink_dir) == 1
    assert report["cases"][0]["sink_readback_verified"]


def test_duplicate_id_is_not_exact_readback(tmp_path: Path) -> None:
    report, sink_dir = _fixture(tmp_path, duplicate=True)
    with pytest.raises(AssertionError, match="duplicate count"):
        verify(report, sink_dir)


def test_role_mismatch_is_not_exact_readback(tmp_path: Path) -> None:
    report, sink_dir = _fixture(tmp_path, wrong_role=True)
    with pytest.raises(AssertionError, match="role mismatch"):
        verify(report, sink_dir)


def test_privacy_canary_is_rejected(tmp_path: Path) -> None:
    report, sink_dir = _fixture(tmp_path)
    path = sink_dir / "one.otlp"
    path.write_bytes(path.read_bytes() + b"PILOT_SECRET_CANARY_do_not_export")
    with pytest.raises(AssertionError, match="leaked"):
        verify(report, sink_dir)
