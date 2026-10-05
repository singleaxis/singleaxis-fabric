"""Independent negative fixtures for the exact Node destination readback gate."""

import importlib.util
from pathlib import Path

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)

MODULE_PATH = Path(__file__).parents[1] / "qualification/run_custom_agent_node_pilot.py"
spec = importlib.util.spec_from_file_location("custom_agent_pilot", MODULE_PATH)
assert spec is not None and spec.loader is not None
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


def record(
    directory: Path, name: str, *, identifier: str = "record-1", outcome: str = "ok"
) -> None:
    request = ExportLogsServiceRequest()
    entry = request.resource_logs.add().scope_logs.add().log_records.add()
    entry.event_name = "agent.evidence.coverage"
    for key, value in {"record_id": identifier, "result_status": outcome}.items():
        attribute = entry.attributes.add()
        attribute.key = key
        attribute.value.string_value = value
    (directory / name).write_bytes(request.SerializeToString())


def expected():
    return {
        "record-1": {
            "event_name": "agent.evidence.coverage",
            "attributes": {"record_id": "record-1", "result_status": "ok"},
            "attribute_types": {
                "record_id": "string_value",
                "result_status": "string_value",
            },
        }
    }


def test_replay_deduplicates_only_matching_records(tmp_path):
    record(tmp_path, "first.otlp")
    record(tmp_path, "replay.otlp")
    assert pilot.readback(tmp_path, expected()) == 2
    record(tmp_path, "conflict.otlp", outcome="error")
    with pytest.raises(AssertionError, match="differs"):
        pilot.readback(tmp_path, expected())


def test_missing_and_extra_records_fail(tmp_path):
    with pytest.raises(AssertionError, match="missing"):
        pilot.readback(tmp_path, expected())
    record(tmp_path, "extra.otlp", identifier="unmatched")
    with pytest.raises(AssertionError, match="unexpected"):
        pilot.readback(tmp_path, expected())


def test_canary_in_actual_sink_bytes_fails(tmp_path):
    record(tmp_path, "leak.otlp", outcome=pilot.CANARY.decode())
    with pytest.raises(AssertionError, match="private"):
        pilot.readback(tmp_path, expected())
