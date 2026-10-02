#!/usr/bin/env python3
"""Parse controlled sink OTLP files and bind each AEEP record to its metadata.

This is a CI fixture verifier, not a generic destination receipt validator.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)

try:
    from otlp_readback_validation import (
        protobuf_attributes,
        validate_metadata_container,
    )
except ModuleNotFoundError:
    from scripts.qualification.otlp_readback_validation import (
        protobuf_attributes,
        validate_metadata_container,
    )

CANARY = b"PILOT_SECRET_CANARY_do_not_export"


def verify(report: dict[str, Any], sink_dir: Path) -> int:
    cases = report.get("cases")
    if not isinstance(cases, list):
        raise ValueError("pilot report cases missing")
    clean = next((case for case in cases if case.get("fault") == "clean"), None)
    if not isinstance(clean, dict):
        raise ValueError("clean pilot case missing")
    records = clean.get("expected_sink_records")
    if not isinstance(records, list) or not records:
        raise ValueError("expected sink record map missing")
    expected = {item["attributes"]["record_id"]: item for item in records}
    if len(expected) != len(records):
        raise ValueError("duplicate expected record ID")
    files = sorted(sink_dir.glob("*.otlp"))
    if not files:
        raise ValueError("no controlled sink OTLP files")
    observed: dict[str, list[dict[str, Any]]] = {}
    for path in files:
        raw = path.read_bytes()
        contains_evidence = any(record_id.encode() in raw for record_id in expected)
        if contains_evidence and (CANARY in raw or b"file://" in raw):
            raise AssertionError(f"governed content or local ref leaked in {path.name}")
        request = ExportLogsServiceRequest()
        try:
            request.ParseFromString(raw)
        except DecodeError:
            if contains_evidence:
                raise AssertionError(
                    f"evidence payload did not decode: {path.name}"
                ) from None
            continue  # Unrelated trace/metric smoke fixture.
        for resource in request.resource_logs:
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    attrs, types = protobuf_attributes(record)
                    record_id = attrs.get("record_id", "")
                    if record_id.startswith("evt-"):
                        if record_id not in expected:
                            raise AssertionError(
                                f"unexpected evidence record: {record_id}"
                            )
                        validate_metadata_container(resource, scope, record)
                        observed.setdefault(record_id, []).append(
                            {
                                "event_name": record.event_name,
                                "attributes": attrs,
                                "attribute_types": types,
                            }
                        )
    if set(observed) != set(expected):
        raise AssertionError(
            f"sink record IDs differ: missing={len(set(expected) - set(observed))} "
            f"extra={len(set(observed) - set(expected))}"
        )
    for record_id, expected_record in expected.items():
        matches = observed[record_id]
        if len(matches) != 1:
            raise AssertionError(
                f"sink duplicate count for {record_id}: {len(matches)}"
            )
        actual = matches[0]
        if actual["event_name"] != expected_record["event_name"]:
            raise AssertionError(f"event name mismatch for {record_id}")
        if set(actual["attributes"]) != set(expected_record["attributes"]):
            raise AssertionError(f"attribute keys mismatch for {record_id}")
        if actual["attribute_types"] != expected_record.get("attribute_types"):
            raise AssertionError(f"attribute types mismatch for {record_id}")
        for key, value in expected_record["attributes"].items():
            if actual["attributes"].get(key) != str(value):
                raise AssertionError(f"{key} mismatch for {record_id}")
    clean["sink_parsed_records_checked"] = len(expected)
    clean["sink_readback_verified"] = True
    return len(expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-path", required=True, type=Path)
    parser.add_argument("--sink-dir", required=True, type=Path)
    args = parser.parse_args()
    report = json.loads(args.report_path.read_text())
    checked = verify(report, args.sink_dir)
    args.report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {"sink_readback_verified": True, "sink_parsed_records_checked": checked}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
