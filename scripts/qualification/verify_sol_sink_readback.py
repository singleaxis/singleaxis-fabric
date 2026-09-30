#!/usr/bin/env python3
"""Exact parsed readback for one synthetic Sol metadata projection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)

CANARY = b"FABRIC_SYNTHETIC_SECRET_DO_NOT_EXPORT"


def _json_attributes(record: dict[str, Any]) -> dict[str, str]:
    values = {}
    for attribute in record["attributes"]:
        value = attribute["value"]
        values[attribute["key"]] = str(value.get("stringValue", value.get("intValue")))
    return values


def _protobuf_attributes(record: Any) -> dict[str, str]:
    values = {}
    for attribute in record.attributes:
        kind = attribute.value.WhichOneof("value")
        if kind in {"string_value", "int_value"}:
            values[attribute.key] = str(getattr(attribute.value, kind))
    return values


def verify(projection: Path, sink_dir: Path) -> dict[str, Any]:
    payload = (projection / "otlp-metadata.json").read_bytes()
    expected: dict[str, dict[str, Any]] = {}
    document = json.loads(payload)
    for resource in document["resourceLogs"]:
        for scope in resource["scopeLogs"]:
            for record in scope["logRecords"]:
                attrs = _json_attributes(record)
                record_id = attrs["record_id"]
                if record_id in expected:
                    raise ValueError("duplicate projected record ID")
                expected[record_id] = {
                    "event_name": record["eventName"],
                    "attributes": attrs,
                }
    if not expected:
        raise ValueError("empty projected evidence set")
    observed: dict[str, list[dict[str, Any]]] = {}
    files = sorted(sink_dir.glob("*.otlp"))
    if not files:
        raise ValueError("no copied fsynced sink files")
    matching_files = []
    for path in files:
        raw = path.read_bytes()
        if not any(record_id.encode() in raw for record_id in expected):
            continue
        matching_files.append(path.name)
        if CANARY in raw or b"file://" in raw:
            raise AssertionError("content canary or local reference escaped into sink")
        request = ExportLogsServiceRequest()
        try:
            request.ParseFromString(raw)
        except DecodeError as exc:
            raise AssertionError("matching sink payload did not parse") from exc
        for resource in request.resource_logs:
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    attrs = _protobuf_attributes(record)
                    record_id = attrs.get("record_id")
                    if record_id in expected:
                        observed.setdefault(record_id, []).append(
                            {"event_name": record.event_name, "attributes": attrs}
                        )
    missing = set(expected) - set(observed)
    if missing:
        raise AssertionError(f"missing {len(missing)} projected IDs in sink readback")
    for record_id, values in expected.items():
        matches = observed[record_id]
        if len(matches) != 1:
            raise AssertionError(f"duplicate sink record for {record_id}")
        if matches[0] != values:
            raise AssertionError(f"sink metadata mismatch for {record_id}")
    return {
        "sink_readback_verified_for_metadata_only": True,
        "record_ids_checked": len(expected),
        "matching_sink_files": matching_files,
        "projected_otlp_sha256": hashlib.sha256(payload).hexdigest(),
        "production_go": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projection-dir", type=Path, required=True)
    parser.add_argument("--sink-dir", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.projection_dir, args.sink_dir)
    path = args.projection_dir / "sink-readback.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write((json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
