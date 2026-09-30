# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The live auth probe must fail when independent sink evidence differs."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip(
    "grpc", reason="source-binding probe requires its isolated grpcio test extra"
)
SCRIPT = Path(__file__).resolve().parents[1] / "qualification/check_source_binding.py"
SPEC = importlib.util.spec_from_file_location("source_binding_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def fixture(tmp_path: Path) -> tuple[argparse.Namespace, object]:
    request, ids = probe._request("bind-fixture", "valid")
    record = request.resource_logs[0].scope_logs[0].log_records[0]
    record.ClearField("body")
    kept = [item for item in record.attributes if item.key != "unapproved_private"]
    del record.attributes[:]
    record.attributes.extend(kept)
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "record_prefixes": ["bind-fixture-"],
                "positive_record_id": ids[0],
                "negative_record_ids": ["bind-fixture-rejected"],
            }
        )
    )
    return argparse.Namespace(report=report, sink_dir=tmp_path), request


def test_exact_probe_record_readback(tmp_path: Path) -> None:
    args, request = fixture(tmp_path)
    (tmp_path / "record.otlp").write_bytes(request.SerializeToString())
    probe.verify(args)
    assert json.loads(args.report.read_text())["durable_readback_verified"] is True


@pytest.mark.parametrize(
    "fault", ["missing", "duplicate", "forged", "body", "extra", "rejected"]
)
def test_readback_differences_never_verify(tmp_path: Path, fault: str) -> None:
    args, request = fixture(tmp_path)
    record = request.resource_logs[0].scope_logs[0].log_records[0]
    if fault == "missing":
        request.ClearField("resource_logs")
    elif fault == "duplicate":
        request.resource_logs.add().CopyFrom(request.resource_logs[0])
    elif fault == "body":
        record.body.string_value = "unexpected-content"
    else:
        for item in record.attributes:
            if fault == "forged" and item.key == "tenant_id":
                item.value.string_value = "another-tenant"
            if item.key == "record_id" and fault in {"extra", "rejected"}:
                item.value.string_value = "bind-fixture-" + fault
    (tmp_path / "record.otlp").write_bytes(request.SerializeToString())
    with pytest.raises(AssertionError):
        probe.verify(args)
    assert not json.loads(args.report.read_text()).get("durable_readback_verified")
