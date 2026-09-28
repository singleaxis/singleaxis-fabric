#!/usr/bin/env python3
"""Installed-wheel conformance smoke for the spec-042 Python byte-call adapter.

Only synthetic bytes and a temporary local store are used. This does not
qualify provider-bound capture in an arbitrary client or produce a GO verdict.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, LocalFilesystemContentStore
from fabric import __file__ as fabric_package_file
from fabric.adapters.byte_boundary import ByteBoundaryAdapter
from fabric.adapters.synthetic_evidence import SyntheticCaptureSession
from fabric.synthetic_otlp import project_synthetic_snapshot
from fabric.synthetic_reconcile import (
    ExpectedByteObject,
    ExpectedOperation,
    SyntheticByteResolver,
    reconcile_synthetic_run,
)

CANARY = b"CLIENT_ADAPTER_SECRET_CANARY"
ROLES = frozenset(
    {
        "interaction.payload",
        "model.request.messages",
        "model.output.messages",
        "tool.call.arguments",
        "tool.call.result",
    }
)


def main() -> int:
    module_file = Path(fabric_package_file).resolve()
    if not module_file.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError(
            "client smoke requires an installed wheel in a virtual environment"
        )
    with tempfile.TemporaryDirectory(prefix="fabric-client-smoke-") as location:
        store = LocalFilesystemContentStore(
            str(Path(location) / "store"), tenant_id="test-tenant"
        )
        recorder = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=ROLES))
        session = SyntheticCaptureSession(
            recorder, tenant_id="test-tenant", run_id="smoke-1"
        )
        model = ByteBoundaryAdapter(session, kind="model", source_id="model-1")
        tool = ByteBoundaryAdapter(session, kind="tool", source_id="tool-1")
        independent: list[tuple[str, str, str, bytes]] = []

        def model_send(payload: bytes) -> bytes:
            independent.append(
                ("model-1", "model-op", "model.request.messages", payload)
            )
            response = b"reply:" + payload
            independent.append(
                ("model-1", "model-op", "model.output.messages", response)
            )
            return response

        def tool_send(payload: bytes) -> bytes:
            independent.append(("tool-1", "tool-op", "tool.call.arguments", payload))
            response = b"\x00tool-result\xff"
            independent.append(("tool-1", "tool-op", "tool.call.result", response))
            return response

        request = b"\x00model-request\xff" + CANARY
        assert (
            model.call(
                request,
                model_send,
                operation_id="model-op",
                attempt_id="try-1",
                context=b"",
            )
            == b"reply:" + request
        )
        assert (
            tool.call(
                b"\xfftool-args\x00",
                tool_send,
                operation_id="tool-op",
                attempt_id="try-1",
            )
            == b"\x00tool-result\xff"
        )
        snapshot = session.snapshot()
        if not snapshot["writer_settled"]:
            raise AssertionError("protected byte writer did not settle")
        resolver = SyntheticByteResolver(store, tenant_id="test-tenant")
        expected = [
            ExpectedByteObject(
                source,
                "provider_bound" if source == "model-1" else "tool",
                operation,
                "try-1",
                role,
                data,
            )
            for source, operation, role, data in independent
        ]
        expected.append(
            ExpectedByteObject(
                "model-1",
                "provider_bound",
                "model-op",
                "try-1",
                "interaction.payload",
                b"",
            )
        )
        outcomes = [
            ExpectedOperation(
                "provider_bound", "model-op", "try-1", {"result_status": "ok"}
            ),
            ExpectedOperation("tool", "tool-op", "try-1", {"result_status": "ok"}),
        ]
        clean = reconcile_synthetic_run(
            snapshot, expected, resolver, expected_operations=outcomes
        )
        if clean["discrepancies"] or clean["verdict"] != "unverified":
            raise AssertionError("installed-wheel exact-byte comparison failed")
        projected, record_ids = project_synthetic_snapshot(snapshot)
        if CANARY in projected or CANARY in json.dumps(snapshot).encode():
            raise AssertionError("secret canary escaped protected content storage")
        if len(record_ids) != len(snapshot["events"]):
            raise AssertionError("metadata projection omitted an evidence event")

        # An unwrapped operation must be visible in independent truth as a gap.
        bypass_payload = b"direct-bypass"
        model_send(bypass_payload)
        bypass_expected = [
            *expected,
            ExpectedByteObject(
                "model-1",
                "provider_bound",
                "model-bypass",
                "try-1",
                "model.request.messages",
                bypass_payload,
            ),
            ExpectedByteObject(
                "model-1",
                "provider_bound",
                "model-bypass",
                "try-1",
                "model.output.messages",
                b"reply:" + bypass_payload,
            ),
        ]
        bypass = reconcile_synthetic_run(
            snapshot, bypass_expected, resolver, expected_operations=outcomes
        )
        if bypass["verdict"] != "partial" or len(bypass["discrepancies"]) != 2:
            raise AssertionError("direct bypass failed to lower evidence verdict")
        if not recorder.close():
            raise AssertionError("protected byte writer did not close cleanly")
    print(
        json.dumps(
            {
                "schema_version": "fabric.client-byte-smoke/v1",
                "installed_wheel": True,
                "exact_byte_objects": len(expected),
                "operation_outcomes": len(outcomes),
                "projected_metadata_records": len(record_ids),
                "clean_verdict": clean["verdict"],
                "bypass_verdict": bypass["verdict"],
                "qualification": "NO_GO",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
