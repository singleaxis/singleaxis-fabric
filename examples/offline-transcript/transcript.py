# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Record and read a local governed transcript — no services required.

Runs entirely on this machine: the Fabric SDK plus a local
customer-controlled store. No Fabric Node, OTLP Collector, Relay, or
SingleAxis Platform is involved — nothing leaves ``--root``.

The script records one small interaction (a model request/response plus
a caller-supplied context file), then reads the transcript back through
the authorized resolver: every object is byte-verified against its
descriptor before content is returned, and a deterministic assertion
proves the recorded bytes are the bytes that come back.

Run::

    python transcript.py --root ./store

Expected output ends with ``PASS``.
"""

from __future__ import annotations

import argparse
import sys

from fabric import (
    ContentCaptureConfig,
    ContentResolver,
    Fabric,
    FabricConfig,
    LocalFilesystemContentStore,
    ResolveStatus,
)

TENANT = "offline-example"


def run(root: str) -> list[str]:
    problems: list[str] = []
    store = LocalFilesystemContentStore(root, tenant_id=TENANT)
    fabric = Fabric(
        FabricConfig(tenant_id=TENANT, agent_id="offline-harness"),
        content_capture=ContentCaptureConfig(
            store=store,
            roles="all",
            durability="inline",  # dev/harness mode: synchronous local writes
        ),
    )

    with fabric.decision(
        session_id="sess-offline", request_id="req-offline"
    ) as decision:
        decision.record_context("notes.txt", "order 8811 was refunded on 2026-09-22")
        with decision.llm_call(
            provider="offline",
            model="model-a",
            input_messages=[{"role": "user", "content": "summarize order 8811"}],
        ) as call:
            call.set_response(
                output_messages=[
                    {
                        "role": "assistant",
                        "content": "order 8811: refunded on 2026-09-22",
                    }
                ]
            )
        fabric.flush_content(timeout_s=5.0)
        manifest_uri = decision.content_manifest_uri
    fabric.close()

    if manifest_uri is None:
        return ["no manifest URI was produced"]

    # Read back through the authorized resolver — descriptor + byte
    # verification runs before any content is returned.
    resolver = ContentResolver(stores=[store])
    export = resolver.export_transcript(manifest_uri, materialize=True)
    if not export["integrity"]["verified"]:
        problems.append(f"integrity failures: {export['integrity']['failures']}")

    context_ref = next(
        e["ref"]
        for s in export["steps"]
        for e in s["entries"]
        if e.get("role") == "context.file"
    )
    resolved = resolver.resolve(context_ref)
    if resolved.status != ResolveStatus.AVAILABLE:
        problems.append(
            f"context.file ref resolved as {resolved.status}, not available"
        )
    elif resolved.content != b"order 8811 was refunded on 2026-09-22":
        problems.append("context.file bytes differ from what was recorded")

    requests = [
        e["text"]
        for s in export["steps"]
        for e in s["entries"]
        if e.get("role") == "model.request.messages" and e.get("status") == "available"
    ]
    if not requests or "order 8811" not in str(requests[0]):
        problems.append("model request not readable in export")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="./store", help="local store root")
    args = parser.parse_args()
    problems = run(args.root)
    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1
    print("PASS — recorded and byte-verified a local transcript with no services")
    return 0


if __name__ == "__main__":
    sys.exit(main())
