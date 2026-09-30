# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Authorized transcript consumer — read, verify, and assert.

A downstream reviewer or evaluation harness resolves a decision's
manifest through the configured governed store, exports the transcript
with per-object integrity verification, and runs a deterministic
assertion over the materialized content. This script never talks to a
Fabric Node, a SingleAxis service, or the model — it reads customer
storage only, and it does not replay tools or side effects.

Run::

    python capture.py --root ./store          # prints decision_id=...
    python evaluate.py --root ./store --decision-id <id>

Assertions (deterministic, content-level — possible only because the
exact bytes are available and byte-verified):

    1.  instructions are readable;
    2.  the first model input is readable;
    3.  the first model output (tool request) is readable;
    4.  the tool arguments are readable;
    5.  the tool result is readable;
    6.  the second model request contains the linked tool result;
    7.  the second model output is readable;
    8.  the caller-supplied context is readable;
    9.  every returned object passed descriptor, size and digest
        verification (``integrity.verified``);
    10. tool-call and attempt links are correct;
    11. completeness reports no unexpected gaps.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from fabric import ContentResolver, LocalFilesystemContentStore


def evaluate(root: str, tenant: str, decision_id: str) -> list[str]:
    store = LocalFilesystemContentStore(root, tenant_id=tenant)
    resolver = ContentResolver(stores=[store])
    manifest = resolver.manifest_for_decision(decision_id)
    if manifest is None:
        print(f"no manifest for decision {decision_id}", file=sys.stderr)
        raise SystemExit(1)
    alias_uri = store.manifest_uri_for_decision(decision_id)
    alias = store.read_manifest(alias_uri)
    doc = resolver.export_transcript(str(alias["manifest_uri"]), materialize=True)
    integrity = doc["integrity"]
    if not integrity["verified"]:
        print(f"integrity failures: {integrity['failures']}", file=sys.stderr)
        raise SystemExit(2)

    problems: list[str] = []

    def materialized(role: str) -> list[Any]:
        """Every verified entry for `role`, in manifest order."""
        return [
            entry["text"]
            for step in doc["steps"]
            for entry in step["entries"]
            if entry.get("role") == role and entry.get("status") == "available"
        ]

    # 1. instructions are readable
    instructions = materialized("model.request.instructions")
    if not any("refund" in json.dumps(i) for i in instructions):
        problems.append("model.request.instructions missing or unreadable")

    # 2. first model input is readable
    requests = materialized("model.request.messages")
    if not requests or "Can I refund $700?" not in json.dumps(requests[0]):
        problems.append("first model.request.messages missing the user question")

    # 3. first model output carries the tool request
    outputs = materialized("model.output.messages")
    if not outputs or "call-1" not in json.dumps(outputs[0]):
        problems.append("first model.output.messages missing tool request call-1")

    # 4. tool arguments are readable
    args = materialized("tool.call.arguments")
    if not args or "refunds" not in json.dumps(args):
        problems.append("tool.call.arguments missing or unreadable")

    # 5. tool result is readable
    results = materialized("tool.call.result")
    if not results or "limit" not in json.dumps(results):
        problems.append("tool.call.result missing or unreadable")

    # 6. second model request contains the linked tool result the model
    #    observed — the causal link that makes the transcript a record,
    #    not a bag of snippets.
    if len(requests) < 2:
        problems.append("second model.request.messages absent")
    else:
        second = json.dumps(requests[1])
        if "tool_call_id" not in second or "call-1" not in second:
            problems.append("second model request lacks the call-1 tool linkage")
        if not results or json.dumps(results[0])[1:-1] not in second:
            problems.append("second model request does not carry the tool result")

    # 7. second model output is readable
    if len(outputs) < 2 or "supervisor" not in json.dumps(outputs[1]):
        problems.append("second model.output.messages missing the final answer")

    # 8. caller-supplied context is readable
    context = materialized("context.file")
    if not context or "approval code" not in json.dumps(context):
        problems.append("context.file missing or unreadable")

    # 10. tool-call and attempt links are correct
    tool_links: set[str] = set()
    for item in manifest["items"]:
        links = item.get("links") or {}
        if "tool_call_id" in links:
            tool_links.add(str(links["tool_call_id"]))
    if tool_links != {"call-1"}:
        problems.append(f"tool_call_id links {sorted(tool_links)} != ['call-1']")

    # 11. completeness reports no unexpected gaps
    completeness = doc.get("completeness", {})
    for gap in ("failed", "dropped", "missing", "pending"):
        if completeness.get(gap):
            problems.append(f"manifest reports {gap} items: {completeness}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="./store")
    parser.add_argument("--tenant", default="example-tenant")
    parser.add_argument("--decision-id", required=True)
    args = parser.parse_args()
    problems = evaluate(args.root, args.tenant, args.decision_id)
    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1
    print("PASS — transcript verified; deterministic content assertions hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
