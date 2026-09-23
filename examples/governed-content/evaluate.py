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

    1. every resolvable object passed digest + length verification;
    2. the effective model request includes the user's refund question;
    3. the model-issued tool call and the tool result share one
       ``tool_call_id`` link.
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
        return [
            entry["text"]
            for step in doc["steps"]
            for item_role, entry in step["content"].items()
            if item_role == role and isinstance(entry, dict) and "text" in entry
        ]

    requests = materialized("model.request.messages")
    serialized = json.dumps(requests, ensure_ascii=False, sort_keys=True)
    if "refund" not in serialized:
        problems.append("model request content does not contain 'refund'")

    tool_links: set[str] = set()
    for item in manifest["items"]:
        links = item.get("links") or {}
        if "tool_call_id" in links:
            tool_links.add(str(links["tool_call_id"]))
    if tool_links != {"call-1"}:
        problems.append(f"tool_call_id links {sorted(tool_links)} != ['call-1']")

    completeness = doc.get("completeness", {})
    if completeness.get("failed") or completeness.get("dropped"):
        problems.append(f"manifest reports gaps: {completeness}")
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
