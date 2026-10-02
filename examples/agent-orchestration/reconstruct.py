# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct the agent run into a renderable journal.

Merges three evidence layers into ``out/journal.json``:

1. **OTLP spans** — identity + causal tree exported through the real
   collector (records.jsonl, decoded by the demo sink).
2. **Governed content** — manifest items resolved through the verified
   resolver; text is attached to the span named in each descriptor's
   ``bindings.span_id`` (decision-level items attach to the decision).
3. **Host events** — ``event_class=audit`` log records the collector
   emitted from the audit log. Joined to spans by time window +
   executable name, and labelled ``inferred`` — provenance near the
   span, never a claimed causal edge (spec 030 attribution honesty).

The journal is the artifact a UI renders: ``viewer/index.html`` loads
``out/journal.js`` (a ``window.JOURNAL = …`` wrapper for file:// use).

Exits non-zero if the run fails any UAT assertion — this doubles as the
acceptance gate for the demo path.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))

OUT = Path(os.environ.get("FABRIC_DEMO_OUT", HERE / "out"))
TENANT = "demo-tenant"
# Fixture tokens that live inside governed content (deploy.log text,
# report body). Governed bytes must never appear in exported telemetry —
# spans carry refs only, so any hit in records.jsonl is a redaction
# breach.
RAW_FORBIDDEN = ["NEW_PRICING_ENGINE", "oom-kill terminated worker 4"]

# A secret-shaped argv token the demo deliberately execs; it must be
# hashed by the collector (never exported raw). Expected digest =
# sha256 of NUL-joined argv, matching the receiver's argvHash.
SECRET_ARGV = ["sh", "-c", "echo DEMO_ARGV_SECRET_7f3a | shasum -a 256 | cut -d' ' -f1"]
SECRET_TOKEN = "DEMO_ARGV_SECRET_7f3a"


def _load_records() -> tuple[list[dict], list[dict]]:
    spans, logs = [], []
    records = OUT / "records.jsonl"
    if not records.exists():
        return spans, logs
    for line in records.read_text().splitlines():
        row = json.loads(line)
        (spans if row["kind"] == "span" else logs).append(row)
    return spans, logs


def _ns_to_s(ns: int) -> float:
    return ns / 1e9


def _content_join(
    decision_id: str, store_root: Path
) -> tuple[dict, dict[str, list[dict]], list[str]]:
    """Resolve every manifest item; bucket verified entries by span_id."""
    from fabric import ContentResolver, LocalFilesystemContentStore

    store = LocalFilesystemContentStore(str(store_root), tenant_id=TENANT)
    resolver = ContentResolver([store])
    manifests = sorted((store_root / TENANT / "manifests").glob("*.json"))
    assert manifests, "no manifest in governed store"
    manifest = json.loads(manifests[-1].read_text())

    by_span: dict[str, list[dict]] = {}
    failures: list[str] = []
    for item in manifest["items"]:
        entry: dict[str, object] = {
            "sequence": item["sequence"],
            "role": item["role"],
            "status": item["status"],
            "status_reason": item.get("status_reason"),
        }
        descriptor = item.get("descriptor") or {}
        bindings = descriptor.get("bindings") or {}
        span_id = bindings.get("span_id")
        if item.get("ref"):
            entry["ref"] = item["ref"]
            result = resolver.resolve(item["ref"], descriptor=descriptor)
            entry["resolve_status"] = result.status.value
            entry["verified"] = bool(result.ok)
            if result.ok and result.content is not None:
                entry["text"] = result.content.decode("utf-8", "replace")
            elif not result.ok:
                failures.append(
                    f"item {item['sequence']} {item['role']}: resolve={result.status.value}"
                )
        by_span.setdefault(str(span_id or "decision"), []).append(entry)
    return manifest, by_span, failures


def _audit_join(logs: list[dict]) -> list[dict]:
    events = []
    for rec in logs:
        attrs = rec.get("attributes") or {}
        if attrs.get("event_class") != "audit":
            continue
        events.append(
            {
                "id": f"audit-{attrs.get('audit.serial')}",
                "syscall": attrs.get("audit.syscall"),
                "result": attrs.get("audit.result"),
                "pid": attrs.get("process.pid"),
                "ppid": attrs.get("process.parent_pid"),
                "comm": attrs.get("process.executable.name"),
                "exe": attrs.get("process.executable.path"),
                "args_sha256": attrs.get("process.command_args_sha256"),
                "peer": attrs.get("network.peer.address"),
                "peer_port": attrs.get("network.peer.port"),
                "path": attrs.get("file.path"),
                "time_s": _ns_to_s(int(rec.get("time_ns") or 0)),
                "source": attrs.get("audit.source"),
                "provenance": "synthetic-agent-shim",
            }
        )
    return sorted(events, key=lambda e: e["time_s"])


def _attach_host(events: list[dict], nodes: list[dict]) -> None:
    """Time-window join: an audit event observed *near* a tool span is
    linked as inferred provenance — never claimed causal. Scored by
    comm/peer appearing in captured args, then tightest window."""
    tool_nodes = [
        n
        for n in nodes
        if (n["attributes"].get("fabric.step.type") or "") == "tool_call"
    ]
    for ev in events:
        cands = [
            n
            for n in tool_nodes
            if n["start_s"] - 1.0 <= ev["time_s"] <= n["end_s"] + 1.0
        ]
        if not cands:
            continue

        def score(node: dict) -> float:
            args = " ".join(str(e.get("text", "")) for e in node["content"])
            s = 0.0
            if (ev["comm"] or "") and ev["comm"] in args:
                s += 100
            if ev["peer"] and str(ev["peer"]) in args and str(ev["peer_port"]) in args:
                s += 100
            if ev["path"] and ev["path"] in args:
                s += 100
            if node["start_s"] <= ev["time_s"] <= node["end_s"]:
                s += 50
            mid = (node["start_s"] + node["end_s"]) / 2
            return s - abs(mid - ev["time_s"])

        best = max(cands, key=score)
        ev["linked_span"] = best["span_id"]
        ev["link"] = "inferred"


def main() -> int:
    decision_json = json.loads((OUT / "decision.json").read_text())
    spans, logs = _load_records()
    store_root = OUT / "store"

    failures: list[str] = []
    if not spans:
        failures.append("no spans reached the sink")

    nodes = [
        {
            "span_id": s["span_id"],
            "parent": s["parent_span_id"],
            "trace_id": s["trace_id"],
            "name": s["name"],
            "start_s": _ns_to_s(int(s["start_ns"])),
            "end_s": _ns_to_s(int(s["end_ns"])),
            "duration_ms": (int(s["end_ns"]) - int(s["start_ns"])) / 1e6,
            "attributes": s["attributes"],
            "events": s.get("events", []),
            "content": [],
        }
        for s in spans
    ]
    nodes.sort(key=lambda n: n["start_s"])

    manifest, by_span, resolve_failures = _content_join(
        decision_json["decision_id"], store_root
    )
    failures.extend(resolve_failures)
    for node in nodes:
        node["content"] = by_span.get(node["span_id"], [])
    decision_node = next(
        (
            n
            for n in nodes
            if n["attributes"].get("fabric.decision_id") == decision_json["decision_id"]
        ),
        None,
    )
    if decision_node is not None:
        decision_node["content"].extend(by_span.get("decision", []))
        decision_node["content"].sort(key=lambda e: e["sequence"])

    host_events = _audit_join(logs)
    _attach_host(host_events, nodes)
    for node in nodes:
        node["host"] = [
            e["id"] for e in host_events if e.get("linked_span") == node["span_id"]
        ]

    # ---------------- UAT assertions ----------------
    kinds: dict[str, int] = {}
    tool_names: set[str] = set()
    for n in nodes:
        attrs = n["attributes"]
        op = attrs.get("gen_ai.operation.name") or ""
        if attrs.get("fabric.decision_id"):
            kinds["decision"] = kinds.get("decision", 0) + 1
        elif op == "chat":
            kinds["model_call"] = kinds.get("model_call", 0) + 1
        elif op == "execute_tool":
            kinds["tool_call"] = kinds.get("tool_call", 0) + 1
            if attrs.get("fabric.tool.name"):
                tool_names.add(str(attrs["fabric.tool.name"]))
        else:
            kinds[str(n["name"])] = kinds.get(str(n["name"]), 0) + 1
    if kinds.get("decision", 0) != 1:
        failures.append(f"expected 1 decision span, saw {kinds.get('decision', 0)}")
    if kinds.get("model_call", 0) != 2:
        failures.append(f"expected 2 model calls, saw {kinds.get('model_call', 0)}")
    expected_tools = {"read_file", "run_shell", "fetch_metrics", "write_report"}
    missing_tools = expected_tools - tool_names
    if missing_tools:
        failures.append(f"missing tool spans: {sorted(missing_tools)}")

    if manifest["decision_id"] != decision_json["decision_id"]:
        failures.append("manifest decision_id mismatch")
    bad_items = [i for i in manifest["items"] if i["status"] not in ("stored",)]
    if bad_items:
        failures.append(
            f"non-stored manifest items: "
            f"{[(i['sequence'], i['role'], i['status']) for i in bad_items]}"
        )
    if manifest.get("completeness", {}).get("stored", 0) < 10:
        failures.append(
            f"suspiciously few stored items: {manifest.get('completeness')}"
        )

    exec_events = [e for e in host_events if e["syscall"] in ("execve", "execveat")]
    if len(exec_events) < 3:
        failures.append(f"expected >=3 exec audit events, saw {len(exec_events)}")
    if not any(e["syscall"] == "connect" for e in host_events):
        failures.append("no connect audit event for the metrics fetch")
    if not any(e["syscall"] == "openat" for e in host_events):
        failures.append("no openat audit event for the log read")

    # Redaction proof: the secret argv ran for real, the collector saw
    # it, and only its sha256 crossed — the token itself never appears.
    import hashlib as _hl

    expected_hash = _hl.sha256("\x00".join(SECRET_ARGV).encode()).hexdigest()
    raw = (
        (OUT / "records.jsonl").read_text() if (OUT / "records.jsonl").exists() else ""
    )
    if SECRET_TOKEN in raw:
        failures.append("raw secret argv leaked into exported telemetry")
    for token in RAW_FORBIDDEN:
        if token in raw:
            failures.append(f"governed-content token in exported telemetry: {token!r}")
    if not any(e.get("args_sha256") == expected_hash for e in exec_events):
        failures.append("secret-argv sha256 not observed on any exec event")

    if decision_node is None:
        failures.append("no decision span in export")
    else:
        attrs = decision_node["attributes"]
        for key in ("fabric.content.manifest_ref",):
            if key not in attrs:
                failures.append(f"decision span missing {key}")
        if attrs.get("fabric.content.manifest_ref") != decision_json["manifest_uri"]:
            failures.append("stamped manifest_ref != resolved manifest uri")

    journal = {
        "schema_version": "fabric.demo-journal/v1",
        "decision": {
            "decision_id": decision_json["decision_id"],
            "manifest_uri": decision_json["manifest_uri"],
            "tenant": TENANT,
            "session_id": "incident-481",
            "request_id": "investigate-481",
        },
        "layers": {
            "sdk": {"governed_store": str(store_root), "durability": "spooled"},
            "otlp": {"spans": len(spans), "log_records": len(logs)},
            "host": {
                "capture": "synthetic agent-emitted audit-format replay on all platforms; "
                "not independent kernel or auditd evidence",
                "provenance": "synthetic-agent-shim",
                "events": len(host_events),
            },
        },
        "manifest": {
            "manifest_id": manifest["manifest_id"],
            "completeness": manifest["completeness"],
            "coverage": manifest.get("coverage", {}),
            "items": manifest["items"],
        },
        "timeline": nodes,
        "host_events": host_events,
        "integrity": {
            "items_resolved_verified": sum(
                1 for n in nodes for e in n["content"] if e.get("verified")
            ),
            "items_total": len(manifest["items"]),
            "secret_argv_sha256": expected_hash,
            "raw_secret_in_telemetry": SECRET_TOKEN in raw,
        },
        "uat_failures": failures,
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "journal.json").write_text(json.dumps(journal, indent=2))
    (OUT / "journal.js").write_text("window.JOURNAL = " + json.dumps(journal) + ";\n")

    print(f"journal: {OUT / 'journal.json'}")
    print(
        f"  spans={len(spans)} host_events={len(host_events)} "
        f"items={len(manifest['items'])} verified={journal['integrity']['items_resolved_verified']}"
    )
    if failures:
        print("UAT FAILURES:", *failures, sep="\n  - ")
        return 1
    print("UAT PASS — all assertions hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
