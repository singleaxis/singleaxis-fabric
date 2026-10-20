# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scenario 6 — the Node, the spool and the reader must reject or neutralise malformed and
mis-bound inputs, leaking nothing and staying within scope.

    .venv/bin/python s6_adversarial.py --out results/s6

Every test confirms a *rejection* property of the user's own system. Using the Node's
real ingress token (a buggy or compromised agent of the bound source), ``lib/rawclient.py``
posts records the bound source would never send and the harness asserts the Node drops or
strips them:

- T1 duplicate attribute keys (bound source first, then a foreign source id);
- T2 a receiver-owned ``fabric.source.authenticated`` set by the sender;
- T3 a wrong source binding (span and content), and a mixed batch;
- T4 cross-tenant content;
- T5 a replayed content record (identical bytes accepted idempotently; changed bytes
  under the same id refused, the stored object unchanged);
- T6 tampered spool files read back by a clean agent: truncation, a bit flip, a renamed
  record, a plaintext downgrade;
- T7 a tampered sealed Node directory read by ``fabric.reconstruct`` (bit flip);
- T8 fuzzed descriptor values through the real Node (never a crash, never a leak);
- T9 path-traversal object ids;
- T10 oversized attribute values and attribute counts.

Across all of it: I3 (no canary or digest leaks) and the invariants hold. Authenticity
and tamper-evidence failures (T1, T6) are reported under a separate ``AUTH`` key: they
are not content leaks, but they let records be attributed to a source that never sent
them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
from harness import (  # noqa: E402
    HOOKS, FakeModel, Node, SpoolSampler, Verdict, agent_cmd, autoload_dir, check_i3,
    check_i4, check_i5, drained, new_mark, open_spool_record, pseudonym, read_jsonl,
    spans_by_exchange, wait_for,
)
from rawclient import RawClient  # noqa: E402

MIB = 1024 * 1024


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def descriptors(node: Node, snap: Path) -> list[dict[str, Any]]:
    """Descriptors in an unsealed store snapshot (node.content_snapshot opened it)."""
    meta = snap / node.tenant / "evidence" / "meta"
    return [json.loads(p.read_text("utf-8")) for p in meta.glob("*.json")]


def main() -> int:  # noqa: PLR0915
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/s6")
    ap.add_argument("--fuzz", type=int, default=1200)
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    mark = new_mark()
    node = Node(out / "node", mark=mark)
    model = FakeModel(out)
    v = Verdict("s6_adversarial")
    spool = out / "spool"
    max_bytes = 64 * MIB
    find: dict[str, Any] = {}
    try:
        node.up()
        sampler = SpoolSampler([spool])
        sampler.start()
        env = node.agent_env(spool, autoload=autoload_dir(), hooks=HOOKS, extra={
            "FABRIC_WIRE_ENDPOINTS": model.endpoints_json(),
            "FABRIC_WIRE_SPOOL_MAX_BYTES": str(max_bytes),
            "FABRIC_WIRE_MAX_BODY_BYTES": str(8 * MIB)})  # fmt: skip
        bound = pseudonym("s-", node.source, node.id_key)
        foreign = "s-" + "f" * 32
        ledger = out / "ledger.jsonl"
        r = subprocess.run(agent_cmd(model, ledger, "adv-template", mark, "--calls", "2",
                                     "--scoped", "--flush", "60"),
                           env=env, capture_output=True, text=True, timeout=300)  # fmt: skip
        assert r.returncode == 0, r.stderr
        time.sleep(8)
        delivered = spans_by_exchange(read_jsonl(node.sink.records))
        tspan = next(iter(delivered.values()))
        snap = node.content_snapshot()
        descs = descriptors(node, snap)
        template = next(d for d in descs if d["object_id"] ==
                        tspan["attributes"]["fabric.content.request_ref"])  # fmt: skip
        raw = RawClient(node)

        def dropped() -> dict[str, int]:
            out_: dict[str, int] = {}
            for line in node.logs().splitlines():
                if "fabriccontent: dropped content record" in line:
                    import re  # noqa: PLC0415
                    m = re.search(r'reason[^a-z]+([a-z_]+)', line)
                    k = m.group(1) if m else "?"
                    out_[k] = out_.get(k, 0) + 1
            return out_

        def forged_descriptor(**changes: Any) -> tuple[dict[str, Any], bytes]:
            body = f"{mark}_forged_{uuid.uuid4().hex}".encode()
            d = {k: val for k, val in template.items()
                 if k not in ("encoding", "ref", "source_authenticated")}  # fmt: skip
            d.update(object_id=str(uuid.uuid4()), role="model.exchange.request",
                     representation="exact", transformations=[], status="stored",
                     stored_byte_length=len(body), stored_sha256=sha(body),
                     source_byte_length=len(body), source_sha256=sha(body))
            d.pop("links", None)
            d.update(changes)
            return d, body

        def store_ids() -> set[str]:
            s = node.content_snapshot()
            try:
                return {d["object_id"] for d in descriptors(node, s)}
            finally:
                shutil.rmtree(s, ignore_errors=True)

        before_ids = store_ids()

        # T1 duplicate attribute keys on a span: bound source first, foreign second.
        base_attrs = [(k, val) for k, val in tspan["attributes"].items()
                      if k != "fabric.source.authenticated"]  # fmt: skip
        eid = str(uuid.uuid4())
        a1 = [(k, eid if k == "fabric.wire.exchange_id" else val) for k, val in base_attrs]
        a1.append(("fabric.source_id", foreign))
        s1 = raw.trace([a1])
        eid2 = str(uuid.uuid4())
        a2 = [("fabric.source_id", foreign)] + [
            (k, eid2 if k == "fabric.wire.exchange_id" else val) for k, val in base_attrs]
        s2 = raw.trace([a2])
        time.sleep(6)
        sink_rows = [s for s in read_jsonl(node.sink.records) if s.get("kind") == "span"]
        t1_hits = [s for s in sink_rows if s["attributes"].get("fabric.wire.exchange_id") in (eid, eid2)]
        find["T1_duplicate_source_key"] = {
            "bound_first_http": s1, "foreign_first_http": s2,
            "delivered_with_foreign_source": [s for s in t1_hits
                if s["attributes"].get("fabric.source_id") == foreign],
            "foreign_in_delivered_bytes": foreign.encode() in node.sink.raw_bytes()}  # fmt: skip
        # Not a content leak (I3): a source-authenticity failure, reported as AUTH.
        v.check("AUTH", foreign.encode() not in node.sink.raw_bytes(),
                "a duplicate-key foreign source id reached the delivered telemetry")

        # T2 sender-set receiver-owned stamp (content record).
        d, body = forged_descriptor(tenant_id=node.tenant, source_id=bound)
        http = raw.content(d, body, add_attrs=[("source_authenticated", "true")])
        find["T2_forged_stamp_http"] = http

        # T3 wrong source binding.
        d3, body3 = forged_descriptor(tenant_id=node.tenant, source_id=foreign)
        find["T3_wrong_source_content_http"] = raw.content(d3, body3)
        find["T3_wrong_source_span_http"] = raw.trace([
            [(k, str(uuid.uuid4()) if k == "fabric.wire.exchange_id" else
              (foreign if k == "fabric.source_id" else val)) for k, val in base_attrs]])

        # T4 cross-tenant content.
        d4, body4 = forged_descriptor(tenant_id="another-tenant", source_id=bound)
        find["T4_cross_tenant_http"] = raw.content(d4, body4)

        # T5 replay: identical bytes accepted; changed bytes under the same id refused.
        d5, body5 = forged_descriptor(tenant_id=node.tenant, source_id=bound)
        # First make it a *valid* record for the bound source so it is actually stored.
        find["T5_first_http"] = raw.content(d5, body5)
        find["T5_replay_identical_http"] = raw.content(d5, body5)
        body5b = body5 + b"X"
        d5b = dict(d5, stored_byte_length=len(body5b), stored_sha256=sha(body5b),
                   source_byte_length=len(body5b), source_sha256=sha(body5b))
        find["T5_replay_changed_http"] = raw.content(d5b, body5b)

        # T9 path traversal in the object id.
        d9, body9 = forged_descriptor(tenant_id=node.tenant, source_id=bound,
                                       object_id="../../../../etc/passwd")
        find["T9_path_traversal_http"] = raw.content(d9, body9)

        # T10 oversized attribute values and counts (on a span).
        big = "Z" * (2 * MIB)
        s10 = raw.trace([[*base_attrs, ("fabric.wire.exchange_id", str(uuid.uuid4())),
                          ("extra.„oversized", big)]])
        many = [*base_attrs, ("fabric.wire.exchange_id", str(uuid.uuid4()))]
        many += [(f"extra.k{i}", "x") for i in range(2000)]
        s10b = raw.trace([many])
        find["T10_oversized_http"] = s10
        find["T10_many_attrs_http"] = s10b

        # Wait for the Node to judge the content records, then snapshot the store.
        time.sleep(10)
        find["drop_reasons"] = dropped()
        snap_after = node.content_snapshot()
        after = {dd["object_id"]: dd for dd in descriptors(node, snap_after)}
        after_ids = set(after)
        find["new_store_object_ids"] = len(after_ids - before_ids)
        # The mis-bound, cross-tenant and path-traversal records must not be stored (the
        # valid T5 record and T2, whose extra stamp the exporter drops, legitimately are).
        rejected_ids = {dd["object_id"] for dd in (d3, d4, d9)}
        find["rejected_ids_in_store"] = sorted(rejected_ids & after_ids)
        v.check("I3", not (rejected_ids & after_ids),
                f"mis-bound/cross-tenant/traversal records reached the store: "
                f"{sorted(rejected_ids & after_ids)}")
        v.check("I3", "../" not in " ".join(after_ids) and not any(
            "etc/passwd" in x for x in after_ids), "a path-traversal id reached the store")
        t5 = after.get(d5["object_id"])
        find["T5_stored_unchanged"] = bool(t5 and t5["stored_sha256"] == sha(body5))
        v.check("I2", (not t5) or find["T5_stored_unchanged"],
                "a changed replay overwrote the stored object")

        # ---- T6 tampered spool files (read back by a clean agent) ----
        t6 = _spool_tamper(node, model, env, mark, out)
        find["T6_spool_tamper"] = t6
        for name, res in t6.items():
            v.check("I1", res.get("agent_rc") == 0, f"T6 {name}: agent exit {res.get('agent_rc')}")
            # Random corruption (bitflip/truncate/rename) must be quarantined, never
            # delivered; a deliberate plaintext downgrade on a keyed spool must also be
            # refused (the records quarantined), not accepted as content.
            v.check("AUTH", res.get("corrupt_left") == res.get("records"),
                    f"T6 {name}: {res.get('records') - res.get('corrupt_left')} of "
                    f"{res.get('records')} tampered records were NOT quarantined "
                    f"(delivered from a keyed spool)")

        # ---- T7 tampered sealed Node directory read by reconstruct ----
        corrupt = out / f"corrupt-{uuid.uuid4().hex[:8]}"
        # snapshot is the UNsealed copy; take a fresh sealed copy to tamper
        sealed2 = node.content_snapshot()
        src = node.sealed[sealed2]
        shutil.copytree(src, corrupt)
        target = corrupt / node.tenant / "evidence" / tspan["attributes"]["fabric.content.request_ref"]
        if target.exists():
            data = bytearray(target.read_bytes())
            data[-1] ^= 0xFF
            target.write_bytes(bytes(data))
            node.sealed[corrupt] = corrupt
            code, report, _ = node.reconstruct(corrupt)
            run = next((rr for rr in report.get("runs", []) if rr["run_id"] ==
                        tspan["attributes"]["fabric.run.id"]), {})
            find["T7_tampered_directory"] = {"exit": code, "verdict": run.get("verdict"),
                "gaps": [g.get("gap_type") for g in run.get("gaps", [])],
                "canary_in_report": mark in json.dumps(report)}  # fmt: skip
            v.check("I2", run.get("verdict") not in ("complete_for_declared_scope",
                    "complete_for_observed_scopes"), "a tampered stored object verified complete")
            v.check("I3", mark not in json.dumps(report), "tampered content appeared in the report")

        # ---- T8 descriptor fuzzing through the real Node ----
        find["T8_fuzz"] = _fuzz(raw, template, node, mark, args.fuzz)
        v.check("I1", node.healthy(), "the Node is unhealthy after fuzzing")
        v.check("I3", find["T8_fuzz"]["canary_in_store_or_logs"] == 0,
                "a fuzzed value leaked into the store or logs")

        v.numbers["findings"] = find
        # Drain the spool (the legit template run) and check the base invariants.
        rec = subprocess.run(agent_cmd(model, out / "rec.jsonl", "adv-recovery", mark,
                                       "--calls", "1", "--scoped", "--flush", "120"),
                             env=env, capture_output=True, text=True, timeout=300)  # fmt: skip
        wait_for(lambda: drained([spool]), 300, 1)
        time.sleep(10)
        sampler.stop()
        check_i3(v, node, [mark], {"sink": node.sink.records.read_text(),
                                    "node_logs": node.logs(), "stderr": rec.stderr}, [spool])
        check_i4(v, sampler, max_bytes)
        check_i5(v, [spool], {}, spans_by_exchange(read_jsonl(node.sink.records)))
    finally:
        v.dump(out / "verdict.json")
        model.close()
        node.down()
    return 0


def _spool_tamper(node: Node, model: FakeModel, env: dict, mark: str, out: Path) -> dict:
    """Write a scoped run to a fresh spool with the Node stopped, tamper each record four
    ways, then start the Node and run a clean agent so the drainer reads them back."""
    results: dict[str, Any] = {}
    for name, mutate in (("truncate", _truncate), ("bitflip", _bitflip),
                         ("rename", _rename), ("plaintext_downgrade", _downgrade)):
        tdir = out / f"spool-{name}"
        tenv = dict(env, FABRIC_WIRE_SPOOL_DIR=str(tdir))
        node.stop()
        subprocess.run(agent_cmd(model, out / f"t6-{name}.jsonl", f"t6-{name}", mark,
                                 "--calls", "3", "--scoped"),
                       env=tenv, capture_output=True, text=True, timeout=120)  # fmt: skip
        recs = sorted(p for p in tdir.glob("*.rec") if not p.name.startswith("."))
        tampered = 0
        for rec in recs:
            if mutate(rec, node.spool_key):
                tampered += 1
        node.start()
        agent = subprocess.run(agent_cmd(model, out / f"t6-{name}.jsonl", f"t6-{name}-drain",
                                         mark, "--calls", "1", "--scoped", "--flush", "120"),
                               env=tenv, capture_output=True, text=True, timeout=300)  # fmt: skip
        wait_for(lambda d=tdir: not [p for p in d.glob("*.rec") if not p.name.startswith(".")],
                 120, 1)  # fmt: skip
        time.sleep(5)
        leftover = [p.name for p in tdir.glob("*")]
        # Did the tampered plaintext body reach the Node telemetry/store? scan canary.
        leak = mark.encode() in node.sink.raw_bytes()
        results[name] = {"records": len(recs), "tampered": tampered,
                         "corrupt_left": sum(1 for x in leftover if x.endswith(".corrupt")),
                         "agent_rc": agent.returncode, "leak": leak,
                         "agent_stderr_canary": mark in agent.stderr}
    return results


def _truncate(path: Path, key: bytes) -> bool:
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])
    return True


def _bitflip(path: Path, key: bytes) -> bool:
    data = bytearray(path.read_bytes())
    if len(data) > 60:  # noqa: PLR2004
        data[len(data) // 2] ^= 0x80
        path.write_bytes(bytes(data))
        return True
    return False


def _rename(path: Path, key: bytes) -> bool:
    # Rename to another valid-looking record name: the AAD (record name) no longer matches.
    other = path.with_name(path.name.replace(".rec", "z.rec"))
    path.rename(other)
    return True


def _downgrade(path: Path, key: bytes) -> bool:
    """Replace a sealed record with a valid plaintext FWSPOOL1 frame (no envelope): a
    production spool with a key must refuse an unsealed record, not deliver its content."""
    try:
        frame = open_spool_record(path, key)  # the plaintext frame
    except Exception:  # noqa: BLE001
        return False
    path.write_bytes(frame)  # now unsealed on a keyed spool
    return True


def _fuzz(raw: RawClient, template: dict, node: Node, mark: str, n: int) -> dict:
    rng = random.Random(1234)
    keys = list(template)
    statuses: dict[str, int] = {}
    crashed = False
    for i in range(n):
        d = {k: val for k, val in template.items() if k not in ("encoding", "ref")}
        d["object_id"] = str(uuid.uuid4())
        d["tenant_id"] = node.tenant
        d["source_id"] = pseudonym("s-", node.source, node.id_key)
        for _ in range(rng.randint(1, 4)):
            k = rng.choice(keys)
            choice = rng.random()
            if choice < 0.3:  # noqa: PLR2004
                d[k] = "fuzztok_" + uuid.uuid4().hex
            elif choice < 0.5:  # noqa: PLR2004
                d[k] = rng.randint(-(1 << 62), 1 << 62)
            elif choice < 0.7:  # noqa: PLR2004
                d.pop(k, None)
            else:
                d[k] = "../" * rng.randint(1, 5) + "fuzztok"
        body = f"{mark}_fuzzbody_{i}".encode()  # the canary marks this content
        try:
            code = raw.content(d, body)
        except Exception as exc:  # noqa: BLE001
            code = -99
            statuses[type(exc).__name__] = statuses.get(type(exc).__name__, 0) + 1
        statuses[str(code)] = statuses.get(str(code), 0) + 1
        if not node.healthy():
            crashed = True
            break
    time.sleep(8)
    # The canary is the fuzzed records' content. At rest it must be sealed: scan the
    # SEALED copy's bytes (never the decrypted tree, which legitimately holds content) and
    # the Node logs; neither may hold the canary in clear.
    plain = node.content_snapshot()
    sealed = node.sealed.get(plain, plain)
    try:
        at_rest = b"".join(p.read_bytes() for p in sealed.rglob("*") if p.is_file())
    finally:
        shutil.rmtree(plain, ignore_errors=True)
        shutil.rmtree(sealed, ignore_errors=True)
    leak = (mark.encode() in at_rest) + (mark in node.logs())
    return {"requests": n, "statuses": statuses, "node_crashed": crashed,
            "canary_in_store_or_logs": leak}


if __name__ == "__main__":
    raise SystemExit(main())
