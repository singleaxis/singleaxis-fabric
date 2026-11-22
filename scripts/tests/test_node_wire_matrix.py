# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.3, unit 055-t17: the TS-1U and TS-1D rows of the Node.js client matrix.

Each row of ``qualification/node-wire/matrix.json`` is one unmodified client script
(``qualification/node-wire/clients/``) run from an application directory where the packed
tarball and the pinned clients are installed (``_node_package.py``), against the scripted
provider of ``qualification/node-wire/harness/provider.py`` and the recording sink. For
every row and profile:

1. **Behaviour identity**: the script runs with the preload off and on; what the
   application observed (results, every event or chunk, errors, statuses), its stderr and
   exit code, and the request bytes the provider received are identical.
2. **Every transport attempt is recorded once**: the reader (``python -m
   fabric.reconstruct``) finds one exchange per model-API POST the provider received
   (an SDK retry and a retry after a transport error are separate attempts), no
   sequence gap and no missing position; the request bytes it replays are the bytes the
   provider received, and every response the provider sent whole replays exactly.
   Non-model requests (a POST to ``/v1/files``, a GET) are never exchanges.
3. **Row-specific rules**: the external undici copy's calls are ``uninstrumented_client``
   losses and the mixed run is not complete; a custom fetch over ``node:http`` is not
   captured and the manifest declares ``node_http`` uncaptured; the tool loop is one
   ``terminated`` run whose seals all recompute.
4. **Every gap is explained and the verdict follows from the gaps**: a gap that lowers a
   verdict is a response cut short (``truncated`` on an exchange that is not complete)
   or a loss the row names; the run is complete exactly when it has no such gap. A row
   whose script aborts or cancels a call is therefore ``partial``, as Python's reader
   reports the same calls (047 §9); ``matrix.json`` names each row's verdict.

Profiles: ``local`` (the local default policy) and ``production`` (a capture policy, the id
key and a sealed spool), both in pseudonymous identity mode, plus one ``clear`` identity
case (R8). The authenticated production path through a real Fabric Node is
``test_node_wire_fabric_node_e2e.py``.

With ``FABRIC_NODE_WIRE_MATRIX_REPORT`` set, a ``fabric.node-wire-matrix-report/v1`` JSON
report of every row is written there (the ``ts-wire-matrix`` CI job uploads it; unit
055-t17 commits the reports of the claimed tuples under ``qualification/node-wire/results/``).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parents[2] / "qualification" / "node-wire" / "harness"
    ),
)

from provider import ScriptedProvider  # noqa: E402

import _node_package  # noqa: E402
from _node_wire_harness import (  # noqa: E402
    EGRESS_AUTH,
    _replayed,
    agent_env,
    reconstruct,
    run_client,
)
from _wire_capture_common import Sink, write_tls  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / "qualification" / "node-wire" / "matrix.json"

_MISSING = _node_package.missing()
_REQUIRED = os.environ.get("FABRIC_REQUIRE_NODE_E2E") == "1"
pytestmark = pytest.mark.skipif(
    _MISSING is not None and not _REQUIRED, reason=_MISSING or ""
)
_RESULTS: list[dict[str, Any]] = []


def _matrix() -> dict[str, Any]:
    matrix: dict[str, Any] = json.loads(MATRIX.read_text(encoding="utf-8"))
    return matrix


def _rows() -> list[dict[str, Any]]:
    return [
        r
        for r in _matrix()["rows"]
        if r.get("test") == "scripts/tests/test_node_wire_matrix.py"
    ]


@pytest.fixture(autouse=True)
def _prerequisites() -> None:
    if _MISSING is not None:
        pytest.fail(f"FABRIC_REQUIRE_NODE_E2E=1 but this machine {_MISSING}")


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    directory = tmp_path_factory.mktemp("f055-t17-matrix")
    _node_package.install_app(directory)
    yield directory
    _write_report(directory)


def _versions(app: Path) -> dict[str, Any]:
    def version(package: str) -> str:
        manifest = app / "node_modules" / package / "package.json"
        return str(json.loads(manifest.read_text())["version"])

    node = _node_package.node_binary()
    assert node is not None
    tarball = _node_package.tarball()
    assert tarball is not None
    return {
        "tuple": _node_package.runtime_tuple(node),
        "artifact_sha256": "sha256:" + hashlib.sha256(tarball.read_bytes()).hexdigest(),
        "sdk": version("@singleaxis/fabric"),
        "clients": {p: version(p) for p in ("openai", "@anthropic-ai/sdk", "undici")},
    }


def _write_report(app: Path) -> None:
    out = os.environ.get("FABRIC_NODE_WIRE_MATRIX_REPORT")
    if not out or not _RESULTS:
        return
    expected = {(r["id"], p) for r in _rows() for p in r["profiles"]}
    seen = {(r["row"], r["profile"]) for r in _RESULTS}
    report = {
        "schema": "fabric.node-wire-matrix-report/v1",
        "source_sha": os.environ.get("FABRIC_SOURCE_SHA", "unknown"),
        **_versions(app),
        "rows": sorted(_RESULTS, key=lambda r: (r["row"], r["profile"])),
        "result": "passed"
        if expected <= seen and all(r["result"] == "passed" for r in _RESULTS)
        else "failed",
    }
    Path(out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", "utf-8")


@pytest.fixture
def sink(tmp_path: Path) -> Iterator[Sink]:
    tls = tmp_path / "tls"
    write_tls(tls)
    destination = Sink(tmp_path / "sink", tls, EGRESS_AUTH)
    destination.directory.mkdir()
    destination.start()
    yield destination
    destination.stop()


def _check_record(
    row: dict[str, Any], root: Path, provider: ScriptedProvider, sink: Sink
) -> dict[str, Any]:
    rows = sink.rows()
    code, report, stderr = reconstruct(rows, root)
    expect = row["expect"]
    if not expect.get("no_exchanges"):
        assert report.get("runs"), (code, stderr)
    exchanges = sorted(
        (e for run in report.get("runs", []) for e in run["exchanges"]),
        key=lambda e: e["source_sequence"],
    )
    sources = report.get("sources", [])
    lost = Counter(
        r["reason"]
        for s in sources
        for r in s["loss_ranges"]
        for _ in range(r["count"])
    )
    attempts = provider.attempts()
    # Attempts the record must not hold as exchanges: an unqualified undici copy's
    # (named uninstrumented_client losses) and a transport no qualified point observes.
    untracked = [
        b for p, b in attempts if any(m in p for m in expect.get("lost_paths", []))
    ]
    uncaptured = [
        b
        for p, b in attempts
        if any(m in p for m in expect.get("uncaptured_paths", []))
    ]
    uninstrumented = expect.get("uninstrumented_client", 0)
    assert len(untracked) == uninstrumented
    # Every other transport attempt to a model API is exactly one exchange.
    assert len(exchanges) == len(attempts) - len(untracked) - len(uncaptured), (
        [e["source_sequence"] for e in exchanges], [p for p, _ in attempts], lost,
    )  # fmt: skip
    assert dict(lost) == (
        {"uninstrumented_client": uninstrumented} if uninstrumented else {}
    )
    # A position with no exchange is a named loss, never an unexplained hole.
    for source in sources:
        named = {
            n for r in source["loss_ranges"]
            for n in range(r["first_sequence"], r["last_sequence"] + 1)
        }  # fmt: skip
        missing = {n for a, b in source["missing_sequences"] for n in range(a, b + 1)}
        assert missing <= named, source
    gap_kinds = {g["gap_type"] for run in report.get("runs", []) for g in run["gaps"]}
    # No position is missing and every seal recomputes (a seal_mismatch or a conflict
    # would mean the record disagrees with what the process sealed).
    assert not gap_kinds & {"sequence_gap", "seal_mismatch", "segment_conflict"}, (
        gap_kinds
    )
    # The request bytes it replays are the bytes the provider received.
    skipped = expect.get("lost_paths", []) + expect.get("uncaptured_paths", [])
    received = Counter(b for p, b in attempts if not any(m in p for m in skipped))
    replayed_requests = Counter(_replayed(root, exchanges, "request"))
    assert replayed_requests == received
    # A response that completed replays exactly as the provider sent it; one cut short
    # (an abort mid-body, a closed connection) replays a prefix of it, never other bytes.
    sent = [b for _, b in provider.sent]
    complete = 0
    for exchange in exchanges:
        (response,) = _replayed(root, [exchange], "response") or [None]
        if response is None:
            # Only a response that never arrived or was cut short has nothing to replay.
            assert exchange.get("response_state") != "complete", exchange
            continue
        if exchange.get("response_state") == "complete":
            complete += 1
            assert response in sent, exchange["source_sequence"]
        else:
            assert any(s.startswith(response) for s in sent), exchange[
                "source_sequence"
            ]
    assert complete >= expect.get("min_complete", 1)
    if expect.get("no_exchanges"):
        assert exchanges == [] and attempts == []
    # Every gap that lowers a verdict is explained by what the script did: a response
    # the application or the transport cut short (truncated, on an exchange that is not
    # complete) or a named loss the row expects. Anything else (a missing or mismatched
    # object, a gap on a complete exchange, an unexpected loss) fails the row, and the
    # verdict is complete exactly when no such gap exists: no false complete and no false
    # partial. Informational gaps (the scripted calls are unrelated conversations) are
    # reported, not counted.
    state_of = {e["exchange_id"]: e.get("response_state") for e in exchanges}
    explained = []
    for run in report.get("runs", []):
        for gap in run["gaps"]:
            if gap.get("effect") == "info":
                continue
            kind, reason = gap["gap_type"], gap.get("reason")
            cut_short = kind == "truncated" and state_of.get(
                gap.get("exchange_id")
            ) not in (None, "complete")
            named = (
                kind == "loss" and uninstrumented and reason == "uninstrumented_client"
            )
            assert cut_short or named, (gap, state_of.get(gap.get("exchange_id")))
            explained.append((kind, reason))
    verdicts = sorted({run["verdict"] for run in report.get("runs", [])})
    for run in report.get("runs", []):
        lowered = any(g.get("effect") != "info" for g in run["gaps"])
        assert run["verdict"].startswith("complete") is not lowered, (
            run["verdict"], run["gaps"],
        )  # fmt: skip
    if "verdict" in expect:
        assert verdicts == [expect["verdict"]], (verdicts, report["runs"][0]["gaps"])
    if verdicts:
        # The reader exits 0 exactly when every run is complete (047 G1).
        assert (code == 0) is all(v.startswith("complete") for v in verdicts), (
            code,
            stderr,
        )
    if expect.get("not_complete"):
        assert not any(v.startswith("complete") for v in verdicts), verdicts
    if "run_state" in expect:
        assert [r.get("run_state") for r in report["runs"]] == [expect["run_state"]]
    if not expect.get("no_exchanges"):
        # 055-t17 "newly visible": on a claimed build, the table shipped in the packed
        # package (gates passed, tuple active) makes manifest 0 declare the point active.
        manifests = sorted(
            (r["attributes"] for r in rows
             if r.get("kind") == "span" and r.get("name") == "fabric.capture_manifest"),
            key=lambda a: a["fabric.manifest.manifest_seq"],
        )  # fmt: skip
        assert manifests, "no capture manifest was delivered"
        # "<point>@<version>:<kind>:<state>:<a>:<b>:<reason>"
        (undici,) = [
            p
            for p in manifests[0]["fabric.manifest.capture_points"]
            if p.startswith("wire.ts.undici@")
        ]
        assert undici.split(":")[2] == "active", undici
    if "uncaptured_class" in expect:
        # The manifest declares what this process could not capture, never a guess.
        declared = [
            r["attributes"].get("fabric.manifest.uncaptured_classes")
            for r in rows
            if r.get("kind") == "span" and r.get("name") == "fabric.capture_manifest"
        ]
        assert declared and all(
            expect["uncaptured_class"] in (d or []) for d in declared
        )
    if "declared_class" in expect:
        # A class learned after install (spec 055 §4.5: a worker thread that did not
        # attach): manifest 0 of that process could not know it; a chained manifest of
        # the same epoch declares it from its cut on.
        chains: dict[Any, list[dict[str, Any]]] = {}
        for r in rows:
            if r.get("kind") == "span" and r.get("name") == "fabric.capture_manifest":
                attrs = r["attributes"]
                chains.setdefault(attrs.get("fabric.source.epoch"), []).append(attrs)
        declaring = [
            chain
            for chain in chains.values()
            if any(
                expect["declared_class"]
                in (a.get("fabric.manifest.uncaptured_classes") or [])
                for a in chain
            )
        ]
        assert declaring, chains
        for chain in declaring:
            first = min(chain, key=lambda a: a["fabric.manifest.manifest_seq"])
            assert expect["declared_class"] not in (
                first.get("fabric.manifest.uncaptured_classes") or []
            )
    if "epochs" in expect:
        # One process, one epoch: cluster.fork() children register their own (§6.4).
        epochs = {e.get("source_epoch") for e in exchanges}
        assert len(epochs) == expect["epochs"], epochs
    return {
        "exchanges": len(exchanges),
        "attempts": len(attempts),
        "losses": dict(lost),
        "verdicts": verdicts,
        "states": dict(Counter(e.get("response_state") for e in exchanges)),
        "gaps": dict(sorted(Counter(f"{t}:{r}" for t, r in explained).items())),
    }


@pytest.mark.parametrize(
    ("row", "profile"),
    [(r, p) for r in _rows() for p in r["profiles"]],
    ids=lambda v: v["id"] if isinstance(v, dict) else v,
)
def test_matrix_row(
    tmp_path: Path, app: Path, sink: Sink, row: dict[str, Any], profile: str
) -> None:
    result: dict[str, Any] = {
        "row": row["id"], "gate": row["gate"], "profile": profile, "result": "failed",
    }  # fmt: skip
    _RESULTS.append(result)
    runs = []
    for preload in (False, True):
        provider = ScriptedProvider()
        try:
            root = tmp_path / ("on" if preload else "off")
            env = agent_env(root, provider, sink, row["dialect"], profile)
            transcript, stderr, code = run_client(
                app, root, row["script"], env, preload
            )
            if preload:
                result["record"] = _check_record(row, root, provider, sink)
            runs.append(
                (transcript, stderr, code, sorted(provider.received), provider.gets)
            )
        finally:
            provider.close()
    off, on = runs
    # Behaviour identity: the application, the provider and the process saw the same.
    assert on[0] == off[0]
    assert on[1:] == off[1:]
    assert "fabric" not in on[1].lower(), on[1]
    for scenario, kind in row.get("observes", {}).items():
        assert kind in on[0][scenario], (scenario, on[0][scenario])
    status = json.loads((tmp_path / "on" / "fabric-status.json").read_text())
    # close() reports false whenever a position was lost (spec 055 §9.4), true otherwise.
    lossless = not row["expect"].get("uninstrumented_client")
    assert status["capture"] == "closed" and status["delivered"] is lossless, status
    assert status["stats"]["backlog"] == 0, status
    for warning in row["expect"].get("status_ids", []):
        assert warning in status["warning_ids"] + status["notice_ids"], status
    result["status_ids"] = sorted(status["warning_ids"] + status["notice_ids"])
    result["scenarios"] = sorted(on[0])
    result["result"] = "passed"
