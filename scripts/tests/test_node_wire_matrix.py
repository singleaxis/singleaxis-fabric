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
   captured and the manifest declares ``node_http`` uncaptured; the tool loop is one run
   that verifies ``complete_for_observed_scopes``/``terminated`` with its seals.

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
import subprocess
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
from _wire_capture_common import Sink, capture_protection, write_tls  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / "qualification" / "node-wire" / "matrix.json"
TENANT = "tenant-matrix"
ID_KEY = "matrix-id-key-0123456789abcdef0123"
SPOOL_KEY = bytes(range(32, 64))
EGRESS_AUTH = "Bearer matrix-egress"

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


def agent_env(
    root: Path, provider: ScriptedProvider, sink: Sink, dialect: str, profile: str
) -> dict[str, str]:
    """Only environment variables: the preload, Fabric's settings and the client's own."""
    base = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("FABRIC_", "OTEL_", "OPENAI_", "ANTHROPIC_", "NODE_"))
    }
    root.mkdir(parents=True, exist_ok=True)
    headers = root / "otlp-headers"
    headers.write_text("Authorization=" + EGRESS_AUTH.replace(" ", "%20") + "\n")
    headers.chmod(0o600)
    endpoint = {
        "endpoint_id": f"matrix-{dialect}", "dialect": dialect, "hosts": ["127.0.0.1"],
        "ports": [provider.port], "schemes": ["http"],
    }  # fmt: skip
    env = {
        **base,
        "NODE_OPTIONS": "--import=@singleaxis/fabric/register",
        "FABRIC_WIRE_AUTOLOAD": "1",
        "FABRIC_TENANT_ID": TENANT,
        "FABRIC_WIRE_SPOOL_DIR": str(root / "spool"),
        "FABRIC_WIRE_ENDPOINTS": json.dumps([endpoint]),
        "FABRIC_OTLP_ENDPOINT": f"https://localhost:{sink.port}",
        "FABRIC_OTLP_HEADERS_FILE": str(headers),
        "FABRIC_OTLP_CERTIFICATE": str(sink.tls / "ca.crt"),
        "FABRIC_WIRE_DRAIN_ON_EXIT_S": "20",
        "FABRIC_WIRE_STATUS_FILE": str(root / "fabric-status.json"),
        "OTEL_SERVICE_NAME": "matrix-agent",
        "BASE": provider.base,
        "MODEL_BASE_URL": provider.base,
    }
    if profile == "local":
        # The local profile: content goes to a directory store the agent writes itself.
        env["FABRIC_WIRE_STORE"] = f"file://{root / 'store'}"
    else:
        # Production: content goes to the Node's content port (here the sink), which
        # needs a capture policy, the id key and a sealed spool (049 §7.3, §7.8).
        env["FABRIC_WIRE_CONTENT_ENDPOINT"] = f"https://localhost:{sink.port}/v1/logs"
        env.update(capture_protection(root, TENANT, SPOOL_KEY))
        env["FABRIC_WIRE_ID_KEY"] = ID_KEY
    if profile == "clear":
        env["FABRIC_IDENTITY_MODE"] = "clear"
    return env


def run_client(
    app: Path, root: Path, script: str, env: dict[str, str], preload: bool
) -> tuple[dict[str, Any], str, int]:
    root.mkdir(parents=True, exist_ok=True)
    if not preload:
        env = {k: v for k, v in env.items() if not k.startswith(("FABRIC_", "NODE_"))}
    node = _node_package.node_binary()
    assert node is not None
    done = subprocess.run(  # noqa: S603
        [node, script], cwd=app, env=env, capture_output=True, text=True, timeout=240,
        check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    transcript: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    transcript.pop("fabric", None)  # what the run API returned differs by design
    return transcript, done.stderr, done.returncode


def file_store(rows: list[dict[str, Any]], root: Path) -> None:
    """Files each content log the sink received as the Node's directory backend does."""
    from fabric.content_store import LocalFilesystemContentStore

    (root / TENANT).mkdir(parents=True, exist_ok=True)
    store = LocalFilesystemContentStore(root=str(root), tenant_id=TENANT)
    for row in rows:
        if row.get("kind") != "log":
            continue
        descriptor = {k: v for k, v in row["attributes"].items() if k != "event_class"}
        if row["body"] is None or "stored_sha256" not in descriptor:
            store.put_descriptor_only(descriptor)
            continue
        descriptor["encoding"] = "binary"
        descriptor["ref"] = store.evidence_ref_for(descriptor["object_id"])
        store.put_bytes_object(descriptor, bytes.fromhex(row["body"]))


def reconstruct(
    rows: list[dict[str, Any]], root: Path
) -> tuple[int, dict[str, Any], str]:
    spans = root / "spans.jsonl"
    spans.write_text(
        "".join(json.dumps(r) + "\n" for r in rows if r.get("kind") == "span")
    )
    store = root / "store"
    if not store.exists():  # production: the content logs the sink received
        file_store(rows, store)
    out = root / "report.json"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.reconstruct", "--spans", str(spans),
         "--store-root", str(store), "--tenant", TENANT, "--out", str(out)],
        env={**os.environ, "FABRIC_WIRE_ID_KEY": ID_KEY}, capture_output=True, text=True,
        timeout=180, check=False,
    )  # fmt: skip
    report = json.loads(out.read_text()) if out.exists() else {}
    return done.returncode, report, done.stderr


def _replayed(root: Path, exchanges: list[dict[str, Any]], side: str) -> list[bytes]:
    from fabric.content_store import LocalFilesystemContentStore

    store = LocalFilesystemContentStore(root=str(root / "store"), tenant_id=TENANT)
    out = []
    for exchange in exchanges:
        obj = (exchange.get("objects") or {}).get(side)
        if obj and obj.get("verification") == "verified":
            out.append(store.read(store.evidence_ref_for(obj["object_id"])))
    return out


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
    verdicts = sorted({run["verdict"] for run in report.get("runs", [])})
    if "verdict" in expect:
        assert verdicts == [expect["verdict"]], (verdicts, report["runs"][0]["gaps"])
        assert code == 0, stderr
    if expect.get("not_complete"):
        assert not any(v.startswith("complete") for v in verdicts), verdicts
    if "run_state" in expect:
        assert [r.get("run_state") for r in report["runs"]] == [expect["run_state"]]
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
    return {
        "exchanges": len(exchanges),
        "attempts": len(attempts),
        "losses": dict(lost),
        "verdicts": verdicts,
        "states": dict(Counter(e.get("response_state") for e in exchanges)),
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
