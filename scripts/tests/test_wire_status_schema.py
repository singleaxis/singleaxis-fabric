# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §4.7: the ``fabric.wire-status/v1`` document has a schema, and the documents
the Python SDK really writes to ``FABRIC_WIRE_STATUS_FILE`` (install, failure, disabled
and exit) validate against it. From unit 055-t14 the TypeScript SDK's documents, produced by the packed package for each
disabled reason and by a capturing install, validate too.

Also pins the diagnostics family: every file under ``contracts/diagnostics/v1`` is listed
in its manifest with its exact SHA-256, and every id a status document carries is
catalogued."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parents[2]
FAMILY = REPO_ROOT / "contracts" / "diagnostics" / "v1"
SCHEMA = FAMILY / "schema" / "wire-status-v1.schema.json"
FIXTURES = FAMILY / "fixtures" / "wire-status"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator() -> Draft202012Validator:
    schema = _json(SCHEMA)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _catalogued() -> set[str]:
    return {entry["id"] for entry in _json(FAMILY / "messages-v1.json")["messages"]}


def _fixtures(kind: str) -> list[Path]:
    return sorted((FIXTURES / kind).glob("*.json"))


@pytest.mark.parametrize("path", _fixtures("valid"), ids=lambda p: p.stem)
def test_valid_status_fixtures_validate(path: Path) -> None:
    document = _json(path)
    _validator().validate(document)
    assert set(document["warning_ids"]) | set(document["notice_ids"]) <= _catalogued()


@pytest.mark.parametrize("path", _fixtures("invalid"), ids=lambda p: p.stem)
def test_invalid_status_fixtures_are_refused(path: Path) -> None:
    assert list(_validator().iter_errors(_json(path))), f"{path.name} was accepted"


def test_fixtures_cover_both_sdks_and_every_capture_state() -> None:
    documents = [_json(p) for p in _fixtures("valid")]
    assert {d.get("sdk_language", "python") for d in documents} == {
        "python",
        "typescript",
    }
    for language in ("python", "typescript"):
        states = {
            d["capture"]
            for d in documents
            if d.get("sdk_language", "python") == language
        }
        assert states == {"installed", "disabled", "not_installed", "closed"}, language


_WRITER = textwrap.dedent(
    """
    import json, os, sys, time
    from fabric import wire

    path = sys.argv[1]
    handle = wire.install_from_env()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                if json.load(fh)["phase"] == "install":
                    break
        time.sleep(0.02)
    with open(path, encoding="utf-8") as fh:
        documents = [json.load(fh)]
    if handle is not None and handle.capturing:
        handle._atexit_close()
        with open(path, encoding="utf-8") as fh:
            documents.append(json.load(fh))
    print(json.dumps(documents))
    """
)


def _python_documents(tmp_path: Path, env: dict[str, str]) -> list[dict[str, Any]]:
    """Run the Python SDK in a clean process with ``env`` and return what it wrote."""
    path = tmp_path / "status.json"
    environ = {
        k: os.environ[k] for k in ("PATH", "HOME", "SYSTEMROOT") if k in os.environ
    }
    environ.update(env, FABRIC_WIRE_STATUS_FILE=str(path))
    script = tmp_path / "writer.py"
    script.write_text(_WRITER, encoding="utf-8")
    done = subprocess.run(
        [sys.executable, str(script), str(path)],
        env=environ,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    documents: list[dict[str, Any]] = json.loads(done.stdout.strip().splitlines()[-1])
    return documents


@pytest.mark.parametrize(
    ("case", "env", "phases"),
    [
        ("install and exit", {"FABRIC_TENANT_ID": "t1", "FABRIC_WIRE_SPOOL_DIR": "off"},
         [("install", "installed"), ("exit", "closed")]),
        ("failure", {"FABRIC_WIRE_ENDPOINTS": "not json"}, [("install", "not_installed")]),
        ("disabled", {"OTEL_SDK_DISABLED": "true"}, [("install", "disabled")]),
    ],
    ids=["install-exit", "failure", "disabled"],
)  # fmt: skip
def test_python_status_documents_validate(
    tmp_path: Path, case: str, env: dict[str, str], phases: list[tuple[str, str]]
) -> None:
    if "FABRIC_TENANT_ID" in env:
        env = dict(env, FABRIC_WIRE_STORE=f"file://{tmp_path / 'store'}")
    documents = _python_documents(tmp_path, env)
    assert [(d["phase"], d["capture"]) for d in documents] == phases, case
    validator = _validator()
    for document in documents:
        errors = [e.message for e in validator.iter_errors(document)]
        assert errors == [], (case, errors)
        assert (
            set(document["warning_ids"]) | set(document["notice_ids"]) <= _catalogued()
        )
        if document["capture"] == "not_installed":
            assert document["reason_id"] in _catalogued()


def test_diagnostics_family_is_pinned() -> None:
    manifest = _json(FAMILY / "manifest.json")
    assert manifest["contract"] == "singleaxis.fabric.diagnostics"
    # 1.1.0: spec 055 §4.7 (the sdk list, the Node.js entries, the wire-status schema);
    # 1.2.0: FW-034 (055-t14: a Node.js spool directory that is unset or unusable)
    # 1.3.0: FW-035 (055-t17: a model call published by an unqualified undici copy)
    assert manifest["version"] == "1.3.0"
    pinned = {manifest["schema"]["path"]: manifest["schema"]["sha256"]}
    pinned.update({f["path"]: f["sha256"] for f in manifest["files"]})
    on_disk = {
        p.relative_to(FAMILY).as_posix()
        for p in FAMILY.rglob("*.json")
        if p.name != "manifest.json"
    }
    assert set(pinned) == on_disk, sorted(set(pinned) ^ on_disk)
    for rel, digest in pinned.items():
        assert hashlib.sha256((FAMILY / rel).read_bytes()).hexdigest() == digest, rel


# ----------------------------------------------------------- TypeScript (unit 055-t14)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _node_package  # noqa: E402

_NODE_MISSING = _node_package.missing()
_NODE_REQUIRED = os.environ.get("FABRIC_REQUIRE_NODE_E2E") == "1"
_node = pytest.mark.skipif(
    _NODE_MISSING is not None and not _NODE_REQUIRED, reason=_NODE_MISSING or ""
)

# Each case: the documents one Node process produces from the packed package. `docs` is
# an array of [label, document]; the case's expectations are (capture, reason, an id).
_TS_PRODUCER = r"""
const { writeFileSync, mkdirSync } = require("node:fs");
const { join } = require("node:path");
const { Worker } = require("node:worker_threads");
const wire = require("@singleaxis/fabric/wire");
const [mode, scratch] = process.argv.slice(2);
const out = [];
const env = JSON.parse(process.env.CASE_ENV || "{}");
const native = JSON.parse(process.env.CASE_NATIVE || "{}");
(async () => {
  if (mode === "env") out.push(["envStatus", wire.envStatus(env, { native })]);
  if (mode === "install") {
    const handle = wire.install();
    if (process.env.CASE_UNMATCHED === "1") {
      // A model-looking POST to a host no endpoint covers (FW-006); it need not connect.
      await fetch("http://unmatched-model.invalid:8080/v1/chat/completions",
        { method: "POST", body: "{}" }).then((r) => r.text(), () => null);
    }
    out.push(["status", handle.status()]);
    if (handle.capturing) {
      await handle.close({ timeoutMs: 3000 });
      out.push(["closed", handle.status()]);
    }
  }
  if (mode === "worker") {
    const doc = await new Promise((resolve, reject) => {
      const w = new Worker(
        'const { parentPort } = require("node:worker_threads");' +
          'parentPort.postMessage(JSON.stringify(require("@singleaxis/fabric/wire").install().status()));',
        { eval: true });
      w.once("message", resolve);
      w.once("error", reject);
    });
    out.push(["worker", JSON.parse(doc)]);
  }
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
"""


@pytest.fixture(scope="module")
def node_app(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if _NODE_MISSING is not None:
        pytest.fail(f"FABRIC_REQUIRE_NODE_E2E=1 but this machine {_NODE_MISSING}")
    directory = tmp_path_factory.mktemp("f055-t14-status-app")
    _node_package.install_app(directory)
    (directory / "produce.cjs").write_text(_TS_PRODUCER, encoding="utf-8")
    return directory


def _ts_documents(
    app: Path,
    tmp_path: Path,
    mode: str,
    env: dict[str, str],
    native: dict[str, Any] | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    environ = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("FABRIC_", "OTEL_", "NODE_"))
    }
    environ.update(env)
    if mode == "env":
        environ = {k: v for k, v in environ.items() if not k.startswith("FABRIC_")}
        environ["CASE_ENV"] = json.dumps(env)
        environ["CASE_NATIVE"] = json.dumps(native or {})
    node = _node_package.node_binary()
    assert node is not None
    done = subprocess.run(  # noqa: S603
        [node, "produce.cjs", mode, str(tmp_path)], cwd=app, env=environ,
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    documents: list[tuple[str, dict[str, Any]]] = [
        (label, doc) for label, doc in json.loads(done.stdout.strip().splitlines()[-1])
    ]
    return documents


def _check(document: dict[str, Any]) -> None:
    errors = [e.message for e in _validator().iter_errors(document)]
    assert errors == [], (document, errors)
    assert document["sdk_language"] == "typescript"
    assert set(document["warning_ids"]) | set(document["notice_ids"]) <= _catalogued()


def _base(tmp_path: Path) -> dict[str, str]:
    spool = tmp_path / "spool"
    return {
        "FABRIC_WIRE_SPOOL_DIR": str(spool),
        "FABRIC_OTLP_ENDPOINT": "http://127.0.0.1:9",
    }


def _garbage_prebuilds(tmp_path: Path, digest_matches: bool) -> dict[str, Any]:
    build = _node_package.runtime_tuple(_node_package.node_binary() or "node")
    directory = tmp_path / "prebuilds"
    (directory / build["platform"]).mkdir(parents=True)
    data = b"not a shared object"
    (directory / build["platform"] / "fabric_wire.node").write_bytes(data)
    native: dict[str, Any] = {"prebuildsDir": str(directory)}
    if digest_matches:
        native["digests"] = {build["platform"]: hashlib.sha256(data).hexdigest()}
    return native


# (case, mode, env builder, native builder, capture, capture_reason, id that must appear)
_TS_CASES: list[tuple[str, str, Any, Any, str, str | None, str | None]] = [
    ("config_invalid", "env", lambda t: {"FABRIC_WIRE_ENDPOINTS": "not json"}, None,
     "not_installed", None, "FW-025"),
    ("otel_sdk_disabled", "env", lambda t: {**_base(t), "OTEL_SDK_DISABLED": "true"}, None,
     "disabled", "otel_sdk_disabled", "FW-007"),
    ("no_spool", "env", lambda t: {}, None, "disabled", "no_spool", "FW-034"),
    ("spool_unusable", "env", lambda t: {**_base(t), "FABRIC_WIRE_SPOOL_DIR": "/dev/null"},
     None, "disabled", "spool_unusable", "FW-034"),
    ("native_missing", "env", _base, lambda t: {"prebuildsDir": str(t / "none")},
     "disabled", "native_missing", "FW-028"),
    ("native_digest_mismatch", "env", _base, lambda t: _garbage_prebuilds(t, False),
     "disabled", "native_digest_mismatch", "FW-028"),
    ("native_load_failed", "env", _base, lambda t: _garbage_prebuilds(t, True),
     "disabled", "native_load_failed", "FW-028"),
    ("platform_unsupported", "env", _base, lambda t: {"platform": "aix"},
     "disabled", "platform_unsupported", "FW-027"),
    ("hook_disabled", "env", lambda t: {**_base(t), "FABRIC_WIRE_UNDICI": "0"}, None,
     "disabled", "hook_disabled", "FW-029"),
    ("autoload_off", "env", _base, None, None, None, "FW-031"),
    ("status_file_unwritable", "env",
     lambda t: {**_base(t), "FABRIC_WIRE_STATUS_FILE": str(t / "missing" / "s.json")},
     None, None, None, "FW-023"),
    ("content_disabled", "env",
     lambda t: {**_base(t), "FABRIC_WIRE_CONTENT_ENDPOINT": "http://127.0.0.1:9/v1/logs",
                "FABRIC_TENANT_ID": "t1"}, None, None, None, "FW-008"),
    ("metadata_only", "env", _base, None, None, None, "FW-003"),
    ("worker_without_process_runtime", "worker", _base, None, "disabled",
     "worker_without_process_runtime", "FW-030"),
]  # fmt: skip


@_node
@pytest.mark.parametrize(
    ("case", "mode", "env", "native", "capture", "reason", "id_"),
    _TS_CASES,
    ids=[c[0] for c in _TS_CASES],
)
def test_typescript_status_documents_validate_for_each_reason(
    node_app: Path, tmp_path: Path, case: str, mode: str, env: Any, native: Any,
    capture: str | None, reason: str | None, id_: str | None,
) -> None:  # fmt: skip
    """Spec 055 §4.7: envStatus() and install().status() from the packed package validate
    for each disabled reason of §4.4 and §4.7, and name the reason's catalogue id."""
    documents = _ts_documents(
        node_app,
        tmp_path,
        mode,
        env(tmp_path),
        None if native is None else native(tmp_path),
    )
    assert documents, case
    for _label, document in documents:
        _check(document)
    document = documents[0][1]
    if capture is not None:
        assert document["capture"] == capture, document
    if reason is not None:
        assert document["status"]["capture_reason"] == reason, document
    if id_ is not None:
        assert id_ in document["warning_ids"] + document["notice_ids"], document
    if document["capture"] == "not_installed":
        assert document["reason_id"] == "FW-014" and document["fix"], document


@_node
def test_typescript_install_and_exit_documents_and_the_status_file_validate(
    node_app: Path, tmp_path: Path
) -> None:
    """A capturing install (the table activates this build): status() before and after
    close() and the status file the Fabric worker wrote at exit."""
    status_file = tmp_path / "status.json"
    env = {
        **_base(tmp_path),
        "FABRIC_WIRE_STATUS_FILE": str(status_file),
        "CASE_UNMATCHED": "1",
    }
    documents = _ts_documents(node_app, tmp_path, "install", env)
    assert [(d["phase"], d["capture"]) for _, d in documents] == [
        ("install", "installed"),
        ("exit", "closed"),
    ], documents
    for _label, document in documents:
        _check(document)
    assert "FW-005" in documents[0][1]["notice_ids"]
    written = json.loads(status_file.read_text(encoding="utf-8"))
    _check(written)
    assert (written["phase"], written["capture"]) == ("exit", "closed")
    assert oct(status_file.stat().st_mode & 0o777) == oct(0o600)
    # FW-006: the unmatched host and the exact value that records it, as Python lists it.
    from fabric.wire._unmatched import UnmatchedModelHosts  # noqa: PLC0415

    python = UnmatchedModelHosts()
    python.note("POST", "http", "unmatched-model.invalid", 8080, "/v1/chat/completions")
    rows = python.status()
    assert documents[0][1]["status"]["unmatched_model_hosts"] == rows, documents[0][1]
    assert "FW-006" in documents[0][1]["warning_ids"]
    for document in (documents[1][1], written):
        assert document["unmatched_model_hosts"] == rows, document
        assert "FW-006" in document["warning_ids"], document
