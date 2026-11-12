# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §4.7: the ``fabric.wire-status/v1`` document has a schema, and the documents
the Python SDK really writes to ``FABRIC_WIRE_STATUS_FILE`` (install, failure, disabled
and exit) validate against it. The TypeScript SDK's documents join from unit 055-t14.

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
    assert {d.get("sdk_language", "python") for d in documents} == {"python", "typescript"}
    for language in ("python", "typescript"):
        states = {d["capture"] for d in documents if d.get("sdk_language", "python") == language}
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
    environ = {k: os.environ[k] for k in ("PATH", "HOME", "SYSTEMROOT") if k in os.environ}
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
        assert set(document["warning_ids"]) | set(document["notice_ids"]) <= _catalogued()
        if document["capture"] == "not_installed":
            assert document["reason_id"] in _catalogued()


def test_diagnostics_family_is_pinned() -> None:
    manifest = _json(FAMILY / "manifest.json")
    assert manifest["contract"] == "singleaxis.fabric.diagnostics"
    # 1.1.0: spec 055 §4.7 (the sdk list, the Node.js entries, the wire-status schema)
    assert manifest["version"] == "1.1.0"
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
