# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §1.4 and §11.1: the npm launcher's ``fabric run`` and ``fabric doctor`` are
tested against the Python CLI's with shared goldens (``sdk/goldens/cli-launcher``).

This module runs every case through the Python CLI; ``sdk/typescript/test/
cli-launcher-goldens.test.ts`` runs the same cases through the npm launcher. A case's
expected result is what both must produce: the compiled environment file ``fabric init``
writes, the runtime of an agent command, the variables ``fabric run`` adds and the
findings it records, and the catalogue ids ``fabric doctor`` reports.

``FABRIC_REGENERATE_GOLDENS=1`` rewrites the expectations from the Python CLI; review
the diff, then make the npm launcher agree."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from fabric.cli import _config, _doctor, _project, _run

GOLDENS = Path(__file__).resolve().parents[2] / "goldens" / "cli-launcher" / "launcher-v1.json"
DOCUMENT: dict[str, Any] = json.loads(GOLDENS.read_text("utf-8"))
REGENERATE = os.environ.get("FABRIC_REGENERATE_GOLDENS") == "1"
STATUS_FILE = re.compile(r"^\{\{dir\}\}/\.fabric/state/runs/[0-9]+-[A-Za-z0-9._-]+\.status\.json$")
LABEL = re.compile(r"^run-[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$")
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX paths and modes")
_RESULTS: dict[str, Any] = {}


def materialize(tmp: Path, name: str) -> Path:
    """The project of the goldens named ``name``, in a fresh directory (its real path)."""
    spec = DOCUMENT["projects"][name]
    directory = tmp / "project"
    directory.mkdir()
    directory = directory.resolve()
    for entry in spec["files"]:
        path = directory / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry["content"], encoding="utf-8")
        path.chmod(int(entry["mode"], 8))
    if spec["fabric.yaml"] is not None:
        (directory / "fabric.yaml").write_text(spec["fabric.yaml"], encoding="utf-8")
        compiled = next(c for c in DOCUMENT["compile"] if c["project"] == name)
        if compiled["compiled_env"] is not None:
            state = directory / ".fabric"
            state.mkdir(mode=0o700)
            path = state / "compiled.env"
            path.write_text(compiled["compiled_env"].replace("{{dir}}", str(directory)), "utf-8")
            path.chmod(0o600)
    return directory


def _prepare_case(directory: Path, case: Mapping[str, Any]) -> None:
    for relative in case.get("remove", ()):
        (directory / relative).unlink()
    for relative, mode in (case.get("chmod") or {}).items():
        (directory / relative).chmod(int(mode, 8))
    if case.get("edit_config"):
        with (directory / "fabric.yaml").open("a", encoding="utf-8") as handle:
            handle.write("# edited after fabric init\n")


def _environ(directory: Path, case: Mapping[str, Any]) -> dict[str, str]:
    return {"PATH": str(directory / "bin"), "HOME": str(directory), **case["environ"]}


def _template(value: str, directory: Path) -> str:
    return value.replace(str(directory), "{{dir}}")


def _save(section: str, index: int, key: str, value: Any) -> None:
    _RESULTS.setdefault(section, {})[(index, key)] = value


@pytest.fixture(scope="module", autouse=True)
def _regenerate() -> Any:
    yield
    if not REGENERATE:
        return
    for section, values in _RESULTS.items():
        for (index, key), value in values.items():
            DOCUMENT[section][index][key] = value
    GOLDENS.write_text(json.dumps(DOCUMENT, indent=2) + "\n", encoding="utf-8")


@pytest.mark.parametrize("index", range(len(DOCUMENT["compile"])))
def test_compiled_environment_file(tmp_path: Path, index: int) -> None:
    """The file ``fabric init`` writes is the golden one, which the npm launcher reads."""
    case = DOCUMENT["compile"][index]
    spec = DOCUMENT["projects"][case["project"]]
    directory = (tmp_path / "project").resolve()
    directory.mkdir()
    for entry in spec["files"]:
        path = directory / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry["content"], encoding="utf-8")
    (directory / "fabric.yaml").write_text(spec["fabric.yaml"], encoding="utf-8")
    project = _project.load(_config.discover(None, {}, directory), {}, {})
    text = _project.render_compiled_env(
        _project.compile_environment(project),
        _project.config_digest(project.config_path),
        _project.launcher_settings(project),
    )
    if REGENERATE:
        _save("compile", index, "compiled_env", _template(text, directory))
        return
    assert text == case["compiled_env"].replace("{{dir}}", str(directory))


@pytest.mark.parametrize("index", range(len(DOCUMENT["detect"])))
def test_runtime_detection(tmp_path: Path, index: int) -> None:
    case = DOCUMENT["detect"][index]
    directory = materialize(tmp_path, "detect")
    command = [word.replace("{{dir}}", str(directory)) for word in case["command"]]
    runtime = _run.detect(command, {"PATH": str(directory / "bin")}, directory)
    interpreter = _template(str(runtime.interpreter), directory) if runtime.interpreter else None
    assert (runtime.kind, interpreter) == (case["kind"], case["interpreter"])


def _probe_runner(probe: Mapping[str, Any] | None) -> Any:
    def runner(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        assert probe is not None, f"asked an interpreter although the case has no probe: {argv}"
        return subprocess.CompletedProcess(argv, 0, json.dumps(probe) + "\n", "")

    return runner


def _record(directory: Path) -> dict[str, Any] | None:
    runs = directory / ".fabric" / "state" / "runs"
    if not runs.is_dir():
        return None
    records = sorted(p for p in runs.glob("*.json") if not p.name.endswith(".status.json"))
    if not records:
        return None
    raw = json.loads(records[-1].read_text("utf-8"))
    keys = ("capture", "runtime", "sensor", "project")
    return {**{key: raw[key] for key in keys}, "finding_ids": [f["id"] for f in raw["findings"]]}


def run_result(directory: Path, environ: Mapping[str, str], env: Mapping[str, str],
               finding_ids: list[str]) -> dict[str, Any]:  # fmt: skip
    """What a golden compares: the variables added or changed, by template."""
    added: dict[str, str] = {}
    for name, value in sorted(env.items()):
        if environ.get(name) == value:
            continue
        templated = _template(value, directory)
        if name == "FABRIC_WIRE_STATUS_FILE":
            assert STATUS_FILE.match(templated), templated
            templated = "<status-file>"
        if name == "FABRIC_RUN_ID" and LABEL.match(templated):
            templated = "<generated-label>"
        added[name] = templated
    removed = sorted(set(environ) - set(env))
    assert not removed, f"fabric run removed variables: {removed}"
    return {"added": added, "finding_ids": finding_ids, "record": _record(directory)}


@pytest.mark.parametrize(
    "index", range(len(DOCUMENT["run"])), ids=[c["name"] for c in DOCUMENT["run"]]
)
def test_run_environment(tmp_path: Path, index: int) -> None:
    """``fabric run``'s environment, findings and run record for each case."""
    case = DOCUMENT["run"][index]
    directory = materialize(tmp_path, case["project"])
    _prepare_case(directory, case)
    environ = _environ(directory, case)
    options = argparse.Namespace(config=None, project=None, quiet=True, exec_mode=True,
                                 run_label=case["run_label"],
                                 no_capture=bool(case.get("no_capture")))  # fmt: skip
    env, findings = _run._prepare(
        options, case["command"], dict(environ), directory, _probe_runner(case["probe"]),
        lambda: 1_700_000_000_000_000_000,
    )  # fmt: skip
    result = run_result(directory, environ, env, [f.id for f in findings])
    if REGENERATE:
        _save("run", index, "expect", result)
        return
    assert result == case["expect"]


def _status_runner(status: Mapping[str, Any] | None) -> Any:
    def runner(argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if status is None:
            return subprocess.CompletedProcess(argv, 1, "", "No module named fabric")
        code = 1 if status.get("warning_ids") else 0
        return subprocess.CompletedProcess(argv, code, json.dumps(status) + "\n", "")

    return runner


@pytest.mark.parametrize(
    "index", range(len(DOCUMENT["doctor"])), ids=[c["name"] for c in DOCUMENT["doctor"]]
)
def test_doctor_findings(tmp_path: Path, index: int) -> None:
    """``fabric doctor``'s catalogue ids (those both CLIs check) and exit code."""
    case = DOCUMENT["doctor"][index]
    directory = materialize(tmp_path, case["project"])
    _prepare_case(directory, case)
    environ = _environ(directory, case)
    status = DOCUMENT["sdk_status"][case["sdk_status"]] if case["sdk_status"] else None
    options = argparse.Namespace(
        config=None, project=None, kubernetes=False, json=True, quiet=False
    )
    report, _ = _doctor.run(
        options, environ, directory, runner=_status_runner(status),
        node_ok=lambda _project, _compiled: case["node_answers"],
        which=lambda name, path=None: shutil.which(name, path=path),
    )  # fmt: skip
    compare = set(case.get("compare") or DOCUMENT["doctor_compare"])
    ids = sorted({f.id for f in report.findings} & compare)
    result = {"ids": ids, "exit_code": report.exit_code}
    if REGENERATE:
        _save("doctor", index, "expect", result)
        return
    assert result == case["expect"]
