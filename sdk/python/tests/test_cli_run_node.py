# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The zero-code Node.js path of ``fabric run`` (spec 055 §13.1, spec 058 §5.5 step 3).

``fabric run -- node agent.js`` appends ``--import=@singleaxis/fabric/register`` to
``NODE_OPTIONS`` and sets ``FABRIC_WIRE_AUTOLOAD=1`` (with the settings Python gets) only
when the package resolves from the agent's directory with TS-1U and TS-1D passed and the
Node build is an ``active`` tuple of its table. Otherwise nothing changes beyond the
explicit API's variables, and the reason is a catalogue finding with its fix (FC-098 to
FC-101). ``NODE_OPTIONS`` is appended to, never overwritten, and never given the preload
twice. The real-process passivity matrix is test_cli_passivity_node.py."""

from __future__ import annotations

import io
import json
import os
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fabric.cli import _config, _doctor, _node, _project, _read, _run, _runstate, _verify

from ._cli_node_support import BUILD, NodeProbe, fake_node, install_package, table, tuple_for
from ._cli_run_support import base_env, make_project
from ._cli_support import parse

PRELOAD = "--import=@singleaxis/fabric/register"


class Exec:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str], dict[str, str]]] = []

    def __call__(self, file: str, argv: Sequence[str], env: Mapping[str, str]) -> None:
        self.calls.append((file, list(argv), dict(env)))


class Stream(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    node_dir = tmp_path / "node-bin"
    fake_node(node_dir)
    base = base_env(tmp_path)
    return {
        **base,
        "PATH": f"{node_dir}{os.pathsep}{base['PATH']}",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/agent-own",
        "OTEL_SERVICE_NAME": "agent",
    }


def _launch(
    project: Path,
    env: dict[str, str],
    command: list[str],
    *flags: str,
    probe: NodeProbe | None = None,
    tty: bool = False,
    cwd: Path | None = None,
) -> tuple[dict[str, str], Stream, NodeProbe]:
    execvpe, stderr = Exec(), Stream(tty)
    probe = probe or NodeProbe()
    options = parse(["run", *flags])
    _run.launch(options, command, env, cwd or project, execvpe=execvpe, stderr=stderr, runner=probe)
    ((_, argv, child),) = execvpe.calls
    assert argv == command  # argv untouched
    return child, stderr, probe


def _added(before: Mapping[str, str], after: Mapping[str, str]) -> dict[str, str]:
    assert set(before) <= set(after), "a variable was removed"
    return {k: v for k, v in after.items() if before.get(k) != v}


def _last(project: Path) -> _runstate.RunRecord:
    return _runstate.load_runs(project / ".fabric")[0]


def test_a_qualified_node_gets_the_preload_and_the_settings(
    tmp_path: Path, env: dict[str, str]
) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    child, stderr, _ = _launch(project, env, ["node", "agent.mjs", "--flag"], "--run", "n-1")
    added = _added(env, child)
    assert child["NODE_OPTIONS"] == PRELOAD
    assert set(added) - {"NODE_OPTIONS"} == {n for n in added if n.startswith("FABRIC_")}
    assert child["FABRIC_WIRE_AUTOLOAD"] == "1" and child["FABRIC_RUN_ID"] == "n-1"
    # The settings Python gets (spec 055 §13.1: TypeScript reads the same names).
    assert child["FABRIC_OTLP_ENDPOINT"].startswith("https://localhost:")
    assert Path(child["FABRIC_WIRE_ID_KEY_FILE"]).is_file()
    assert child["FABRIC_WIRE_STATUS_FILE"].endswith("-n-1.status.json")
    assert "PYTHONPATH" not in child
    assert {k: v for k, v in child.items() if k.startswith("OTEL_")} == {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/agent-own",
        "OTEL_SERVICE_NAME": "agent",
    }
    assert stderr.getvalue() == ""
    record = _last(project)
    assert (record.runtime, record.capture) == ("node", "on")
    assert [f["id"] for f in record.findings] == ["FC-048"]  # only: no `fabric up` Node
    assert record.interpreter == str(tmp_path / "node-bin" / "node")


def test_node_options_is_appended_to_never_overwritten(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    own = "--max-old-space-size=512 --enable-source-maps"
    child, _, _ = _launch(project, {**env, "NODE_OPTIONS": own}, ["node", "a.js"])
    assert child["NODE_OPTIONS"] == f"{own} {PRELOAD}"
    # A NODE_OPTIONS that already loads the preload, in any spelling, is left as it is.
    for already in (
        PRELOAD,
        "--require=@singleaxis/fabric/register",
        "--trace-warnings -r @singleaxis/fabric/register",
        "--import @singleaxis/fabric/register --no-warnings",
    ):
        child, _, _ = _launch(project, {**env, "NODE_OPTIONS": already}, ["node", "a.js"])
        assert child["NODE_OPTIONS"] == already
    # A blank NODE_OPTIONS gets the entry alone.
    child, _, _ = _launch(project, {**env, "NODE_OPTIONS": "  "}, ["node", "a.js"])
    assert child["NODE_OPTIONS"] == PRELOAD


def _touch(path: Path) -> None:
    """A new modification time: the cached answer of the Node at ``path`` no longer holds."""
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 10**9))


def _unchanged(env: Mapping[str, str], child: Mapping[str, str]) -> None:
    """Spec 055 §13.1 "otherwise changes nothing": no preload, no autoload; only the
    explicit API's variables (the behaviour before the zero-code path)."""
    assert set(_added(env, child)) <= set(_run.NODE_VARIABLES)
    assert "NODE_OPTIONS" not in child and "FABRIC_WIRE_AUTOLOAD" not in child


def test_without_the_package_nothing_changes_and_the_install_line_is_said(
    tmp_path: Path, env: dict[str, str]
) -> None:
    project = make_project(tmp_path, env)
    child, stderr, probe = _launch(project, env, ["node", "a.js"], tty=True)
    _unchanged(env, child)
    said = stderr.getvalue()
    assert "FC-098" in said and "npm i @singleaxis/fabric" in said
    assert probe.calls == []  # the package decides first: Node is not even asked
    record = _last(project)
    assert record.capture == "off" and record.findings[0]["id"] == "FC-098"


@pytest.mark.parametrize(
    ("package", "why"),
    [
        ({"register": False, "qualification": table()}, "has no zero-code preload"),
        ({"register": True, "qualification": None}, "has no qualification table"),
        (
            {"register": True, "qualification": table(gates={"TS-1U": "passed"})},
            "gates TS-1D not passed",
        ),
        (
            {
                "register": True,
                "qualification": table(
                    gates={"TS-1U": "not_passed", "TS-1D": "not_passed"},
                ),
            },
            "gates TS-1U, TS-1D not passed",
        ),
        (
            {"register": True, "qualification": table([tuple_for(BUILD, "audited")])},
            "claims no Node.js build",
        ),
    ],
    ids=["no-preload", "no-table", "one-gate", "no-gates", "no-active-tuple"],
)
def test_an_unqualified_package_changes_nothing(
    tmp_path: Path, env: dict[str, str], package: dict[str, Any], why: str
) -> None:
    project = make_project(tmp_path, env)
    install_package(project, package["qualification"], register=package["register"])
    child, stderr, _ = _launch(project, env, ["node", "a.js"], tty=True)
    _unchanged(env, child)
    said = stderr.getvalue()
    assert "FC-099" in said and why in said and "npm i @singleaxis/fabric@latest" in said


@pytest.mark.parametrize(
    "exports",
    [
        None,  # the package's own exports, with the file removed
        {"default": "./dist/register.js"},
        {"import": "./dist/missing.js", "require": "./dist/register.cjs"},
        {"import": "../outside.js"},
        {"require": "./dist/register.cjs"},  # nothing an --import can resolve
    ],
    ids=["file-removed", "default-removed", "import-target-missing", "outside", "require-only"],
)
def test_a_preload_node_cannot_load_is_never_added(
    tmp_path: Path, env: dict[str, str], exports: dict[str, str] | None
) -> None:
    """I3: ``--import`` of a missing file stops Node before the agent's first line
    (ERR_MODULE_NOT_FOUND), so a partial install changes nothing and says why."""
    project = make_project(tmp_path, env)
    package = install_package(project, table())
    if exports is None:
        (package / "dist" / "register.js").unlink()
    else:
        (package / "dist" / "register.js").unlink()
        (project / "node_modules" / "@singleaxis" / "outside.js").write_text("")
        manifest = json.loads((package / "package.json").read_text())
        manifest["exports"]["./register"] = exports
        (package / "package.json").write_text(json.dumps(manifest))
    child, stderr, _ = _launch(project, env, ["node", "a.js"], tty=True)
    _unchanged(env, child)
    said = stderr.getvalue()
    assert "FC-099" in said and "preload file is missing" in said


def test_the_preload_follows_the_export_key_order_node_uses(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """Node's ESM resolver takes the first matching condition in the object's own key
    order: ``{"node": ..., "import": ...}`` loads the ``node`` file."""
    project = make_project(tmp_path, env)
    package = install_package(project, table())
    manifest = json.loads((package / "package.json").read_text())
    manifest["exports"]["./register"] = {"node": "./dist/register.cjs", "import": "./dist/x.js"}
    (package / "package.json").write_text(json.dumps(manifest))
    child, _, _ = _launch(project, env, ["node", "a.js"])
    assert child["NODE_OPTIONS"] == PRELOAD


def test_a_tuple_names_one_bundled_undici() -> None:
    """As the SDK's ``activeTuple``: the bundled undici must equal the tuple's; a tuple
    that names none never qualifies a Node that reports one."""
    no_undici = {k: v for k, v in tuple_for(BUILD).items() if k != "undici"}
    assert _node.build_decision(table([no_undici]), BUILD) is not None
    assert _node.build_decision(table([no_undici]), {**BUILD, "undici": None}) is None
    assert _node.build_decision(table(), BUILD) is None


def test_an_unqualified_node_build_changes_nothing_and_lists_the_qualified_ones(
    tmp_path: Path, env: dict[str, str]
) -> None:
    project = make_project(tmp_path, env)
    other = {**BUILD, "node": "24.30.0", "undici": "7.40.0"}
    install_package(project, table([tuple_for(BUILD), tuple_for(other, "audited")]))
    for build in (
        {**BUILD, "node": "22.23.5", "undici": "6.29.1"},  # below Node 24
        {**BUILD, "node": "24.0.0", "undici": "7.8.0"},
        other,  # audited, never active
        {**BUILD, "undici": "7.99.0"},  # a listed version with another bundled undici
    ):
        _touch(tmp_path / "node-bin" / "node")  # another Node at the same path
        child, stderr, _ = _launch(project, env, ["node", "a.js"], probe=NodeProbe(build), tty=True)
        _unchanged(env, child)
        said = stderr.getvalue()
        assert "FC-100" in said and f"Node {build['node']} on linux-x64-glibc" in said
        assert "qualified: Node 24.22.3 on linux-x64-glibc" in said
    # A Node that cannot be asked its version is not qualified either.
    _touch(tmp_path / "node-bin" / "node")
    child, stderr, _ = _launch(project, env, ["node", "a.js"], probe=NodeProbe(fail=True), tty=True)
    _unchanged(env, child)
    assert "FC-100" in stderr.getvalue() and "did not say its version" in stderr.getvalue()


def test_an_unsupported_platform_changes_nothing(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    child, stderr, _ = _launch(
        project, env, ["node", "a.js"], probe=NodeProbe({**BUILD, "platform": "darwin-arm64"}),
        tty=True,
    )  # fmt: skip
    _unchanged(env, child)
    said = stderr.getvalue()
    assert "FC-101" in said and "darwin-arm64" in said and "linux-x64-glibc" in said
    assert _last(project).findings[0]["id"] == "FC-101"


def test_node_not_on_path(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    bare = {**env, "PATH": str(tmp_path / "empty")}
    child, stderr, _ = _launch(project, bare, ["npx", "tsx", "a.ts"], tty=True)
    _unchanged(bare, child)
    assert "FC-100" in stderr.getvalue() and "node not found" in stderr.getvalue()


def test_the_package_resolves_from_a_parent_directory(tmp_path: Path, env: dict[str, str]) -> None:
    """Node resolves ``@singleaxis/fabric`` through ``node_modules`` up the tree, so an
    agent started from a subdirectory of its project is qualified the same way."""
    project = make_project(tmp_path, env)
    install_package(project, table())
    sub = project / "src" / "agents"
    sub.mkdir(parents=True)
    config = str(project / "fabric.yaml")
    child, _, _ = _launch(project, env, ["node", "a.js"], "--config", config, cwd=sub)
    assert child["NODE_OPTIONS"] == PRELOAD


def test_a_shell_that_turns_the_autoload_off_gets_no_preload(
    tmp_path: Path, env: dict[str, str]
) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    shell = {**env, "FABRIC_WIRE_AUTOLOAD": "0", "NODE_OPTIONS": "--no-warnings"}
    child, _, _ = _launch(project, shell, ["node", "a.js"])
    assert child["NODE_OPTIONS"] == "--no-warnings" and child["FABRIC_WIRE_AUTOLOAD"] == "0"
    assert _last(project).capture == "off"


def test_no_capture_changes_nothing_for_node(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    child, _, probe = _launch(project, env, ["node", "a.js"], "--no-capture")
    assert child == env and probe.calls == []


@pytest.mark.parametrize(
    "command",
    [["node", "a.js"], ["npx", "tsx", "a.ts"], ["tsx", "a.ts"], ["ts-node", "a.ts"],
     ["uv", "run", "node", "a.js"]],
    ids=" ".join,
)  # fmt: skip
def test_every_node_launcher_gets_the_preload(
    tmp_path: Path, env: dict[str, str], command: list[str]
) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    child, _, probe = _launch(project, env, command)
    assert child["NODE_OPTIONS"] == PRELOAD
    assert probe.calls[0][0] == str(tmp_path / "node-bin" / "node")


def test_a_script_with_a_node_shebang(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    pinned = fake_node(tmp_path / "pinned")
    on_path = tmp_path / "node-bin" / "node"
    for line, node in ((f"#!{pinned}", pinned), ("#!/usr/bin/env node", on_path)):
        script = project / "agent"
        script.write_text(f"{line}\nconsole.log('hi')\n")
        script.chmod(0o755)
        child, _, probe = _launch(project, env, [str(script)])
        assert child["NODE_OPTIONS"] == PRELOAD and probe.calls[0][0] == str(node)


def test_the_node_answer_is_cached_by_path_and_modification_time(
    tmp_path: Path, env: dict[str, str]
) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    probe = NodeProbe()
    for _ in range(3):
        _launch(project, env, ["node", "a.js"], probe=probe)
    assert len(probe.calls) == 1
    node = tmp_path / "node-bin" / "node"
    _touch(node)
    _launch(project, env, ["node", "a.js"], probe=probe)  # an upgraded Node is asked again
    assert len(probe.calls) == 2
    # A failed answer is never cached: installing a listed Node is the fix.
    failing = NodeProbe(fail=True)
    _touch(node)
    for _ in range(2):
        _launch(project, env, ["node", "a.js"], probe=failing)
    assert len(failing.calls) == 2


def test_the_node_path_fits_the_pre_exec_budget(tmp_path: Path, env: dict[str, str]) -> None:
    """058 §5.5: at most 150 ms before exec with a warm cache, for the Node.js branch too
    (package lookup, table, cached Node answer). Node is asked once, on the cold run."""
    project = make_project(tmp_path, env)
    install_package(project, table())
    probe = NodeProbe()
    _launch(project, env, ["node", "a.js"], probe=probe)  # warms the Node answer cache
    started = time.perf_counter()
    for _ in range(5):
        child, _, _ = _launch(project, env, ["node", "a.js"], probe=probe)
        assert child["NODE_OPTIONS"] == PRELOAD
    assert (time.perf_counter() - started) / 5 < 0.15
    assert len(probe.calls) == 1


def test_the_probe_never_inherits_the_agents_node_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NODE_OPTIONS", "--require=/agent/own/hook.js")
    probe = NodeProbe()
    _node.probe(tmp_path / "node", None, probe)
    seen: dict[str, Any] = {}

    def runner(argv: list[str], **kwargs: Any) -> Any:
        seen.update(kwargs)
        return probe(argv)

    _node.probe(tmp_path / "node", None, runner)
    assert "NODE_OPTIONS" not in seen["env"] and seen["stdin"] is not None


def test_append_and_detect_the_preload() -> None:
    assert _node.append_preload(None) == PRELOAD
    assert _node.append_preload("--inspect") == f"--inspect {PRELOAD}"
    assert _node.has_preload('--title "a b" --import=@singleaxis/fabric/register')
    assert not _node.has_preload("--import=@singleaxis/fabric/wire")
    assert not _node.has_preload("--import=./@singleaxis/fabric/register.js")
    assert not _node.has_preload('--title "unbalanced')


# ---------------------------------------------------------------- verify and doctor


def _record(runtime: str, capture: str, *ids: tuple[str, str]) -> _runstate.RunRecord:
    record = _runstate.RunRecord(label="r", started_ns=1, command="node", runtime=runtime)
    record.capture = capture
    record.findings = [{"id": i, "detail": d} for i, d in ids]
    return record


_RESOLVED = {"capture.exec": False, "capture.http_hosts": []}
_RUN = {"counts": {"exchanges": 2}, "chains": {"decisions": {"verdict": "complete"}}}


@pytest.mark.parametrize(
    ("record", "runs", "row"),
    [
        (_record("node", "on"), [_RUN], ("recorded", "2 exchange(s)")),
        (
            _record("node", "off", ("FC-098", "not found")),
            [],
            ("fix", "npm i @singleaxis/fabric in the agent's project (FC-098)"),
        ),
        (
            _record("node", "off", ("FC-099", "gates TS-1D not passed")),
            [],
            ("fix", "npm i @singleaxis/fabric@latest in the agent's project (FC-099)"),
        ),
        (
            _record("node", "off", ("FC-100", "Node 22.23.5 on linux-x64-glibc; qualified: x")),
            [],
            ("invisible",
             "unsupported_version: Node 22.23.5 on linux-x64-glibc; qualified: x (FC-100)"),
        ),
        (
            _record("node", "off", ("FC-101", "darwin-arm64; qualified: x")),
            [],
            ("invisible", "unsupported_runtime: darwin-arm64; qualified: x (FC-101)"),
        ),
        (_record("other", "off"), [], ("invisible", None)),
    ],
    ids=["recorded", "package-missing", "package-unqualified", "node-unqualified",
         "platform-unsupported", "other-runtime"],
)  # fmt: skip
def test_verify_states_the_node_model_call_row(
    record: _runstate.RunRecord, runs: list[dict[str, Any]], row: tuple[str, str | None]
) -> None:
    """058 §12, spec 055 §13.1: ``recorded`` for a qualified Node, ``fix`` when the preload
    could not be added, ``invisible`` with the reason when Node is not qualified."""
    (first, *_) = _read.coverage(_RESOLVED, record, runs, None)
    assert first.question == "model calls (requests and responses)"
    assert first.state == row[0]
    if row[1] is not None:
        assert first.note == row[1]
    else:
        assert first.note.startswith("unsupported_runtime:")


def test_doctor_never_asks_a_node_binary_for_the_python_sdk(
    tmp_path: Path, env: dict[str, str]
) -> None:
    project = make_project(tmp_path, env)
    install_package(project, table())
    _launch(project, env, ["node", "a.js"])
    assert _last(project).interpreter == str(tmp_path / "node-bin" / "node")
    loaded = _runstate.find_run(project / ".fabric", None)[0]
    assert loaded is not None and loaded.runtime == "node"

    def which(name: str, path: str | None = None) -> str | None:
        return "/usr/bin/python3" if name == "python3" else None

    located = _config.discover(None, env, project)
    found = _doctor.interpreter_for(_project.load(located, {}, env), env, which)
    assert found == Path("/usr/bin/python3")


def test_run_record_json_round_trips_a_node_run(tmp_path: Path, env: dict[str, str]) -> None:
    project = make_project(tmp_path, env)
    _launch(project, env, ["node", "a.js"])
    record = _last(project)
    text = json.loads(record.path.read_text()) if record.path else {}
    assert text["runtime"] == "node" and text["findings"][0]["id"] == "FC-098"


def test_verify_judges_a_captured_node_run_and_reads_its_chains_from_the_view() -> None:
    """A Node.js run with capture on is held to the reader's verdict like a Python run
    (never a pass without decisions); its 056 chains come from the reader's per-run view
    when the report entry has none (its manifests list no effect capture point)."""
    captured, bare = _record("node", "on"), _record("node", "off", ("FC-098", "x"))
    assert _verify._judged(captured) and not _verify._judged(bare)
    assert _verify._judged(_record("python", "off")) and not _verify._judged(_record("other", "on"))
    report_entry = {"run_id": "source:s-1:1", "verdict": "complete_for_declared_scope",
                    "counts": {"exchanges": 2}, "run_state": "terminated"}  # fmt: skip
    chains = {"decisions": {"verdict": "complete"}}
    view = SimpleNamespace(run_id="source:s-1:1", result=SimpleNamespace(chains=chains))
    (run,) = _verify.with_chains([report_entry], SimpleNamespace(runs=[view]))
    assert run["chains"] == chains and "chains" not in report_entry
    annotated = {**report_entry, "chains": {"decisions": {"verdict": "partial"}}}
    (kept,) = _verify.with_chains([annotated], SimpleNamespace(runs=[view]))
    assert kept["chains"] == annotated["chains"]  # the reader's own entry wins
    # Judged: no decisions recorded is a finding, for Node.js as for Python.
    (finding,) = _verify._judge([report_entry], captured)
    assert finding.id == "FC-068" and "decisions not observed" in (finding.detail or "")


def test_doctor_names_the_reason_and_fix_of_the_last_node_run(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """Spec 055 §13.1: `fabric doctor` repeats why the last Node.js run was not captured,
    with the catalogue fix (here: install the package)."""
    project = make_project(tmp_path, env)
    _launch(project, env, ["node", "a.js"], "--run", "n-2")
    report, lines = _doctor.run(
        parse(["doctor"]),
        env,
        project,
        node_ok=lambda *_: True,
        which=lambda name, path=None: None,
    )
    # Said once: the check of the project as it is now (its fix), not again for the run.
    (finding,) = [f for f in report.findings if f.id == "FC-098"]
    assert (finding.detail or "").startswith("now: ")
    assert "npm i @singleaxis/fabric" in (finding.detail or "")
    assert "npm i @singleaxis/fabric" in finding.entry["fix"]
    assert any("last run: n-2 (node, node), capture off" in line for line in lines)
    assert any("zero-code capture off" in line for line in lines)


def test_doctor_checks_a_node_project_with_the_rule_of_run_not_the_python_sdk(
    tmp_path: Path, env: dict[str, str]
) -> None:
    """A Node.js agent's SDK is ``@singleaxis/fabric``: doctor decides it as ``fabric run``
    does and never asks a Python interpreter for the Python SDK, whose install line would
    not help (spec 055 §13.1). A reason the last run had and the project no longer has is
    still repeated as the last run's."""
    project = make_project(tmp_path, env)
    _launch(project, env, ["node", "a.js"], "--run", "n-3")  # FC-098: no package yet
    install_package(project, table())
    probe = NodeProbe()
    report, lines = _doctor.run(
        parse(["doctor"]),
        env,
        project,
        runner=probe,
        node_ok=lambda *_: True,
        which=lambda name, path=None: None,
    )
    assert all(Path(argv[0]).name == "node" for argv in probe.calls), probe.calls
    assert not {f.id for f in report.findings} & {"FC-050", "FC-091"}  # the Python SDK checks
    assert any("qualifies Node 24.22.3 on linux-x64-glibc" in line for line in lines)
    (stale,) = [f for f in report.findings if f.id == "FC-098"]
    assert (stale.detail or "").startswith("last run n-3")
    # The same project with an unqualified Node: the current reason, with its fix.
    _touch(tmp_path / "node-bin" / "node")
    report, _ = _doctor.run(
        parse(["doctor"]),
        env,
        project,
        runner=NodeProbe({**BUILD, "node": "24.0.0"}),
        node_ok=lambda *_: True,
        which=lambda name, path=None: None,
    )
    (now,) = [f for f in report.findings if f.id == "FC-100"]
    assert (now.detail or "").startswith("now: Node 24.0.0 on linux-x64-glibc")


def test_verify_offers_no_python_only_fix_for_a_node_run() -> None:
    """``fabric init --exec`` and ``--http-host`` turn on Python hooks; for a Node.js run
    they change nothing, so those rows are ``invisible`` with the reason, and the run API
    named is the Node.js one."""
    rows = {r.question: r for r in _read.coverage(_RESOLVED, _record("node", "on"), [_RUN], None)}
    for question in ("commands the agent ran", "network contacts (non-model HTTP)"):
        assert rows[question].state == "invisible"
        assert rows[question].note.startswith("unsupported_runtime:")
        assert "fabric init" not in rows[question].note
    assert "@singleaxis/fabric/wire" in rows["end user and session"].note
    python = {
        r.question: r for r in _read.coverage(_RESOLVED, _record("python", "on"), [_RUN], None)
    }
    assert python["commands the agent ran"].note == "fabric init --exec"
    assert "fabric.wire.run" in python["end user and session"].note
