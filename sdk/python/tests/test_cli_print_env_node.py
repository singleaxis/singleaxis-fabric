# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric run --print-env`` for a Node.js command against the shared goldens (spec 055
§13.1, spec 058 §1.4): ``contracts/cli-config/v1/fixtures/print-env/node-v1.json``.

Each case gives the compiled environment (``.fabric/compiled.env``, what the npm launcher
reads), the installed package's state, this machine's Node build and the format; the
golden is the exact text and the finding ids. The npm launcher's ``run --print-env``
(058 WP8-9) must produce the same text from the same file. Regenerate after a deliberate
change with ``FABRIC_UPDATE_GOLDENS=1`` and review the diff."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from fabric.cli import _node, _run

from ._cli_node_support import BUILD, NodeProbe, fake_node, install_package, table, tuple_for
from ._cli_run_support import base_env, make_project
from ._cli_support import parse

REPO = Path(__file__).resolve().parents[3]
GOLDENS = REPO / "contracts" / "cli-config" / "v1" / "fixtures" / "print-env" / "node-v1.json"
UPDATE = os.environ.get("FABRIC_UPDATE_GOLDENS") == "1"
DOCUMENT: dict[str, Any] = json.loads(GOLDENS.read_text("utf-8"))


def _compiled(text: str) -> dict[str, str]:
    """``compiled.env`` as the launcher reads it: one KEY=value per line, the value is
    everything after the first ``=``; comments and blank lines skipped."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            name, _, value = line.partition("=")
            out[name] = value
    return out


def _package(project: Path, state: str) -> None:
    if state == "qualified":
        install_package(project, table())
    elif state == "gates-not-passed":
        install_package(project, table(gates={"TS-1U": "passed", "TS-1D": "not_passed"}))
    elif state == "no-preload":
        install_package(project, table(), register=False)
    elif state == "audited-only":
        install_package(project, table([tuple_for(BUILD, "audited")]))
    else:
        assert state == "absent", state


@pytest.mark.parametrize("case", DOCUMENT["cases"], ids=lambda c: c["name"])
def test_print_env_for_node_equals_the_shared_golden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: dict[str, Any]
) -> None:
    env = base_env(tmp_path)
    project = make_project(tmp_path, env)
    fake_node(tmp_path / "node-bin")
    env["PATH"] = f"{tmp_path / 'node-bin'}{os.pathsep}{env['PATH']}"
    _package(project, case["package"])
    compiled = _compiled(DOCUMENT["compiled_env"])
    real_load = _run._load_project

    def load(*args: Any) -> tuple[Any, dict[str, str]]:
        found, _ = real_load(*args)
        assert found.resolved["node.mode"] == DOCUMENT["node_mode"]
        return found, dict(compiled)

    monkeypatch.setattr(_run, "_load_project", load)
    options = parse(["run", "--print-env", *case["flags"], "--", *case["command"]])
    report, (text,) = _run.print_env(
        options, options.agent_command, env, project, runner=NodeProbe(case["node"])
    )
    ids = [f.id for f in report.findings if f.id != "FC-009"]
    if UPDATE:
        case["output"], case["finding_ids"] = text.splitlines(), ids
        GOLDENS.write_text(json.dumps(DOCUMENT, indent=2, ensure_ascii=False) + "\n", "utf-8")
        return
    assert text.splitlines() == case["output"]
    assert ids == case["finding_ids"]
    data = report.to_json()["data"]
    qualified = any(line.endswith("@singleaxis/fabric/register") or
                    "NODE_OPTIONS" in line for line in case["output"])  # fmt: skip
    assert data["runtime"] == "node"
    assert data["node_options_append"] == (_node.PRELOAD if qualified else None)
    assert "OTEL_" not in text


def test_the_goldens_cover_every_format_and_every_reason() -> None:
    cases = DOCUMENT["cases"]
    qualified = {c["format"] for c in cases if not c["finding_ids"]}
    assert qualified == set(_run.FORMATS)
    reasons = {i for c in cases for i in c["finding_ids"]}
    assert reasons >= {"FC-098", "FC-099", "FC-100", "FC-101"}
    # docker and k8s describe a container, whose Node is the image's: this machine's
    # unqualified Node or platform does not decide them, a note names the builds.
    for case in cases:
        if case["format"] in ("docker", "k8s"):
            assert not set(case["finding_ids"]) & {"FC-100", "FC-101"}, case["name"]


def test_the_golden_sh_appends_through_a_real_shell(tmp_path: Path) -> None:
    """The ``sh`` golden keeps a NODE_OPTIONS the launcher already sets (I2)."""
    import subprocess  # noqa: PLC0415

    (case,) = [c for c in DOCUMENT["cases"] if c["name"] == "qualified-sh"]
    script = "\n".join(case["output"]) + '\nprintf %s "$NODE_OPTIONS"'
    preload = "--import=@singleaxis/fabric/register"
    for before, after in (("", preload), ("--inspect=0", f"--inspect=0 {preload}")):
        environ = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if before:
            environ["NODE_OPTIONS"] = before
        shown = subprocess.run(  # noqa: S603
            ["sh", "-c", script],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            env=environ,
        ).stdout
        assert shown == after


def test_the_goldens_are_pinned_in_the_contract_manifest() -> None:
    import hashlib  # noqa: PLC0415

    manifest = json.loads((GOLDENS.parents[2] / "manifest.json").read_text("utf-8"))
    pins = {f["path"]: f["sha256"] for f in manifest["files"]}
    assert (
        pins["fixtures/print-env/node-v1.json"] == hashlib.sha256(GOLDENS.read_bytes()).hexdigest()
    )
