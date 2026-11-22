# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""G8 and I2/I3 (spec 058 §3.2, §4.1) for a Node.js agent (spec 055 §13.1), with real
processes and a real ``node``.

For a qualified package and Node, the same with the agent's own ``NODE_OPTIONS``, no
package, a Node build the package does not qualify, a broken configuration and no
configuration, the agent started by ``fabric run -- node child.cjs`` has the same argv,
stdin, stdout, stderr (not a terminal), exit code and working directory as a bare run and
the PID ``fabric run`` started with (``exec``). Its environment differs only by
``FABRIC_*`` variables and, when qualified, the preload appended to ``NODE_OPTIONS``: what
the agent set there is kept, first and unchanged. No ``OTEL_*`` variable changes. A
package whose preload file is missing (a partial install, which a bare ``--import``
would turn into ``ERR_MODULE_NOT_FOUND`` before the agent's first line) gets no preload. The
installed package here carries an inert preload: this checks the launcher, and the
preload's own passivity is spec 055's ``ts-wire-passivity`` gate."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric.cli import _node, _run

from ._cli_node_support import install_package, table, tuple_for
from ._cli_run_support import base_env, make_project

NODE = shutil.which("node")
pytestmark = [
    pytest.mark.skipif(os.name != "posix", reason="exec semantics are POSIX"),
    pytest.mark.skipif(NODE is None, reason="needs node on PATH"),
]
STDIN = b"the agent's own input\n\x00\xff"
PRELOAD = "--import=@singleaxis/fabric/register"
CASES = (
    "qualified",
    "qualified-own-node-options",
    "package-absent",
    "node-unqualified",
    "preload-file-missing",
    "broken-config",
    "missing-config",
)
#: The G8 child for Node: prints its argv and the digest of its stdin, writes a fixed line
#: on stderr, dumps its environment, working directory and pid to argv[2], exits 7.
CHILD = """
const fs = require("node:fs"), crypto = require("node:crypto");
const data = fs.readFileSync(0);
process.stdout.write(JSON.stringify({argv: process.argv.slice(2),
  stdin: crypto.createHash("sha256").update(data).digest("hex")}) + "\\n");
process.stderr.write("child stderr line\\n");
fs.writeFileSync(process.argv[2], JSON.stringify({env: process.env, cwd: process.cwd(),
  pid: process.pid}));
process.exitCode = 7;
"""


def _this_build() -> dict[str, Any]:
    assert NODE is not None
    answer = _node.probe(Path(NODE), None)
    assert "error" not in answer, answer
    return {k: answer[k] for k in ("node", "undici", "platform")}


@pytest.fixture
def world(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[dict[str, Any]]:
    case: str = request.param
    env = {
        **base_env(tmp_path),
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/agent-own-collector",
        "OTEL_SERVICE_NAME": "agent-own-service",
        "AGENT_SETTING": "kept",
    }
    if case == "qualified-own-node-options":
        env["NODE_OPTIONS"] = "--no-warnings --max-old-space-size=256"
    if case in ("broken-config", "missing-config"):
        project = tmp_path / "agent-project"
        project.mkdir()
        if case == "broken-config":
            (project / "fabric.yaml").write_text("schema: fabric.config/v1\nnode: [not, a, map\n")
    else:
        project = make_project(tmp_path, env)
    build = _this_build()
    if case.startswith("qualified") or case in ("broken-config", "missing-config"):
        install_package(project, table([tuple_for(build)]))
    elif case == "node-unqualified":
        install_package(project, table([tuple_for({**build, "node": "24.999.0"})]))
    elif case == "preload-file-missing":  # a partial install: Node could not load it
        package = install_package(project, table([tuple_for(build)]))
        (package / "dist" / "register.js").unlink()
    (project / "child.cjs").write_text(CHILD)
    yield {"case": case, "env": env, "project": project, "dump": tmp_path / "dump.json"}


def _run_it(
    argv: list[str], world: dict[str, Any]
) -> tuple[subprocess.CompletedProcess[bytes], int, dict[str, Any]]:
    process = subprocess.Popen(  # noqa: S603
        argv,
        cwd=world["project"],
        env=world["env"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate(STDIN, timeout=120)
    done = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    dump = json.loads(world["dump"].read_text())
    world["dump"].unlink()
    return done, process.pid, dump


@pytest.mark.parametrize("world", CASES, indirect=True)
def test_a_node_agent_sees_a_bare_run_but_for_fabric_variables(world: dict[str, Any]) -> None:
    assert NODE is not None
    agent = [NODE, "child.cjs", str(world["dump"]), "--an", "arg with space"]
    bare, _, bare_dump = _run_it(agent, world)
    fabric = [sys.executable, "-m", "fabric.cli", "run", "--", *agent]
    run, pid, run_dump = _run_it(fabric, world)
    assert (run.returncode, run.stdout, run.stderr) == (bare.returncode, bare.stdout, bare.stderr)
    assert bare.returncode == 7 and b"child stderr line" in bare.stderr
    assert run_dump["pid"] == pid, "fabric run must exec the agent, not start a child"
    assert run_dump["cwd"] == bare_dump["cwd"]
    before, after = bare_dump["env"], run_dump["env"]
    assert set(before) <= set(after), "a variable was removed"
    changed = {k for k in after if before.get(k) != after[k]}
    assert {k for k in changed if not k.startswith("FABRIC_")} <= {"NODE_OPTIONS"}
    assert {k: v for k, v in after.items() if k.startswith("OTEL_")} == {
        k: v for k, v in before.items() if k.startswith("OTEL_")
    }
    case = world["case"]
    if case.startswith("qualified"):
        assert after["FABRIC_WIRE_AUTOLOAD"] == "1"
        own = before.get("NODE_OPTIONS")
        assert after["NODE_OPTIONS"] == (f"{own} {PRELOAD}" if own else PRELOAD)
    elif case in ("package-absent", "node-unqualified", "preload-file-missing"):
        # spec 055 §13.1: no preload, no autoload; the explicit API's settings only
        assert changed <= set(_run.NODE_VARIABLES)
    else:  # I3: a configuration problem leaves the environment exactly as it was
        assert after == before


def test_fabric_run_for_node_opens_no_socket_and_resolves_no_name(tmp_path: Path) -> None:
    """I2 on the Node path: the package lookup and the Node probe (a child process) open
    no socket in the ``fabric run`` process before exec."""
    assert NODE is not None
    env = base_env(tmp_path)
    project = make_project(tmp_path, env)
    install_package(project, table([tuple_for(_this_build())]))
    log = tmp_path / "socket-events.log"
    driver = (
        "import sys\n"
        f"LOG = {str(log)!r}\n"
        "def hook(event, args):\n"
        "    if event.startswith('socket.'):\n"
        "        with open(LOG, 'a') as handle:\n"
        "            handle.write(event + '\\n')\n"
        "sys.addaudithook(hook)\n"
        "from fabric.cli import main\n"
        "raise SystemExit(main(sys.argv[1:]))\n"
    )
    script = "process.stdout.write(process.env.NODE_OPTIONS || '')"
    for _ in range(2):  # cold and warm Node probe cache
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", driver, "run", "--", NODE, "-e", script],
            cwd=project,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0 and result.stdout == PRELOAD, result.stderr
    assert not log.exists() or log.read_text() == ""
