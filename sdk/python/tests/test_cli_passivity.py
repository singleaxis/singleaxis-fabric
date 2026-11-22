# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""G8 and I2/I3 (spec 058 §3.2, §4.1): ``fabric run`` is passive, with real processes.

For a valid configuration with the Node up, the Node down, a broken configuration, no
configuration, and an interpreter without the SDK, the agent started by ``fabric run``
has the same argv, stdin, stdout, stderr (not a terminal), exit code and working
directory as a bare run, the PID ``fabric run`` started with (``exec``), and an
environment that differs only by ``FABRIC_*`` variables and the autoload directory first
on ``PYTHONPATH``; no ``OTEL_*`` variable changes. ``fabric run`` itself opens no socket
and resolves no name."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ._cli_run_support import CHILD, FakeNode, base_env, free_port, make_project, secrets_dir

pytestmark = pytest.mark.skipif(os.name != "posix", reason="exec semantics are POSIX")
STDIN = b"the agent's own input\n\x00\xff"
CASES = ("valid-node-up", "node-down", "broken-config", "missing-config", "sdk-missing")


@pytest.fixture
def world(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[dict[str, Any]]:
    case: str = request.param
    env = {
        **base_env(tmp_path),
        "PYTHONPATH": str(tmp_path / "agent-own-path"),
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9/agent-own-collector",
        "OTEL_SERVICE_NAME": "agent-own-service",
        "AGENT_SETTING": "kept",
    }
    port = free_port()
    node = None
    python = sys.executable
    if case in ("valid-node-up", "node-down", "sdk-missing"):
        project = make_project(tmp_path, env, port=port)
        if case == "valid-node-up":
            node = FakeNode(secrets_dir(env), port)
        if case == "sdk-missing":
            venv = tmp_path / "bare-venv"
            subprocess.run(  # noqa: S603
                [sys.executable, "-m", "venv", "--without-pip", str(venv)],
                check=True,
                capture_output=True,
            )
            python = str(venv / "bin" / "python")
    else:
        project = tmp_path / "agent-project"
        project.mkdir()
        if case == "broken-config":
            (project / "fabric.yaml").write_text("schema: fabric.config/v1\nnode: [not, a, map\n")
    child = tmp_path / "child.py"
    child.write_text(CHILD)
    try:
        yield {
            "case": case,
            "env": env,
            "project": project,
            "python": python,
            "child": child,
            "dump": tmp_path / "dump.json",
        }
    finally:
        if node is not None:
            node.close()


def _run(
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
def test_the_agent_sees_a_bare_run_but_for_fabric_variables(world: dict[str, Any]) -> None:
    agent = [world["python"], str(world["child"]), str(world["dump"]), "--an", "arg with space"]
    bare, _, bare_dump = _run(agent, world)
    fabric = [sys.executable, "-m", "fabric.cli", "run", "--", *agent]
    run, pid, run_dump = _run(fabric, world)
    assert (run.returncode, run.stdout, run.stderr) == (bare.returncode, bare.stdout, bare.stderr)
    assert bare.returncode == 7 and b"child stderr line" in bare.stderr
    assert run_dump["pid"] == pid, "fabric run must exec the agent, not start a child"
    assert run_dump["cwd"] == bare_dump["cwd"]
    before, after = bare_dump["env"], run_dump["env"]
    assert set(before) <= set(after), "a variable was removed"
    changed = {k for k in after if before.get(k) != after[k]}
    assert {k for k in changed if not k.startswith("FABRIC_")} <= {"PYTHONPATH"}
    assert {k: v for k, v in after.items() if k.startswith("OTEL_")} == {
        k: v for k, v in before.items() if k.startswith("OTEL_")
    }
    capturing = world["case"] in ("valid-node-up", "node-down")
    if capturing:
        assert after["FABRIC_WIRE_AUTOLOAD"] == "1"
        assert after["PYTHONPATH"].endswith(os.pathsep + before["PYTHONPATH"])
    else:  # I3: any problem before exec leaves the environment exactly as it was
        assert after == before


@pytest.mark.parametrize("flags", [[], ["--no-such-flag"]], ids=["run", "mistyped-flag"])
def test_the_agent_gets_the_signal_dispositions_of_a_bare_run(
    tmp_path: Path, flags: list[str]
) -> None:
    """Python ignores SIGPIPE (and SIGXFSZ) at start-up and an ignored signal survives
    exec: the agent must still get the default, or a pipeline in it no longer stops on a
    closed pipe. A shell cannot reset a signal ignored on entry, so `kill -PIPE $$` shows
    the disposition it was given."""
    env = base_env(tmp_path)
    project = make_project(tmp_path, env)
    agent = ["sh", "-c", "kill -PIPE $$; kill -XFSZ $$; echo survived"]
    bare = subprocess.run(  # noqa: S603 - Popen restores the default dispositions
        agent, cwd=project, env=env, capture_output=True, timeout=60, check=False
    )
    run = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.cli", "run", *flags, "--", *agent],
        cwd=project,
        env=env,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert bare.returncode != 0 and bare.stdout == b""
    assert (run.returncode, run.stdout, run.stderr) == (bare.returncode, bare.stdout, bare.stderr)


def test_fabric_run_opens_no_socket_and_resolves_no_name(tmp_path: Path) -> None:
    """I2: every socket event of the `fabric run` process before exec is recorded (the
    hook dies with the process image at exec)."""
    env = base_env(tmp_path)
    project = make_project(tmp_path, env)
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
    for _ in range(2):  # cold and warm interpreter cache
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", driver, "run", "--", sys.executable, "-c", "print('agent ran')"],
            cwd=project,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0 and result.stdout == "agent ran\n", result.stderr
    assert not log.exists() or log.read_text() == ""


@pytest.mark.parametrize(
    "locale_env",
    [{}, {"LC_CTYPE": "UTF-8"}, {"LANG": "C"}, {"LC_ALL": "C.UTF-8"}],
    ids=["no-locale", "ctype-set", "lang-c", "lc-all"],
)
def test_the_agent_gets_no_locale_variable_python_added_for_itself(
    tmp_path: Path, locale_env: dict[str, str]
) -> None:
    """I2: a Python started in the C locale sets LC_CTYPE for itself (PEP 538) before
    `fabric` runs; exec must not hand that to the agent. A Python agent coerces its own
    locale and hides it, so the agent here is `env`, as any non-Python program is."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path / "home"),
        **locale_env,
    }
    agent = ["env"]
    bare = subprocess.run(  # noqa: S603
        agent, cwd=tmp_path, env=env, capture_output=True, timeout=60, check=True
    )
    run = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.cli", "run", "--", *agent],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=120,
        check=True,
    )
    # macOS CoreFoundation writes __CF_USER_TEXT_ENCODING into any process that loads it
    # (every login session already has it); it is the system's, not Fabric's.
    system = (b"__CF_USER_TEXT_ENCODING=",)
    seen = sorted(line for line in run.stdout.splitlines() if not line.startswith(system))
    assert seen == sorted(line for line in bare.stdout.splitlines() if not line.startswith(system))


def test_startup_environ_undoes_only_pythons_own_coercion() -> None:
    from fabric.cli._run import startup_environ  # noqa: PLC0415

    def nothing(_: str) -> str | None:
        return None

    def unreadable(_: str) -> str | None:
        raise OSError("no /proc here")

    coerced = {"PATH": "/bin", "LC_CTYPE": "C.UTF-8"}
    # Linux: the start-up block decides exactly.
    assert startup_environ(coerced, initial=nothing) == {"PATH": "/bin"}
    assert startup_environ(coerced, initial=lambda _: "C") == {"PATH": "/bin", "LC_CTYPE": "C"}
    assert startup_environ(coerced, initial=lambda _: "C.UTF-8") == coerced
    # Elsewhere: UTF-8 mode that nothing else turned on shows the C start-up locale.
    assert startup_environ(coerced, utf8_mode=1, xoptions={}, initial=unreadable) == {
        "PATH": "/bin"
    }
    assert startup_environ(
        {**coerced, "LANG": "en_US.UTF-8"}, utf8_mode=1, xoptions={}, initial=unreadable
    ) == {"PATH": "/bin", "LANG": "en_US.UTF-8", "LC_CTYPE": "C"}
    for kept in (
        startup_environ(coerced, utf8_mode=0, xoptions={}, initial=unreadable),
        startup_environ({**coerced, "PYTHONUTF8": "1"}, utf8_mode=1, xoptions={},
                        initial=unreadable),
        startup_environ(coerced, utf8_mode=1, xoptions={"utf8": True}, initial=unreadable),
        startup_environ({**coerced, "PYTHONCOERCECLOCALE": "0"}, initial=nothing),
        # PEP 538: a non-empty LC_ALL turns the coercion off, while its C locale still
        # turns UTF-8 mode on (PEP 540): the LC_CTYPE is the shell's own.
        startup_environ({**coerced, "LC_ALL": "C"}, utf8_mode=1, xoptions={},
                        initial=unreadable),
    ):  # fmt: skip
        assert kept["LC_CTYPE"] == "C.UTF-8"
    other = {"PATH": "/bin", "LC_CTYPE": "en_US.UTF-8"}
    assert startup_environ(other, initial=nothing) == other
