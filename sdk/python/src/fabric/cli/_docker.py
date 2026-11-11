# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The local Docker daemon, driven through the ``docker`` command (spec 058 §5.4).

``fabric up`` and ``fabric down`` act once, when invoked, on the local daemon and on one
Compose project that is always named ``fabric-<project>`` (I5): no other project,
container or workload is ever stopped, removed or restarted. Secrets never appear on a
command line; containers get file paths. The CLI opens no socket to Docker itself."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from ._report import EXIT_PREREQUISITE, CliError, Finding

#: The only Compose subcommands this CLI runs (a test pins it, I5).
COMPOSE_COMMANDS = frozenset({"up", "down", "ps", "logs", "version"})


@dataclass(frozen=True)
class Result:
    code: int
    stdout: str
    stderr: str

    def tail(self, lines: int = 3) -> str:
        """Docker's own last lines (local output only)."""
        text = (self.stderr.strip() or self.stdout.strip()).splitlines()
        return " | ".join(line.strip() for line in text[-lines:] if line.strip())[:600]


Runner = Callable[[Sequence[str], Mapping[str, str] | None, IO[str] | None], Result]


def _run(argv: Sequence[str], environ: Mapping[str, str] | None, echo: IO[str] | None) -> Result:
    """Run ``argv``; ``echo``: also copy its stderr there as it arrives (pull progress)."""
    process = subprocess.Popen(  # noqa: S603 - argv is built here, never from a shell string
        list(argv), env=dict(environ) if environ is not None else None,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        errors="replace",
    )  # fmt: skip
    collected: list[str] = []

    def pump() -> None:
        assert process.stderr is not None  # noqa: S101
        for line in process.stderr:
            collected.append(line)
            if echo is not None:
                echo.write(line)
                echo.flush()

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    assert process.stdout is not None  # noqa: S101
    stdout = process.stdout.read()
    code = process.wait()
    reader.join(timeout=5)
    return Result(code, stdout, "".join(collected))


class Docker:
    """``docker`` and ``docker compose`` for one Compose project."""

    def __init__(self, environ: Mapping[str, str], *, runner: Runner | None = None,
                 which: Callable[[str], str | None] = shutil.which,
                 echo: IO[str] | None = None) -> None:  # fmt: skip
        self._environ = environ
        self._runner = runner or _run
        self._which = which
        self._echo = echo
        self._binary: str | None = None

    def _docker(self) -> str:
        if self._binary is None:
            found = self._which("docker")
            if not found:
                raise CliError([Finding("FC-019", "docker was not found on PATH")],
                               EXIT_PREREQUISITE)  # fmt: skip
            self._binary = found
        return self._binary

    def run(self, *args: str, echo: bool = False) -> Result:
        return self._runner([self._docker(), *args], self._environ,
                            self._echo if echo else None)  # fmt: skip

    def require(self) -> dict[str, Any]:
        """Docker with Compose v2 and a daemon that answers, or ``FC-019``/``FC-020``
        (exit 3). Returns ``docker info``."""
        if self.run("compose", "version").code != 0:
            raise CliError([Finding("FC-019", "`docker compose version` failed: the Compose v2 "
                                    "plugin is missing")], EXIT_PREREQUISITE)  # fmt: skip
        info = self.run("info", "--format", "{{json .}}")
        if info.code != 0:
            raise CliError([Finding("FC-020", info.tail(1) or "docker info failed")],
                           EXIT_PREREQUISITE)  # fmt: skip
        try:
            parsed = json.loads(info.stdout)
        except json.JSONDecodeError:
            parsed = {}
        return parsed if isinstance(parsed, dict) else {}

    def compose(self, project: str, file: Path | None, command: str, *args: str,
                echo: bool = False) -> Result:  # fmt: skip
        """One Compose subcommand on this project (and no other)."""
        if command not in COMPOSE_COMMANDS:
            raise ValueError(f"compose {command} is not a command fabric runs")
        argv = ["compose", "-p", project]
        if file is not None:
            argv += ["-f", str(file)]
        return self.run(*argv, command, *args, echo=echo)


def interactive_echo(as_json: bool, quiet: bool) -> IO[str] | None:
    """Where Docker's progress goes: the terminal, when a person is watching."""
    if as_json or quiet or not sys.stderr.isatty():
        return None
    return sys.stderr
