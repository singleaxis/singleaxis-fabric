# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the ``fabric`` CLI tests (spec 058 WP8-2, WP8-3): a recording fake
of the ``docker`` command and a project fixture with a private state home."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from fabric import cli
from fabric.cli._docker import Docker, Result

DOCKER_DESKTOP = {
    "OperatingSystem": "Docker Desktop",
    "KernelVersion": "6.12.76-linuxkit",
    "CgroupVersion": "2",
    "SecurityOptions": ["name=seccomp,profile=builtin"],
}
LINUX_ENGINE = {
    "OperatingSystem": "Ubuntu 24.04.1 LTS",
    "KernelVersion": "6.8.0-45-generic",
    "CgroupVersion": "2",
    "SecurityOptions": ["name=apparmor", "name=seccomp"],
}


@dataclass
class FakeDocker:
    """Records every ``docker`` invocation; answers ``info``, ``compose version`` and the
    Compose subcommands ``fabric`` runs. ``fail`` maps a Compose subcommand (or ``info``,
    ``run``) to the result it returns instead of success."""

    info: Mapping[str, Any] = field(default_factory=lambda: dict(DOCKER_DESKTOP))
    fail: dict[str, Result] = field(default_factory=dict)
    running: set[str] = field(default_factory=lambda: {"fabric-sensor"})
    calls: list[list[str]] = field(default_factory=list)
    #: `docker ps` rows of the Compose project: (container name, project-dir label).
    containers: list[tuple[str, str]] = field(default_factory=list)

    def __call__(  # noqa: PLR0911 - one return per docker subcommand
        self, argv: Sequence[str], environ: Mapping[str, str] | None, echo: IO[str] | None
    ) -> Result:
        args = list(argv[1:])
        self.calls.append(args)
        if args[:2] == ["compose", "version"]:
            return self.fail.get("version", Result(0, "Docker Compose version v2.29.0\n", ""))
        if args[0] == "info":
            return self.fail.get("info", Result(0, json.dumps(self.info), ""))
        if args[0] == "ps":
            rows = "".join(f"{name}\t{directory}\n" for name, directory in self.containers)
            return self.fail.get("docker-ps", Result(0, rows, ""))
        if args[0] == "run":
            return self.fail.get("run", Result(0, "", ""))
        assert args[0] == "compose", args
        command = next(a for a in args[1:] if a in ("up", "down", "ps", "logs"))
        if command in self.fail:
            return self.fail[command]
        if command == "ps":
            service = args[-1]
            return Result(0, json.dumps({"Service": service}) if service in self.running else "",
                          "")  # fmt: skip
        if command == "logs":
            return Result(0, "last log line of the service\n", "")
        return Result(0, "", "")

    def client(self, environ: Mapping[str, str] | None = None) -> Docker:
        return Docker(environ or {}, runner=self, which=lambda _name: "/usr/bin/docker")

    def compose_calls(self, command: str) -> list[list[str]]:
        return [call for call in self.calls if call[0] == "compose" and command in call]


def parse(args: list[str]) -> Any:
    """The options ``fabric ARGS`` parses to."""
    return cli.build_parser().parse_args(args)


def secret_values(directory: Path) -> list[bytes]:
    """Byte strings that must never appear in any output or rendered file: the id key and
    the base64 body lines of every private key."""
    values: list[bytes] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.suffix == ".crt":
            continue
        data = path.read_bytes()
        if b"PRIVATE KEY" in data:
            values.extend(line for line in data.splitlines()
                          if line and not line.startswith(b"-----"))  # fmt: skip
        else:
            values.append(data.strip())
    assert values, "no secret was generated"
    return values


def mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o777
