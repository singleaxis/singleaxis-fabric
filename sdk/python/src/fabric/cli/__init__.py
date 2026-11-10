# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric``: the operator CLI (spec 058 §5) that plans, configures, starts, launches capture
for and verifies the recorder on the customer's own infrastructure.

The CLI runs outside the agent. Autoload never imports this package, and nothing here is
imported by the capture path (a test pins both). It has no fleet management, no rollout
and no phone-home: no command opens a network connection the operator did not ask for.

Commands (the I1 allowlist; additions need a spec change): ``plan``, ``init``, ``up``,
``down``, ``run``, ``verify``, ``doctor``, ``show``, ``version``, ``help``. This release
builds ``version`` and ``help``; the others say so and point at the manual route.

Exit codes: 0 success; 1 a check did not pass; 2 usage or configuration error; 3 a
prerequisite is missing. ``fabric run`` exits with the agent's exit code."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from typing import NoReturn

from .._version import __version__
from . import _config, _providers
from ._report import (
    EXIT_OK,
    EXIT_USAGE,
    CliError,
    Finding,
    Report,
    emit,
)

#: The commands of spec 058 §5.1 (I1). Nothing else ships.
COMMANDS: tuple[str, ...] = (
    "plan", "init", "up", "down", "run", "verify", "doctor", "show", "version", "help",
)  # fmt: skip
#: The commands this release builds; the rest of COMMANDS report FC-010.
BUILT: frozenset[str] = frozenset({"version", "help"})
_SUMMARIES = {
    "plan": "predict what Fabric would record for this project",
    "init": "write fabric.yaml, generated secrets and the compiled environment",
    "up": "start the local Fabric Node and destination",
    "down": "stop what `fabric up` started",
    "run": "run an agent command with capture on",
    "verify": "check that a recorded run reached the destination intact",
    "doctor": "check this machine and project for setup problems",
    "show": "show recorded runs",
    "version": "print the CLI, SDK and endpoint-table versions",
    "help": "show this help",
}


class _Parser(argparse.ArgumentParser):
    """argparse with usage errors as ``FC-006`` findings (exit 2), never a traceback."""

    commands: dict[str, argparse.ArgumentParser]

    def error(self, message: str) -> NoReturn:
        raise CliError([Finding("FC-006", message)])


def _common(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("options on every command")
    group.add_argument("--config", metavar="PATH", help="fabric.yaml to use (default: discovered)")
    group.add_argument("--project", metavar="NAME", help="project name (default: directory name)")
    group.add_argument("--json", action="store_true", help="print the fabric.cli-report/v1 JSON")
    group.add_argument("--quiet", action="store_true", help="print errors only")
    group.add_argument("--no-color", action="store_true", help="never color the output")


def build_parser() -> _Parser:
    parser = _Parser(prog="fabric", description=__doc__.split("\n\n")[0] if __doc__ else None,
                     add_help=False)  # fmt: skip
    parser.add_argument("-h", "--help", action="store_true", help="show this help")
    parser.add_argument("--version", action="store_true", help="print the version")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_Parser)
    parser.commands = {}
    for name in COMMANDS:
        sub = commands.add_parser(name, help=_SUMMARIES[name], add_help=True)
        _common(sub)
        if name == "help":
            sub.add_argument("topic", nargs="?", choices=COMMANDS, help="a command")
        parser.commands[name] = sub
    return parser


def _version(options: argparse.Namespace) -> tuple[Report, list[str]]:
    """``fabric version``: versions, and the ``fabric.yaml`` the other commands would use."""
    located = _config.discover(options.config, os.environ)
    report = Report("version", config=located.to_json())
    report.data = {
        "cli_version": __version__, "sdk_version": __version__,
        "endpoint_table_version": _providers.table_version(),
        "builtin_endpoints": [m.endpoint_id for m in _providers.builtin()],
    }  # fmt: skip
    lines = [f"fabric {__version__} (singleaxis-fabric {__version__})",
             f"endpoint table version {_providers.table_version()}: "
             + ", ".join(report.data["builtin_endpoints"])]  # fmt: skip
    if located.path is None:
        lines.append("config: no fabric.yaml found")
        return report, lines
    try:
        document = _config.load(located)
    except CliError as exc:
        report.findings.extend(exc.findings)  # informational: version itself succeeded
        lines.append(f"config: {located.path} ({located.source}; not usable)")
        return report, lines
    resolved = _config.resolve(document, {"project": options.project}, os.environ,
                               _config.project_dir(located))  # fmt: skip
    report.findings.extend(_config.override_findings(resolved))
    report.data["project"] = resolved["project"]
    report.data["profile"] = resolved["profile"]
    lines.append(f"config: {located.path} ({located.source}); project {resolved['project']}, "
                 f"profile {resolved['profile']}")  # fmt: skip
    return report, lines


def _help(parser: _Parser, topic: str | None) -> str:
    if topic and topic != "help":
        return parser.commands[topic].format_help()
    lines = ["usage: fabric COMMAND [options]", "", "commands:"]
    lines += [f"  {name:<8} {_SUMMARIES[name]}" + ("" if name in BUILT else " (not built yet)")
              for name in COMMANDS]  # fmt: skip
    lines += ["", "options on every command: --config PATH, --project NAME, --json, --quiet, "
              "--no-color", "exit codes: 0 ok, 1 a check did not pass, 2 usage or configuration "
              "error, 3 a prerequisite is missing", "",
              "Run `fabric COMMAND --help` for a command's options."]  # fmt: skip
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the ``fabric`` and ``singleaxis-fabric`` console scripts."""
    args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    as_json = "--json" in args
    try:
        options = parser.parse_args(args)
    except CliError as exc:
        return emit(Report("fabric", findings=exc.findings, exit_code=exc.exit_code), [],
                    as_json=as_json, quiet=False)  # fmt: skip
    except SystemExit as exc:  # --help on a command
        return EXIT_OK if exc.code in (0, None) else EXIT_USAGE
    if options.version:
        sys.stdout.write(f"fabric {__version__}\n")
        return EXIT_OK
    command = options.command
    if command is None or options.help or command == "help":
        sys.stdout.write(_help(parser, getattr(options, "topic", None)) + "\n")
        return EXIT_OK
    handlers: dict[str, Callable[[argparse.Namespace], tuple[Report, list[str]]]] = {
        "version": _version,
    }
    try:
        if command not in BUILT:
            raise CliError([Finding("FC-010", f"fabric {command}")])
        report, lines = handlers[command](options)
    except CliError as exc:
        report = Report(command, findings=exc.findings, exit_code=exc.exit_code)
        lines = []
    return emit(report, lines, as_json=options.json, quiet=options.quiet)
