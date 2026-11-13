# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric``: the operator CLI (spec 058 §5) that plans, configures, starts, launches capture
for and verifies the recorder on the customer's own infrastructure.

The CLI runs outside the agent. Autoload never imports this package, and nothing here is
imported by the capture path (a test pins both). It has no fleet management, no rollout
and no phone-home: no command opens a network connection the operator did not ask for.

Commands (the I1 allowlist; additions need a spec change): ``plan``, ``init``, ``up``,
``down``, ``run``, ``verify``, ``doctor``, ``show``, ``version``, ``help``. This release
builds ``init``, ``up``, ``down``, ``run``, ``verify``, ``doctor`` and ``show`` for the local
profile, ``version`` and ``help``; ``plan`` says so and points at the manual route.

Exit codes: 0 success; 1 a check did not pass; 2 usage or configuration error; 3 a
prerequisite is missing. ``fabric run`` exits with the agent's exit code."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from typing import NoReturn

from .._version import __version__
from . import _args, _config, _images, _init, _providers, _run, _up
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
BUILT: frozenset[str] = frozenset({
    "init", "up", "down", "run", "verify", "doctor", "show", "version", "help",
})  # fmt: skip
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
        elif name == "init":
            _init.add_arguments(sub)
        elif name == "up":
            _up.add_up_arguments(sub)
        elif name == "down":
            _up.add_down_arguments(sub)
        elif name == "run":
            _run.add_arguments(sub)
        elif name == "verify":
            _args.add_verify_arguments(sub)
        elif name == "doctor":
            _args.add_doctor_arguments(sub)
        elif name == "show":
            _args.add_show_arguments(sub)
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
        # §11.2: the images `fabric up` runs, pinned by digest as packaged data.
        "images": _images.resolve({}).to_json(),
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
    options = "options on every command: --config PATH, --project NAME, --json, --quiet, --no-color"
    exits = ("exit codes: 0 ok, 1 a check did not pass, 2 usage or configuration error, "
             "3 a prerequisite is missing")  # fmt: skip
    lines += ["", options, exits, "", "Run `fabric COMMAND --help` for a command's options."]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:  # noqa: PLR0911 - one return per outcome
    """Entry point of the ``fabric`` and ``singleaxis-fabric`` console scripts."""
    args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    command_argv: list[str] | None = None
    # Everything after the first -- of `fabric [flags] run ...` is the agent's: split it off
    # before parsing, so a mistyped flag (even one placed before `run`) never stops it.
    if "--" in args and "run" in args[: args.index("--")]:
        split = args.index("--")
        args, command_argv = args[:split], args[split + 1 :]
    as_json = "--json" in args
    try:
        options = parser.parse_args(args)
    except CliError as exc:
        if command_argv:  # I3: a mistyped fabric run flag never stops the agent
            return _run.launch_unchanged(command_argv, exc.findings)
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
    if command == "run":
        agent = command_argv if command_argv is not None else _strip_dashes(options.agent_command)
        if not options.print_env:
            # Never through emit: the agent's stdout is its own (I2).
            return _run.launch(options, agent)
        options.agent_command = agent
    handlers: dict[str, Callable[[argparse.Namespace], tuple[Report, list[str]]]] = {
        "version": _version, "init": _init.run, "up": _up.run_up, "down": _up.run_down,
        "run": lambda o: _run.print_env(o, o.agent_command), "verify": _reader_command("verify"),
        "doctor": _reader_command("doctor"), "show": _reader_command("show"),
    }  # fmt: skip
    try:
        if command not in BUILT:
            raise CliError([Finding("FC-010", f"fabric {command}")])
        report, lines = handlers[command](options)
    except CliError as exc:
        report = Report(command, findings=exc.findings, exit_code=exc.exit_code)
        lines = []
    return emit(report, lines, as_json=options.json, quiet=options.quiet)


def _strip_dashes(command: Sequence[str]) -> list[str]:
    """``fabric run python app.py`` without ``--``: argparse leaves the words as given."""
    words = list(command)
    return words[1:] if words[:1] == ["--"] else words


def _reader_command(name: str) -> Callable[[argparse.Namespace], tuple[Report, list[str]]]:
    """``verify``, ``show`` and ``doctor`` import the reader: only when one of them runs,
    so ``fabric run`` stays inside its start-up budget (§5.5)."""

    def handler(options: argparse.Namespace) -> tuple[Report, list[str]]:
        if name == "verify":
            from . import _verify  # noqa: PLC0415 - loaded only for this command

            return _verify.run(options)
        if name == "show":
            from . import _show  # noqa: PLC0415 - loaded only for this command

            return _show.run(options)
        from . import _doctor  # noqa: PLC0415 - loaded only for this command

        return _doctor.run(options)

    return handler
