# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``python -m fabric.wire``:

- ``--print-autoload-path``: the directory to put on ``PYTHONPATH`` (autoload also needs
  ``FABRIC_WIRE_AUTOLOAD=1``, spec 047 §3);
- ``drain [--spool DIR] [--until-empty] [--timeout SECONDS]``: deliver an agent spool
  with no agent running, using the agent's own ``FABRIC_*`` / ``OTEL_*`` environment
  (a one-shot container's last step, a sidecar, a Kubernetes preStop hook). Prints one
  JSON summary line. Exit 0: nothing deliverable left; 1: records remain (they stay on
  disk for the next drainer or agent); 2: usage or configuration error.
- ``status``: the configuration diagnostics the autoload would log for this environment
  (wire capture, content capture, hooks), as one JSON line; installs nothing. Run it with
  the agent's ``FABRIC_*`` / ``OTEL_*`` environment: the autoload itself keeps them off the
  agent's stdout and stderr unless ``FABRIC_WIRE_DIAGNOSTICS=stderr``. Exit 0: no
  warnings; 1: at least one (listed under ``warnings``); 2: usage error."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

USAGE = (
    "usage: python -m fabric.wire --print-autoload-path\n"
    "       python -m fabric.wire drain [--spool DIR] [--until-empty] [--timeout SECONDS]\n"
    "       python -m fabric.wire status\n"
)


def autoload_path() -> str:
    """Absolute path of the directory holding the autoload ``sitecustomize``."""
    return str((Path(__file__).resolve().parent.parent / "_autoload").resolve())


def _drain_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m fabric.wire drain", add_help=True)
    parser.add_argument("--spool", help="spool directory (default: FABRIC_WIRE_SPOOL_DIR)")
    parser.add_argument("--until-empty", action="store_true",
                        help="return once nothing deliverable is left (default: run until "
                             "SIGTERM, as a sidecar)")  # fmt: skip
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="give up after SECONDS; records left stay on disk (exit 1)",
    )
    return parser


def _drain(argv: Sequence[str]) -> int:
    try:
        options = _drain_parser().parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    if options.timeout is not None and options.timeout < 0:
        sys.stderr.write("fabric.wire drain: --timeout must not be negative\n")
        return 2
    from ._drain import CaptureActiveError, NoSpoolError, run  # noqa: PLC0415

    try:
        result = run(options.spool, until_empty=options.until_empty, timeout_s=options.timeout)
    except (NoSpoolError, CaptureActiveError) as exc:
        sys.stderr.write(f"fabric.wire drain: {exc}\n")
        return 2
    except ValueError as exc:  # class only: a configuration message can echo a value
        sys.stderr.write(f"fabric.wire drain: invalid configuration ({type(exc).__name__}); "
                         "check the FABRIC_WIRE_* and OTEL_EXPORTER_OTLP_* settings\n")  # fmt: skip
        return 2
    sys.stdout.write(json.dumps(result.to_json(), sort_keys=True) + "\n")
    return 0 if result.drained or (not options.until_empty and result.remaining == 0) else 1


def _status() -> int:
    from ._status import env_status  # noqa: PLC0415

    status = env_status()
    sys.stdout.write(json.dumps(status, sort_keys=True) + "\n")
    return 1 if status["warnings"] else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--print-autoload-path"]:
        sys.stdout.write(autoload_path() + "\n")
        return 0
    if args and args[0] == "drain":
        return _drain(args[1:])
    if args == ["status"]:
        return _status()
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
