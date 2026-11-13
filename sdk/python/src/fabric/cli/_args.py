# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The arguments of ``fabric verify``, ``show`` and ``doctor`` (spec 058 §5.6-§5.8).

Kept apart from the commands, which import the reader: building the parser must stay
cheap, because ``fabric run`` builds it too and adds at most 150 ms before ``exec``
(§5.5)."""

from __future__ import annotations

import argparse
import math

DEFAULT_WAIT_S = 30.0


def _seconds(text: str) -> float:
    """``--wait``: a finite number of seconds, zero or more."""
    try:
        value = float(text)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds (0 or more)")
    return value


def add_verify_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "run",
        nargs="?",
        metavar="RUN",
        help="the run label to read (default: the last `fabric run`)",
    )
    parser.add_argument(
        "--canary-only",
        action="store_true",
        help="check the path with the canary; do not read a run",
    )
    parser.add_argument(
        "--spans",
        metavar="PATH",
        help="read the run from this span export (a destination Fabric cannot read back)",
    )
    parser.add_argument("--strict", action="store_true", help="a warning fails too")
    parser.add_argument(
        "--wait",
        type=_seconds,
        default=DEFAULT_WAIT_S,
        metavar="SECONDS",
        help="how long to wait for records to reach the destination (default 30)",
    )
    # Accepted so the answer is FC-011 naming the manual route, not an argparse error.
    parser.add_argument("--production", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--kubernetes", action="store_true", help=argparse.SUPPRESS)


def add_show_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "run", nargs="?", metavar="RUN", help="the run label (default: the last `fabric run`)"
    )
    parser.add_argument("--list", action="store_true", help="list recent runs with verdicts")
    view = parser.add_mutually_exclusive_group()
    view.add_argument("--actions", action="store_true", help="the reader's action view")
    view.add_argument("--transcript", action="store_true", help="the conversation only")
    parser.add_argument(
        "--content", action="store_true", help="print content even when stdout is not a terminal"
    )


def add_doctor_arguments(parser: argparse.ArgumentParser) -> None:
    # Accepted so the answer is FC-011 naming the manual route, not an argparse error.
    parser.add_argument("--kubernetes", action="store_true", help=argparse.SUPPRESS)
