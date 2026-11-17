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
        help="how long to wait for records to reach the destination (default 30; with "
        "--kubernetes and --spans, 180: for a run of the pods your rollout restarted)",
    )
    # Accepted so the answer is FC-011 naming the manual route, not an argparse error.
    parser.add_argument("--production", action="store_true", help=argparse.SUPPRESS)
    add_kubernetes_arguments(parser, "verify")


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
    add_kubernetes_arguments(parser, "doctor")


#: What ``--kubernetes`` does on each command (spec 058 §5.2, §5.4, §5.6, §5.7).
_KUBERNETES_HELP = {
    "plan": "read the cluster of the current kube context (read-only) and predict what "
    "Fabric would record there",
    "up": "install the Fabric release into the cluster of the current kube context with Helm",
    "down": "remove the Fabric release from the cluster of the current kube context",
    "verify": "check the Fabric release in the cluster of the current kube context "
    "(read-only), then read the run from --spans",
    "doctor": "diagnose the Fabric release in the cluster of the current kube context (read-only)",
}
KUBERNETES_PRESETS = ("local", "production", "production-host-sensor")


def add_kubernetes_arguments(parser: argparse.ArgumentParser, command: str) -> None:
    """``--kubernetes`` and the options that go with it on ``command``."""
    group = parser.add_argument_group("Kubernetes")
    group.add_argument("--kubernetes", action="store_true", help=_KUBERNETES_HELP[command])
    group.add_argument(
        "--namespace",
        metavar="NS",
        default="fabric-system" if command in ("up", "down") else None,
        help="the release's namespace (default fabric-system"
        + ("" if command in ("up", "down") else "; found by itself when there is one release")
        + ")",
    )
    if command not in ("up", "down"):
        return
    group.add_argument("--release", metavar="NAME", default="fabric",
                       help="the Helm release name (default fabric)")  # fmt: skip
    if command == "down":
        return
    group.add_argument("--preset", choices=KUBERNETES_PRESETS, default="local",
                       help="the chart preset (default local: a trial Node; the production "
                       "presets need your destination, given with --values or --set)")  # fmt: skip
    group.add_argument(
        "--tenant", metavar="ID", help="the tenant id (default: fabric.yaml's, when there is one)"
    )
    group.add_argument("--agent-namespace", action="append", metavar="NS",
                       help="a namespace whose agents send to the Node (repeatable)")  # fmt: skip
    group.add_argument("--injector", action="store_true",
                       help="install the opt-in pod injector for the agent namespaces")  # fmt: skip
    group.add_argument(
        "--values",
        action="append",
        metavar="FILE",
        help="a Helm values file of your own (repeatable; wins over the preset)",
    )
    group.add_argument("--set", action="append", metavar="KEY=VALUE",
                       help="a Helm value of your own (repeatable; never a secret)")  # fmt: skip
    group.add_argument("--chart", metavar="REF",
                       help="the chart to install (default: this CLI release's chart)")  # fmt: skip
    group.add_argument("--host-node", action="append", metavar="NODE",
                       help="with --render and the host sensor: a node that runs it "
                       "(repeatable; default: read from the cluster)")  # fmt: skip
    group.add_argument("--render", metavar="DIR",
                       help="write the Helm values and the Secret manifests into DIR for your "
                       "own pipeline instead of installing")  # fmt: skip
