# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Drain an agent spool with no agent running (``python -m fabric.wire drain``).

An agent process delivers its spool's backlog while it runs and gives up at its bounded
exit budget, so records a one-shot container left behind waited for the next agent
process on the same volume, and one that never came never delivered them (reliability
run, S1/S3/S4). The drainer is that next process without an agent: it reads the agent's
own configuration (``FABRIC_WIRE_*``, ``OTEL_EXPORTER_OTLP_*``), builds the same spool
sender, takes the spool lock when no live process holds it, and delivers exactly as an
agent would (bodies to the Node, then spans; a record is deleted only after every part
was accepted). It installs no capture: no model client is teed, and no source epoch,
manifest or heartbeat of its own is written. As the lock holder it also recovers dead
processes' loss-ledger slots and declares orphaned epochs (spec 050 §3.2 rule 5).

``--until-empty`` returns once nothing deliverable is left (exit 0) or at ``--timeout``
with records still on disk (exit 1; they stay for the next drainer or agent). Without
it the drainer runs as a sidecar until SIGTERM or SIGINT."""

from __future__ import annotations

import dataclasses
import os
import signal
import threading
import time
from collections.abc import Mapping
from typing import Any

_POLL_S = 0.2
_CLOSE_S = 10.0


class NoSpoolError(ValueError):
    """The configuration names no spool directory (fixed text)."""

    def __init__(self) -> None:
        super().__init__("no spool: set FABRIC_WIRE_SPOOL_DIR or pass --spool")


class CaptureActiveError(ValueError):
    """Capture is installed in this process: a drainer runs in a process of its own."""

    def __init__(self) -> None:
        super().__init__("capture is installed in this process; run the drainer on its own")


@dataclasses.dataclass(frozen=True)
class DrainResult:
    drained: bool  # nothing deliverable left
    delivered: int
    remaining: int  # deliverable records still on disk
    undecryptable: int  # records sealed under another spool key (left on disk)
    quarantined: int
    seconds: float

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def drain(
    environ: Mapping[str, str],
    *,
    spool_dir: str | None = None,
    until_empty: bool = True,
    timeout_s: float | None = None,
    stop: threading.Event | None = None,
) -> DrainResult:
    """Deliver the spool's records with the agent's configuration; ``ValueError`` when the
    configuration is invalid or names no spool."""
    from .._loss import get_loss_emitter  # noqa: PLC0415
    from . import current_handle  # noqa: PLC0415
    from ._config import config_from_env  # noqa: PLC0415
    from ._sender import build_sender  # noqa: PLC0415

    if current_handle() is not None:
        raise CaptureActiveError
    env = dict(environ)
    if spool_dir is not None:
        env["FABRIC_WIRE_SPOOL_DIR"] = spool_dir
    config, _ = config_from_env(env)
    if config.spool_dir is None:
        raise NoSpoolError
    sender = build_sender(config, get_loss_emitter(), None, None)
    if sender is None:  # pragma: no cover - a spool directory always builds a sender
        raise ValueError("no spool sender")
    stop = stop or threading.Event()
    started = time.monotonic()
    deadline = None if timeout_s is None else started + max(0.0, timeout_s)
    sender.wake()  # starts the sender thread: it takes the lock as soon as it is free
    empty = False
    while not stop.is_set():
        pending, _ = sender.backlog()
        # Empty: nothing deliverable, and, while holding the lock, a full drain pass
        # (orphan recovery and epoch scan included) found nothing more to do. Without the
        # lock a live process is draining: an empty directory is still empty.
        empty = pending == 0 and (not sender.spool.holder or sender.idle_passes > 0)
        if until_empty and empty:
            break
        if deadline is not None and time.monotonic() >= deadline:
            break
        stop.wait(_POLL_S)
    sender.close(_CLOSE_S)
    pending, sealed = sender.backlog()
    stats = sender.stats()
    return DrainResult(
        drained=empty and pending == 0, delivered=int(stats.get("delivered", 0)),
        remaining=pending, undecryptable=sealed, quarantined=int(stats.get("quarantined", 0)),
        seconds=round(time.monotonic() - started, 3),
    )  # fmt: skip


def run(spool_dir: str | None, *, until_empty: bool, timeout_s: float | None) -> DrainResult:
    """:func:`drain` from ``os.environ``, stopping on SIGTERM or SIGINT (a sidecar's or a
    preStop hook's end)."""
    stop = threading.Event()
    previous = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, lambda *_: stop.set())
    try:
        return drain(os.environ, spool_dir=spool_dir, until_empty=until_empty,
                     timeout_s=timeout_s, stop=stop)  # fmt: skip
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
