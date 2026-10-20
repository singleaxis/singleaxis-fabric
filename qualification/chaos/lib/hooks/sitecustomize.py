# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Chaos fault-injection hooks, in place of Fabric's autoload ``sitecustomize``.

This directory goes on ``PYTHONPATH`` instead of Fabric's autoload directory. It does what
the autoload does (``FABRIC_WIRE_AUTOLOAD=1`` -> ``fabric.wire.install_from_env()``, every
failure swallowed), with a clock fault applied before and the other faults after. Fabric's
code is never edited: the hooks wrap module globals of an installed process from the
outside, selected by ``CHAOS_FAULT`` (``kind:probability[:seed]``):

- ``spool_write``: SIGKILL inside ``Spool.write`` at a random step (after the temp file
  is reserved, between body writes, before ``fsync``, before the rename, before the
  directory fsync);
- ``send``: SIGKILL inside the sender, after a body was accepted by the Node, after a
  span batch was exported and before its records were retired;
- ``protect``: SIGKILL inside the PROTECT stage (between capture and protection);
- ``clock``: shift ``time.time``/``time.time_ns`` by ``CHAOS_CLOCK_SKEW_S`` seconds, and
  with ``CHAOS_CLOCK_JUMP_S`` jump the wall clock by that much after ``CHAOS_CLOCK_JUMP_AFTER``
  seconds (a backwards step when negative).

``CHAOS_FAULT_LOG`` names a file that gets one line just before the kill (which step).
"""

from __future__ import annotations

import os
import random
import signal
import sys
import time

_SPEC = os.environ.get("CHAOS_FAULT", "")


def _die(step: str) -> None:
    path = os.environ.get("CHAOS_FAULT_LOG")
    if path:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.write(fd, f"{os.getpid()} {step}\n".encode())
        os.fsync(fd)
        os.close(fd)
    os.kill(os.getpid(), signal.SIGKILL)


def _install_spool_write(prob: float, rng: random.Random) -> None:
    from fabric.wire import _spool  # noqa: PLC0415

    real = os

    class _Os:
        def __getattr__(self, name: str):  # noqa: ANN204
            value = getattr(real, name)
            if name in ("write", "fsync", "pwrite", "close", "open") and callable(value):

                def wrapped(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
                    if rng.random() < prob:
                        _die(f"spool_write:{name}:before")
                    result = value(*args, **kwargs)
                    if rng.random() < prob / 2:
                        _die(f"spool_write:{name}:after")
                    return result

                return wrapped
            if name == "rename":

                def renamed(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
                    if rng.random() < prob:
                        _die("spool_write:rename:before")
                    result = real.rename(*args, **kwargs)
                    if rng.random() < prob:
                        _die("spool_write:rename:after")
                    return result

                return renamed
            return value

    _spool.os = _Os()  # type: ignore[assignment]


def _install_send(prob: float, rng: random.Random) -> None:
    from fabric.wire import _content, _sender  # noqa: PLC0415

    send = _content.NodeContentClient.send

    def send_then_maybe_die(self, descriptor, body):  # noqa: ANN001, ANN202
        result = send(self, descriptor, body)
        if result == "ok" and rng.random() < prob:
            _die("send:after_body")
        return result

    _content.NodeContentClient.send = send_then_maybe_die  # type: ignore[method-assign]
    retire = _sender.Sender._retire_delivered

    def retire_maybe_die(self):  # noqa: ANN001, ANN202
        if self._retiring and rng.random() < prob:
            _die("send:after_export_before_retire")
        return retire(self)

    _sender.Sender._retire_delivered = retire_maybe_die  # type: ignore[method-assign]


def _install_protect(prob: float, rng: random.Random) -> None:
    from fabric.wire import _protect  # noqa: PLC0415

    side = _protect.Protector.side

    def side_maybe_die(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        if rng.random() < prob:
            _die("protect:before")
        result = side(self, *args, **kwargs)
        if rng.random() < prob:
            _die("protect:after")
        return result

    _protect.Protector.side = side_maybe_die  # type: ignore[method-assign]


def _install_clock() -> None:
    skew = float(os.environ.get("CHAOS_CLOCK_SKEW_S", "0"))
    jump = float(os.environ.get("CHAOS_CLOCK_JUMP_S", "0"))
    after = float(os.environ.get("CHAOS_CLOCK_JUMP_AFTER", "0"))
    real_time, real_ns, start = time.time, time.time_ns, time.monotonic()

    def offset() -> float:
        return skew + (jump if jump and time.monotonic() - start >= after else 0.0)

    time.time = lambda: real_time() + offset()  # type: ignore[assignment]
    time.time_ns = lambda: real_ns() + int(offset() * 1e9)  # type: ignore[assignment]


def _autoload() -> None:
    if getattr(sys, "_fabric_wire_autoload_ran", False):
        return
    sys._fabric_wire_autoload_ran = True  # type: ignore[attr-defined]
    if os.environ.get("FABRIC_WIRE_AUTOLOAD", "").strip().lower() not in ("1", "true"):
        return
    try:
        from fabric.wire import install_from_env  # noqa: PLC0415

        install_from_env()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"chaos hooks: autoload failed ({type(exc).__name__})\n")


def _main() -> None:
    kind, _, rest = _SPEC.partition(":")
    if kind == "clock":
        _install_clock()
    _autoload()
    if not _SPEC or kind == "clock":
        return
    prob_s, _, seed_s = rest.partition(":")
    prob = float(prob_s or 0)
    rng = random.Random(int(seed_s) if seed_s else os.getpid() ^ int(time.time_ns()))
    try:
        if kind == "spool_write":
            _install_spool_write(prob, rng)
        elif kind == "send":
            _install_send(prob, rng)
        elif kind == "protect":
            _install_protect(prob, rng)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"chaos hooks: {kind} not installed ({type(exc).__name__})\n")


_main()
