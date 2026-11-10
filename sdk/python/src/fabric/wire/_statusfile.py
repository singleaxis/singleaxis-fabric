# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``FABRIC_WIRE_STATUS_FILE`` (spec 058 §13.2): where an autoloaded process tells the
operator what it captured, without writing to the agent's stdout or stderr.

At install the SDK writes the install's status (the ``python -m fabric.wire status`` facts
plus the handle's state) to that path, or, when capture could not be installed, the reason
and its fix. At exit, inside the existing exit budget, it rewrites the file with the
process's final counters. ``fabric doctor`` and ``fabric verify`` read it.

The file is local output: it may name a model host a request went to (so the operator
can add it), never a key, a header, a URL credential or content. It is written mode 0600,
atomically (a temporary file renamed over it), and a failure to write it is one diagnostic
on the ``fabric.wire`` logger, never an error in the agent (spec 057 B1-B4)."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import os
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ._diagnose import reason_id

if TYPE_CHECKING:
    from . import WireHandle

STATUS_FILE_ENV = "FABRIC_WIRE_STATUS_FILE"
SCHEMA = "fabric.wire-status/v1"
_LOG = logging.getLogger("fabric.wire")
MSG_UNWRITABLE = (
    "fabric.wire: the status file could not be written (%s). Fix: point "
    "FABRIC_WIRE_STATUS_FILE at a writable path in a directory that exists [FW-023]"
)
_STATE = {"warned": False}  # the unwritable-file diagnostic is logged once per process
# The install document is written on a thread; once a process wrote its exit document, a
# late install write never replaces it.
_ORDER = threading.Lock()
_EXITED: set[str] = set()


def path_from_env(environ: Mapping[str, str]) -> str | None:
    """The status file path, or ``None`` (unset: nothing is written)."""
    return (environ.get(STATUS_FILE_ENV) or "").strip() or None


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _head(phase: str) -> dict[str, Any]:
    from .._version import __version__  # noqa: PLC0415

    return {"schema": SCHEMA, "phase": phase, "written_at": _now(), "pid": os.getpid(),
            "sdk_version": __version__}  # fmt: skip


def write(path: str, document: Mapping[str, Any]) -> bool:
    """Write ``document`` to ``path`` atomically (mode 0600); ``False`` on any failure
    (logged once, by error class only)."""
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        data = (json.dumps(document, sort_keys=True, default=str) + "\n").encode("utf-8")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                     0o600)  # fmt: skip
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        return True
    except Exception as exc:
        with contextlib.suppress(Exception):
            os.unlink(tmp)
        if not _STATE["warned"]:
            _STATE["warned"] = True
            with contextlib.suppress(Exception):
                _LOG.warning(MSG_UNWRITABLE, type(exc).__name__)
        return False


def diagnostics(handle: WireHandle) -> tuple[list[str], list[str]]:
    """``(warning ids, notice ids)`` of an installed handle (catalogue ids, 058 §13.2)."""
    from ..tracing import capture_otlp_configured, is_private_provider  # noqa: PLC0415
    from ._status import withheld_roles  # noqa: PLC0415

    if not handle.capturing:
        return ["FW-007"], []
    warnings: list[str] = []
    notices = ["FW-005"]
    config, gate = handle.config, handle.gate
    provider = config.tracer_provider
    if config.spool_dir is None and provider is not None and is_private_provider(provider) and (
        not capture_otlp_configured()
    ):  # fmt: skip
        warnings.append("FW-002")
    if gate is not None:
        if gate.content_capture == "disabled":
            warnings.append("FW-008")
        elif gate.content_capture == "metadata_only" and gate.reason == "no_store":
            notices.append("FW-003")
        if withheld_roles(config, gate):
            warnings.append("FW-004")
    with contextlib.suppress(Exception):
        if handle._tee.unmatched.status():
            warnings.append("FW-006")
    return warnings, notices


def install_document(handle: WireHandle) -> dict[str, Any]:
    warnings, notices = diagnostics(handle)
    document = _head("install")
    document.update({"capture": "installed" if handle.capturing else "disabled",
                     "status": handle.status(), "warning_ids": warnings,
                     "notice_ids": notices})  # fmt: skip
    return document


def failure_document(error: str, why: str, hint: str | None) -> dict[str, Any]:
    document = _head("install")
    document.update({"capture": "not_installed", "error": error, "reason": why,
                     "reason_id": reason_id(why), "warning_ids": ["FW-001"],
                     "notice_ids": []})  # fmt: skip
    if hint:
        document["fix"] = hint
    return document


def exit_document(handle: WireHandle, delivered: bool) -> dict[str, Any]:
    warnings, notices = diagnostics(handle)
    document = _head("exit")
    document.update({"capture": "closed", "delivered": delivered,
                     "stats": dataclasses.asdict(handle.stats()), "warning_ids": warnings,
                     "notice_ids": notices})  # fmt: skip
    with contextlib.suppress(Exception):
        if unmatched := handle._tee.unmatched.status():
            document["unmatched_model_hosts"] = unmatched
    return document


def at_install(handle: WireHandle, path: str) -> None:
    """Write the install document on a daemon thread: the agent's start-up never waits for
    it (the handle's status reads the spool directory). Never raises."""

    def work() -> None:
        with contextlib.suppress(Exception):
            document = install_document(handle)
            with _ORDER:
                if path not in _EXITED:
                    write(path, document)

    with contextlib.suppress(Exception):
        threading.Thread(target=work, name="fabric-status-file", daemon=True).start()


def at_failure(path: str, error: str, why: str, hint: str | None) -> None:
    """Capture was not installed: the reason and its fix (the agent runs unrecorded)."""
    with contextlib.suppress(Exception):
        write(path, failure_document(error, why, hint))


def at_exit(handle: WireHandle, path: str, delivered: bool, deadline: float) -> None:
    """The final counters, inside the exit budget (bounded by ``deadline``)."""
    from .._loss import run_bounded  # noqa: PLC0415

    if time.monotonic() >= deadline:
        return

    def work() -> bool:
        document = exit_document(handle, delivered)
        with _ORDER:
            _EXITED.add(path)
            return write(path, document)

    with contextlib.suppress(Exception):
        run_bounded(work, deadline, "fabric-status-file")
