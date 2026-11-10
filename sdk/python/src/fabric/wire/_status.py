# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``python -m fabric.wire status``: the configuration diagnostics the zero-code autoload
would log for this environment, as one JSON object, without installing capture, patching a
client, writing to the spool or opening a connection. With a spool configured it reads
(never writes) the spool directory: how many records wait there, and the exit note a process
left when it exited with records nobody was draining (field finding F1).

The autoload keeps its diagnostics off the monitored process's stdout and stderr (a child
process an agent's tool starts inherits the autoload, and its output is what the model
reads). This is where an operator reads them instead: run it with the agent's environment,
or set ``FABRIC_WIRE_DIAGNOSTICS=stderr`` to print them from every autoloaded process.
A configuration error is described by its reason and its fix (``_diagnose.py``), scrubbed
so no secret, URL credential or query string is printed; nothing else echoes a value, path
or id."""

from __future__ import annotations

import contextlib
import os
import re
from typing import Any

from .. import hooks
from . import (
    _MSG_CONTENT_DISABLED,
    _MSG_LLM_CONTENT_IGNORED,
    _MSG_MIGRATE_IGNORED,
    _MSG_NO_DESTINATION,
    _MSG_OTEL_DISABLED,
    _env_defaults,
    _gate,
    _otel_disabled,
    _truthy,
)
from ._config import ENDPOINT_TABLE_VERSION
from ._diagnose import describe, not_installed_message, reason_id

DIAGNOSTICS_ENV = "FABRIC_WIRE_DIAGNOSTICS"
# Modes whose content needs a customer transformation (spec 049 §7.7), which the
# environment cannot name: under the autoload every such role is withheld.
_MASKING_MODES = frozenset({"redact", "masked_only", "original_plus_masked"})
_MSG_CONTENT_WITHHELD = (
    "fabric.wire: content capture is enabled, but the capture policy masks %s (%s) and the "
    "autoload has no transformation for them: their content is withheld "
    "(store_reason=protection_failed), so a command reads as 'exec pid N' and output "
    "matching cannot apply. Fix: give those roles retain_original or metadata_only in the "
    "policy, or install in code with transformations= and FABRIC_REDACTION_ENDPOINT [FW-004]"
)


def _check_delivery(config: Any) -> None:
    """Build, then discard, what install would build from the environment for delivery (the
    capture span exporter, the Node content client): their configuration errors are raised
    at construction. Nothing is sent."""
    from .. import tracing  # noqa: PLC0415

    if config.spool_dir is not None or tracing.capture_otlp_configured():
        exporter = tracing.build_capture_span_exporter()
        with contextlib.suppress(Exception):
            exporter.shutdown()
    if config.content_endpoint is not None:
        from ._content import content_client_from_env  # noqa: PLC0415

        client = content_client_from_env(os.environ, endpoint=config.content_endpoint)
        with contextlib.suppress(Exception):
            client.close()


_MSG_SPOOL_BACKLOG = (
    "fabric.wire: %d records wait in the spool; a process that exited at %s left %d there "
    "with no process draining it. They are delivered only when a process captures to or "
    "drains this spool again. Fix: run `python -m fabric.wire drain --until-empty` with the "
    "agent's environment; for batch or serverless workers set FABRIC_WIRE_DRAIN_ON_EXIT_S, "
    "or keep FABRIC_WIRE_SPOOL_DIR on durable storage with a drainer (sidecar) [FW-009]"
)


def _spool_status(config: Any) -> tuple[dict[str, Any] | None, list[str]]:
    """The spool's backlog, read only: ``({"records": n, "left_at_exit": note?}, warnings)``;
    ``(None, [])`` without a spool directory."""
    from ._spool import read_exit_note  # noqa: PLC0415

    directory = config.spool_dir
    if directory is None or not os.path.isdir(directory):
        return None, []
    try:
        records = sum(1 for name in os.listdir(directory)
                      if name.endswith(".rec") and not name.startswith("."))  # fmt: skip
    except OSError:
        return None, []
    spool: dict[str, Any] = {"records": records}
    warnings: list[str] = []
    if (note := read_exit_note(directory)) is not None:
        spool["left_at_exit"] = note
        if records:
            warnings.append(_MSG_SPOOL_BACKLOG % (records, note["exited_at"],
                                                  note["records_left"]))  # fmt: skip
    return spool, warnings


def _span_destination(config: Any, mode: str) -> str:
    """Where the capture spans go: ``otlp`` (an OTLP endpoint is set), ``application``
    (``FABRIC_WIRE_TRACER=global``: the application's own tracer provider, which this
    command cannot see) or ``none`` (the private provider has no exporter: dropped)."""
    from .. import tracing  # noqa: PLC0415

    if config.spool_dir is not None or tracing.capture_otlp_configured():
        return "otlp"
    return "application" if mode == "global" else "none"


def withheld_roles(config: Any, gate: Any) -> list[tuple[str, str]]:
    """``(role, mode)`` of each role the policy masks with no transformation configured."""
    policy = gate.policy
    if gate.content_capture != "enabled" or policy is None:
        return []
    transformations = config.transformations or {}
    return sorted(
        (role, mode) for role, mode in policy.modes.items()
        if mode in _MASKING_MODES and role not in transformations
    )  # fmt: skip


def _wire_status() -> tuple[dict[str, Any], list[str], bool]:
    """``(wire section, warnings, capturing)`` for ``os.environ``."""
    from ._config import config_from_env  # noqa: PLC0415

    warnings: list[str] = []
    try:
        config, mode = config_from_env(os.environ)
        config = _env_defaults(config)
        if _otel_disabled():
            return {"configuration": "valid", "capture": "disabled"}, [_MSG_OTEL_DISABLED], False
        gate = _gate(config)
        _check_delivery(config)
    except Exception as exc:
        error = type(exc).__name__
        why, hint = describe(exc)  # scrubbed: never a value from the environment
        invalid = {"configuration": "invalid", "error": error, "capture": "not_installed",
                   "reason": why, "reason_id": reason_id(why)}  # fmt: skip
        if hint:
            invalid["fix"] = hint
        return invalid, [not_installed_message(error, why, hint)], False
    destination = _span_destination(config, mode)
    wire: dict[str, Any] = {
        "configuration": "valid", "capture": "enabled", "profile": gate.profile,
        "content_capture": gate.content_capture, "span_destination": destination,
        # 058 §8.1 / §13.2 endpoint_set: the endpoints recorded and the table they came from.
        "endpoint_set": [m.endpoint_id for m in config.all_endpoints],
        "endpoint_table_version": ENDPOINT_TABLE_VERSION,
    }  # fmt: skip
    if destination == "none":
        warnings.append(_MSG_NO_DESTINATION)
    if gate.content_capture == "disabled":
        wire["content_capture_reason"] = gate.reason
        warnings.append(_MSG_CONTENT_DISABLED % (gate.reason, gate.profile))
    if withheld := withheld_roles(config, gate):
        wire["content_withheld_roles"] = [role for role, _ in withheld]
        roles = ", ".join(role for role, _ in withheld)
        modes = ", ".join(sorted({mode for _, mode in withheld}))
        warnings.append(_MSG_CONTENT_WITHHELD % (roles, modes))
    if config.spool_migrate_plaintext and gate.profile == "production":
        warnings.append(_MSG_MIGRATE_IGNORED)
    if _truthy(os.environ.get("FABRIC_CAPTURE_LLM_CONTENT")):
        warnings.append(_MSG_LLM_CONTENT_IGNORED)
    spool, backlog = _spool_status(config)
    if spool is not None:
        wire["spool"] = spool
        warnings.extend(backlog)
    return wire, warnings, True


def env_status() -> dict[str, Any]:
    """The status object ``python -m fabric.wire status`` prints."""
    autoload = (os.environ.get("FABRIC_WIRE_AUTOLOAD") or "").strip().lower() in ("1", "true")
    diagnostics = (os.environ.get(DIAGNOSTICS_ENV) or "").strip().lower() == "stderr"
    wire, warnings, capturing = _wire_status()
    hook_status = hooks.env_status(os.environ, capturing=capturing)
    warnings.extend(hook_status.pop("warnings"))
    # 058 §13.1: the catalogue id of each warning that carries one, and the facts that are
    # not problems (they never change the exit code): the endpoint set, metadata-only.
    ids = [m.group(1) for w in warnings if (m := _ID_RE.search(w))]
    notices = []
    if capturing:
        notices.append("FW-005")
        if wire.get("content_capture") == "metadata_only":
            notices.append("FW-003")
    return {
        "autoload": autoload, "diagnostics": "stderr" if diagnostics else "silent",
        "wire": wire, "hooks": hook_status, "warnings": warnings, "warning_ids": ids,
        "notice_ids": notices,
    }  # fmt: skip


_ID_RE = re.compile(r"\[(F[CWERN]-[0-9]{3})\]$")
