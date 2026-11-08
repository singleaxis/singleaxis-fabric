# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``python -m fabric.wire status``: the configuration diagnostics the zero-code autoload
would log for this environment, as one JSON object, without installing capture, patching a
client, touching the spool or opening a connection.

The autoload keeps its diagnostics off the monitored process's stdout and stderr (a child
process an agent's tool starts inherits the autoload, and its output is what the model
reads). This is where an operator reads them instead: run it with the agent's environment,
or set ``FABRIC_WIRE_DIAGNOSTICS=stderr`` to print them from every autoloaded process.
Class-only text, like ``WireHandle.status()``: never a value, path or id."""

from __future__ import annotations

import contextlib
import os
from typing import Any

from .. import hooks
from . import (
    _MSG_CONTENT_DISABLED,
    _MSG_LLM_CONTENT_IGNORED,
    _MSG_MIGRATE_IGNORED,
    _MSG_NOT_INSTALLED,
    _MSG_OTEL_DISABLED,
    _env_defaults,
    _gate,
    _otel_disabled,
    _truthy,
)

DIAGNOSTICS_ENV = "FABRIC_WIRE_DIAGNOSTICS"


def _check_delivery(config: Any) -> None:
    """Build, then discard, what install would build from the environment for delivery (the
    capture span exporter, the Node content client): their configuration errors are raised
    at construction. Nothing is sent."""
    from .. import tracing  # noqa: PLC0415

    if config.spool_dir is not None or tracing.otlp_endpoint_configured():
        exporter = tracing.build_capture_span_exporter()
        with contextlib.suppress(Exception):
            exporter.shutdown()
    if config.content_endpoint is not None:
        from ._content import content_client_from_env  # noqa: PLC0415

        client = content_client_from_env(os.environ, endpoint=config.content_endpoint)
        with contextlib.suppress(Exception):
            client.close()


def _wire_status() -> tuple[dict[str, Any], list[str], bool]:
    """``(wire section, warnings, capturing)`` for ``os.environ``."""
    from ._config import config_from_env  # noqa: PLC0415

    warnings: list[str] = []
    try:
        config, _mode = config_from_env(os.environ)
        config = _env_defaults(config)
        if _otel_disabled():
            return {"configuration": "valid", "capture": "disabled"}, [_MSG_OTEL_DISABLED], False
        gate = _gate(config)
        _check_delivery(config)
    except Exception as exc:
        error = type(exc).__name__
        invalid = {"configuration": "invalid", "error": error, "capture": "not_installed"}
        return invalid, [_MSG_NOT_INSTALLED % error], False
    wire: dict[str, Any] = {
        "configuration": "valid", "capture": "enabled", "profile": gate.profile,
        "content_capture": gate.content_capture,
    }  # fmt: skip
    if gate.content_capture == "disabled":
        wire["content_capture_reason"] = gate.reason
        warnings.append(_MSG_CONTENT_DISABLED % (gate.reason, gate.profile))
    if config.spool_migrate_plaintext and gate.profile == "production":
        warnings.append(_MSG_MIGRATE_IGNORED)
    if _truthy(os.environ.get("FABRIC_CAPTURE_LLM_CONTENT")):
        warnings.append(_MSG_LLM_CONTENT_IGNORED)
    return wire, warnings, True


def env_status() -> dict[str, Any]:
    """The status object ``python -m fabric.wire status`` prints."""
    autoload = (os.environ.get("FABRIC_WIRE_AUTOLOAD") or "").strip().lower() in ("1", "true")
    diagnostics = (os.environ.get(DIAGNOSTICS_ENV) or "").strip().lower() == "stderr"
    wire, warnings, capturing = _wire_status()
    hook_status = hooks.env_status(os.environ, capturing=capturing)
    warnings.extend(hook_status.pop("warnings"))
    return {
        "autoload": autoload, "diagnostics": "stderr" if diagnostics else "silent",
        "wire": wire, "hooks": hook_status, "warnings": warnings,
    }  # fmt: skip
