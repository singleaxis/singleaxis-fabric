# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Sanitized diagnostics for Fabric-managed exports (spec 048 §8), shared by the capture
exporters (``fabric.tracing``) and the explicit line's managed exporter
(``fabric._span_protection``): exporter, header-parser and HTTP-client log records emitted
inside a Fabric-managed export or construction carry only codes and class names."""

from __future__ import annotations

import contextlib
import logging
import threading
from collections.abc import Iterator
from enum import Enum

__all__ = ["sanitized_export_diagnostics"]

_EXPORT_SCOPE = threading.local()
_EXPORTER_LOGGERS = (
    "opentelemetry.exporter.otlp.proto.http.trace_exporter",
    "opentelemetry.exporter.otlp.proto.grpc.exporter",
    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
    "opentelemetry.util.re", "urllib3.connectionpool", "urllib3.util.retry",
)  # fmt: skip


def _safe_log_arg(value: object) -> object:
    if isinstance(value, (bool, int, float)):
        return value  # status codes, retry counts, backoff seconds
    if isinstance(value, Enum):
        return value.name  # e.g. a gRPC status code
    if isinstance(value, BaseException):
        return type(value).__name__
    return "<redacted>"  # URLs, reason phrases, error details: never echoed


class _SanitizedExportDiagnostics(logging.Filter):
    """Inside Fabric's exports only, reduce exporter log records to codes and class names."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(_EXPORT_SCOPE, "active", False):
            args = record.args if isinstance(record.args, tuple) else ()
            if not isinstance(record.msg, str) or (record.args and not args):
                record.msg, args = "OTLP exporter diagnostic (%s)", (type(record.msg).__name__,)
            exc = record.exc_info[1] if record.exc_info else None
            record.args = tuple(_safe_log_arg(arg) for arg in args)
            if exc is not None:  # the traceback text may carry the exception message
                record.msg = f"{record.msg} [{type(exc).__name__}]"
            record.exc_info = record.exc_text = record.stack_info = None
        return True


_DIAGNOSTICS_FILTER = _SanitizedExportDiagnostics()


@contextlib.contextmanager
def sanitized_export_diagnostics() -> Iterator[None]:
    """Sanitize exporter and HTTP-client log records emitted on this thread inside the block.

    Fabric does not patch the OTel library: a filter on the exporter, OTLP header parser
    and urllib3 loggers rewrites only records produced while a Fabric-owned export or
    construction runs on this thread, so the host's own exporters log exactly as before.
    """
    for name in _EXPORTER_LOGGERS:
        logging.getLogger(name).addFilter(_DIAGNOSTICS_FILTER)  # idempotent
    previous = getattr(_EXPORT_SCOPE, "active", False)
    _EXPORT_SCOPE.active = True
    try:
        yield
    finally:
        _EXPORT_SCOPE.active = previous
