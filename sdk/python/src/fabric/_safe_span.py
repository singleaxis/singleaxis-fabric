# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fail-open span recording (spec 049 §7.1 rules 2, 3 and 6).

Every attribute, event, status and exception the decision line writes goes through a
:class:`SafeSpan`: a failure in the host's tracer, span or processor is caught, counted
through ``on_error`` and logged class-only, and the reporting API proceeds. A recording
failure therefore never escapes into the application, and never replaces the
application's own exception on exit from a ``with`` block."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable, Iterator, Mapping
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import INVALID_SPAN, INVALID_SPAN_CONTEXT, Span, SpanContext, SpanKind
from opentelemetry.trace.status import Status, StatusCode

from ._safe_log import exc_class, safe_log

_LOG = logging.getLogger("fabric.recorder")
_AttrValue = Any  # an OpenTelemetry attribute value


def log_recording_error(exc: BaseException) -> None:
    """The default ``on_error``: a class-only diagnostic."""
    safe_log(_LOG, logging.DEBUG, "fabric: a recording step failed (%s)", exc_class(exc))


class SafeSpan(Span):
    """A :class:`~opentelemetry.trace.Span` that forwards to ``inner`` and never raises.

    Reads fall back to neutral values (an invalid span context, not recording); any other
    attribute is forwarded unchanged, so the wrapper stands in for the host span."""

    def __init__(
        self, inner: Span, on_error: Callable[[BaseException], None] = log_recording_error
    ) -> None:
        self._inner = inner
        self._on_error = on_error

    @property
    def inner(self) -> Span:
        return self._inner

    def _failed(self, exc: BaseException) -> None:
        with contextlib.suppress(Exception):
            self._on_error(exc)

    def end(self, end_time: int | None = None) -> None:
        try:
            self._inner.end(end_time)
        except Exception as exc:
            self._failed(exc)

    def get_span_context(self) -> SpanContext:
        try:
            return self._inner.get_span_context()
        except Exception as exc:
            self._failed(exc)
            return INVALID_SPAN_CONTEXT

    def set_attributes(self, attributes: Mapping[str, _AttrValue]) -> None:
        try:
            self._inner.set_attributes(attributes)
        except Exception as exc:
            self._failed(exc)

    def set_attribute(self, key: str, value: _AttrValue) -> None:
        try:
            self._inner.set_attribute(key, value)
        except Exception as exc:
            self._failed(exc)

    def add_event(
        self,
        name: str,
        attributes: Mapping[str, _AttrValue] | None = None,
        timestamp: int | None = None,
    ) -> None:
        try:
            self._inner.add_event(name, attributes, timestamp)
        except Exception as exc:
            self._failed(exc)

    def add_link(
        self, context: SpanContext, attributes: Mapping[str, _AttrValue] | None = None
    ) -> None:
        try:
            self._inner.add_link(context, attributes)
        except Exception as exc:
            self._failed(exc)

    def update_name(self, name: str) -> None:
        try:
            self._inner.update_name(name)
        except Exception as exc:
            self._failed(exc)

    def is_recording(self) -> bool:
        try:
            return bool(self._inner.is_recording())
        except Exception as exc:
            self._failed(exc)
            return False

    def set_status(self, status: Status | StatusCode, description: str | None = None) -> None:
        try:
            self._inner.set_status(status, description)
        except Exception as exc:
            self._failed(exc)

    def record_exception(
        self,
        exception: BaseException,
        attributes: Mapping[str, _AttrValue] | None = None,
        timestamp: int | None = None,
        escaped: bool = False,
    ) -> None:
        try:
            self._inner.record_exception(exception, attributes, timestamp, escaped)
        except Exception as exc:
            self._failed(exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class SpanScope:
    """``tracer.start_as_current_span(...)`` entered and exited fail-open.

    :meth:`enter` returns a :class:`SafeSpan` (over the invalid span when the tracer
    fails); :meth:`exit` passes the block's exception to the tracer's context manager and
    never raises, so the caller's own exception always propagates unchanged."""

    __slots__ = ("_cm", "_on_error")

    def __init__(self, on_error: Callable[[BaseException], None] = log_recording_error) -> None:
        self._cm: contextlib.AbstractContextManager[Span] | None = None
        self._on_error = on_error

    def enter(self, tracer: trace.Tracer, name: str, **kwargs: Any) -> SafeSpan:
        try:
            self._cm = tracer.start_as_current_span(name, **kwargs)
            return SafeSpan(self._cm.__enter__(), self._on_error)
        except Exception as exc:
            self._cm = None
            with contextlib.suppress(Exception):
                self._on_error(exc)
            return SafeSpan(INVALID_SPAN, self._on_error)

    def exit(self, exc: BaseException | None) -> None:
        cm, self._cm = self._cm, None
        if cm is None:
            return
        try:
            if exc is None:
                cm.__exit__(None, None, None)
            else:
                cm.__exit__(type(exc), exc, exc.__traceback__)
        except BaseException as failure:
            if failure is exc:
                return  # the context manager re-raised the block's own exception
            with contextlib.suppress(Exception):
                self._on_error(failure)


@contextlib.contextmanager
def child_span(
    tracer: trace.Tracer,
    name: str,
    *,
    kind: SpanKind = SpanKind.INTERNAL,
    on_error: Callable[[BaseException], None] = log_recording_error,
) -> Iterator[SafeSpan]:
    """A short Fabric-owned child span (memory, retrieval) recorded fail-open."""
    scope = SpanScope(on_error)
    span = scope.enter(tracer, name, kind=kind)
    try:
        yield span
    finally:
        scope.exit(None)


__all__ = ["SafeSpan", "SpanScope", "child_span", "log_recording_error"]
