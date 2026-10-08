# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""In-process LLM wire capture (spec 042).

Tees the exact request/response bytes of ``httpx`` model calls into the customer's
byte store and emits one span per call. Importing this module patches nothing and
does not import ``httpx``; :func:`install` or the env-gated autoload starts capture,
which always fails open.
"""

from __future__ import annotations

import atexit
import contextlib
import dataclasses
import logging
import os
import threading
import time
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any

from .._sequence import SourceAllocator, get_allocator, run_scope
from ._config import DEFAULT_ENDPOINTS, WireConfig
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ExchangeSink

if TYPE_CHECKING:
    from ._transport import AsyncWireTransport, WireTee, WireTransport

__all__ = [
    "DEFAULT_ENDPOINTS", "AsyncWireTransport", "CaptureJob", "CapturedBody", "EndpointMatcher",
    "ExchangeSink", "WireConfig", "WireHandle", "WireStats", "WireTransport", "current_handle",
    "flush", "install", "install_from_env", "run", "uninstall",
]  # fmt: skip

_LOG = logging.getLogger("fabric.wire")
_LOCK = threading.RLock()
_HANDLE: WireHandle | None = None
_DRAIN_SHARE = 0.75  # of the close budget; the rest delivers the shutdown loss records


def _after_fork_in_child() -> None:
    global _LOCK  # noqa: PLW0603
    _LOCK = threading.RLock()  # another parent thread may have held it


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


@dataclasses.dataclass(frozen=True, slots=True)
class WireStats:
    """Counters only, never content."""

    matched: int
    submitted: int
    dropped: int
    truncated: int
    internal_errors: int
    store_failures: int
    spans_emitted: int
    queue_depth: int
    inflight_bytes: int


class WireHandle:
    """An installed wire tee, returned by :func:`install`."""

    def __init__(self, config: WireConfig, tee: WireTee, *, patched: bool) -> None:
        self.config, self._tee, self._patched = config, tee, patched
        self._result: bool | None = None  # set once closed

    @property
    def allocator(self) -> SourceAllocator:
        return self._tee.allocator

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Wait for queued exchanges, then emit pending losses and heartbeats."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        drained = self._tee.flush(timeout_s)
        return self._tee.loss.flush(max(0.0, deadline - time.monotonic())) and drained

    def close(self, timeout_s: float | None = None) -> bool:
        """Restore httpx, drain, report what missed the deadline as losses, flush. Idempotent.

        Returns within ``timeout_s`` even when the store or the exporter is blocked.
        """
        global _HANDLE  # noqa: PLW0603
        from . import _transport  # noqa: PLC0415

        with _LOCK:
            if self._result is not None:
                return self._result
            self._result = False
            if _HANDLE is self:
                _HANDLE = _transport._ACTIVE = None
                if self._patched:
                    _transport.unpatch_httpx()
        with contextlib.suppress(Exception):
            atexit.unregister(self._atexit_close)
            timeout = self.config.shutdown_timeout_s if timeout_s is None else timeout_s
            deadline = time.monotonic() + max(0.0, timeout)
            drained = self._tee.close(timeout * _DRAIN_SHARE)
            self._result = self._tee.loss.flush(max(0.0, deadline - time.monotonic())) and drained
        return self._result

    def uninstall(self) -> None:
        self.close()

    def stats(self) -> WireStats:
        values = self._tee.stats()
        return WireStats(**{f.name: values.get(f.name, 0) for f in dataclasses.fields(WireStats)})

    def _atexit_close(self) -> None:
        with contextlib.suppress(BaseException):  # interpreter shutdown
            self.close()


def install(config: WireConfig | None = None, /, **overrides: Any) -> WireHandle:
    """Install the tee; idempotent. Invalid configuration raises before anything is patched."""
    global _HANDLE  # noqa: PLW0603
    from .._loss import get_loss_emitter  # noqa: PLC0415
    from . import _transport  # noqa: PLC0415

    with _LOCK:
        if _HANDLE is not None:
            _LOG.warning("fabric.wire: already installed; returning the active handle")
            return _HANDLE
        config = dataclasses.replace(config, **overrides) if config else WireConfig(**overrides)
        loss = get_loss_emitter()
        if config.tracer_provider is not None:
            loss.set_tracer_provider(config.tracer_provider)
        allocator = get_allocator("wire", source_id=config.source_id)
        tee = _transport.WireTee(config, allocator=allocator, loss=loss)
        _HANDLE = WireHandle(config, tee, patched=config.patch_httpx)
        if config.patch_httpx:
            _transport.patch_httpx()
        _transport._ACTIVE = tee
        atexit.register(_HANDLE._atexit_close)
        return _HANDLE


def install_from_env(environ: Mapping[str, str] | None = None) -> WireHandle | None:
    """Install from ``FABRIC_*`` variables (spec 042 §3); invalid config logs one warning.

    Loss and heartbeat records always use the private always-on provider; with
    ``FABRIC_WIRE_TRACER=global`` only exchange spans use the host's provider (losses
    fall back to it only when no OTLP endpoint is configured for the private one).
    """
    try:
        from .._loss import get_loss_emitter  # noqa: PLC0415
        from ..tracing import build_private_provider, otlp_endpoint_configured  # noqa: PLC0415
        from ._config import config_from_env  # noqa: PLC0415

        config, tracer_mode = config_from_env(os.environ if environ is None else environ)
        if tracer_mode == "private" or otlp_endpoint_configured():
            private = build_private_provider()
            get_loss_emitter().set_tracer_provider(private)
            if tracer_mode == "private":
                config = dataclasses.replace(config, tracer_provider=private)
        return install(config)
    except Exception as exc:
        _LOG.warning("fabric.wire: capture not installed (%s)", type(exc).__name__)
        return None


def current_handle() -> WireHandle | None:
    return _HANDLE


def uninstall() -> None:
    if (handle := _HANDLE) is not None:
        handle.close()


def flush(timeout_s: float = 5.0) -> bool:
    return _HANDLE.flush(timeout_s) if _HANDLE is not None else True


def _run_marker(run_id: str) -> None:
    if (handle := _HANDLE) is not None:
        with contextlib.suppress(Exception):  # capture fails open
            handle._tee.loss.heartbeat(handle.allocator, run_id=run_id)


@contextlib.contextmanager
def run(run_id: str) -> Iterator[None]:
    """Scope an explicit run; heartbeat run markers on entry and exit bound its window."""
    with run_scope(run_id):
        _run_marker(run_id)
        try:
            yield
        finally:
            _run_marker(run_id)


def __getattr__(name: str) -> Any:
    if name in ("WireTransport", "AsyncWireTransport"):
        from . import _transport  # noqa: PLC0415

        return getattr(_transport, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
