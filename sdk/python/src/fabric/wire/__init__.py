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
from typing import TYPE_CHECKING, Any, Literal

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

    def _exchange_providers(self) -> tuple[object, ...]:
        """Where exchange spans go: the configured provider, else the host's global one."""
        from opentelemetry import trace  # noqa: PLC0415

        return (self.config.tracer_provider or trace.get_tracer_provider(),)

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Wait for queued exchanges, force-flush the exchange provider (the host's in global
        mode), then emit and export pending losses and heartbeats; all within ``timeout_s``.

        ``False`` when anything was not delivered in time, or a loss/heartbeat record was
        sampled away by a host-supplied provider.
        """
        deadline = time.monotonic() + max(0.0, timeout_s)
        drained = self._tee.flush(timeout_s)
        remaining = max(0.0, deadline - time.monotonic())
        return self._tee.loss.flush(remaining, also=self._exchange_providers()) and drained

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
            self._tee.loss.final(self.allocator)  # this epoch allocates nothing more
            remaining = max(0.0, deadline - time.monotonic())
            flushed = self._tee.loss.flush(remaining, also=self._exchange_providers())
            self._result = flushed and drained
        return self._result

    def uninstall(self) -> None:
        self.close()

    def stats(self) -> WireStats:
        values = self._tee.stats()
        return WireStats(**{f.name: values.get(f.name, 0) for f in dataclasses.fields(WireStats)})

    def _atexit_close(self) -> None:
        """Interpreter exit: everything within ``shutdown_timeout_s``, nothing inline.

        Close (drain, ``final`` heartbeat, flush), close the loss emitter, then shut down
        Fabric's private providers, each on a helper thread; when the flush did not
        succeed the exporter is presumed blocked and the shutdown is skipped.
        """
        with contextlib.suppress(BaseException):  # interpreter shutdown
            from .. import _loss  # noqa: PLC0415
            from ..tracing import is_private_provider  # noqa: PLC0415

            deadline = time.monotonic() + max(0.0, self.config.shutdown_timeout_s)
            closed = self.close()
            loss = self._tee.loss
            flushed = loss.close(max(0.0, deadline - time.monotonic())) and closed
            providers = {self.config.tracer_provider, loss.tracer_provider} - {None}
            for provider in providers if flushed else ():
                if is_private_provider(provider):
                    shutdown = lambda p=provider: p.shutdown() or True  # noqa: E731
                    _loss.run_bounded(shutdown, deadline, "fabric-provider-shutdown")


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
        loss.exit_timeout_s = config.shutdown_timeout_s
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


def _run_marker(run_id: str, kind: Literal["run_start", "run_end"]) -> None:
    if (handle := _HANDLE) is not None:
        with contextlib.suppress(Exception):  # capture fails open
            handle._tee.loss.heartbeat(handle.allocator, kind=kind, run_id=run_id)


@contextlib.contextmanager
def run(run_id: str) -> Iterator[None]:
    """Scope an explicit run; ``run_start``/``run_end`` heartbeats bound its window."""
    with run_scope(run_id):
        _run_marker(run_id, "run_start")
        try:
            yield
        finally:
            _run_marker(run_id, "run_end")


def __getattr__(name: str) -> Any:
    if name in ("WireTransport", "AsyncWireTransport"):
        from . import _transport  # noqa: PLC0415

        return getattr(_transport, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
