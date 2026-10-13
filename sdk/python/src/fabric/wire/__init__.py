# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""In-process LLM wire capture (specs 042, 043). Importing it patches nothing; :func:`install`
or the env-gated autoload starts capture, which always fails open."""

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

from .._sequence import RunScope, SourceAllocator, get_allocator, run_scope
from ._config import DEFAULT_ENDPOINTS, WireConfig
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ExchangeSink

if TYPE_CHECKING:
    from opentelemetry.sdk.trace.export import SpanExporter

    from ._content import NodeContentClient
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
    spooled: int = 0
    spool_bytes: int = 0
    spool_full_drops: int = 0
    delivered: int = 0
    send_retries: int = 0
    content_rejected: int = 0
    quarantined: int = 0
    markers_dropped: int = 0


class WireHandle:
    """An installed wire tee, returned by :func:`install`."""

    def __init__(self, config: WireConfig, tee: WireTee, *, patched: bool) -> None:
        self.config, self._tee, self._patched = config, tee, patched
        self._result: bool | None = None  # set once closed

    @property
    def allocator(self) -> SourceAllocator:
        return self._tee.allocator

    def _deliver(self, timeout_s: float, *, closing: bool) -> bool:
        """Through the spool sender, else the exchange (or global) and loss providers."""
        from opentelemetry import trace  # noqa: PLC0415

        if (sender := self._tee.sender) is not None:  # undelivered records stay on disk
            return sender.close(timeout_s) if closing else sender.flush(timeout_s)
        providers = (self.config.tracer_provider or trace.get_tracer_provider(),)
        return self._tee.loss.flush(timeout_s, also=providers)

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Deliver queued exchanges, losses and heartbeats within ``timeout_s``; ``False`` when
        anything was not delivered in time or a host provider sampled it away."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        drained = self._tee.flush(timeout_s)
        return self._deliver(max(0.0, deadline - time.monotonic()), closing=False) and drained

    def close(self, timeout_s: float | None = None) -> bool:
        """Restore httpx, drain, report what missed the deadline as losses, deliver; within
        ``timeout_s`` even when the store, disk or exporter is blocked. Idempotent."""
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
            self._result = self._deliver(remaining, closing=True) and drained
        return self._result

    def uninstall(self) -> None:
        self.close()

    def stats(self) -> WireStats:
        values = self._tee.stats()
        return WireStats(**{f.name: values.get(f.name, 0) for f in dataclasses.fields(WireStats)})

    def _atexit_close(self) -> None:
        """At exit, bounded: close, then shut Fabric's exporter/providers down on a helper
        thread unless delivery failed (the exporter is then presumed blocked)."""
        with contextlib.suppress(BaseException):  # interpreter shutdown
            from .. import _loss  # noqa: PLC0415
            from ..tracing import is_private_provider  # noqa: PLC0415

            deadline = time.monotonic() + max(0.0, self.config.shutdown_timeout_s)
            closed = self.close()
            loss, sender = self._tee.loss, self._tee.sender
            if sender is None:  # the direct path: the loss emitter's thread and provider
                closed = loss.close(max(0.0, deadline - time.monotonic())) and closed
            providers = {self.config.tracer_provider, loss.tracer_provider} - {None}
            targets: list[Any] = [sender.exporter] if sender else [
                p for p in providers if is_private_provider(p)]  # fmt: skip
            for target in targets if closed else ():  # else presumed blocked: skipped
                shutdown = lambda t=target: t.shutdown() or True  # noqa: E731
                _loss.run_bounded(shutdown, deadline, "fabric-shutdown")


def install(
    config: WireConfig | None = None, /, *, span_exporter: SpanExporter | None = None,
    content_client: NodeContentClient | None = None, **overrides: Any,
) -> WireHandle:  # fmt: skip
    """Install the tee (idempotent; invalid config raises first). The spool delivers through
    ``span_exporter`` and ``content_client`` (defaults: from the environment)."""
    global _HANDLE  # noqa: PLW0603
    from .._loss import get_loss_emitter  # noqa: PLC0415
    from . import _transport  # noqa: PLC0415
    from ._sender import build_sender  # noqa: PLC0415

    with _LOCK:
        if _HANDLE is not None:
            _LOG.warning("fabric.wire: already installed; returning the active handle")
            return _HANDLE
        config = dataclasses.replace(config, **overrides) if config else WireConfig(**overrides)
        loss = get_loss_emitter()
        sender = build_sender(config, loss, span_exporter, content_client)
        if config.tracer_provider is not None:
            loss.set_tracer_provider(config.tracer_provider)
        loss.exit_timeout_s = config.shutdown_timeout_s
        allocator = get_allocator("wire", source_id=config.source_id)
        tee = _transport.WireTee(config, allocator=allocator, loss=loss, sender=sender)
        loss.attach(sender.wake if sender is not None else None)
        if sender is not None:  # starts draining: replays what earlier processes left
            sender.wake()
        _HANDLE = WireHandle(config, tee, patched=config.patch_httpx)
        if config.patch_httpx:
            _transport.patch_httpx()
        _transport._ACTIVE = tee
        atexit.register(_HANDLE._atexit_close)
        return _HANDLE


def install_from_env(environ: Mapping[str, str] | None = None) -> WireHandle | None:
    """Install from ``FABRIC_*`` (042 §3, 043 §1); invalid settings log one warning naming the
    error class only. Without a spool losses use the private provider (global mode: exchanges
    the host's, and losses too without an OTLP endpoint)."""
    try:
        from .._loss import get_loss_emitter  # noqa: PLC0415
        from ..tracing import build_private_provider, otlp_endpoint_configured  # noqa: PLC0415
        from ._config import config_from_env  # noqa: PLC0415

        config, tracer_mode = config_from_env(os.environ if environ is None else environ)
        if config.spool_dir is None and (tracer_mode == "private" or otlp_endpoint_configured()):
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


@contextlib.contextmanager
def run(run_id: str) -> Iterator[None]:
    """Scope an explicit run. Each entry is a new scope (``fabric.run.scope_id``) whose
    ``run_start``/``run_end`` markers bound the calls started inside it (spec 043 §6)."""
    handle = _HANDLE

    def mark(scope: RunScope, kind: Literal["run_start", "run_end"]) -> None:
        if handle is not None:
            with contextlib.suppress(Exception):  # capture fails open
                handle._tee.loss.heartbeat(handle.allocator, kind=kind, scope=scope)

    with run_scope(run_id) as scope:
        mark(scope, "run_start")
        try:
            yield
        finally:
            mark(scope, "run_end")


def __getattr__(name: str) -> Any:
    if name in ("WireTransport", "AsyncWireTransport"):
        from . import _transport  # noqa: PLC0415

        return getattr(_transport, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
