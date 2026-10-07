# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""In-process LLM wire capture (spec 042, Phase 1).

Tees the exact request and response bytes of model API calls made through
``httpx`` — which the OpenAI and Anthropic Python SDKs and LiteLLM use —
without framework knowledge. Bytes go to the customer-controlled content-v2
byte store; OTLP carries only digests, ids and metadata.

Importing this module patches nothing and does not import ``httpx``.
Capture starts only after an explicit :func:`install` (or the env-gated
autoload in ``fabric/_autoload/sitecustomize.py``). Capture fails open: the
host's HTTP traffic is never altered, delayed or failed by the tee.
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
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .._sequence import SequenceAllocator, run_scope
from ._config import DEFAULT_ENDPOINTS, WireConfig
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ExchangeSink, StitchKeys

if TYPE_CHECKING:
    from ._transport import AsyncWireTransport, WireTee, WireTransport

__all__ = [
    "DEFAULT_ENDPOINTS",
    "AsyncWireTransport",
    "CaptureJob",
    "CapturedBody",
    "EndpointMatcher",
    "ExchangeSink",
    "StitchKeys",
    "WireConfig",
    "WireHandle",
    "WireStats",
    "WireTransport",
    "current_handle",
    "flush",
    "install",
    "install_from_env",
    "run",
    "uninstall",
]

_LOG = logging.getLogger("fabric.wire")
_LOCK = threading.RLock()
_HANDLE: WireHandle | None = None


@dataclass(frozen=True, slots=True)
class WireStats:
    """Counters only — never content."""

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
    """An installed wire tee. Returned by :func:`install`."""

    def __init__(self, config: WireConfig, tee: WireTee, *, patched: bool) -> None:
        self.config = config
        self._tee = tee
        self._patched = patched
        self._closed = False
        self._close_result = True
        self._lock = threading.Lock()

    @property
    def allocator(self) -> SequenceAllocator:
        """The ``wire`` sequence allocator this tee sequences exchanges with."""
        return self._tee.allocator

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Wait for queued exchanges, then emit pending loss records and watermarks."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        drained = self._tee.flush(timeout_s)
        remaining = max(0.0, deadline - time.monotonic())
        loss_ok = self._tee.loss.flush(remaining)
        provider = self.config.tracer_provider
        force_flush = getattr(provider, "force_flush", None) if provider is not None else None
        if callable(force_flush):
            remaining_ms = max(int((deadline - time.monotonic()) * 1000), 0)
            try:
                loss_ok = bool(force_flush(remaining_ms)) and loss_ok
            except Exception:
                loss_ok = False
        return drained and loss_ok

    def close(self, timeout_s: float | None = None) -> bool:
        """Stop capturing (restoring patched methods), drain, and flush. Idempotent."""
        with self._lock:
            if self._closed:
                return self._close_result
            self._closed = True
        timeout = self.config.shutdown_timeout_s if timeout_s is None else timeout_s
        self._deactivate()
        with contextlib.suppress(Exception):
            atexit.unregister(self._atexit_close)
        result = False
        try:
            deadline = time.monotonic() + max(0.0, timeout)
            drained = self._tee.close(timeout)
            remaining = max(0.0, deadline - time.monotonic())
            flushed = self._tee.loss.flush(remaining)
            result = drained and flushed
        except Exception:
            result = False
        self._close_result = result
        return result

    def uninstall(self) -> None:
        """Restore the original httpx methods and close this handle."""
        self.close()

    def stats(self) -> WireStats:
        values = self._tee.stats()
        return WireStats(
            **{f.name: int(values.get(f.name, 0)) for f in dataclasses.fields(WireStats)}
        )

    def _deactivate(self) -> None:
        global _HANDLE  # noqa: PLW0603
        from . import _transport  # noqa: PLC0415

        with _LOCK:
            if _HANDLE is self:
                _HANDLE = None
                _transport.set_active_tee(None)
                if self._patched:
                    _transport.unpatch_httpx()

    def _atexit_close(self) -> None:
        with contextlib.suppress(BaseException):  # interpreter shutdown
            self.close()


def install(config: WireConfig | None = None, /, **overrides: Any) -> WireHandle:
    """Install the wire tee; idempotent (a second call returns the active handle).

    ``overrides`` replace fields of ``config`` (or of a default
    :class:`WireConfig`). Invalid configuration raises ``ValueError`` before
    anything is patched.
    """
    global _HANDLE  # noqa: PLW0603
    with _LOCK:
        if _HANDLE is not None:
            _LOG.warning("fabric.wire: already installed; returning the active handle")
            return _HANDLE
        if config is None:
            config = WireConfig(**overrides)
        elif overrides:
            config = dataclasses.replace(config, **overrides)
        if not isinstance(config, WireConfig):
            raise TypeError("config must be a WireConfig")
        from .._loss import get_loss_emitter  # noqa: PLC0415
        from .._sequence import get_allocator  # noqa: PLC0415
        from . import _transport  # noqa: PLC0415

        loss = get_loss_emitter()
        if config.tracer_provider is not None:
            loss.set_tracer_provider(config.tracer_provider)
        allocator = get_allocator("wire", source_id=config.source_id)
        tee = _transport.WireTee(config, allocator=allocator, loss=loss)
        handle = WireHandle(config, tee, patched=config.patch_httpx)
        if config.patch_httpx:
            _transport.patch_httpx()
        _transport.set_active_tee(tee)
        _HANDLE = handle
        atexit.register(handle._atexit_close)
        return handle


def install_from_env(environ: Mapping[str, str] | None = None) -> WireHandle | None:
    """Install from ``FABRIC_*`` environment variables (spec 042 §3).

    Invalid configuration installs nothing and logs one warning (fail open).
    ``FABRIC_WIRE_TRACER=private`` (the default) emits through a private
    :class:`~opentelemetry.sdk.trace.TracerProvider` built from the standard
    ``OTEL_EXPORTER_OTLP_*`` variables; it never sets the global provider.
    """
    env = os.environ if environ is None else environ
    try:
        from ._config import config_from_env  # noqa: PLC0415

        config, tracer_mode = config_from_env(env)
        if tracer_mode == "private":
            from ..tracing import build_private_provider  # noqa: PLC0415

            config = dataclasses.replace(config, tracer_provider=build_private_provider())
        handle = install(config)
        tenant_id = env.get("FABRIC_TENANT_ID") or None
        if tenant_id:
            from .._loss import configure_loss_emitter  # noqa: PLC0415

            configure_loss_emitter(tenant_id=tenant_id)
        return handle
    except Exception as exc:
        _LOG.warning(
            "fabric.wire: capture not installed (invalid configuration: %s)",
            type(exc).__name__,
        )
        return None


def current_handle() -> WireHandle | None:
    """The installed handle, if any."""
    return _HANDLE


def uninstall() -> None:
    """Uninstall the active handle, if any."""
    handle = _HANDLE
    if handle is not None:
        handle.uninstall()


def flush(timeout_s: float = 5.0) -> bool:
    """Flush the active handle; ``True`` when nothing is installed."""
    handle = _HANDLE
    return handle.flush(timeout_s) if handle is not None else True


@contextmanager
def run(run_id: str) -> Iterator[None]:
    """Scope an explicit run; on exit emit a run-close watermark (spec 042 §7).

    The run's ``run_sequence`` counter is *not* reset on exit: reusing the
    same run id later (a retried job, one id per chat session, nested or
    concurrent scopes, a task that outlives the block) keeps numbering where
    it left off, so exchanges never collide on ``run_sequence``. Each exit
    declares the run's high-water ``run_sequence`` at that moment; the
    verifier uses the latest one.
    """
    with run_scope(run_id):
        try:
            yield
        finally:
            handle = _HANDLE
            if handle is not None:
                try:
                    from .._loss import get_loss_emitter  # noqa: PLC0415

                    high_water = handle.allocator.run_high_water(run_id)
                    get_loss_emitter().emit_watermark(
                        handle.allocator,
                        run_id=run_id,
                        run_high_water=-1 if high_water is None else high_water,
                    )
                except Exception:  # noqa: S110 - capture fails open
                    pass


def __getattr__(name: str) -> Any:
    if name in ("WireTransport", "AsyncWireTransport"):
        from . import _transport  # noqa: PLC0415

        return getattr(_transport, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
