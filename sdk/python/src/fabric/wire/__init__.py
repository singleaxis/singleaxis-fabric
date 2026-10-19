# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""In-process LLM wire capture (specs 047, 048). Importing it patches nothing; :func:`install`
or the env-gated autoload starts capture, which always fails open."""

from __future__ import annotations

import atexit
import contextlib
import dataclasses
import functools
import logging
import os
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING, Any, Literal

from .._sequence import (
    RunScope,
    SourceAllocator,
    default_source_id,
    encode_opaque_id,
    get_allocator,
    id_key_from_env,
    key_id,
    labels_from_env,
    run_scope,
    source_label,
)
from ._config import DEFAULT_ENDPOINTS, WireConfig
from ._keys import SPOOL_KEY_BYTES, TOKEN_KEY_MIN_BYTES, key_from_env
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ExchangeSink
from ._policy import ContentGate, decide, policy_from_env
from ._protect import Transformation

if TYPE_CHECKING:
    from opentelemetry.sdk.trace.export import SpanExporter

    from .._loss import PrivateFallback
    from ._content import NodeContentClient
    from ._transport import AsyncWireTransport, WireTee, WireTransport

__all__ = [
    "DEFAULT_ENDPOINTS", "AsyncWireTransport", "CaptureJob", "CapturedBody", "EndpointMatcher",
    "ExchangeSink", "Transformation", "WireConfig", "WireHandle", "WireStats", "WireTransport",
    "current_handle",
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
    # 1 while the spool's directory barrier is not established (spec 048 §2): spooled
    # records are delivered but not durable against power loss, and flush()/close()
    # return False; failed attempts so far.
    spool_undurable: int = 0
    spool_barrier_failures: int = 0
    # Matched requests deferred to an explicit model call (fabric._capture_scope); a
    # local counter only, never exported as telemetry.
    deferred_to_explicit: int = 0
    # Exchange spans refused because the provider had a Fabric-protected route and no
    # private provider was available (each is a ``span_dropped`` loss).
    spans_refused: int = 0
    # Spool records sealed under another key, left for a process holding it (049 §7.8).
    spool_undecryptable: int = 0


class WireHandle:
    """An installed wire tee, returned by :func:`install`."""

    def __init__(
        self, config: WireConfig, tee: WireTee, *, patched: bool,
        fallback: PrivateFallback | None = None, gate: ContentGate | None = None,
    ) -> None:  # fmt: skip
        from .._loss import PrivateFallback  # noqa: PLC0415

        self.config, self._tee, self._patched = config, tee, patched
        self.gate = gate
        self._fallback = fallback or PrivateFallback(None)
        self._result: bool | None = None  # set once closed

    def status(self) -> dict[str, Any]:
        """The install's content state (049 §7.3): profile, ``content_capture`` and its
        reason, policy reference, pseudonym mode and key id, spool encryption. Values
        only, never a key, path or content; ``{}`` for a handle built without a gate."""
        return {} if self.gate is None else self.gate.status()

    @property
    def allocator(self) -> SourceAllocator:
        return self._tee.allocator

    def _deliver(self, timeout_s: float, *, closing: bool) -> bool:
        """Through the spool sender, else the exchange (or global) and loss providers."""
        from opentelemetry import trace  # noqa: PLC0415

        if (sender := self._tee.sender) is not None:  # undelivered records stay on disk
            return sender.close(timeout_s) if closing else sender.flush(timeout_s)
        # Resolved now: the host may have installed a Fabric-protected global provider since
        # install. A refused route (``None``) is never reported as delivered.
        provider = self._tee.pipeline.resolved_provider()
        providers = (provider,) if provider is not None else (trace.get_tracer_provider(),)
        delivered = self._tee.loss.flush(timeout_s, also=providers)
        return delivered and provider is not None

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
            providers = {self.config.tracer_provider, loss.tracer_provider,
                         self._fallback.provider} - {None}  # fmt: skip
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
    from .._loss import PrivateFallback, get_loss_emitter  # noqa: PLC0415
    from . import _transport  # noqa: PLC0415
    from ._sender import build_sender  # noqa: PLC0415

    with _LOCK:
        if _HANDLE is not None:
            _LOG.warning("fabric.wire: already installed; returning the active handle")
            return _HANDLE
        config = dataclasses.replace(config, **overrides) if config else WireConfig(**overrides)
        if config.id_key is None and (key := id_key_from_env(os.environ)) is not None:
            config = dataclasses.replace(config, id_key=key)
        if config.labels is None:
            config = dataclasses.replace(config, labels=labels_from_env(os.environ))
        config = _protection_from_env(config)
        gate = _gate(config)
        explicit = config.tracer_provider is not None
        if config.spool_dir is None and (
            _protected_provider(config.tracer_provider) if explicit else _protected_global()
        ):
            # D3: a Fabric-protected provider (the global one, or one passed in) never
            # carries wire spans (its metadata-only projection would erase them).
            from ..tracing import (  # noqa: PLC0415
                build_private_provider,
                capture_service_name,
                otlp_endpoint_configured,
            )

            if not otlp_endpoint_configured():
                raise ValueError(
                    "a Fabric-protected tracer provider cannot carry wire spans"
                    if explicit
                    else "a Fabric-protected global tracer provider cannot carry wire spans"
                )
            private = build_private_provider(service_name=capture_service_name(
                id_key=config.id_key, clear=config.labels == "clear"))  # fmt: skip
            config = dataclasses.replace(config, tracer_provider=private)
        loss = get_loss_emitter()
        sender = build_sender(config, loss, span_exporter, content_client)
        if config.tracer_provider is not None:
            loss.set_tracer_provider(config.tracer_provider)
        loss.exit_timeout_s = config.shutdown_timeout_s
        # The same rule at emit time: the host may install a protected provider later.
        fallback = PrivateFallback(
            None if sender is not None else functools.partial(_fallback_provider, config, loss)
        )
        loss.set_fallback(fallback)
        allocator = get_allocator("wire", source_id=_source_id(config, gate))
        tee = _transport.WireTee(
            config, allocator=allocator, loss=loss, sender=sender, fallback=fallback, gate=gate
        )
        loss.attach(sender.wake if sender is not None else None)
        if sender is not None:  # starts draining: replays what earlier processes left
            sender.wake()
        _HANDLE = WireHandle(config, tee, patched=config.patch_httpx, fallback=fallback, gate=gate)
        _log_gate(gate)
        if config.patch_httpx:
            _transport.patch_httpx()
        _transport._ACTIVE = tee
        atexit.register(_HANDLE._atexit_close)
        if _truthy(os.environ.get("FABRIC_CAPTURE_LLM_CONTENT")):
            _LOG.warning(
                "fabric.wire: FABRIC_CAPTURE_LLM_CONTENT does not affect wire capture; "
                "wire already stores content off telemetry"
            )
        return _HANDLE


def _protection_from_env(config: WireConfig) -> WireConfig:
    """Fill the capture policy and keys an explicit config left unset from ``FABRIC_*``
    (049 §7.3, §7.7, §7.8); a malformed value raises (fixed text, never the value)."""
    env = os.environ
    changes: dict[str, Any] = {}
    if config.capture_policy is None and (policy := policy_from_env(env)) is not None:
        changes["capture_policy"] = policy
    if config.tokenization_key is None:
        token = key_from_env(env, "FABRIC_TOKENIZATION_KEY", minimum=TOKEN_KEY_MIN_BYTES)
        if token is not None:
            changes["tokenization_key"] = token
    if config.spool_key is None:
        spool = key_from_env(env, "FABRIC_WIRE_SPOOL_KEY", exact=SPOOL_KEY_BYTES)
        if spool is not None:
            changes["spool_key"] = spool
    return dataclasses.replace(config, **changes) if changes else config


def _gate(config: WireConfig) -> ContentGate:
    return decide(
        node=config.content_endpoint is not None, store=config.store is not None,
        policy=config.capture_policy, id_key=config.id_key, spool=config.spool_dir is not None,
        spool_key=config.spool_key is not None,
        key_id=key_id(config.id_key) if config.id_key is not None else None,
    )  # fmt: skip


def _log_gate(gate: ContentGate) -> None:
    """049 §7.3: never blocked, but not silent: every install logs a disabled content state,
    by reason only (class-only text, no values)."""
    if gate.content_capture == "disabled":
        _LOG.warning(
            "fabric.wire: content capture disabled (%s, %s profile); metadata capture continues",
            gate.reason, gate.profile,
        )  # fmt: skip


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def _protected_provider(provider: Any) -> bool:
    """Whether ``provider`` has a Fabric-protected route (see :func:`_protected_global`)."""
    try:
        from ..tracing import has_protected_route  # noqa: PLC0415

        return has_protected_route(provider)
    except Exception:
        return False


def _fallback_provider(config: WireConfig, loss: Any) -> Any:
    """The private provider for records a protected route would erase: the loss emitter's
    when it is private, else a new one when an OTLP endpoint is set, else ``None``."""
    from ..tracing import (  # noqa: PLC0415
        build_private_provider,
        capture_service_name,
        is_private_provider,
        otlp_endpoint_configured,
    )

    if is_private_provider(current := loss.tracer_provider):
        return current
    if config.tracer_provider is not None and is_private_provider(config.tracer_provider):
        return config.tracer_provider
    if not otlp_endpoint_configured():
        return None
    return build_private_provider(service_name=capture_service_name(
        id_key=config.id_key, clear=config.labels == "clear"))  # fmt: skip


def _protected_global() -> bool:
    """Whether the global tracer provider has a Fabric-protected route (a
    ``MetadataOnlySpanExporter`` from ``install_default_provider``, content opt-in included).
    Wire never adds a pass-through to that projection: a scope-based one would be spoofable."""
    try:
        from ..tracing import trace_export_protection_status  # noqa: PLC0415

        status = trace_export_protection_status()
        return bool(status.get("protected_routes") or status.get("content_opt_in_routes"))
    except Exception:
        return False


def _source_id(config: WireConfig, gate: ContentGate | None = None) -> str:
    """The emitted source id (J1): the configured, ``FABRIC_SOURCE_ID`` or default label as
    its ``s-`` pseudonym, unchanged only under ``labels="clear"``. In the production profile
    without ``FABRIC_WIRE_ID_KEY`` no value derived from a host- or caller-supplied id leaves
    the process (049 §2.9 rule 5): the source id is random per process."""
    if gate is not None and gate.profile == "production" and config.id_key is None:
        return "s-" + uuid.uuid4().hex
    chosen = config.source_id or os.environ.get("FABRIC_SOURCE_ID") or default_source_id("wire")
    return source_label(encode_opaque_id(chosen), config.id_key, clear=config.labels == "clear")


def install_from_env(environ: Mapping[str, str] | None = None) -> WireHandle | None:
    """Install from ``FABRIC_*`` (047 §3, 048 §1); invalid settings log one warning naming the
    error class only. Without a spool losses use the private provider (global mode: exchanges
    the host's, and losses too without an OTLP endpoint). A Fabric-protected global provider
    never carries wire spans: global mode then resolves to the private provider when an OTLP
    endpoint is set, and otherwise capture is not installed (one class-only warning)."""
    try:
        from .._loss import get_loss_emitter  # noqa: PLC0415
        from ..tracing import (  # noqa: PLC0415
            build_private_provider,
            capture_service_name,
            otlp_endpoint_configured,
        )
        from ._config import config_from_env  # noqa: PLC0415

        config, tracer_mode = config_from_env(os.environ if environ is None else environ)
        if config.spool_dir is None and tracer_mode == "global" and _protected_global():
            # D3: a Fabric-protected global provider never carries wire spans.
            if not otlp_endpoint_configured():
                _LOG.warning(
                    "fabric.wire: capture not installed (%s)", "ProtectedGlobalTracerProvider"
                )
                return None
            tracer_mode = "private"
        if config.spool_dir is None and (tracer_mode == "private" or otlp_endpoint_configured()):
            private = build_private_provider(service_name=capture_service_name(
                id_key=config.id_key, clear=config.labels == "clear"))  # fmt: skip
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
    ``run_start``/``run_end`` markers bound the calls started inside it (spec 048 §6).
    ``run_id`` is emitted only as its ``r-`` pseudonym (keyed by ``FABRIC_WIRE_ID_KEY``); in
    the production profile without that key, only the generated source fallback."""
    handle = _HANDLE

    def mark(scope: RunScope, kind: Literal["run_start", "run_end"]) -> None:
        if handle is not None:
            with contextlib.suppress(Exception):  # capture fails open
                handle._tee.loss.heartbeat(handle.allocator, kind=kind, scope=scope)

    key = handle.config.id_key if handle is not None else None
    emitted = None
    if (
        handle is not None
        and handle.gate is not None
        and (handle.gate.profile == "production" and key is None)
    ):  # 049 §2.9 rule 5: the generated source fallback, nothing derived from run_id
        allocator = handle.allocator
        emitted = encode_opaque_id(f"source:{allocator.source_id}:{allocator.epoch}")
    with run_scope(run_id, key, emitted=emitted) as scope:
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
