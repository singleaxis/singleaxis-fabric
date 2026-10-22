# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""In-process LLM wire capture (specs 047, 048) and the run structure of the records input
(spec 050). Importing it patches nothing; :func:`install` or the env-gated autoload starts
capture, which always fails open.

**Records-only install** (050 §3.1). An application with no model HTTP traffic to tee
installs with ``install(patch_httpx=False, patch_aiohttp=False)`` (or ``FABRIC_WIRE_HTTPX=0``
with ``FABRIC_WIRE_AIOHTTP=0``). It gets the same spool, allocator, manifests, segments and
sender, and therefore the same delivery guarantee, for the records input alone; the capture
manifest reports the wire points ``installed_inactive``.

**Runs** (050 §3.6). :func:`run` scopes a run; :func:`resume_token` /
:func:`resume_tokens` seal its open segment and return ``fr3/`` tokens that continue it in
another process (``run(resume=…)``, env ``FABRIC_RUN_RESUME_TOKEN``, or ``baggage``
``fabric.resume`` across a service boundary); :func:`end_run` ends a run from its tokens.
A clear run id is mapped before it is emitted (pseudonymous by default) and is never put in
a token: only Fabric-emitted tokens cross a process boundary."""

from __future__ import annotations

import atexit
import contextlib
import dataclasses
import functools
import logging
import os
import secrets
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal, cast

from .._capture_types import COUNTERS, EndRunStatus, RunOutcome, ScopeStatus, StopReason, strict
from .._sequence import (
    OPAQUE_ID_RE,
    RunScope,
    SourceAllocator,
    current_run_scope,
    default_source_id,
    encode_opaque_id,
    get_allocator,
    id_key_from_env,
    key_id,
    labels_from_env,
    run_pseudonym,
    run_scope,
    source_label,
)
from ..redaction import RedactionService, Transformation
from ._config import DEFAULT_ENDPOINTS, WireConfig, migrate_plaintext_from_env
from ._keys import SPOOL_KEY_BYTES, TOKEN_KEY_MIN_BYTES, key_from_env
from ._model import CapturedBody, CaptureJob, EndpointMatcher, ExchangeSink
from ._policy import ContentGate, decide, policy_from_env

if TYPE_CHECKING:
    from opentelemetry.sdk.trace.export import SpanExporter

    from .._loss import PrivateFallback
    from .._records import RecordsInput
    from ._content import NodeContentClient
    from ._registration import Registration
    from ._transport import AsyncWireTransport, WireTee, WireTransport

__all__ = [
    "DEFAULT_ENDPOINTS", "AsyncWireTransport", "CaptureJob", "CapturedBody", "EndpointMatcher",
    "ExchangeSink", "RedactionService", "Transformation", "WireConfig", "WireHandle",
    "WireStats", "WireTransport",
    "current_handle",
    "end_run", "flush", "install", "install_from_env", "resume_token", "resume_tokens", "run",
    "uninstall",
]  # fmt: skip

_LOG = logging.getLogger("fabric.wire")
_LOCK = threading.RLock()
_HANDLE: WireHandle | None = None
_DRAIN_SHARE = 0.75  # of the close budget; the rest delivers the shutdown loss records


def _after_fork_in_child() -> None:
    global _LOCK  # noqa: PLW0603
    _LOCK = threading.RLock()  # another parent thread may have held it
    with contextlib.suppress(Exception):
        _use_proxy_snapshot()
    # A multiprocessing worker ends in os._exit (no atexit): its capture is closed by a
    # multiprocessing finalizer instead (agent matrix D1). Finalizers registered here would
    # be cleared by the worker's bootstrap, so one is registered by its after-forkers.
    util = sys.modules.get("multiprocessing.util")
    if (handle := _HANDLE) is not None and util is not None:
        with contextlib.suppress(Exception):
            util.register_after_fork(handle, _finalize_in_worker)


def _finalize_in_worker(handle: WireHandle) -> None:
    """In a forked multiprocessing worker: close capture when the worker exits normally
    (``util._exit_function``, before ``os._exit``), after the application's finalizers."""
    with contextlib.suppress(Exception):
        util = sys.modules["multiprocessing.util"]
        util.Finalize(None, handle._atexit_close, exitpriority=-100)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)

# The system proxy configuration as read at install (macOS only; see _prime_fork_safety).
_PROXY_SNAPSHOT: tuple[dict[str, Any], dict[str, str]] | None = None


def _prime_fork_safety() -> None:
    """Keep ``fork`` as safe as it was without capture (049 §7.1, agent matrix D2). On
    macOS the system proxy lookup (``urllib.request.getproxies``/``proxy_bypass``, made by
    httpx and requests with no proxy variable set) goes through SystemConfiguration. In a
    forked child of a multithreaded parent it either aborts under the Objective-C
    fork-safety check (first lookup in the child) or reuses the parent's session and
    intermittently segfaults (looked up in the parent before). Fabric's threads make the
    host multithreaded, so the configuration is read once here, on the installing thread
    before any Fabric thread starts, and a forked child answers urllib's two lookups from
    that snapshot instead (:func:`_after_fork_in_child`): the values the parent saw at
    install, never a crash. Fabric's own delivery never consults them (pinned proxies)."""
    global _PROXY_SNAPSHOT  # noqa: PLW0603
    if _PROXY_SNAPSHOT is not None or sys.platform != "darwin":
        return
    with contextlib.suppress(Exception):
        import _scproxy  # type: ignore[import-not-found]  # noqa: PLC0415
        import urllib.request  # noqa: PLC0415

        _PROXY_SNAPSHOT = (dict(_scproxy._get_proxy_settings()), dict(_scproxy._get_proxies()))
        _ = urllib.request.getproxies  # imported now: a child patches it, never re-imports


def _use_proxy_snapshot() -> None:
    """In a forked child: urllib's SystemConfiguration lookups return the snapshot."""
    if (snapshot := _PROXY_SNAPSHOT) is None:
        return
    request = sys.modules.get("urllib.request")
    if request is None or not hasattr(request, "_get_proxies"):
        return
    settings, proxies = snapshot
    setattr(request, "_get_proxy_settings", lambda: {  # noqa: B010
        k: list(v) if isinstance(v, list) else v for k, v in settings.items()})  # fmt: skip
    setattr(request, "_get_proxies", lambda: dict(proxies))  # noqa: B010


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
    # Plaintext spool records sealed in place by the explicit local migration (049 §7.8).
    spool_migrated: int = 0
    # Calls to the customer-run redaction service (049 §7.7 rule 4; contracts/redaction/v1)
    # that timed out, were refused at the in-flight bound, or failed otherwise; each
    # withheld its content (protection_failed).
    redaction_timeouts: int = 0
    redaction_saturated: int = 0
    redaction_failures: int = 0
    # Model calls sent through a client wire capture does not tee (requests, urllib3): each
    # is an ``uninstrumented_client`` loss (agent matrix D4).
    uninstrumented_calls: int = 0
    # Exchanges lost because the spool's volume was full (ENOSPC/EDQUOT; ``disk_full``
    # losses, chaos report D1); run markers not spooled yet (retried, kept in the spool's
    # loss ledger); loss and marker records a drainer recovered from the ledger slots of
    # processes that died with them unspooled.
    disk_full_drops: int = 0
    markers_held: int = 0
    ledger_recovered: int = 0


class WireHandle:
    """An installed wire tee, returned by :func:`install`."""

    def __init__(
        self, config: WireConfig, tee: WireTee | None, *, patched: bool,
        fallback: PrivateFallback | None = None, gate: ContentGate | None = None,
    ) -> None:  # fmt: skip
        """``tee=None``: capture is disabled (``OTEL_SDK_DISABLED``): nothing is patched,
        no thread runs, nothing is recorded, and :meth:`status` says so."""
        from .._loss import PrivateFallback  # noqa: PLC0415

        self.config, self._tee_or_none, self._patched = config, tee, patched
        self.gate = gate
        self._fallback = fallback or PrivateFallback(None)
        self._result: bool | None = None  # set once closed
        # 050 §3.1-§3.2: the epoch registration and the records input of this install
        # (``None`` until WP-10 and WP-11a build them).
        self.registration: Registration | None = None
        self.records: RecordsInput | None = None

    @property
    def _tee(self) -> WireTee:
        if (tee := self._tee_or_none) is None:
            raise RuntimeError("capture is disabled")
        return tee

    @property
    def capturing(self) -> bool:
        """``False`` when capture is disabled (``OTEL_SDK_DISABLED``)."""
        return self._tee_or_none is not None

    def status(self) -> dict[str, Any]:
        """The install's content state (049 §7.3): profile, ``content_capture`` and its
        reason, policy reference, pseudonym mode and key id, spool encryption. Values
        only, never a key, path or content; ``{}`` for a handle built without a gate.
        ``spool_key_id`` names the key sealing the spool (049 §7.8), never the key."""
        if self._tee_or_none is None:
            return {"capture": "disabled", "capture_reason": "otel_sdk_disabled"}
        if self.gate is None:
            return {}
        sender = self._tee.sender
        status = {"capture": "active", **self.gate.status(), **_client_status(self.config),
                  "spool_key_id": sender.spool.key_id if sender is not None else None}  # fmt: skip
        if sender is not None:  # 049 §7.8: never "encrypted" while plaintext records remain
            plaintext = sender.spool.plaintext_records()
            status["spool_plaintext_records"] = plaintext
            status["spool_encrypted"] = bool(status["spool_encrypted"]) and plaintext == 0
        status.update(_p1_status(self))
        return status

    @property
    def allocator(self) -> SourceAllocator:
        return self._tee.allocator

    def _deliver(self, timeout_s: float, *, closing: bool, exiting: bool = False) -> bool:
        """Through the spool sender, else the exchange (or global) and loss providers."""
        from opentelemetry import trace  # noqa: PLC0415

        if (sender := self._tee.sender) is not None:  # undelivered records stay on disk
            if closing:
                return sender.close(timeout_s, exiting=exiting)
            return sender.flush(timeout_s)
        # Resolved now: the host may have installed a Fabric-protected global provider since
        # install. A refused route (``None``) is never reported as delivered.
        provider = self._tee.pipeline.resolved_provider()
        providers = (provider,) if provider is not None else (trace.get_tracer_provider(),)
        delivered = self._tee.loss.flush(timeout_s, also=providers)
        return delivered and provider is not None

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Deliver queued exchanges, losses and heartbeats within ``timeout_s``; ``False`` when
        anything was not delivered in time or a host provider sampled it away."""
        if not self.capturing:
            return False  # nothing was recorded: no delivery can be claimed
        deadline = time.monotonic() + max(0.0, timeout_s)
        drained = self._tee.flush(timeout_s)
        return self._deliver(max(0.0, deadline - time.monotonic()), closing=False) and drained

    def close(self, timeout_s: float | None = None) -> bool:
        """Restore httpx, drain, report what missed the deadline as losses, deliver; within
        ``timeout_s`` even when the store, disk or exporter is blocked. Idempotent."""
        return self._close(timeout_s, exiting=False)

    def _close(self, timeout_s: float | None, *, exiting: bool) -> bool:
        """``exiting``: the process is ending; a process that does not drain the spool
        only makes its records durable there, for the drainer (never waits on another)."""
        global _HANDLE  # noqa: PLW0603
        from . import _transport  # noqa: PLC0415

        with _LOCK:
            if self._result is not None:
                return self._result
            self._result = False
            if not self.capturing:
                if _HANDLE is self:
                    _HANDLE = None
                return False
            if _HANDLE is self:
                _HANDLE = _transport._ACTIVE = None
                if self._patched:
                    _transport.unpatch_httpx()
                from . import _aiohttp, _detect  # noqa: PLC0415

                _aiohttp.unpatch_aiohttp()
                _detect.unpatch_detectors()
        with contextlib.suppress(Exception):
            atexit.unregister(self._atexit_close)
            timeout = self.config.shutdown_timeout_s if timeout_s is None else timeout_s
            deadline = time.monotonic() + max(0.0, timeout)
            drained = self._tee.close(timeout * _DRAIN_SHARE)
            _p1_uninstalled(self)  # 050 §3.8: the wire points' state change, before final
            _p1_final(self)  # 050 §3.6: final() seals every open segment first
            self._tee.loss.final(self.allocator)  # this epoch allocates nothing more
            _p1_detach(self)
            remaining = max(0.0, deadline - time.monotonic())
            self._result = self._deliver(remaining, closing=True, exiting=exiting) and drained
            _p1_closed(self)
        return self._result

    def uninstall(self) -> None:
        self.close()

    def stats(self) -> WireStats:
        values = self._tee.stats() if self.capturing else {}
        return WireStats(**{f.name: values.get(f.name, 0) for f in dataclasses.fields(WireStats)})

    def _atexit_close(self) -> None:
        """At exit (atexit, or a multiprocessing worker's finalizer), bounded: close, then
        shut Fabric's exporter/providers down on a helper thread unless delivery failed
        (the exporter is then presumed blocked)."""
        if not self.capturing:
            return
        with contextlib.suppress(BaseException):  # interpreter shutdown
            from .. import _loss  # noqa: PLC0415
            from ..tracing import is_private_provider  # noqa: PLC0415

            deadline = time.monotonic() + max(0.0, self.config.shutdown_timeout_s)
            closed = self._close(None, exiting=True)
            loss, sender = self._tee.loss, self._tee.sender
            if sender is None:  # the direct path: the loss emitter's thread and provider
                closed = loss.close(max(0.0, deadline - time.monotonic())) and closed
            providers = {self.config.tracer_provider, loss.tracer_provider,
                         self._fallback.provider} - {None}  # fmt: skip
            targets: list[Any] = [sender.owned_exporter()] if sender else [
                p for p in providers if is_private_provider(p)]  # fmt: skip
            targets = [target for target in targets if target is not None]
            for target in targets if closed else ():  # else presumed blocked: skipped
                shutdown = lambda t=target: t.shutdown() or True  # noqa: E731
                _loss.run_bounded(shutdown, deadline, "fabric-shutdown")


def install(
    config: WireConfig | None = None, /, *, span_exporter: SpanExporter | None = None,
    content_client: NodeContentClient | None = None, **overrides: Any,
) -> WireHandle:  # fmt: skip
    """Install the tee (idempotent; invalid config raises first). The spool delivers through
    ``span_exporter`` and ``content_client`` (defaults: from the environment).

    ``patch_httpx=False, patch_aiohttp=False`` is the records-only install (050 §3.1): no
    model client is teed, and the records input, segments, manifests, spool and sender work
    exactly as with the tee."""
    global _HANDLE  # noqa: PLW0603
    from .._loss import PrivateFallback, get_loss_emitter  # noqa: PLC0415
    from . import _transport  # noqa: PLC0415
    from ._sender import build_sender  # noqa: PLC0415

    _prime_fork_safety()  # before any Fabric thread starts
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
        if _otel_disabled():
            # The OpenTelemetry kill switch also stops Fabric's capture, never silently
            # (agent matrix D6): one warning, and status() says so.
            _LOG.warning("fabric.wire: capture disabled (OTEL_SDK_DISABLED); nothing is "
                         "recorded")  # fmt: skip
            _HANDLE = WireHandle(config, None, patched=False)
            return _HANDLE
        gate = _gate(config)
        if config.spool_migrate_plaintext and gate.profile == "production":
            # 049 §7.8: never in production; plaintext records there are quarantined.
            _LOG.warning("fabric.wire: spool plaintext migration is ignored in the production "
                         "profile; plaintext spool records are quarantined")  # fmt: skip
            config = dataclasses.replace(config, spool_migrate_plaintext=False)
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
        registration = _p1_attach(allocator, loss, tee, config, gate)
        loss.attach(sender.wake if sender is not None else None)
        if sender is not None:  # starts draining: replays what earlier processes left
            sender.wake()
        _HANDLE = WireHandle(config, tee, patched=config.patch_httpx, fallback=fallback, gate=gate)
        _p1_installed(_HANDLE, registration)
        _log_gate(gate)
        _p1_patch(_HANDLE)  # the client tees, and a failed patch's manifest
        _transport._ACTIVE = tee
        atexit.register(_HANDLE._atexit_close)
        if _truthy(os.environ.get("FABRIC_CAPTURE_LLM_CONTENT")):
            _LOG.warning(
                "fabric.wire: FABRIC_CAPTURE_LLM_CONTENT does not affect wire capture; "
                "wire already stores content off telemetry"
            )
        return _HANDLE


def _p1_attach(
    allocator: SourceAllocator, loss: Any, tee: WireTee, config: WireConfig | None = None,
    gate: ContentGate | None = None,
) -> Registration | None:  # fmt: skip
    """050 §3.2-§3.3, before the handle is published: register the epoch on the spool and
    attach the run table (bound to the allocator, the marker queue and the pipeline's seal
    accumulator), the seal accumulator and the settle hooks. Each step fails open (capture
    continues unregistered, or without segments)."""
    from .. import _segments  # noqa: PLC0415
    from . import _registration  # noqa: PLC0415

    registration = None
    with contextlib.suppress(Exception):
        spool = tee.sender.spool if tee.sender is not None else None
        registration = _registration.register(spool, allocator.source_id, allocator.epoch)
    table = None
    with contextlib.suppress(Exception):
        table = _segments.new_run_table()
        bind = getattr(table, "bind", None)
        if callable(bind):
            bind(allocator=allocator, loss=loss, seals=tee.pipeline.seals,
                 key=config.id_key if config is not None else None,
                 production=gate is not None and gate.profile == "production")  # fmt: skip
    with contextlib.suppress(Exception):
        allocator.attach(segments=table, seals=tee.pipeline.seals)
        tee.pipeline.set_settle(allocator.settle)
        loss.set_settle(allocator.settle)
    return registration


def _p1_status(handle: WireHandle) -> dict[str, Any]:
    """050 status lines (values only): the epoch registration (WP-10), the records input's
    counters and the fail-open counters (R9), the seal accumulator's and run table's stats."""
    from .. import _segments  # noqa: PLC0415

    out: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        registration = handle.registration
        out["registration"] = registration.status if registration is not None else "failed"
        out.update(COUNTERS.snapshot())
        if (records := handle.records) is not None:
            out.update(records.stats.snapshot())
        stats = getattr(handle._tee.pipeline.seals, "stats", None)
        if callable(stats):
            out["seals"] = dict(stats())
        table = handle.allocator.segments
        if isinstance(table, _segments.SegmentTable):
            out["runs"] = table.stats()
    return out


_WIRE_POINTS = ("wire.py.httpx", "wire.py.aiohttp")


def _p1_patch(handle: WireHandle) -> None:
    """Patch the client tees the config enables; 050 §3.8 (WP-13 hand-off): a tee whose
    patch failed is a capture-point state change (the next chained manifest)."""
    from .. import _manifest  # noqa: PLC0415

    _patch_clients(handle.config)
    with contextlib.suppress(Exception):
        states = _client_status(handle.config)["capture_points"]
        for point in _WIRE_POINTS:
            if states.get(point) == "failed":
                _manifest.capture_point_changed(handle, point, "failed", "internal_error")


def _p1_uninstalled(handle: WireHandle) -> None:
    """050 §3.8 (WP-13 hand-off): ``uninstall()`` is a state change of every wire tee that
    was active, chained before the epoch's ``final``."""
    from .. import _manifest  # noqa: PLC0415

    with contextlib.suppress(Exception):
        document = _manifest.current_document(handle.allocator) or {}
        for row in document.get("capture_points", ()):
            if row.get("id") in _WIRE_POINTS and row.get("state") == "active":
                _manifest.capture_point_changed(handle, row["id"], "disabled", "shutdown")


def _p1_installed(handle: WireHandle, registration: Registration | None) -> None:
    """050 §3.1, §3.8: the handle's records input and manifest 0 of its epoch."""
    from .. import _manifest  # noqa: PLC0415
    from .._records import RecordsInput  # noqa: PLC0415

    handle.registration = registration
    with contextlib.suppress(Exception):
        handle.records = RecordsInput(handle)
        _manifest.emit_initial(handle)


def _p1_final(handle: WireHandle) -> None:
    """050 §3.6 ``final()`` trigger: seal the open segments before the ``final`` marker."""
    with contextlib.suppress(Exception):
        handle.allocator.segments.on_final()
    with contextlib.suppress(Exception):
        if handle.registration is not None:
            handle.registration.final()


def _p1_detach(handle: WireHandle) -> None:
    """After ``final``: the closed install settles nothing more."""
    with contextlib.suppress(Exception):
        handle._tee.loss.set_settle(None)
        handle._tee.pipeline.set_settle(None)
        handle.allocator.attach()
        handle.records = None


def _p1_closed(handle: WireHandle) -> None:
    """After delivery: release the registration (its file goes once ``final`` is spooled)."""
    with contextlib.suppress(Exception):
        if handle.registration is not None:
            handle.registration.close()


def _patch_clients(config: WireConfig) -> None:
    """The process-global tees the config enables: httpx/httpx2, aiohttp."""
    from . import _aiohttp, _detect, _transport  # noqa: PLC0415

    if config.patch_httpx:
        _transport.patch_httpx()
        _detect.patch_detectors()  # the clients wire does not tee: their model calls count
    if config.patch_aiohttp:
        _aiohttp.patch_aiohttp()


def _client_status(config: WireConfig) -> dict[str, Any]:
    """The wire capture points' states and the HTTP clients a model call may have used
    unseen (049 §2.8; until the capture manifest is built, status() declares them)."""
    from . import _aiohttp, _detect, _transport  # noqa: PLC0415

    flavors = {module for module, _ in _transport._PATCHED}
    httpx_state = "active" if flavors else "failed" if config.patch_httpx else "disabled"
    if _aiohttp.patched():
        aiohttp_state = "active"
    elif not config.patch_aiohttp:
        aiohttp_state = "disabled"
    else:
        aiohttp_state = "failed" if _aiohttp.installed() else "installed_inactive"
    patched = lambda name: name in flavors or (name == "aiohttp" and _aiohttp.patched())  # noqa: E731
    unseen = {*_detect.seen(), *_detect.loaded_unpatched(patched)}
    return {"capture_points": {"wire.py.httpx": httpx_state, "wire.py.aiohttp": aiohttp_state},
            "uninstrumented_clients": sorted(unseen)}  # fmt: skip


def _protection_from_env(config: WireConfig) -> WireConfig:
    """Fill the capture policy, keys and redaction service an explicit config left unset
    from ``FABRIC_*`` (049 §7.3, §7.7, §7.8); a malformed value raises (fixed text, never
    the value)."""
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
    if not config.spool_migrate_plaintext and migrate_plaintext_from_env(env):
        changes["spool_migrate_plaintext"] = True
    if config.redaction is None and (service := RedactionService.from_env(env)) is not None:
        changes["redaction"] = service
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


def _otel_disabled() -> bool:
    """``OTEL_SDK_DISABLED``, parsed as the OpenTelemetry SDK parses it."""
    return os.environ.get("OTEL_SDK_DISABLED", "").strip().lower() == "true"


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
    _prime_fork_safety()  # before the private provider starts its export thread
    try:
        from .._loss import get_loss_emitter  # noqa: PLC0415
        from ..tracing import (  # noqa: PLC0415
            build_private_provider,
            capture_service_name,
            otlp_endpoint_configured,
        )
        from ._config import config_from_env  # noqa: PLC0415

        env = os.environ if environ is None else environ
        config, tracer_mode = config_from_env(env)
        if _otel_disabled():
            return install(config)  # disabled: nothing is built
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
        handle = install(config)
        from .._segments import intake_environment  # noqa: PLC0415

        intake_environment(handle, env)  # same-host FABRIC_RUN_ID / FABRIC_RUN_RESUME_TOKEN
        return handle
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


_RUN_LABEL = "fabric-run"  # run_scope's own argument; the scope carries the emitted id


def _guarded(call: Callable[..., Any], *args: Any) -> Any:
    """A run-table hook, fail-open (R9): a Fabric failure is counted, never raised into the
    block, except under ``FABRIC_RECORDS_STRICT=1``."""
    try:
        return call(*args)
    except Exception:
        COUNTERS.internal_errors += 1
        if strict():
            raise
        return None


def _scope_status(exc: BaseException) -> ScopeStatus:
    """S34 of a block that raised: ``cancelled`` for cancellation and interpreter exits."""
    import asyncio  # noqa: PLC0415

    cancelled = (asyncio.CancelledError, KeyboardInterrupt, SystemExit, GeneratorExit)
    return "cancelled" if isinstance(exc, cancelled) else "error"


@contextlib.contextmanager
def run(
    run_id: str | None = None, *, session_id: str | None = None, user_id: str | None = None,
    parent_run_id: str | None = None, resumed_from: str | None = None,
    links: Sequence[str] = (), resume: str | Sequence[str] | None = None,
    resumable: bool = False, final: bool = False, open_deadline_s: int | None = None,
) -> Iterator[None]:  # fmt: skip
    """Scope a run (spec 048 §6, 050 §3.6). Each entry is a new scope
    (``fabric.run.scope_id``) whose ``run_start``/``run_end`` markers bound the calls and
    records started inside it, in a segment of the run (``fabric.run.segment_id``).

    The run id is decided by the five run-identity rules (module ``fabric._segments``):
    ``resume`` tokens (or, for the first outermost block, ``FABRIC_RUN_RESUME_TOKEN``)
    carry the run's correlation id; else ``run_id`` (or same-host ``FABRIC_RUN_ID``) is
    mapped by the identity rule: its ``r-`` pseudonym (keyed by ``FABRIC_WIRE_ID_KEY``) in
    the default pseudonymous mode, any string accepted; as given only in the explicit
    ``clear`` identity mode; in the production profile without a key, the generated source
    fallback. Without either a fresh ``r-`` correlation id is minted. ``session_id`` and
    ``user_id`` become ``sess-``/``usr-`` pseudonyms (omitted without a key);
    ``parent_run_id``, ``resumed_from`` and ``links`` follow the run-id rule. They ride on
    the run's root ``run_start``.

    The run's outermost block exit in this process seals its segment: terminal for a run
    that is not ``resumable`` (or a ``final=True`` block), non-terminal otherwise.
    ``resumable`` and ``open_deadline_s`` (60..31536000) mark a run that continues
    elsewhere. Fail-open (R9): a malformed argument is dropped, a non-string ``run_id``
    runs the block uncaptured; ``FABRIC_RECORDS_STRICT=1`` raises ``ValueError`` instead
    (also for a run id outside the opaque-id pattern)."""
    if run_id is not None and not isinstance(run_id, str):
        COUNTERS.api_misuse += 1
        if strict():
            raise ValueError("run_id must be a str")
        yield  # the block runs uncaptured
        return
    if strict() and run_id is not None and not OPAQUE_ID_RE.fullmatch(run_id):
        raise ValueError("run_id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    handle = _HANDLE if _HANDLE is not None and _HANDLE.capturing else None
    from .. import _segments  # noqa: PLC0415

    table = _guarded(_segments.active_table, handle) if handle is not None else None
    plan = None
    if table is not None:
        plan = _guarded(functools.partial(
            table.prepare, run_id, session_id=session_id, user_id=user_id,
            parent_run_id=parent_run_id, resumed_from=resumed_from, links=links,
            resume=resume, resumable=resumable, final=final,
            open_deadline_s=open_deadline_s, outermost=current_run_scope() is None,
        ))  # fmt: skip
    if table is None or plan is None:
        with _legacy_run(handle, run_id):
            yield
        return
    with run_scope(_RUN_LABEL, emitted=plan.run_id) as scope:
        _guarded(table.enter, plan, scope)
        status: ScopeStatus = "ok"
        try:
            yield
        except BaseException as exc:
            status = _scope_status(exc)
            raise
        finally:
            _guarded(table.exit, scope, status)


@contextlib.contextmanager
def _legacy_run(handle: WireHandle | None, run_id: str | None) -> Iterator[None]:
    """A run scope without segments: no handle (the scope only scopes the context), or a
    run table of the frozen protocol only (its block hooks, plus 048 run markers)."""

    def mark(scope: RunScope, kind: Literal["run_start", "run_end"]) -> None:
        if handle is not None:
            from .. import _segments  # noqa: PLC0415

            with contextlib.suppress(Exception):  # capture fails open
                if not isinstance(handle.allocator.segments, _segments.SegmentTable):
                    # 048 markers; a segment table's own hooks emit the typed ones
                    handle._tee.loss.heartbeat(handle.allocator, kind=kind, scope=scope)
            with contextlib.suppress(Exception):  # 050 §3.6 block hooks
                segments = handle.allocator.segments
                hook = segments.on_block_enter if kind == "run_start" else segments.on_block_exit
                hook(scope)

    key = handle.config.id_key if handle is not None else None
    if run_id is None:
        emitted = "r-" + secrets.token_hex(16)  # rule 5: minted, no caller input
    elif (
        handle is not None
        and handle.gate is not None
        and (handle.gate.profile == "production" and key is None)
    ):  # 049 §2.9 rule 5: the generated source fallback, nothing derived from run_id
        allocator = handle.allocator
        emitted = encode_opaque_id(f"source:{allocator.source_id}:{allocator.epoch}")
    else:
        emitted = run_pseudonym(run_id, key)
    with run_scope(_RUN_LABEL, emitted=emitted) as scope:
        mark(scope, "run_start")
        try:
            yield
        finally:
            mark(scope, "run_end")


def resume_token() -> str | None:
    """Seal the current run's open segment (non-terminal, ``resumable=true``) and return its
    ``fr3/`` token (050 §3.6); ``None`` outside a run or when not capturing. Never raises
    (except under ``FABRIC_RECORDS_STRICT=1``)."""
    from .._segments import resume_token as issue  # noqa: PLC0415

    return issue()


def resume_tokens(branches: int) -> tuple[str, ...]:
    """``branches`` (1..64) branch tokens of one seal, each for exactly one consumer;
    ``()`` outside a run or when not capturing."""
    from .._segments import resume_tokens as issue  # noqa: PLC0415

    return issue(branches)


def end_run(
    run_id: str | None, outcome: RunOutcome, *, resume: Sequence[str],
    stop_reason: StopReason | None = None,
) -> EndRunStatus:  # fmt: skip
    """End a run from its resume tokens (an orchestrator's call, 050 §3.6): a zero-width
    terminal segment whose ``run_end`` carries ``outcome``. ``run_id=None`` takes the run id
    from the tokens. Returns ``ended``, ``refused_no_token``, ``refused_bad_token``,
    ``refused_conflicting_tokens``, ``not_capturing`` or ``failed``; never raises."""
    from .._segments import end_run as end  # noqa: PLC0415

    return cast("EndRunStatus", end(run_id, outcome, resume=resume, stop_reason=stop_reason))


def __getattr__(name: str) -> Any:
    if name in ("WireTransport", "AsyncWireTransport"):
        from . import _transport  # noqa: PLC0415

        return getattr(_transport, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
