# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Model calls through HTTP clients wire capture does not tee (agent matrix D4, spec 049
§2.6 reason ``uninstrumented_client``).

Whether ``requests`` or ``urllib3`` is merely imported says nothing: Fabric's own OTLP/HTTP
exporter imports both. So a zero-content detector sits where those clients send:
``requests.adapters.HTTPAdapter.send`` and ``urllib3.connectionpool.HTTPConnectionPool.
urlopen`` (which ``requests`` and ``botocore`` use). A request that matches a model endpoint
(the wire matcher: POST, host, scheme, port, path) takes the next source sequence and is
recorded as a ``fabric.capture_loss`` with reason ``uninstrumented_client``: the record
says a model call happened that it does not hold, so reconstruct never calls the run
complete. Nothing is read from the request but its method and URL, nothing is changed,
the client's own result or exception is returned as is, and a call inside a live explicit
model call is the explicit record's (049 §5 rule 13). Retries and redirects that urllib3
makes inside one call are that call.

:func:`loaded_unpatched` adds what can only be known by presence: an HTTP client library
wire capture tees (``httpx``, ``httpx2``, ``aiohttp``) loaded in the process but not
patched. Both go to ``WireHandle.status()``; until the capability manifest is built
(spec 049 §2.8, P1) the status and the loss records are where this is declared."""

from __future__ import annotations

import contextlib
import contextvars
import functools
import importlib
import importlib.util
import os
import sys
import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .._capture_scope import current_explicit_model_scope

_PATCH_LOCK = threading.Lock()
_PATCHED: dict[tuple[type, str], tuple[Any, Any]] = {}
_INSIDE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "fabric_wire_uninstrumented_call", default=False
)
_SEEN: set[str] = set()  # client classes that sent a model call (this process)
_COUNT = [0]  # model calls through them (this process)


def _active() -> Any:
    from . import _transport  # noqa: PLC0415

    return _transport._ACTIVE


def _detect(client: str, method: Any, url: str) -> None:
    """Account one model call sent through ``client``; never raises."""
    with contextlib.suppress(Exception):
        tee = _active()
        if tee is None or tee.closed or current_explicit_model_scope() is not None:
            return
        parts = urlsplit(url)
        if tee.index.match(str(method).upper(), parts.scheme, parts.hostname or "", parts.port,
                           parts.path) is None:  # fmt: skip
            return
        tee.lose_uninstrumented()
        _SEEN.add(client)
        _COUNT[0] += 1


def _wrap_requests_send(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        if _INSIDE.get() or _active() is None:
            return original(self, request, *args, **kwargs)
        _detect("requests", getattr(request, "method", ""), str(getattr(request, "url", "")))
        token = _INSIDE.set(True)  # its urllib3 call is this call
        try:
            return original(self, request, *args, **kwargs)
        finally:
            _INSIDE.reset(token)

    return send


def _wrap_urlopen(original: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(original)
    def urlopen(self: Any, method: Any, url: Any, *args: Any, **kwargs: Any) -> Any:
        if _INSIDE.get() or _active() is None:
            return original(self, method, url, *args, **kwargs)
        with contextlib.suppress(Exception):
            target = str(url)
            if not target.lower().startswith(("http://", "https://")):  # a path on this pool
                port = f":{self.port}" if self.port else ""
                target = f"{self.scheme}://{self.host}{port}{target}"
            _detect("urllib3", method, target)
        token = _INSIDE.set(True)  # retries and redirects inside it are this call
        try:
            return original(self, method, url, *args, **kwargs)
        finally:
            _INSIDE.reset(token)

    return urlopen


def _urllib3_pool() -> Any:
    return importlib.import_module("urllib3.connectionpool").HTTPConnectionPool


def _requests_adapter() -> Any:
    return importlib.import_module("requests.adapters").HTTPAdapter


def _installed(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def patch_detectors() -> None:
    """Patch the detectors of whichever of requests/urllib3 is installed; idempotent, inert
    without an active tee; a failure skips that client (capture never depends on it)."""
    with _PATCH_LOCK:
        if _PATCHED:
            return
        plan: list[tuple[str, Callable[[], Any], str, Callable[..., Any]]] = [
            ("urllib3", _urllib3_pool, "urlopen", _wrap_urlopen),
            ("requests", _requests_adapter, "send", _wrap_requests_send),
        ]
        for package, load, attr, wrap in plan:
            with contextlib.suppress(Exception):
                if not _installed(package):
                    continue
                cls = load()  # a fixed module: nothing here names one at run time
                original = vars(cls)[attr]
                wrapper = wrap(original)
                wrapper.__fabric_wire_patch__ = True
                _PATCHED[cls, attr] = (original, wrapper)
                setattr(cls, attr, wrapper)


def unpatch_detectors() -> None:
    with _PATCH_LOCK:
        for (cls, attr), (original, wrapper) in _PATCHED.items():
            if vars(cls).get(attr) is wrapper:
                setattr(cls, attr, original)
        _PATCHED.clear()


def seen() -> list[str]:
    return sorted(_SEEN)


def count() -> int:
    return _COUNT[0]


def loaded_unpatched(patched: Callable[[str], bool]) -> list[str]:
    """Teeable client libraries imported in this process that are not patched."""
    return [name for name in ("aiohttp", "httpx", "httpx2")
            if name in sys.modules and not patched(name)]  # fmt: skip


def _after_fork_in_child() -> None:
    global _PATCH_LOCK  # noqa: PLW0603
    _PATCH_LOCK = threading.Lock()
    _SEEN.clear()  # a child is a new source: what its parent saw is the parent's
    _COUNT[0] = 0


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
