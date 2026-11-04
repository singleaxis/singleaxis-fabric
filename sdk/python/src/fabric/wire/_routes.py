# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The route table of every httpx/httpx2 transport request (spec 053 §5.4; spec 056
§7.3.3 (j)). 054 WP5-00a is the next owner of this module.

The wire tee calls :func:`decide` once per request, at its capture decision
(``WireTee.handle_sync``/``handle_async`` in ``_transport.py``), and the request takes the
first route that applies, in this order:

1. ``internal``: Fabric's own I/O (the hooks internal-I/O guard, 053 §4.1), or a request
   to one of Fabric's own endpoints (its Node, export or redaction endpoint) while a
   non-model rule is registered. Nothing records it.
2. ``owned``: an explicit producer that records ``network`` steps itself is live (053
   §4.3 D2), or the MCP hook's owner marker (:func:`owner_marker`) is set around the
   request. Excluded from the non-model route.
3. ``model``: a qualified model endpoint matched (``EndpointIndex``): the wire input, on
   exactly today's code path.
4. ``nonmodel``: a registered non-model rule matched the request's scheme, canonical host
   and port exactly (``fabric.hooks._http``, capture point ``http.nonmodel``).
5. ``none``: nothing is recorded.

Model routing needs no rule: with no rule registered (the HTTP hook off) a request routes
``model`` exactly when the endpoint index matches it outside Fabric's own I/O. A rule is
registered with :func:`register_route` and removed with :func:`unregister_route`; the table
is replaced as a whole (copy on write), so the hot path reads it without a lock. Nothing
here raises into the application: :func:`decide` is called inside the tee's own
fail-open section.
"""

from __future__ import annotations

import contextlib
import os
import threading
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal, NamedTuple

from .._capture_scope import explicit_owner
from ..hooks import _guard
from ..hooks._config import canonical_host

if TYPE_CHECKING:
    from ._match import EndpointIndex
    from ._model import EndpointMatcher, WireApi

__all__ = [
    "ROUTES", "Decision", "Route", "RouteRule", "decide", "owner_marker", "register_route",
    "request_key", "route", "rules", "unregister_route",
]  # fmt: skip

Route = Literal["internal", "owned", "model", "nonmodel", "none"]
ROUTES: Final[tuple[Route, ...]] = ("internal", "owned", "model", "nonmodel", "none")
# (scheme, canonical host, port): what a non-model rule matches.
Key = tuple[str, str, int]
_DEFAULT_PORTS: Final = {"https": 443, "http": 80}
_OWNED_KIND: Final = "network"  # the step kind of http.nonmodel records


@dataclass(frozen=True, slots=True, eq=False)
class RouteRule:
    """A registered non-model rule set: ``hosts`` maps an exact request key to the rule's
    index in its allowlist; ``internal`` are Fabric's own endpoints, never recorded;
    ``handler`` records a request that matched (``fabric.hooks._http.HttpChannel``, whose
    ``handle_sync``/``handle_async`` the tee calls). Compared by identity."""

    name: str
    hosts: dict[Key, int]
    handler: Any
    internal: frozenset[Key] = field(default_factory=frozenset)


class Decision(NamedTuple):
    """One request's route, with what the route needs: the model endpoint and API
    (``model``), or the matching rule and its index (``nonmodel``)."""

    route: Route
    found: tuple[EndpointMatcher, WireApi] | None = None
    rule: RouteRule | None = None
    rule_index: int | None = None


INTERNAL: Final = Decision("internal")
OWNED: Final = Decision("owned")
NONE: Final = Decision("none")

_LOCK = threading.Lock()
_RULES: tuple[RouteRule, ...] = ()
# Raw (IDNA) request host -> canonical host, or None: a request host is checked once.
_HOSTS: dict[bytes, str | None] = {}
_MAX_CACHED_HOSTS: Final = 1024
# 053 §4.3: the MCP hook marks its own httpx calls; the non-model route skips them.
_OWNER: ContextVar[bool] = ContextVar("fabric_wire_route_owner", default=False)


def register_route(rule: RouteRule) -> None:
    """Add a non-model rule (idempotent for the same rule object)."""
    global _RULES  # noqa: PLW0603
    with _LOCK:
        if not any(existing is rule for existing in _RULES):
            _RULES = (*_RULES, rule)


def unregister_route(rule: RouteRule) -> None:
    """Remove a rule registered earlier (nothing when it is not registered)."""
    global _RULES  # noqa: PLW0603
    with _LOCK:
        _RULES = tuple(existing for existing in _RULES if existing is not rule)


def rules() -> tuple[RouteRule, ...]:
    """The registered rules, in registration order."""
    return _RULES


@contextlib.contextmanager
def owner_marker() -> Iterator[None]:
    """Mark the enclosed requests as owned by another hook channel (the MCP hook's own
    httpx calls, 053 §4.3): they route ``owned``, never ``nonmodel``."""
    token = _OWNER.set(True)
    try:
        yield
    finally:
        _OWNER.reset(token)


def request_key(url: Any) -> Key | None:
    """``(scheme, canonical host, port)`` of an httpx URL, read from its raw (IDNA) host,
    or ``None`` when it has none Fabric can match (an unknown scheme, a host that is not
    a name or address)."""
    scheme = url.scheme
    default = _DEFAULT_PORTS.get(scheme) if type(scheme) is str else None
    raw = url.raw_host
    if default is None or type(raw) is not bytes or not raw:
        return None
    try:
        host = _HOSTS[raw]
    except KeyError:
        host = _canonical(raw)
        if len(_HOSTS) < _MAX_CACHED_HOSTS:
            _HOSTS[raw] = host
    if host is None:
        return None
    port = url.port
    return scheme, host, default if port is None else port


def _canonical(raw: bytes) -> str | None:
    try:
        host = raw.decode("ascii")
        return canonical_host(f"[{host}]" if ":" in host else host)
    except ValueError:  # UnicodeDecodeError included
        return None


def decide(request: Any, index: EndpointIndex | None) -> Decision:
    """The route of ``request`` (053 §5.4 order), with the model match or non-model rule
    it found. ``index`` is the installed tee's endpoint index (``None``: no model route).
    Raises only what reading the request raises (the tee's fail-open section counts it)."""
    if _guard.active():
        return INTERNAL
    table = _RULES
    key: Key | None = None
    if table:
        key = request_key(request.url)
        if key is not None and any(key in rule.internal for rule in table):
            return INTERNAL
    if _OWNER.get() or explicit_owner(_OWNED_KIND):
        return OWNED
    if index is not None:
        url = request.url
        found = index.match(request.method, url.scheme, url.host, url.port, url.path)
        if found is not None:
            return Decision("model", found)
    if key is not None:
        for rule in table:
            found_index = rule.hosts.get(key)
            if found_index is not None:
                return Decision("nonmodel", None, rule, found_index)
    return NONE


def route(request: Any) -> Route:
    """The route of ``request`` under the installed wire tee (``none`` without one, or
    when the request cannot be read)."""
    from . import _transport  # noqa: PLC0415 - _transport imports this module

    tee = _transport._ACTIVE
    try:
        return decide(request, None if tee is None else tee.index).route
    except Exception:
        return "none"


def _after_fork_in_child() -> None:
    global _LOCK  # noqa: PLW0603
    _LOCK = threading.Lock()  # a parent thread may have held it at fork


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
