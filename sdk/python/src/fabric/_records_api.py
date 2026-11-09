# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The records core (spec 051 §4.2, WP2-1a; pulled forward by spec 057 OD-15).

One internal entry point, :func:`emit`, a thin layer over the records input of spec 050
(``RecordsInput.begin`` / ``Attempt.emit``): it maps the reporting arguments to registry
keys, builds the bodies (by reference for ``bytes``/``str``, through the bounded walker for
plain JSON, descriptor-only otherwise), encodes links, timing and ``update_of``, and calls
``Attempt.emit``. Lifecycle, result status and OTLP status are separate inputs (R4).

Every public reporting API built on it fails open (R9): it never raises into the
application, never waits and never runs application code. A recorder fault is counted
(``internal_errors``), an invalid argument is counted (``api_misuse``) and dropped or
coerced; only ``FABRIC_RECORDS_STRICT=1`` raises, with fixed text. Without an installed
capture handle nothing is recorded and the call returns an unrecorded handle.
"""

from __future__ import annotations

import contextvars
import functools
import hashlib
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar

from ._capture_types import (
    COUNTERS,
    UUID4_RE,
    DescriptorOnlyBody,
    RecordBody,
    mint_uuid4,
    misuse,
    strict,
)
from ._records import RECORDS_POINT, records_input
from ._roles import ROLES
from ._sequence import EmittedId
from .records._handles import RecordHandle
from .records._vocab import ACTOR_TYPES, LINK_TYPES, normalise
from .records._walker import walk

if TYPE_CHECKING:
    from ._records import Attempt, RecordsInput

P = ParamSpec("P")
R = TypeVar("R")

MAX_LINKS = 16  # fabric.step.links (051 §5.1)
DEFAULT_ROLE_CAP = 1 << 20
_CAPS = {"64 KiB": 65536, "256 KiB": 262144, "1 MiB": 1 << 20, "4 MiB": 4 << 20}
_RETAINING = frozenset({"retain_original", "original_plus_masked"})


# ----------------------------------------------------------------- argument types
@dataclass(frozen=True, slots=True)
class ActorRef:
    """Who acted (S03/S04) or decided (052 D07): a closed ``type`` and an optional caller
    id, emitted as the keyed ``act-`` pseudonym (never clear in the default mode)."""

    type: str = "unknown"
    id: str | None = None


@dataclass(frozen=True, slots=True)
class Link:
    """A reported link (X21): a registry link type other than ``parent`` and its target —
    a :class:`RecordHandle` or ``ControlRef`` (same process), or a caller's logical step
    id (mapped as ``fabric.step.id`` is)."""

    type: str
    target: object


@dataclass(frozen=True, slots=True)
class EncodedLink:
    """A link the records core has already resolved to a Fabric-emitted id (``type``,
    ``namespace``, ``id``). Internal only: a caller's plain tuple is never taken as one, so
    no caller id reaches ``fabric.step.links`` without going through :func:`step_target`."""

    type: str
    namespace: str
    id: str


@dataclass(frozen=True, slots=True)
class Body:
    """One content body: a role of the role table, the value and its media type."""

    role: str
    value: object
    media_type: str | None = None


@dataclass(frozen=True, slots=True)
class Timing:
    """``started_at``/``ended_at`` as unix ns (``int``) or an aware ``datetime``."""

    started_at: int | datetime | None = None
    ended_at: int | datetime | None = None


@dataclass(frozen=True, slots=True)
class Bindings:
    """Context bound by :func:`context` (051 §4.2 "Bindings")."""

    conversation_id: str | None = None
    turn_id: str | None = None
    actor: ActorRef | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


_BINDINGS: contextvars.ContextVar[Bindings | None] = contextvars.ContextVar(
    "fabric_records_bindings", default=None
)


@contextmanager
def context(
    *, conversation_id: str | None = None, turn_id: str | None = None,
    actor: ActorRef | None = None,
) -> Iterator[None]:  # fmt: skip
    """Bind a conversation, turn and default actor to every records call in the block.
    Setting the binding never raises; the block's own exception propagates unchanged."""
    token = None
    try:
        token = _BINDINGS.set(Bindings(conversation_id, turn_id, actor))
    except Exception:  # pragma: no cover - ContextVar.set does not fail in practice
        COUNTERS.internal_errors += 1
    try:
        yield
    finally:
        if token is not None:
            _BINDINGS.reset(token)


# ----------------------------------------------------------------- fail-open decorator
def never_raises(default: Callable[[], R]) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """A records API never raises into the application (R9): a misuse counts
    ``api_misuse``, any other ``Exception`` counts ``internal_errors``, and the call returns
    a fresh ``default()``. Under ``FABRIC_RECORDS_STRICT=1`` the exception propagates.
    ``BaseException`` (cancellation, ``KeyboardInterrupt``) is the application's and always
    propagates."""
    from ._capture_types import RecordsMisuseError  # noqa: PLC0415 - avoid a cycle at import

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(fn)
        def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
            try:
                return fn(*args, **kwargs)
            except RecordsMisuseError:
                COUNTERS.api_misuse += 1
                if strict():
                    raise
            except Exception:
                COUNTERS.internal_errors += 1
                if strict():
                    raise
            return default()

        return guarded

    return decorate


# ----------------------------------------------------------------- the records input
_WIRE: Any = None  # fabric.wire, imported on first use (it imports this package lazily)


def current_records() -> RecordsInput | None:
    """The records input of the installed capture handle while it captures, else None."""
    global _WIRE  # noqa: PLW0603 - a cached module reference, set once
    if _WIRE is None:
        from . import wire  # noqa: PLC0415

        _WIRE = wire
    records = records_input(_WIRE.current_handle())
    return records if records is not None and records.active else None


def _ns(value: object) -> int | None:
    if type(value) is int:
        return value if 0 <= value < 1 << 63 else None
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            return None  # a naive datetime is dropped (051 §4.2 "Timing")
        return int(value.timestamp() * 1_000_000_000)
    return None


def timing_window(timing: Timing | None) -> tuple[int, int, str]:
    """(start ns, end ns, timing basis): ``reported`` when both times are valid and
    ordered; otherwise an instant at record time with basis ``not_captured``. Invalid
    times are dropped and counted, never raised."""
    now = time.time_ns()
    if timing is None:
        return now, now, "not_captured"
    start, end = _ns(timing.started_at), _ns(timing.ended_at)
    if timing.started_at is not None and start is None:
        misuse("started_at")
    if timing.ended_at is not None and end is None:
        misuse("ended_at")
    if start is not None and end is not None:
        if end < start:
            misuse("ended_at before started_at")
            return now, now, "not_captured"
        return start, end, "reported"
    at = start if start is not None else end
    if at is not None:
        return at, at, "reported"
    return now, now, "not_captured"


# ----------------------------------------------------------------- ids
def map_v2(records: RecordsInput | None, prefix: str, value: object) -> str | None:
    """A caller id as emitted under the identity rule (R8, A6): an ``EmittedId`` of this
    input as is; the keyed v2 pseudonym; ``None`` without a key. Non-strings are misuse."""
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        misuse(f"{prefix} id must be a non-empty str")
        return None
    if records is None:
        return None
    return records.v2(prefix, value)


def mint_id(records: RecordsInput | None) -> str:
    """A Fabric-minted uuid4 (an ``EmittedId`` of the input when one is active)."""
    value = mint_uuid4()
    return records._ids.mint(value) if records is not None else value


def step_target(records: RecordsInput, target: object) -> tuple[str, str] | None:
    """A link target as ``(namespace, id)``: a handle or control ref by its attempt uid
    (``attempt``); an ``EmittedId`` uuid4 of this input (``attempt``); a caller's logical
    step id, mapped (``step``). Anything else is misuse."""
    uid = getattr(target, "attempt_uid", None)
    if isinstance(uid, str) and UUID4_RE.fullmatch(uid):
        return "attempt", str.__str__(uid)
    if isinstance(target, EmittedId) and UUID4_RE.fullmatch(target):
        return "attempt", str.__str__(target)
    if isinstance(target, str) and target:
        return "step", str.__str__(records.map_id(target))
    misuse("link target")
    return None


def encode_links(records: RecordsInput, links: Sequence[object]) -> list[str]:
    """``fabric.step.links`` entries ``<type>/<namespace>/<id>`` (at most 16)."""
    out: list[str] = []
    if isinstance(links, (str, bytes)) or not isinstance(links, Sequence):
        misuse("links must be a sequence")
        return out
    for link in links:
        if type(link) is EncodedLink:  # resolved by the core itself
            out.append(f"{link.type}/{link.namespace}/{link.id}")
            continue
        if not isinstance(link, Link) or link.type not in LINK_TYPES:
            misuse("link")
            continue
        target = step_target(records, link.target)
        if target is not None:
            out.append(f"{link.type}/{target[0]}/{target[1]}")
    if len(out) > MAX_LINKS:
        misuse("more than 16 links")
        out = out[:MAX_LINKS]
    return list(dict.fromkeys(out))


def actor_attributes(records: RecordsInput, actor: ActorRef | None) -> dict[str, Any]:
    """``fabric.actor.type`` (closed) and ``fabric.actor.id`` (``act-``). A record without
    an actor gets the default the caller of :func:`emit` names."""
    if actor is None:
        bound = _BINDINGS.get()
        actor = bound.actor if bound is not None else None
    if actor is None:
        return {}
    if not isinstance(actor, ActorRef):
        misuse("actor must be an ActorRef")
        return {}
    out: dict[str, Any] = {"fabric.actor.type": normalise(actor.type, ACTOR_TYPES, "actor type")}
    actor_id = map_v2(records, "act", actor.id)
    if actor_id is not None:
        out["fabric.actor.id"] = actor_id
    return out


# ----------------------------------------------------------------- bodies
def role_cap(role: str) -> int:
    row = ROLES.get(role)
    if row is None:
        return DEFAULT_ROLE_CAP
    return _CAPS.get(row.cap, DEFAULT_ROLE_CAP)


def build_body(records: RecordsInput, body: Body) -> RecordBody | DescriptorOnlyBody | None:
    """One body under 051 §4.2 rules 1-4: the role's mode first (``omit``: nothing is
    built, no digest); ``bytes``/``str`` by reference; plain JSON through the bounded
    walker; anything else descriptor-only ``parse_failed``, never converted."""
    if not isinstance(body, Body) or body.role not in ROLES:
        misuse("body role")
        return None
    if records.mode_of(body.role) == "omit":
        return None
    row = ROLES[body.role]
    boundary = row.boundary[0]
    value = body.value
    if type(value) is bytes or type(value) is str:
        fallback = "text/plain" if type(value) is str else "application/octet-stream"
        media = body.media_type or fallback
        if not row.admits_media(media):
            misuse("body media type")
            media = row.media_types[0] if "*" not in row.media_types[0] else media
        return RecordBody(body.role, value, media, boundary)
    media = "application/json"
    walked = walk(value, role_cap(body.role))
    if walked.outcome == "ok" and walked.text is not None:
        return RecordBody(body.role, walked.text, media, boundary)
    if walked.outcome == "too_large":
        return DescriptorOnlyBody(body.role, media, boundary, "not_captured", "payload_too_large")
    return DescriptorOnlyBody(body.role, media, boundary, "not_captured", "parse_failed")


def retained_digest(records: RecordsInput, role: str, data: bytes) -> str | None:
    """A digest of an original payload only when the role resolves to a retaining mode
    (051 §4.2 "Digest gating"); never under a non-retaining mode."""
    if records.mode_of(role) not in _RETAINING:
        return None
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------- emit
def emit(
    kind: str, *, attrs: Mapping[str, Any], records: RecordsInput | None = None,
    point: str = RECORDS_POINT, name_hint: str = "fabric.activity",
    bodies: Sequence[Body] = (), links: Sequence[object] = (), timing: Timing | None = None,
    attempt: Attempt | None = None, phase: str = "end", lifecycle: str | None = "completed",
    result_status: str | None = "ok", otlp_status: str = "unset", update_of: str | None = None,
    actor: ActorRef | None = None, default_actor: str = "agent", step_id: str | None = None,
) -> RecordHandle:  # fmt: skip
    """Emit one record of step ``kind`` and return its handle (``recorded=False`` when
    nothing was recorded). Raises only Fabric misuse, which the public APIs' fail-open
    wrappers count; callers never see an exception from here."""
    records = records or current_records()
    if records is None:
        return RecordHandle.unrecorded()
    owned = attempt is None
    if attempt is None:
        attempt = records.begin(kind, point, step_id=step_id)  # type: ignore[arg-type]
        if attempt is None:
            return RecordHandle.unrecorded()
    out: dict[str, Any] = dict(attrs)
    start, end, basis = timing_window(timing)
    out["fabric.step.timing_basis"] = basis
    if links:
        encoded = encode_links(records, links)
        if encoded:
            out["fabric.step.links"] = encoded
    if update_of is not None:
        out["fabric.step.update_of"] = update_of
    bound = _BINDINGS.get()
    if actor is not None or (bound is not None and bound.actor is not None):
        out.update(actor_attributes(records, actor))
    if "fabric.actor.type" not in out:
        out["fabric.actor.type"] = default_actor
    if bound is not None:
        for key, prefix, value in (("fabric.conversation_id", "conv", bound.conversation_id),
                                   ("fabric.turn_id", "turn", bound.turn_id)):  # fmt: skip
            mapped = map_v2(records, prefix, value)
            if mapped is not None:
                out.setdefault(key, mapped)
    built = [b for b in (build_body(records, body) for body in bodies) if b is not None] if (
        bodies) else ()  # fmt: skip
    recorded = attempt.emit(
        phase,  # type: ignore[arg-type]
        name_hint=name_hint, attributes=out, start_ns=start, end_ns=end,
        lifecycle=lifecycle if phase != "update" else None,  # type: ignore[arg-type]
        result_status=result_status if phase != "update" else None,  # type: ignore[arg-type]
        otlp_status=otlp_status,  # type: ignore[arg-type]
        bodies=built,
    )  # fmt: skip
    if not owned:
        return RecordHandle(attempt, records, recorded, kind)
    return RecordHandle(attempt, records, bool(recorded), kind)


__all__ = [
    "ActorRef", "Bindings", "Body", "EncodedLink", "Link", "Timing", "actor_attributes",
    "build_body", "context", "current_records", "emit", "encode_links", "map_v2", "mint_id",
    "never_raises", "retained_digest", "role_cap", "step_target", "timing_window",
]  # fmt: skip
