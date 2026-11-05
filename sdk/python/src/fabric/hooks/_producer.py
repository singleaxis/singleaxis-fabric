# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The hook adapter over the records input (spec 053 §3 B1-B6, §4.1, §4.3).

One :class:`HookProducer` per hooks install. It is a thin layer over the install's
:class:`~fabric._records.RecordsInput` that adds what every hook channel needs and nothing
else: the per-channel enabled :class:`Switch`, the Fabric internal-I/O guard, and same-kind
explicit ownership (D2). Every record a channel emits goes through
:meth:`HookProducer.begin`, which opens an attempt with provenance ``observed`` (so the
record carries ``fabric.capture.input=records`` and ``fabric.capture.source=observed`` and
may hold ``protocol`` bodies), then :meth:`fabric._records.Attempt.emit` (B2).

The cheap exits of :meth:`HookProducer.begin` run in the order 053 §4.1 item 1 fixes: the
enabled flag, the internal-I/O guard, then same-kind explicit ownership. Nothing here waits,
does I/O or raises into the application (R9): a failure returns ``None`` (or the fail value
of the call) and is counted; ``FABRIC_RECORDS_STRICT=1`` raises Fabric-internal misuse in
tests only.

A channel module (``fabric.hooks._exec`` for ``exec.subprocess``) exposes one entry point,
``install_channel(producer, patches) -> HookChannel``, which the hooks install calls once.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from typing import TYPE_CHECKING, Literal, Protocol, cast

from .._capture_scope import explicit_owner
from .._capture_types import (
    EVIDENCE_MEDIA_TYPE,
    EVIDENCE_ROLE,
    DescriptorOnlyBody,
    EvidenceContinuation,
    EvidenceDoc,
    PrivacyMode,
    StepKind,
    fail_open,
    misuse,
)
from . import _guard

if TYPE_CHECKING:
    from .._records import Attempt, RecordsInput
    from ..wire import WireHandle
    from ._config import HooksConfig

__all__ = [
    "CHANNEL_ENTRY", "HookChannel", "HookPoint", "HookProducer", "Switch", "UnsupportedChannel",
]  # fmt: skip

HookPoint = Literal["exec.subprocess", "http.nonmodel", "remote.sandbox"]
CHANNEL_ENTRY = "install_channel"  # the one entry point of a channel module

# Producer counters per channel (status() material: counts only, never a value).
_COUNTER_NAMES = ("attempts", "not_capturing", "internal_skipped", "deferred_to_explicit")
_PAIR = 2  # a continuation is (index, final)


class UnsupportedChannel(Exception):  # noqa: N818 - a capability outcome, not a failure
    """Raised by a channel's entry point when this runtime cannot host it: the capability
    becomes ``unsupported`` with ``reason`` (``unsupported_runtime`` or
    ``unsupported_version``), published to the manifest. Never an action-time error."""

    def __init__(self, reason: Literal["unsupported_runtime", "unsupported_version"]) -> None:
        super().__init__(reason)
        self.reason = reason


class HookChannel(Protocol):
    """What a channel's entry point returns. Patching is done through the
    :class:`~fabric.hooks._patches.PatchSet` it was given, which the install restores."""

    def status(self) -> Mapping[str, int]:
        """The channel's own counters (counts only)."""
        ...

    def close(self) -> None:
        """Release channel state (weak associations, caches). Patches are restored by the
        install, not here. Must not wait or raise."""
        ...


class Switch:
    """A channel's enabled flag. Wrappers read ``switch.on`` first and call straight
    through when it is ``False`` (053 §4.1 item 1: the cheapest exit)."""

    __slots__ = ("on",)

    def __init__(self, on: bool = False) -> None:
        self.on = on


class HookProducer:
    """The records-input producer every hook channel uses (one per hooks install)."""

    __slots__ = ("_host_id", "_switches", "config", "counters", "records", "wire")

    def __init__(self, wire: WireHandle, records: RecordsInput, config: HooksConfig) -> None:
        self.wire, self.records, self.config = wire, records, config
        self._switches: dict[str, Switch] = {}
        self.counters: dict[str, dict[str, int]] = {}
        self._host_id: tuple[str | None] | None = None

    # -- channel state ----------------------------------------------------------------

    def switch(self, point: str) -> Switch:
        """The enabled flag of the channel at ``point`` (created off on first use)."""
        found = self._switches.get(point)
        if found is None:
            found = self._switches[point] = Switch()
            self.counters[point] = dict.fromkeys(_COUNTER_NAMES, 0)
        return found

    def enabled(self, point: str) -> bool:
        """Whether the channel at ``point`` is on and the capture handle still captures."""
        found = self._switches.get(point)
        return found is not None and found.on and self.records.active

    def _count(self, point: str, name: str) -> None:
        counters = self.counters.get(point)
        if counters is not None:
            counters[name] += 1

    # -- B1-B6 ------------------------------------------------------------------------

    @fail_open(None)
    def begin(
        self, point: HookPoint, kind: StepKind, *, parent_attempt: str | None = None,
        version: str | None = None,
    ) -> Attempt | None:  # fmt: skip
        """Open an observed attempt of step ``kind`` at ``point`` (B1), or ``None``: the
        channel is off, the call is Fabric's own I/O (guard), an explicit producer owns this
        kind here (D2: counted ``deferred_to_explicit``; the projection reports the hook's
        fields ``not_captured(deferred_to_explicit)``), or the capture handle no longer
        captures. ``parent_attempt`` is a reported parent attempt uid (056 A0). ``version``
        is the emitted point's version when it is not Fabric's own (``remote.sandbox``
        names the observed provider SDK's: spec 056 §7.3.3 (k))."""
        found = self._switches.get(point)
        if found is None or not found.on:
            return None
        if _guard.active():
            self._count(point, "internal_skipped")
            return None
        if explicit_owner(kind):
            self._count(point, "deferred_to_explicit")
            return None
        attempt = self.records.begin(
            kind, point if version is None else f"{point}@{version}", provenance="observed",
            parent_attempt=parent_attempt,
        )  # fmt: skip
        self._count(point, "attempts" if attempt is not None else "not_capturing")
        return attempt

    @fail_open("omit")
    def mode(self, role: str) -> PrivacyMode:
        """B5: the privacy mode of ``role`` before any serialisation; ``omit`` means build
        no body at all (cached per epoch by the records input)."""
        return cast("PrivacyMode", self.records.mode_of(role))

    @fail_open(None)
    def ident(self, prefix: str, value: str) -> str | None:
        """B6: the identity rule (R8) for a caller-derived id: the ``v2`` pseudonym, the
        clear value in clear mode, or ``None`` (omit it) without a key."""
        return self.records.v2(prefix, value)

    @property
    def host_id(self) -> str | None:
        """``fabric.execution.host_id``: the ``hst-`` identity of the configured host label
        (053 C41, trusted configuration only), computed once; ``None`` without a label or
        a key."""
        cached = self._host_id
        if cached is None:
            label = self.config.host_label
            cached = self._host_id = (self.ident("hst", label) if label else None,)
        return cached[0]

    def evidence(
        self, type_id: str, item: Mapping[str, object], *,
        continuation: tuple[int, bool] | None = None, boundary: str = "caller",
    ) -> EvidenceDoc | DescriptorOnlyBody:  # fmt: skip
        """B4: the record's one evidence object holding exactly one ``item`` (053 §3.2),
        bounds and the type's closed schema checked before serialising; a descriptor-only
        ``record.evidence`` body (``parse_failed`` or ``payload_too_large``) otherwise.
        ``continuation`` is ``(index, final)`` of a streamed piece; ``boundary`` is the
        descriptor's boundary should the document be refused."""
        cont: EvidenceContinuation | None = None
        if continuation is not None:
            index, final = (
                continuation if type(continuation) is tuple and len(continuation) == _PAIR
                else (None, None)
            )  # fmt: skip
            if type(index) is not int or index < 0 or type(final) is not bool:
                misuse("evidence continuation must be (int >= 0, bool)")
                return DescriptorOnlyBody.for_reason(
                    EVIDENCE_ROLE, EVIDENCE_MEDIA_TYPE, boundary, "parse_failed"
                )
            cont = EvidenceContinuation(index, final)
        return EvidenceDoc.build(type_id, (item,), continuation=cont, boundary=boundary)

    def guard(self) -> contextlib.AbstractContextManager[None]:
        """The Fabric internal-I/O guard: hooks record nothing inside it."""
        return _guard.internal()

    def snapshot(self) -> dict[str, dict[str, int]]:
        """Per-channel producer counters (``status()``)."""
        return {point: dict(values) for point, values in self.counters.items()}
