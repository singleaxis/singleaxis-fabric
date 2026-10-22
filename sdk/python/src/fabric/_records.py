# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The records input (spec 050 §3.4): sequenced records on the wire spool, one per handle.

WP-01 freezes the interface; every method is a typed, fail-open stub with today's
behaviour (nothing is sequenced: :meth:`RecordsInput.begin` returns ``None``, so every
producer keeps its current path). WP-11a implements rule A (attribute projection), rule N
(names), the phase table, bodies, ``mode_of``, ``v2`` and record jobs.

Fail-open (R9): every call returns ``None``/``False``/``"omit"`` on misuse or an internal
failure and counts it (:data:`fabric._capture_types.COUNTERS`); it raises only under
``FABRIC_RECORDS_STRICT=1``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING

from ._capture_types import (
    PROVENANCES,
    STEP_KINDS,
    AnyBody,
    EvidenceDoc,
    Lifecycle,
    OtlpStatus,
    Phase,
    PrivacyMode,
    Provenance,
    RecordsMisuseError,
    ResultStatus,
    SpanIds,
    StepKind,
    fail_open,
)
from ._sequence import V2_TYPES

if TYPE_CHECKING:
    from opentelemetry.util.types import AttributeValue

    from ._sequence import EmittedId
    from .wire import WireHandle

_NO_ALIASES: Mapping[str, str] = MappingProxyType({})


class Attempt:
    """One step attempt on the records input (§3.4). ``uid`` is a dashed uuid4 minted by
    Fabric (X19), never taken from the caller."""

    __slots__ = ("kind", "point", "provenance", "records", "uid")

    def __init__(
        self, records: RecordsInput, uid: EmittedId, kind: StepKind, point: str,
        provenance: Provenance = "reported",
    ) -> None:  # fmt: skip
        self.records, self.uid, self.kind = records, uid, kind
        self.point, self.provenance = point, provenance

    @fail_open(False)
    def emit(
        self, phase: Phase, *, name_hint: str, attributes: Mapping[str, AttributeValue],
        start_ns: int, end_ns: int, lifecycle: Lifecycle | None = None,
        result_status: ResultStatus | None = None, otlp_status: OtlpStatus = "unset",
        bodies: Sequence[AnyBody] = (), evidence: EvidenceDoc | None = None,
        event_id: str | None = None, span_ids: SpanIds | None = None,
    ) -> bool:  # fmt: skip
        """Emit one sequenced record of this attempt; ``False`` when nothing was emitted.
        ``lifecycle``, ``result_status`` and ``otlp_status`` are three independent inputs
        resolved by :func:`fabric._capture_types.resolve_status_inputs` (R4). Stub until
        WP-11a: nothing is emitted."""
        return False


class RecordsInput:
    """The records input of one installed wire handle (§3.1 "Activation")."""

    __slots__ = ("handle",)

    def __init__(self, handle: WireHandle | None = None) -> None:
        self.handle = handle

    @fail_open(None)
    def begin(
        self, kind: StepKind, point: str, *, provenance: Provenance = "reported",
        step_id: str | None = None, parent_attempt: str | None = None,
        aliases: Mapping[str, str] = _NO_ALIASES,
    ) -> Attempt | None:  # fmt: skip
        """Open an attempt of step ``kind`` at capture point ``point``; ``None`` while the
        records input is not active (the stub always: producers keep their current path).
        An unknown ``kind`` or ``provenance`` is misuse."""
        if kind not in STEP_KINDS:
            raise RecordsMisuseError("records API misuse: unknown step kind")
        if provenance not in PROVENANCES:
            raise RecordsMisuseError("records API misuse: unknown provenance")
        return None

    @fail_open("omit")
    def mode_of(self, role: str) -> PrivacyMode:
        """The privacy mode the capture policy resolves for ``role`` (049 §2.7), cached per
        epoch; ``omit`` when content capture is disabled, the role is unknown, or on any
        failure (fail closed). Producers call it before serialising a body. Stub: ``omit``."""
        return "omit"

    @fail_open(None)
    def v2(self, prefix: str, value: str) -> str | None:
        """The identity rule (R8): an ``EmittedId`` of this handle's issuer unchanged; the
        keyed v2 pseudonym in pseudonymous mode (``None`` without a key); the value as given
        in clear mode. An unknown ``prefix`` is misuse. Stub: ``None`` (omitted)."""
        if prefix not in V2_TYPES:
            raise RecordsMisuseError("records API misuse: unknown v2 prefix")
        return None


def records_input(handle: WireHandle | None) -> RecordsInput | None:
    """The records input of ``handle`` while it captures, else ``None`` (§3.1)."""
    if handle is None or not handle.capturing:
        return None
    return getattr(handle, "records", None)


__all__ = ["Attempt", "RecordsInput", "records_input"]
