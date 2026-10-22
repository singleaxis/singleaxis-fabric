# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline run reconstruction and integrity verdict (specs 047 §9, 048 §6-§7).

The verifier is read-only and the only component that parses messages. It
normalizes exchange, loss and heartbeat spans, accounts for every allocated
sequence per ``(source_id, source_epoch)``, verifies stored bytes against
the span digests and descriptors, derives message digests and tool-call ids
from those bytes, stitches exchanges into threads and states a verdict per
``fabric.wire.run()`` scope and per run. Completeness is claimed only for
what the record holds: a scoped run is at best ``complete_for_observed_scopes``
(spec 048 §6, decision H5). The verdict is an integrity statement about the
*record*; it never judges the agent.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from fabric import _seal
from fabric._model_names import HASHED_MODEL_RE, expose_model, parse_model_allowlist
from fabric._sequence import encode_opaque_id
from fabric._version import __version__
from fabric.reconstruct._graph import RunGraph, SegmentNode, build_run_graphs
from fabric.reconstruct._ids import report_run_id, report_source_id, report_tenant_id
from fabric.reconstruct._inputs import (
    A_OBJECT_IDS,
    A_REQUEST_SHA256,
    A_RESPONSE_SHA256,
    A_STEP_ID,
    ExchangeObs,
    HeartbeatObs,
    LossObs,
    MalformedMarkerObs,
    ManifestObs,
    Observation,
    ReconstructInputError,
    RecordObs,
    SegmentSealObs,
    SpanFormat,
    SpanRecord,
    digest_value,
    list_span_inputs,
    object_id_from_ref,
    observe,
    opaque_id,
    prefixed_digest,
    read_span_file,
    uuid4_value,
)
from fabric.reconstruct._objects import ObjectResult, StoreReader
from fabric.reconstruct._report import (
    SCHEMA_VERSION,
    Check,
    Gap,
    GapType,
    format_datetime,
    format_ns,
    gap_counts,
    run_verdict,
    sort_gaps,
    verdict_for,
)
from fabric.reconstruct._stitch import WireApi, continuation_digests, extract_stitch_keys
from fabric.reconstruct._stitch_check import StitchView, stitch_run

SourceKey = tuple[str, int]
Segment = tuple[int, int, str | None]


class ProjectionSink(Protocol):
    """What the step projection (spec 050 §3.13, WP-32) collects while the verifier runs:
    the verifier itself (attached first; read only once the report is built), every
    observation with the span it came from (ids in report form), and each reported
    exchange's verified bodies and stitch view, while one run's bodies are in memory. Called
    only when a projection is requested; the report never depends on it."""

    def attach(self, verifier: Any) -> None: ...

    def observed(self, obs: Observation, span: SpanRecord) -> None: ...

    def exchange_read(
        self,
        exchange: ExchangeObs,
        request: ObjectResult,
        response: ObjectResult | None,
        view: StitchView,
    ) -> None: ...


Profile = Literal["local", "production"]
Side = Literal["request", "response"]

_ROLES: dict[Side, str] = {
    "request": "model.exchange.request",
    "response": "model.exchange.response",
}
_BYTE_GAPS = frozenset({"missing_object", "digest_mismatch", "truncated"})
_STITCH_GAPS = frozenset(
    {"unparsed_exchange", "prefix_break", "unmatched_tool_call", "unresolved_previous_response"}
)
_HTTP_ERROR = 400
# Response states that say a response was received: its digest must be recorded. An
# ``abandoned`` stream had a response; an ``error`` one did when its status was recorded.
_RESPONSE_EXPECTED = frozenset({"complete", "closed_early", "abandoned"})
# D6: a run lists at most this many missing segments (or conflicted sequences) of one
# stretch of a source individually; a longer stretch is summarized per reason, so the
# report grows with runs + distinct ranges, never runs x ranges (spec 047 §9 step 3).
_LISTED_SEGMENTS = 16
# Spec 050 §3.12 defaults: --max-clock-uncertainty, and the record cap of a records span.
DEFAULT_MAX_CLOCK_UNCERTAINTY_NS = 300_000_000_000
_MAX_RECORD_OBJECTS = 8


# --------------------------------------------------------------------------
# Per-source sequence accounting
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _Source:
    """One ``(source_id, source_epoch)``: its missing ranges, computed once.

    The missing ranges and their loss/unexplained segments are kept as flat
    sorted arrays so a run looks up the ranges in or after its window by
    bisection (D6): runs never copy or rescan the source's loss list.
    """

    key: SourceKey
    sequences: set[int] = field(default_factory=set)
    losses: set[LossObs] = field(default_factory=set)
    heartbeat: int = -1
    final: int | None = None
    top: int = -1
    missing: list[tuple[int, int]] = field(default_factory=list)
    # Missing ranges as parallel sorted arrays (ranges are disjoint and ascending).
    missing_low: list[int] = field(default_factory=list)
    missing_high: list[int] = field(default_factory=list)
    # Every segment of every missing range, in order, as parallel arrays;
    # ``segment_of[i]`` is the index of missing range i's first segment
    # (with a trailing sentinel). ``reason`` is ``None`` for an unexplained part.
    seg_low: list[int] = field(default_factory=list)
    seg_high: list[int] = field(default_factory=list)
    seg_reason: list[str | None] = field(default_factory=list)
    segment_of: list[int] = field(default_factory=list)
    # Segment indices per reason (one gap class each), ascending.
    by_reason: dict[str | None, list[int]] = field(default_factory=dict)
    # Sequences claimed by conflicting observations (one exchange id seen with
    # different values, or one sequence claimed by several exchange ids). No
    # window holding one can be complete, whichever run the claims name.
    conflicted: set[int] = field(default_factory=set)
    conflicted_sorted: list[int] = field(default_factory=list)
    # Spec 050 §3.12: the manifests seen (one row per distinct document), epochs declared
    # unsealed, and sequence windows without a trustworthy manifest (rule R1) as
    # ``(first, last or None for "to the top", reason)``.
    manifests: list[ManifestObs] = field(default_factory=list)
    unsealed_epochs: set[int] = field(default_factory=set)
    manifestless: list[tuple[int, int | None, str]] = field(default_factory=list)
    manifest_conflict: bool = False

    def finalize(self) -> None:
        self.top = max(
            [self.heartbeat, *self.sequences, *(loss.last_sequence for loss in self.losses)]
        )
        previous = -1
        for sequence in sorted(self.sequences):
            if sequence > previous + 1:
                self.missing.append((previous + 1, sequence - 1))
            previous = sequence
        if self.top > previous:
            self.missing.append((previous + 1, self.top))
        ordered = sorted(self.losses, key=lambda x: (x.first_sequence, x.reason, x.last_sequence))
        # One sweep over the ascending missing ranges: ``active`` holds, in sorted
        # order, the loss records that can still overlap a later range.
        active: list[LossObs] = []
        position = 0
        for first, last in self.missing:
            while position < len(ordered) and ordered[position].first_sequence <= last:
                active.append(ordered[position])
                position += 1
            active = [loss for loss in active if loss.last_sequence >= first]
            self.missing_low.append(first)
            self.missing_high.append(last)
            self.segment_of.append(len(self.seg_low))
            for low, high, reason in _segments(first, last, active):
                self.by_reason.setdefault(reason, []).append(len(self.seg_low))
                self.seg_low.append(low)
                self.seg_high.append(high)
                self.seg_reason.append(reason)
        self.segment_of.append(len(self.seg_low))

    def finalize_conflicts(self) -> None:
        self.conflicted_sorted = sorted(self.conflicted)

    def tail_problem(self) -> str | None:
        """Why this epoch's end is unknown; ``None`` when a final heartbeat ended it.

        A ``final`` heartbeat is written by a clean close and names the last
        sequence the epoch allocated. It ends the epoch only if nothing seen
        for the epoch lies beyond it (spec 047 §9.5, rev 5).
        """

        if self.final is None:
            return "no_final_heartbeat"
        if self.top > self.final:
            return "activity_after_final_heartbeat"
        return None

    def to_json(self, exchanges: int, *, p1: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "source_id": self.key[0],
            "source_epoch": self.key[1],
            "exchanges": exchanges,
            "heartbeat_sequence": self.heartbeat,
            "missing_sequences": [[first, last] for first, last in self.missing],
            "loss_ranges": [
                {
                    "reason": loss.reason,
                    "first_sequence": loss.first_sequence,
                    "last_sequence": loss.last_sequence,
                    "count": loss.count,
                }
                | ({} if loss.segment_id is None else {"segment_id": loss.segment_id})
                for loss in sorted(
                    self.losses,
                    key=lambda x: (x.first_sequence, x.last_sequence, x.reason, x.segment_id or ""),
                )
            ],
        }
        if self.final is not None:
            out["final_heartbeat_sequence"] = self.final
        if p1:  # spec 050 §3.12; absent for a pre-P1 capture
            out["manifests"] = [
                {"manifest_id": m.manifest_id, "sha256": m.sha256, "manifest_seq": m.manifest_seq}
                for m in self.manifests
            ]
            out["unsealed_epochs"] = sorted(self.unsealed_epochs)
        return out


def _segments(first: int, last: int, losses: Sequence[LossObs]) -> list[Segment]:
    """Split a missing range into loss-covered (with reason) and unexplained parts."""

    out: list[Segment] = []
    position = first
    for loss in losses:
        low, high = max(loss.first_sequence, position), min(loss.last_sequence, last)
        if high < low:
            continue
        if low > position:
            out.append((position, low - 1, None))
        out.append((low, high, loss.reason))
        position = high + 1
    if position <= last:
        out.append((position, last, None))
    return out


ScopeState = Literal["closed", "open", "conflict"]
# (source, run id, last_sequence, segment id): a P1 marker names its segment (spec 050).
Marker = tuple[SourceKey, str, int, str | None]


@dataclass(slots=True)
class _Scope:
    """One ``fabric.wire.run()`` block entry, keyed by its scope id (spec 048 §6).

    Markers pair by scope id only, never by run id or parity: the ``run_start``
    markers of the scope and exactly one distinct ``run_end``, on one source
    epoch, naming the same run, with ``a <= b``, close the scope over
    ``[a + 1, b]``. A scope has one ``run_start``, or (spec 050 §9 delta 1) one
    per segment when segments open inside the block: continuation markers,
    each naming a distinct segment, whose lowest ``last_sequence`` is ``a``.
    A missing marker leaves it ``open``; anything else is a ``conflict``.
    ``problem`` is ``None`` only for a closed scope whose tagged exchanges and
    records (of any run) all carry its run id and lie on its source inside its
    window.
    """

    scope_id: str
    starts: set[Marker] = field(default_factory=set)
    ends: set[Marker] = field(default_factory=set)
    exchanges: list[ExchangeObs] = field(default_factory=list)
    records: list[RecordObs] = field(default_factory=list)
    state: ScopeState = "open"
    key: SourceKey = ("", 0)
    start: int | None = None
    end: int | None = None
    problem: str | None = None

    def _paired_start(self) -> tuple[SourceKey, str, int] | None:
        """The scope's entry ``(source, run id, a)`` when its starts pair (delta 1)."""
        if not self.starts:
            return None
        sources = {(key, run_id) for key, run_id, _, _ in self.starts}
        segments = [segment for *_, segment in self.starts]
        continuation = None not in segments and len(set(segments)) == len(segments)
        if len(sources) != 1 or (len(self.starts) > 1 and not continuation):
            return None
        ((key, run_id),) = sources
        return key, run_id, min(last for _, _, last, _ in self.starts)

    def finalize(self) -> None:
        paired = self._paired_start()
        if paired is not None and len(self.ends) == 1:
            start_key, run_id, low = paired
            ((end_key, end_run, high, _),) = self.ends
            if start_key == end_key and run_id == end_run and low <= high:
                self.state, self.key, self.start, self.end = "closed", start_key, low, high
                if any(
                    exchange.run_id != run_id
                    or exchange.source != start_key
                    or not low < exchange.source_sequence <= high
                    for exchange in self.exchanges
                ):
                    self.problem = "exchange_outside_run_markers"
                elif any(
                    record.run_id != run_id
                    or record.source != start_key
                    or not low < record.source_sequence <= high
                    for record in self.records
                ):
                    self.problem = "record_outside_run_markers"
                return
        if (self.starts and self.ends) or (self.starts and paired is None) or len(self.ends) > 1:
            self.state, self.problem = "conflict", "scope_conflict"
        else:
            self.state, self.problem = "open", "run_not_closed"
        markers = self.starts | self.ends
        self.key = min(
            [key for key, *_ in markers]
            + [x.source for x in self.exchanges]
            + [x.source for x in self.records]
        )
        starts = {last for key, _, last, _ in self.starts if key == self.key}
        ends = {last for key, _, last, _ in self.ends if key == self.key}
        if paired is not None and paired[0] == self.key:
            self.start = paired[2]
        else:
            self.start = next(iter(starts)) if len(starts) == 1 else None
        self.end = next(iter(ends)) if len(ends) == 1 else None

    def to_json(self, exchanges: int) -> dict[str, Any]:
        out: dict[str, Any] = {
            "scope_id": self.scope_id,
            "source_id": self.key[0],
            "source_epoch": self.key[1],
            "state": self.state,
        }
        if self.start is not None:
            out["start_sequence"] = self.start
        if self.end is not None:
            out["end_sequence"] = self.end
        out["exchanges"] = exchanges
        return out


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def reconstruct(
    span_paths: Sequence[str | os.PathLike[str]],
    *,
    store: Any | None = None,
    tenant_id: str | None = None,
    run_ids: Collection[str] | None = None,
    generated_at: datetime | None = None,
    model_allowlist: Sequence[str] = (),
    id_key: bytes | None = None,
    wait_for_objects_s: float = 0.0,
    profile: Profile | None = None,
    trusted_source: bool = False,
    evaluated_at: datetime | None = None,
    clock_uncertainty_ns: int = 0,
    max_clock_uncertainty_ns: int = DEFAULT_MAX_CLOCK_UNCERTAINTY_NS,
    graphs_out: list[RunGraph] | None = None,
    projection_sink: ProjectionSink | None = None,
) -> dict[str, Any]:
    """Reconstruct runs from span files and an optional customer store.

    A ``span_paths`` entry that is a directory stands for its ``*.otlp`` files.
    ``wait_for_objects_s`` bounds how long, in total from the start, an absent
    object (or its descriptor) is re-read before it is reported missing: content
    can still be in flight to the store just after a run (default ``0``: no wait).

    ``model_allowlist`` extends the built-in model allowlist (spec 048 §7):
    exact names or ``prefix*`` entries. ``id_key`` (``FABRIC_WIRE_ID_KEY``) keys
    the label pseudonyms: the report shows tenant, source and run ids only in
    pseudonymous form (decision J1); ``run_ids`` (clear, pseudonym or fallback ids)
    are matched through the same projection (:func:`report_run_id`). Returns a
    ``fabric.run-reconstruction/v1`` document.

    Source authentication (spec 049 §7.9, decision 20): in the ``production``
    ``profile`` every record must carry the Node's ``fabric.source.authenticated``
    stamp, and a stamp counts only on trusted readback. ``trusted_source`` says the
    span files are the Node's own telemetry export or destination, read from a location
    the operator trusts; otherwise they are imported and none of their records is
    authenticated, whatever it carries. Content objects are always read back from the
    configured store. ``profile`` ``None`` means ``production`` when any span carries
    the stamp (only a bound Node writes it), else ``local``. A failed check is a
    ``source_unauthenticated`` gap with effect ``unverified``.

    Run structure (spec 050 §3.12): records-input records fill their source's sequence
    accounting; ``segment_seal`` markers are recomputed from the records, exchanges and
    segment-attributed losses naming the segment; manifests are chained per source epoch.
    ``evaluated_at`` (default ``generated_at``, else now) is when run states and deadlines
    are evaluated; ``clock_uncertainty_ns`` is added to each segment's declared clock
    uncertainty and ``max_clock_uncertainty_ns`` bounds it (the segment graph's inputs).
    ``graphs_out``, when given, receives the per-run segment graphs (the projection's input);
    ``projection_sink`` collects what the step projection needs (WP-32).
    Raises :class:`ReconstructInputError` for unusable input or options.
    """

    document, graphs = reconstruct_with_graphs(
        span_paths,
        store=store,
        tenant_id=tenant_id,
        run_ids=run_ids,
        generated_at=generated_at,
        model_allowlist=model_allowlist,
        id_key=id_key,
        wait_for_objects_s=wait_for_objects_s,
        profile=profile,
        trusted_source=trusted_source,
        evaluated_at=evaluated_at,
        clock_uncertainty_ns=clock_uncertainty_ns,
        max_clock_uncertainty_ns=max_clock_uncertainty_ns,
        projection_sink=projection_sink,
    )
    if graphs_out is not None:
        graphs_out.extend(graphs)
    return document


def reconstruct_with_graphs(
    span_paths: Sequence[str | os.PathLike[str]],
    *,
    store: Any | None = None,
    tenant_id: str | None = None,
    run_ids: Collection[str] | None = None,
    generated_at: datetime | None = None,
    model_allowlist: Sequence[str] = (),
    id_key: bytes | None = None,
    wait_for_objects_s: float = 0.0,
    profile: Profile | None = None,
    trusted_source: bool = False,
    evaluated_at: datetime | None = None,
    clock_uncertainty_ns: int = 0,
    max_clock_uncertainty_ns: int = DEFAULT_MAX_CLOCK_UNCERTAINTY_NS,
    projection_sink: ProjectionSink | None = None,
) -> tuple[dict[str, Any], list[RunGraph]]:
    """:func:`reconstruct`, plus the per-run segment graphs the step projection reads."""

    if not list(span_paths):
        raise ReconstructInputError("at least one span file is required")
    paths = list_span_inputs(span_paths)
    allowlist = _allowlist(model_allowlist)
    reader = (
        StoreReader(store, tenant_id, wait_for_objects_s=wait_for_objects_s)
        if store is not None
        else None
    )
    if profile not in (None, "local", "production"):
        raise ReconstructInputError("profile must be local or production")
    if clock_uncertainty_ns < 0 or max_clock_uncertainty_ns < 0:
        raise ReconstructInputError("clock uncertainties are durations of at least 0")
    now = datetime.now(tz=UTC)
    generated = generated_at or now
    evaluated = evaluated_at or generated
    span_files: list[dict[str, Any]] = []
    verifier = _Verifier(reader, allowlist, id_key, store=store if reader is not None else None)
    verifier.projection_sink = projection_sink
    if projection_sink is not None:
        projection_sink.attach(verifier)
    for index, path in enumerate(paths, start=1):
        fmt, records = read_span_file(path, label=f"span file {index}")
        span_files.append(_span_file_entry(path, fmt, len(records)))
        for number, record in enumerate(records, start=1):
            try:
                observation = observe(record)
            except ReconstructInputError:
                raise ReconstructInputError(
                    f"span file {index} span {number}: an exchange span has a malformed identity"
                ) from None
            verifier.add(observation, record)
    verifier.finalize()
    verifier.trusted_source = trusted_source
    verifier.production = (
        profile == "production" if profile is not None else verifier.stamp_observed
    )
    graphs = build_run_graphs(
        verifier.segment_nodes(),
        evaluated_at=evaluated,
        clock_uncertainty_ns=clock_uncertainty_ns,
        max_clock_uncertainty_ns=max_clock_uncertainty_ns,
    )
    verifier.graphs = {graph.run_id: graph for graph in graphs}
    verifier.evaluated_at = format_datetime(evaluated)
    inputs: dict[str, Any] = {
        "span_files": span_files,
        "telemetry_origin": "trusted_readback" if trusted_source else "imported",
        "profile": "production" if verifier.production else "local",
        "evaluated_at": verifier.evaluated_at,
    }
    if reader is not None:
        tenant = report_tenant_id(reader.tenant_id, id_key)
        inputs["store"] = {"kind": reader.kind, "tenant_id": tenant}
    wanted = None if run_ids is None else {report_run_id(value, id_key) for value in run_ids}
    runs, scopes = verifier.build_runs(wanted)
    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": format_datetime(generated),
        "verifier": {"name": "fabric.reconstruct", "version": __version__},
        "inputs": inputs,
        "sources": [
            verifier.sources[key].to_json(verifier.exchange_count[key], p1=verifier.p1)
            for key in sorted(verifier.sources)
        ],
        "runs": runs,
        "scopes": scopes,
    }
    return document, graphs


def _allowlist(entries: Sequence[str]) -> tuple[str, ...]:
    """Validate extra allowlist entries; the error never echoes an entry."""

    if isinstance(entries, str):
        entries = (entries,)
    out: list[str] = []
    for entry in entries:
        try:
            parsed = parse_model_allowlist(entry) if isinstance(entry, str) else ()
        except ValueError:
            parsed = ()
        if parsed != (entry,):
            raise ReconstructInputError(
                "model allowlist entries must be model names or name prefixes ending in '*'"
            ) from None
        out.append(entry)
    return tuple(out)


def _span_file_entry(path: str | os.PathLike[str], fmt: SpanFormat, count: int) -> dict[str, Any]:
    """A span file by digest, format and record count; never its path, which can name a
    user (home directory) or host layout the report's readers need not see."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "sha256": "sha256:" + digest.hexdigest(),
        "format": fmt,
        "records": count,
    }


# --------------------------------------------------------------------------
# Segments (spec 050 §3.12)
# --------------------------------------------------------------------------

SegmentMember = ExchangeObs | RecordObs
SegmentState = Literal["sealed", "unsealed", "conflict"]
SealCheck = Literal["verified", "mismatch", "unverified", "unsealed", "conflict"]
_DESCRIPTOR_ONLY = frozenset({"not_captured", "unsupported"})


@dataclass(slots=True)
class _Segment:
    """Everything the record names about one segment: its run markers, its seal(s), the
    records and exchanges carrying its id, and the losses attributed to it (R3)."""

    segment_id: str
    starts: set[HeartbeatObs] = field(default_factory=set)
    ends: set[HeartbeatObs] = field(default_factory=set)
    seals: set[SegmentSealObs] = field(default_factory=set)
    members: list[SegmentMember] = field(default_factory=list)
    losses: set[LossObs] = field(default_factory=set)
    key: SourceKey = ("", 0)
    state: SegmentState = "unsealed"
    check: SealCheck = "unsealed"
    gaps: list[Gap] = field(default_factory=list)

    def keys(self) -> set[SourceKey]:
        keys = {(m.source_id, m.source_epoch) for m in self.starts | self.ends}
        keys |= {seal.source for seal in self.seals} | {m.source for m in self.members}
        return keys | {(loss.source_id, loss.source_epoch) for loss in self.losses}

    @property
    def seal(self) -> SegmentSealObs | None:
        return next(iter(self.seals)) if len(self.seals) == 1 else None

    @property
    def run_ids(self) -> set[str]:
        ids = {m.run_id for m in self.starts | self.ends if m.run_id is not None}
        ids |= {seal.run_id for seal in self.seals if seal.run_id is not None}
        return ids | {m.run_id for m in self.members if m.run_id is not None}

    @property
    def scope_ids(self) -> tuple[str, ...]:
        ids = {m.scope_id for m in self.starts | self.ends if m.scope_id is not None}
        ids |= {seal.scope_id for seal in self.seals if seal.scope_id is not None}
        ids |= {m.scope_id for m in self.members if m.scope_id is not None}
        return tuple(sorted(ids))

    def opening(self) -> HeartbeatObs | None:
        """The ``run_start`` that opened the segment: the earliest one naming predecessors
        (an inner block's start in the same segment names none), else the earliest."""
        starts = sorted(self.starts, key=lambda m: (m.last_sequence, m.scope_id or ""))
        named = [m for m in starts if m.info is not None and m.info.predecessors]
        chosen = named or starts
        return chosen[0] if chosen else None

    def gap(self, gap_type: GapType, effect: Literal["partial", "unverified"], **kw: Any) -> None:
        self.gaps.append(
            Gap(gap_type, effect, source_id=self.key[0], source_epoch=self.key[1],
                segment_id=self.segment_id, **kw)
        )  # fmt: skip

    def to_json(self) -> dict[str, Any]:
        """The run's ``segments[]`` entry (the step projection's segment shape)."""
        opening, seal = self.opening(), self.seal
        info = opening.info if opening is not None else None
        out: dict[str, Any] = {
            "segment_id": self.segment_id,
            "source_id": self.key[0],
            "source_epoch": self.key[1],
        }
        if seal is not None:
            out["last_sequence"] = seal.seal_last_sequence
            if seal.manifest_digest is not None:
                out["manifest_digest"] = seal.manifest_digest
            if seal.terminal is not None:
                out["terminal"] = seal.terminal
        out["predecessors"] = list(info.predecessors) if info is not None else []
        out["state"] = self.state
        if seal is not None:
            out["seal_digest"] = seal.seal_digest
            if seal.branch_ids:
                out["branch_ids"] = list(seal.branch_ids)
        if info is not None and info.declared_branches:
            out["declared_branches"] = list(info.declared_branches)
        if info is not None and info.branch_ids:
            out["consumes_branch_ids"] = list(info.branch_ids)
        resumable = seal.resumable if seal is not None else None
        if resumable is None and info is not None:
            resumable = info.resumable
        if resumable is not None:
            out["resumable"] = resumable
        return out


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------


class _Verifier:
    def __init__(
        self,
        reader: StoreReader | None,
        allowlist: Sequence[str] = (),
        key: bytes | None = None,
        *,
        store: Any | None = None,
    ) -> None:
        self.reader = reader
        self.store = store  # the duck-typed store behind ``reader`` (record descriptors)
        self.allowlist = tuple(allowlist)
        self.key = key
        # Every distinct observation per exchange id, in input order. Identical
        # retries are one observation; differing ones are all kept (each claim
        # of a sequence, run and scope counts) and mark the id conflicting.
        self.observations: dict[str, list[ExchangeObs]] = {}
        self.conflicts: set[str] = set()
        self.sources: dict[SourceKey, _Source] = {}
        self.exchange_count: dict[SourceKey, int] = defaultdict(int)
        self._counted: set[tuple[str, SourceKey]] = set()
        self.claims: dict[tuple[SourceKey, int], set[str]] = defaultdict(set)
        self.scopes: dict[str, _Scope] = {}
        self.run_scopes: dict[str, set[str]] = defaultdict(set)
        self._heartbeats: set[HeartbeatObs] = set()
        # Scopes named by a run marker with malformed fields: never closed (sol2 #5).
        self.malformed_scopes: set[str] = set()
        # 049 §7.9: the Node's source stamp. Sources with an unstamped loss or heartbeat
        # record, exchange ids with an unstamped observation, and whether any span is
        # stamped. ``production``/``trusted_source`` are set before runs are built.
        self.unstamped_sources: set[SourceKey] = set()
        self.unstamped_exchanges: set[str] = set()
        self.stamp_observed = False
        self.production = False
        self.trusted_source = False
        # Spec 050 §3.12: records, segments, seals and manifests.
        self.records: set[RecordObs] = set()
        self.run_records: dict[str, list[RecordObs]] = defaultdict(list)
        self.segments: dict[str, _Segment] = {}
        self._seals: set[SegmentSealObs] = set()
        self.manifest_obs: dict[SourceKey, set[ManifestObs]] = defaultdict(set)
        self.manifest_claims: dict[SourceKey, int] = {}  # highest manifest_seq a marker names
        # (run id, source, manifest digest, scope id): a run marker or seal names a manifest.
        self.manifest_refs: set[tuple[str, SourceKey, str, str | None]] = set()
        self.periodic: set[SourceKey] = set()
        self.unsealed: dict[SourceKey, str] = {}  # epoch -> why it is unsealed
        self.run_gaps: dict[str, list[tuple[Gap, tuple[str, ...]]]] = defaultdict(list)
        self.run_segments: dict[str, list[_Segment]] = defaultdict(list)
        self.graphs: dict[str, RunGraph] = {}
        self.evaluated_at: str | None = None
        self.p1 = False
        self._descriptors: dict[str, tuple[str | None, bool]] = {}
        self.projection_sink: ProjectionSink | None = None  # WP-32: the step projection

    def _scope(self, scope_id: str, run_id: str) -> _Scope:
        self.run_scopes[run_id].add(scope_id)
        if scope_id not in self.scopes:
            self.scopes[scope_id] = _Scope(scope_id)
        return self.scopes[scope_id]

    def _source(self, key: SourceKey) -> _Source:
        if key not in self.sources:
            self.sources[key] = _Source(key)
        return self.sources[key]

    def _segment(self, segment_id: str) -> _Segment:
        if segment_id not in self.segments:
            self.segments[segment_id] = _Segment(segment_id)
        return self.segments[segment_id]

    def _labels(self, obs: Observation | None) -> Observation | None:
        """Source and run ids in their report form (decision J1), before any accounting, so
        legacy clear and pseudonymous records of one source or run are one. A predecessor
        entry's source id is projected the same way, so it names the segment's source."""
        if obs is None:
            return None
        if isinstance(obs, MalformedMarkerObs):
            heartbeat = self._labels(obs.heartbeat)
            return MalformedMarkerObs(obs.scope_id, cast("HeartbeatObs | None", heartbeat))
        changes: dict[str, Any] = {"source_id": report_source_id(obs.source_id, self.key)}
        run_id = getattr(obs, "run_id", None)
        if run_id is not None:
            changes["run_id"] = report_run_id(run_id, self.key)
        if isinstance(obs, HeartbeatObs) and obs.info is not None and obs.info.predecessors:
            changes["info"] = dataclasses.replace(
                obs.info, predecessors=tuple(map(self._predecessor, obs.info.predecessors))
            )
        return dataclasses.replace(obs, **changes)

    def _predecessor(self, entry: str) -> str:
        if entry == "none":
            return entry
        parts = entry.split("/")
        parts[1] = report_source_id(parts[1], self.key)
        return "/".join(parts)

    def _stamp(self, obs: Observation) -> None:
        """Note whether ``obs`` carries the Node's stamp (049 §7.9); any unstamped copy of a
        record counts, whichever copy the accounting keeps."""
        if isinstance(obs, MalformedMarkerObs):
            return
        if obs.authenticated:
            self.stamp_observed = True
        elif isinstance(obs, ExchangeObs):
            self.unstamped_exchanges.add(obs.exchange_id)
        else:
            self.unstamped_sources.add((obs.source_id, obs.source_epoch))

    def _claim_manifest(self, key: SourceKey, manifest_seq: int | None) -> None:
        if manifest_seq is not None:
            self.manifest_claims[key] = max(manifest_seq, self.manifest_claims.get(key, -1))

    def add(self, obs: Observation | None, span: SpanRecord | None = None) -> None:
        obs = self._labels(obs)
        if obs is not None:
            self._stamp(obs)
            if self.projection_sink is not None and span is not None:
                self.projection_sink.observed(obs, span)
        if isinstance(obs, MalformedMarkerObs):
            self.malformed_scopes.add(obs.scope_id)
            self.add(obs.heartbeat)
        elif isinstance(obs, ExchangeObs):
            self._add_exchange(obs)
        elif isinstance(obs, RecordObs):
            self._add_record(obs)
        elif isinstance(obs, LossObs):
            self._source((obs.source_id, obs.source_epoch)).losses.add(obs)
            if obs.segment_id is not None:
                self._segment(obs.segment_id).losses.add(obs)
        elif isinstance(obs, SegmentSealObs):
            self._add_seal(obs)
        elif isinstance(obs, ManifestObs):
            self.manifest_obs[obs.source].add(obs)
            source = self._source(obs.source)
            # A manifest's after_source_sequence was allocated before it was written.
            source.heartbeat = max(source.heartbeat, obs.after_source_sequence)
        elif isinstance(obs, HeartbeatObs):
            self._add_heartbeat(obs)

    def _add_exchange(self, obs: ExchangeObs) -> None:
        seen = self.observations.setdefault(obs.exchange_id, [])
        if obs in seen:
            return  # an identical retry (at-least-once delivery)
        seen.append(obs)
        if len(seen) > 1:
            self.conflicts.add(obs.exchange_id)
        self._source(obs.source).sequences.add(obs.source_sequence)
        if (obs.exchange_id, obs.source) not in self._counted:
            self._counted.add((obs.exchange_id, obs.source))
            self.exchange_count[obs.source] += 1
        self.claims[(obs.source, obs.source_sequence)].add(obs.exchange_id)
        if obs.scope_id is not None:
            self._scope(obs.scope_id, obs.run_id).exchanges.append(obs)
        if obs.segment_id is not None:
            self._segment(obs.segment_id).members.append(obs)

    def _add_record(self, obs: RecordObs) -> None:
        """A records-input record fills its position as an exchange does (spec 050 §3.12);
        a differing record (or an exchange) at the same position is a conflicting claim."""
        if obs in self.records:
            return  # an identical retry
        self.records.add(obs)
        self._source(obs.source).sequences.add(obs.source_sequence)
        self.claims[(obs.source, obs.source_sequence)].add("record:" + obs.fingerprint)
        if obs.run_id is not None:
            self.run_records[obs.run_id].append(obs)
        if obs.scope_id is not None and obs.run_id is not None:
            self._scope(obs.scope_id, obs.run_id).records.append(obs)
        if obs.segment_id is not None:
            self._segment(obs.segment_id).members.append(obs)

    def _add_seal(self, obs: SegmentSealObs) -> None:
        self._claim_manifest(obs.source, obs.manifest_seq)
        if obs in self._seals:
            return
        self._seals.add(obs)
        source = self._source(obs.source)
        source.heartbeat = max(source.heartbeat, obs.last_sequence)
        self._segment(obs.segment_id).seals.add(obs)
        if obs.manifest_digest is not None and obs.run_id is not None:
            self.manifest_refs.add((obs.run_id, obs.source, obs.manifest_digest, obs.scope_id))

    def _add_heartbeat(self, obs: HeartbeatObs) -> None:
        key = (obs.source_id, obs.source_epoch)
        self._claim_manifest(key, obs.manifest_seq)
        if obs in self._heartbeats:
            # Deduplicated by logical identity (source, epoch, kind, run id, scope id,
            # last sequence, segment), never by span id: a retried export re-sends the
            # same record under a new span id and must not count twice.
            return
        self._heartbeats.add(obs)
        source = self._source(key)
        source.heartbeat = max(source.heartbeat, obs.last_sequence)
        if obs.kind == "final":
            source.final = max(obs.last_sequence, -1 if source.final is None else source.final)
        elif obs.kind == "periodic":
            self.periodic.add(key)
        elif obs.scope_id is not None and obs.run_id is not None:
            scope = self._scope(obs.scope_id, obs.run_id)
            marks = scope.starts if obs.kind == "run_start" else scope.ends
            marks.add((key, obs.run_id, obs.last_sequence, obs.segment_id))
            if obs.segment_id is not None:
                segment = self._segment(obs.segment_id)
                (segment.starts if obs.kind == "run_start" else segment.ends).add(obs)
            if obs.info is not None and obs.info.manifest_digest is not None:
                self.manifest_refs.add((obs.run_id, key, obs.info.manifest_digest, obs.scope_id))

    def finalize(self) -> None:
        for source in self.sources.values():
            source.finalize()
        for (key, sequence), ids in self.claims.items():
            if len(ids) > 1 or not ids.isdisjoint(self.conflicts):
                self.sources[key].conflicted.add(sequence)
        for source in self.sources.values():
            source.finalize_conflicts()
        for scope in self.scopes.values():
            scope.finalize()
            if scope.scope_id in self.malformed_scopes:  # a malformed marker names it
                scope.state, scope.problem = "conflict", "malformed_record"
        self.p1 = bool(self.segments or self.manifest_obs)
        for key in sorted(set(self.manifest_obs) | set(self.manifest_claims)):
            self._check_manifests(key)
        self._unsealed_epochs()
        for segment_id in sorted(self.segments):
            self._check_segment(self.segments[segment_id])
        self._check_manifest_refs()

    # -- manifests (spec 050 §3.12) --------------------------------------------

    def _check_manifests(self, key: SourceKey) -> None:
        """The chain of one ``(source, epoch)``: contiguous ``manifest_seq`` from 0, each
        ``previous_manifest_sha256`` the digest of its predecessor, and no heartbeat naming
        a ``manifest_seq`` above the highest present. A failure records the sequence window
        as manifest-less (rule R1); two different manifest 0 documents are a conflict."""
        source = self._source(key)
        present = sorted(self.manifest_obs.get(key, ()), key=lambda m: (m.manifest_seq, m.sha256))
        source.manifests = present
        by_seq: dict[int, list[ManifestObs]] = defaultdict(list)
        for manifest in present:
            by_seq[manifest.manifest_seq].append(manifest)
        source.manifest_conflict = len(by_seq.get(0, ())) > 1
        # A sequence with two different documents is as good as missing.
        single = {seq: docs[0] for seq, docs in by_seq.items() if len(docs) == 1}
        good = sorted(single)
        top = max([self.manifest_claims.get(key, -1), *by_seq])
        windows = source.manifestless
        previous: ManifestObs | None = None
        expected = 0
        for index, seq in enumerate(good):
            manifest = single[seq]
            low = 0 if previous is None else previous.after_source_sequence + 1
            if seq > expected:
                windows.append((low, manifest.after_source_sequence, "manifest_missing"))
            elif previous is not None and manifest.previous_sha256 != previous.sha256:
                following = good[index + 1] if index + 1 < len(good) else None
                high = None if following is None else single[following].after_source_sequence
                windows.append((low, high, "chain_mismatch"))
            previous, expected = manifest, seq + 1
        if top >= expected:
            low = 0 if previous is None else previous.after_source_sequence + 1
            windows.append((low, None, "manifest_missing"))

    def _unsealed_epochs(self) -> None:
        """Epochs declared unsealed by a manifest 0 (``unsealed_prior_epochs``, listed on
        the declaring source) and orphan epochs: a P1 capture's epoch seen only through
        periodic heartbeats, without a final heartbeat or a manifest of its own (the
        drainer's heartbeat for an orphaned registration, 050 §3.2 rule 5)."""
        for key, manifests in self.manifest_obs.items():
            for manifest in manifests:
                for epoch in manifest.unsealed_prior_epochs:
                    self.sources[key].unsealed_epochs.add(epoch)
                    self.unsealed.setdefault((key[0], epoch), "unsealed_prior_epoch")
        if not self.p1:
            return
        for key in self.periodic:
            if self.sources[key].final is None and key not in self.manifest_obs:
                self.sources[key].unsealed_epochs.add(key[1])
                self.unsealed.setdefault(key, "orphan_epoch")

    def _check_manifest_refs(self) -> None:
        """A run marker or seal naming a manifest digest that no manifest of its source
        epoch has: the configuration it ran under is unknown (``manifest_gap``)."""
        for run_id, key, digest, scope_id in sorted(self.manifest_refs, key=repr):
            known = {manifest.sha256 for manifest in self.manifest_obs.get(key, ())}
            if digest in known:
                continue
            gap = Gap("manifest_gap", "unverified", source_id=key[0], source_epoch=key[1],
                      reason="unknown_manifest" if known else "manifest_missing")  # fmt: skip
            self.run_gaps[run_id].append((gap, () if scope_id is None else (scope_id,)))

    # -- seals (spec 050 §3.7, 049 §2.12) --------------------------------------

    def _check_segment(self, segment: _Segment) -> None:
        keys = segment.keys()
        seal = segment.seal
        segment.key = seal.source if seal is not None else min(keys)
        if len(keys) > 1:
            segment.gap("segment_conflict", "partial", reason="segment_on_two_sources")
        if len(segment.seals) > 1:
            segment.gap("segment_conflict", "partial", reason="conflicting_seal")
        named = {m.info.predecessors for m in segment.starts if m.info and m.info.predecessors}
        if len(named) > 1:
            segment.gap("segment_conflict", "partial", reason="conflicting_predecessors")
        if self.sources[segment.key].manifest_conflict:
            segment.gap("segment_conflict", "partial", reason="manifest_conflict")
        if segment.key in self.unsealed:
            segment.gap("unsealed_epoch", "partial", reason=self.unsealed[segment.key])
        if seal is not None:
            segment.check = self._check_seal(segment, seal)
        elif segment.seals:
            segment.check = "conflict"
        elif segment.members or segment.losses:
            # 049 §2.12 rule 3: a segment with records and no seal (X44).
            segment.gap("unsealed_segment", "partial", reason="source_lost")
        conflicted = any(gap.gap_type == "segment_conflict" for gap in segment.gaps)
        if conflicted or segment.check in ("mismatch", "conflict"):
            segment.state = "conflict"
        else:
            segment.state = "unsealed" if seal is None else "sealed"
        scopes = segment.scope_ids
        for run_id in sorted(segment.run_ids):
            self.run_segments[run_id].append(segment)
            self.run_gaps[run_id].extend((gap, scopes) for gap in segment.gaps)

    def _check_seal(self, segment: _Segment, seal: SegmentSealObs) -> SealCheck:
        """Recompute the seal (§3.7) from the records and exchanges of the seal's source
        naming the segment and the losses naming it (never by sequence range, R3)."""
        last = seal.seal_last_sequence
        members = [m for m in segment.members if m.source == seal.source]
        for sequence in sorted({m.source_sequence for m in members if m.source_sequence > last}):
            # 049 G1: a record of a sealed segment above its last_sequence.
            segment.gap("segment_conflict", "partial", first_sequence=sequence,
                        last_sequence=sequence, reason="record_after_seal")  # fmt: skip
        entries, problem = self._seal_entries(segment, seal, members)
        if problem == "inexact_loss_range":
            segment.gap("seal_mismatch", "partial", reason=problem)
            return "mismatch"
        if problem is not None:
            segment.gap("seal_mismatch", "unverified", reason=problem)
            return "unverified"
        if any(len(found) > 1 for found in entries.values()):
            segment.gap("seal_mismatch", "partial", reason="conflicting_member")
            return "mismatch"
        pairs = [(position, next(iter(found))) for position, found in sorted(entries.items())]
        try:
            digest = _seal.seal_digest(pairs)
        except NotImplementedError:
            segment.gap("seal_mismatch", "unverified", reason="seal_rule_unavailable")
            return "unverified"
        if digest != seal.seal_digest:
            segment.gap("seal_mismatch", "partial", reason="digest_differs")
            return "mismatch"
        return "verified"

    def _seal_entries(
        self, segment: _Segment, seal: SegmentSealObs, members: Sequence[SegmentMember]
    ) -> tuple[dict[int, set[str]], str | None]:
        """Every member position's candidate entries, and why they cannot all be computed
        here (``inexact_loss_range``: a segment-attributed range is always exact)."""
        entries: dict[int, set[str]] = defaultdict(set)
        problem: str | None = None
        for member in members:
            if member.source_sequence > seal.seal_last_sequence:
                continue
            entry, why = self._member_entry(member)
            if entry is None:
                problem = problem or why
            else:
                entries[member.source_sequence].add(entry)
        for loss in segment.losses:
            if (loss.source_id, loss.source_epoch) != seal.source:
                continue
            if loss.count != loss.last_sequence - loss.first_sequence + 1:
                return entries, "inexact_loss_range"
            for position in range(loss.first_sequence, loss.last_sequence + 1):
                entries[position].add(_seal.loss_entry(loss.reason))
        return entries, problem

    def _member_entry(self, member: SegmentMember) -> tuple[str | None, str | None]:
        """``(record digest, None)``, or ``(None, why)`` when it cannot be computed here."""
        span = member.span
        if span is None:  # a P1 exchange always keeps its span
            return None, "member_unreadable"
        attributes = span.attributes
        content: list[str | None]
        if isinstance(member, ExchangeObs):
            sides = (attributes.get(A_REQUEST_SHA256), attributes.get(A_RESPONSE_SHA256))
            content = [digest for digest in map(digest_value, sides) if digest is not None]
        else:
            found, why = self._record_content(attributes.get(A_OBJECT_IDS))
            if why is not None:
                return None, why
            if found is None:  # malformed object ids: a value no emitter writes
                return f"unhashable:{member.source_sequence}", None
            content = found
        try:
            digest = _seal.record_digest(
                name=span.name, start_ns=span.start_ns, end_ns=span.end_ns, status=span.status,
                attributes=attributes, content=content,
            )  # fmt: skip
        except NotImplementedError:
            return None, "seal_rule_unavailable"
        except (ValueError, TypeError):  # a float or map: never what the emitter sealed
            return f"unhashable:{member.source_sequence}", None
        return digest, None

    def _record_content(self, object_ids: Any) -> tuple[list[str | None] | None, str | None]:
        """The ``stored_sha256`` of each object a record names, in list order, ``None``
        for a descriptor-only object (§3.7). Read from the configured store's descriptors;
        ``(None, why)`` when there is no store or a descriptor cannot be read."""
        if object_ids is None:
            return [], None
        if (
            not isinstance(object_ids, list)
            or not 1 <= len(object_ids) <= _MAX_RECORD_OBJECTS
            or any(uuid4_value(object_id) is None for object_id in object_ids)
        ):
            return None, None
        if self.store is None or self.reader is None:
            return None, "no_store"
        content: list[str | None] = []
        for object_id in object_ids:
            if object_id not in self._descriptors:
                self._descriptors[object_id] = self._stored_digest(object_id)
            digest, ok = self._descriptors[object_id]
            if not ok:
                return None, "content_unavailable"
            content.append(digest)
        return content, None

    def _stored_digest(self, object_id: str) -> tuple[str | None, bool]:
        if self.store is None or self.reader is None:
            return None, False
        try:
            descriptor = self.store.read_descriptor(self.store.evidence_ref_for(object_id))
        except ImportError:
            raise  # a missing reader dependency is a setup error
        except Exception:
            return None, False
        if (
            not isinstance(descriptor, Mapping)
            or descriptor.get("object_id") != object_id
            or descriptor.get("tenant_id") != self.reader.tenant_id
        ):
            return None, False
        stored = descriptor.get("stored_sha256")
        if stored is None and descriptor.get("status") in _DESCRIPTOR_ONLY:
            return None, True
        return (stored, True) if prefixed_digest(stored) is not None else (None, False)

    def segment_nodes(self) -> list[SegmentNode]:
        """The segment graph's input: one node per segment whose run is known."""
        nodes: list[SegmentNode] = []
        for segment_id in sorted(self.segments):
            segment = self.segments[segment_id]
            opening, seal = segment.opening(), segment.seal
            run_id = opening.run_id if opening is not None else min(segment.run_ids, default=None)
            if run_id is None:
                continue
            info = opening.info if opening is not None else None
            nodes.append(
                SegmentNode(
                    segment_id=segment_id,
                    run_id=run_id,
                    source_id=segment.key[0],
                    epoch=segment.key[1],
                    predecessors=info.predecessors if info is not None else (),
                    id_basis=info.id_basis if info is not None else None,
                    branch_ids=info.branch_ids if info is not None else (),
                    declared_branches=info.declared_branches if info is not None else (),
                    start_ns=info.start_ns if info is not None else None,
                    last_sequence=seal.seal_last_sequence if seal is not None else None,
                    terminal=seal.terminal if seal is not None else None,
                    resumable=seal.resumable if seal is not None else None,
                    clock_uncertainty_ns=self._clock_uncertainty(segment.key),
                    # WP-31: the seal's minted branch ids, digest and time, the segment's
                    # state, and the run_start's resumable flag and deadline override.
                    issued_branch_ids=seal.branch_ids if seal is not None else (),
                    manifest_digest=seal.manifest_digest if seal is not None else None,
                    state=segment.state,
                    start_resumable=info.resumable if info is not None else None,
                    open_deadline_s=info.open_deadline_s if info is not None else None,
                    manifest_open_run_deadline_s=self._open_run_deadline(segment.key),
                    sealed_ns=seal.sealed_ns if seal is not None else None,
                )
            )
        return nodes

    def _open_run_deadline(self, key: SourceKey) -> int | None:
        """The ``limits.open_run_deadline_s`` of the source epoch's latest manifest."""
        for manifest in reversed(self.sources[key].manifests):
            limits = manifest.document.get("limits")
            value = limits.get("open_run_deadline_s") if isinstance(limits, Mapping) else None
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                return value
        return None

    def _clock_uncertainty(self, key: SourceKey) -> int | None:
        """The declared ``clock.uncertainty_ns`` of the source epoch's latest manifest."""
        for manifest in reversed(self.sources[key].manifests):
            clock = manifest.document.get("clock")
            value = clock.get("uncertainty_ns") if isinstance(clock, Mapping) else None
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        return None

    def run_ids_of(self, run_id: str) -> tuple[str, ...]:
        """``run_id`` and the run ids the segment graph merged into it (WP-31)."""
        graph = self.graphs.get(run_id)
        return (run_id,) if graph is None else graph.member_run_ids()

    def build_runs(
        self, wanted: set[str] | None
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """The reported runs and, in run order, the per-scope verdicts of their scopes."""

        # WP-31: a run the segment graph merged (caller_join, legacy) is one report run under
        # its canonical id; its other run ids are its run_aliases.
        canonical = {alias: graph.run_id for graph in self.graphs.values()
                     for alias in graph.run_aliases}  # fmt: skip
        observed: dict[str, list[ExchangeObs]] = defaultdict(list)
        for observations in self.observations.values():
            for exchange in observations:
                observed[canonical.get(exchange.run_id, exchange.run_id)].append(exchange)
        run_scopes: dict[str, set[str]] = defaultdict(set)
        for run_id, scope_ids in self.run_scopes.items():
            run_scopes[canonical.get(run_id, run_id)] |= scope_ids
        runs: list[dict[str, Any]] = []
        scopes: list[dict[str, Any]] = []
        # An epoch that allocated sequences (its heartbeats say so) of which no exchange, no
        # record and no scope marker arrived (a killed fork worker, wire/_forks.py) is
        # reported as its source-fallback run, every sequence missing: a loss, never silence.
        seen = {x.source for xs in observed.values() for x in xs}
        seen |= {scope.key for scope in self.scopes.values()}
        seen |= {record.source for record in self.records}
        silent = {
            encode_opaque_id(f"source:{key[0]}:{key[1]}"): key
            for key, source in self.sources.items()
            if key not in seen and source.top >= 0
        }
        for run_id in sorted(set(observed) | set(run_scopes) | set(silent)):
            if wanted is not None and not wanted & set(self.run_ids_of(run_id)):
                continue
            members = [self.scopes[scope_id] for scope_id in run_scopes.get(run_id, ())]
            run = _Run(self, run_id, observed.get(run_id, []), members, silent.get(run_id))
            if run.windows:
                report, scope_reports = run.build()
                runs.append(report)
                scopes.extend(scope_reports)
        return runs, scopes


# --------------------------------------------------------------------------
# One run
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _Window:
    """One declared window of a run on one source epoch.

    ``closed_by`` names the evidence that proves its end: the scope's own
    ``run_start`` / ``run_end`` markers (a window with ``scope_id``) or, for
    a run without scopes, the epoch's final heartbeat. ``None`` when the end
    is not proven.
    """

    key: SourceKey
    low: int
    high: int
    scope_id: str | None = None
    closed_by: Literal["run_markers", "final_heartbeat"] | None = None

    def to_json(self, heartbeat: int) -> dict[str, Any]:
        out: dict[str, Any] = {
            "source_id": self.key[0],
            "source_epoch": self.key[1],
            "first_sequence": self.low,
            "last_sequence": self.high,
            "heartbeat_sequence": heartbeat,
        }
        if self.scope_id is not None:
            out["scope_id"] = self.scope_id
        if self.closed_by is not None:
            out["closed_by"] = self.closed_by
        return out


@dataclass(slots=True)
class _Bodies:
    request: ObjectResult
    response: ObjectResult | None
    skipped: bool


def _ranges(sequences: Iterable[int]) -> list[list[int]]:
    """Sorted positions as ``[first, last]`` runs of consecutive sequences."""
    out: list[list[int]] = []
    for sequence in sorted(set(sequences)):
        if out and out[-1][1] + 1 == sequence:
            out[-1][1] = sequence
        else:
            out.append([sequence, sequence])
    return out


def _attempts(records: Iterable[RecordObs]) -> list[dict[str, Any]]:
    """Every records-input attempt of a run with its complete position set (specs 050 and
    054: the projection lists at most 64 ``event_ids`` per step; the report keeps all of
    them): ``attempt_uid``, the step id when the records carry one, the number of
    positions, and per source epoch the positions as ranges of consecutive sequences."""
    by_attempt: dict[str, dict[SourceKey, set[int]]] = defaultdict(lambda: defaultdict(set))
    steps: dict[str, set[str]] = defaultdict(set)
    for record in records:
        by_attempt[record.attempt_uid][record.source].add(record.source_sequence)
        step_id = record.span.attributes.get(A_STEP_ID)
        if isinstance(step_id, str) and opaque_id(step_id) is not None:
            steps[record.attempt_uid].add(step_id)
    out: list[dict[str, Any]] = []
    for attempt_uid, positions in by_attempt.items():
        entry: dict[str, Any] = {"attempt_uid": attempt_uid}
        if len(steps[attempt_uid]) == 1:
            (entry["step_id"],) = steps[attempt_uid]
        entry["records"] = sum(len(found) for found in positions.values())
        entry["sequences"] = [
            {"source_id": key[0], "source_epoch": key[1], "ranges": _ranges(found)}
            for key, found in sorted(positions.items())
        ]
        out.append(entry)
    out.sort(key=lambda e: (e["sequences"][0]["source_id"], e["sequences"][0]["source_epoch"],
                            e["sequences"][0]["ranges"][0][0], e["attempt_uid"]))  # fmt: skip
    return out


def _by_source(exchanges: Iterable[ExchangeObs]) -> dict[SourceKey, list[int]]:
    out: dict[SourceKey, list[int]] = defaultdict(list)
    for exchange in exchanges:
        out[exchange.source].append(exchange.source_sequence)
    return out


class _Run:
    """One run id: its windows, gaps and, for a scoped run, one verdict per scope.

    ``observed`` holds every distinct observation naming the run, including
    every version of a conflicting exchange id (each claim counts). The
    report lists one entry per exchange id; a gap about an exchange counts
    against every scope any of its observations names.
    """

    def __init__(
        self,
        verifier: _Verifier,
        run_id: str,
        observed: list[ExchangeObs],
        scopes: Sequence[_Scope],
        silent: SourceKey | None = None,
    ) -> None:
        self.verifier = verifier
        self.run_id = run_id
        self.observed = observed
        representative: dict[str, ExchangeObs] = {}
        self.scopes_of: dict[str, set[str]] = defaultdict(set)
        for exchange in observed:
            if not exchange.malformed:  # a malformed observation's payload is never used
                representative.setdefault(exchange.exchange_id, exchange)
            if exchange.scope_id is not None:
                self.scopes_of[exchange.exchange_id].add(exchange.scope_id)
        self.members = sorted(
            representative.values(),
            key=lambda x: (x.start_ns, x.source_id, x.source_epoch, x.source_sequence),
        )
        self.order = {exchange.exchange_id: i for i, exchange in enumerate(self.members)}
        self.scopes = sorted(
            scopes, key=lambda x: (x.key, -2 if x.start is None else x.start, x.scope_id)
        )
        self.gaps: list[Gap] = []
        self.scope_gaps: dict[str, list[Gap]] = {scope.scope_id: [] for scope in self.scopes}
        # The scopes a window gap found right now belongs to (spec 048 §6, H5).
        self._attribute: tuple[str, ...] = ()
        self.windows: list[_Window] = []
        if self.scopes:
            self._scoped()
        else:
            self._unscoped()
        if silent is not None and not observed and not self.scopes:
            top = self.verifier.sources[silent].top
            self.windows.append(_Window(silent, 0, top))
            self._inside_gaps(silent, 0, top)
            self._tail(silent, self.verifier.sources[silent].tail_problem())
        self.windows.sort(key=lambda w: (w.key, w.low, w.high, w.scope_id or ""))

    def _add(self, gap: Gap, scopes: Iterable[str] | None = None) -> None:
        """Record a gap for the run and for each scope it counts against."""

        self.gaps.append(gap)
        for scope_id in self._attribute if scopes is None else scopes:
            if scope_id in self.scope_gaps:
                self.scope_gaps[scope_id].append(gap)

    # -- completeness (spec 047 §9.5 rule b, spec 048 §6) ----------------------

    def _unscoped(self) -> None:
        """A run without scopes: only the epoch's final heartbeat proves its end."""

        for key, own in sorted(_by_source(self.observed).items()):
            problem = self.verifier.sources[key].tail_problem()
            closed_by: Literal["final_heartbeat"] | None = (
                "final_heartbeat" if problem is None else None
            )
            self.windows.append(_Window(key, min(own), max(own), None, closed_by))
            self._near_gaps(key, min(own), max(own))
            self._tail(key, problem)

    def _scoped(self) -> None:
        """A run with scopes: each scope is judged on its own (decision H5).

        A closed scope's window ``[a + 1, b]`` is proven by its markers:
        ``a`` was allocated before entry and ``b + 1`` after exit, so only
        sequences inside it matter, and any missing one is ``partial`` (it
        cannot be attributed to a particular concurrent scope, so it counts
        against every scope whose window holds it). An open or conflicting
        scope, or a scoped exchange outside its scope, is ``unverified``; so
        is an exchange of the run that started outside every scope (a
        run-level gap that belongs to no scope).
        """

        for scope in self.scopes:
            self._attribute = (scope.scope_id,)
            own = [x for x in self.observed if x.scope_id == scope.scope_id]
            if scope.problem is None and scope.start is not None and scope.end is not None:
                if scope.start < scope.end:
                    self.windows.append(
                        _Window(
                            scope.key, scope.start + 1, scope.end, scope.scope_id, "run_markers"
                        )
                    )
                self._inside_gaps(scope.key, scope.start + 1, scope.end)
                continue
            self._open_scope(scope, own)
        self._attribute = ()
        unscoped = [x for x in self.observed if x.scope_id is None]
        for key, own_sequences in sorted(_by_source(unscoped).items()):
            low, high = min(own_sequences), max(own_sequences)
            self.windows.append(_Window(key, low, high))
            self._near_gaps(key, low, high)
            self._tail(key, "exchange_outside_run_markers")

    def _open_scope(self, scope: _Scope, own: Sequence[ExchangeObs]) -> None:
        """An unproven scope: bounds come from its exchanges and whatever markers exist."""

        key = scope.key
        on_key = [x.source_sequence for x in own if x.source == key]
        on_key += [x.source_sequence for x in scope.records if x.source == key]
        lows = [*on_key, *([] if scope.start is None else [scope.start + 1])]
        highs = [*on_key, *([] if scope.end is None else [scope.end])]
        low = min(lows) if lows else max(min(highs), 0)
        high = max(max(highs, default=low), low)
        self.windows.append(_Window(key, low, high, scope.scope_id))
        if scope.state == "closed" and scope.start is not None and scope.end is not None:
            self._inside_gaps(key, scope.start + 1, scope.end)
        else:
            self._inside_gaps(key, low, high)
            if scope.end is None:
                self._inside_gaps(key, high + 1, None, "unverified")
        self._tail(key, scope.problem)
        elsewhere: dict[SourceKey, list[int]] = defaultdict(list)
        members: list[ExchangeObs | RecordObs] = [*own, *scope.records]
        for member in members:
            if member.source != key:
                elsewhere[member.source].append(member.source_sequence)
        for other, sequences in sorted(elsewhere.items()):
            self.windows.append(_Window(other, min(sequences), max(sequences)))
            self._near_gaps(other, min(sequences), max(sequences))

    def _inside_gaps(
        self,
        key: SourceKey,
        low: int,
        high: int | None,
        effect: Literal["partial", "unverified"] = "partial",
    ) -> None:
        """Missing sequences within ``[low, high]`` (open-ended when ``high`` is None)."""

        source = self.verifier.sources[key]
        top = source.top if high is None else high
        # The segments intersecting [low, top]: segments are disjoint and ascending.
        first = bisect_left(source.seg_high, low)
        end = bisect_right(source.seg_low, top)
        self._segment_gaps(key, first, end, low, top, effect)
        self._conflicted(key, low, top)

    def _near_gaps(self, key: SourceKey, low: int, high: int) -> None:
        """Spec 047 §9.5 rule (b) for a window bounded only by its exchanges.

        A missing sequence inside the window, or adjacent to it (it may be
        the run's own first or last call), is ``partial``. One after the
        window may be the run's lost later call: ``unverified``, even under a
        final heartbeat (which proves only that nothing beyond it exists).
        """

        source = self.verifier.sources[key]
        # Whole missing ranges intersecting [low - 1, high + 1] are partial; every
        # range after them (first > high + 1, hence last >= low) is unverified.
        near = bisect_left(source.missing_high, low - 1)
        after = bisect_right(source.missing_low, high + 1)
        segment_of = source.segment_of
        if near < after:
            self._segment_gaps(key, segment_of[near], segment_of[after], None, None, "partial")
        self._segment_gaps(key, segment_of[after], segment_of[-1], None, None, "unverified")
        self._conflicted(key, low - 1, high + 1)

    def _segment_gaps(
        self,
        key: SourceKey,
        first: int,
        end: int,
        low: int | None,
        high: int | None,
        effect: Literal["partial", "unverified"],
    ) -> None:
        """Gaps for the source's segments ``[first, end)``, clipped to ``[low, high]``.

        Up to :data:`_LISTED_SEGMENTS` segments are each one gap. A longer
        stretch (many runs over a heavily load-shed source, D6) is one gap per
        reason, from its first to its last segment of that reason in the
        stretch: the range then also spans recorded sequences, and the
        source's ``missing_sequences`` and ``loss_ranges`` list the parts
        once. The gap types, effects and reasons, hence every verdict and
        check, are the same either way.
        """

        if end <= first:
            return
        source = self.verifier.sources[key]
        seg_low, seg_high = source.seg_low, source.seg_high
        if end - first <= _LISTED_SEGMENTS:
            pairs = [(index, index) for index in range(first, end)]
            reasons = [source.seg_reason[index] for index in range(first, end)]
        else:
            pairs, reasons = [], []
            for reason, indices in source.by_reason.items():
                start, stop = bisect_left(indices, first), bisect_left(indices, end)
                if start < stop:
                    pairs.append((indices[start], indices[stop - 1]))
                    reasons.append(reason)
        for (head, tail), reason in zip(pairs, reasons, strict=True):
            gap_low = seg_low[head] if low is None else max(seg_low[head], low)
            gap_high = seg_high[tail] if high is None else min(seg_high[tail], high)
            self._sequence_gap(key, gap_low, gap_high, reason, effect)

    def _conflicted(self, key: SourceKey, low: int, high: int) -> None:
        """A sequence with conflicting claims inside a window invalidates it (partial).

        Beyond :data:`_LISTED_SEGMENTS` such sequences in one window, they are
        one gap from the first to the last (D6); each is in no other report
        field, but the verdict and check are the same.
        """

        conflicted = self.verifier.sources[key].conflicted_sorted
        found = conflicted[bisect_left(conflicted, low) : bisect_right(conflicted, high)]
        if len(found) > _LISTED_SEGMENTS:
            found_ranges = [(found[0], found[-1])]
        else:
            found_ranges = [(sequence, sequence) for sequence in found]
        for first, last in found_ranges:
            self._add(
                Gap(
                    "digest_mismatch",
                    "partial",
                    source_id=key[0],
                    source_epoch=key[1],
                    first_sequence=first,
                    last_sequence=last,
                    reason="conflicting_claim",
                )
            )

    def _sequence_gap(
        self,
        key: SourceKey,
        low: int,
        high: int,
        reason: str | None,
        effect: Literal["partial", "unverified"],
    ) -> None:
        unexplained = "unattributed" if effect == "unverified" else None
        self._add(
            Gap(
                "loss" if reason is not None else "sequence_gap",
                effect,
                source_id=key[0],
                source_epoch=key[1],
                first_sequence=low,
                last_sequence=high,
                reason=reason or unexplained,
            )
        )

    def _tail(self, key: SourceKey, problem: str | None) -> None:
        if problem is not None:
            self._add(
                Gap(
                    "tail_unverified",
                    "unverified",
                    source_id=key[0],
                    source_epoch=key[1],
                    reason=problem,
                )
            )

    def build(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """The run's report entry and one verdict entry per scope (decision H5)."""

        for exchange in self.observed:
            if exchange.malformed:  # its claims count; its payload proves nothing (sol2 #5)
                self._add(
                    Gap(
                        "digest_mismatch",
                        "partial",
                        exchange_id=exchange.exchange_id,
                        reason="malformed_record",
                    ),
                    () if exchange.scope_id is None else (exchange.scope_id,),
                )
        bodies = {exchange.exchange_id: self._bodies(exchange) for exchange in self.members}
        exchanges, views = [], []
        for exchange in self.members:
            entry, view = self._exchange(exchange, bodies[exchange.exchange_id])
            exchanges.append(entry)
            views.append(view)
        stitched = stitch_run(views)
        sink = self.verifier.projection_sink
        if sink is not None:
            for exchange, view in zip(self.members, views, strict=True):
                read = bodies[exchange.exchange_id]
                sink.exchange_read(exchange, read.request, read.response, view)
        for gap in stitched.gaps:
            self._add(gap, self._scopes_of(gap.exchange_id))
        self._structure_gaps()
        if self.verifier.production:
            self._authentication(bodies)
        for entry in exchanges:
            entry["thread_id"] = stitched.thread_of[entry["exchange_id"]]
            continued = stitched.continues.get(entry["exchange_id"])
            if continued is not None:
                entry["continues_exchange_id"] = continued
        gaps = sort_gaps(self.gaps, self.order)
        checks = self._checks(gaps, list(bodies.values()), views, bool(self.members))
        out: dict[str, Any] = {
            "run_id": self.run_id,
            "verdict": run_verdict(verdict_for(gaps, checks), scoped=bool(self.scopes)),
            "declared_scope": {
                "windows": [
                    window.to_json(self.verifier.sources[window.key].heartbeat)
                    for window in self.windows
                ],
            },
        }
        scope_reports: list[dict[str, Any]] = []
        if self.scopes:
            listed = [scope.to_json(len(self._scope_members(scope))) for scope in self.scopes]
            out["scopes"] = listed
            by_id = {view.exchange_id: view for view in views}
            for scope, entry in zip(self.scopes, listed, strict=True):
                ids = self._scope_members(scope)
                scope_gaps = sort_gaps(self.scope_gaps[scope.scope_id], self.order)
                scope_checks = self._checks(
                    scope_gaps, [bodies[i] for i in ids], [by_id[i] for i in ids], bool(ids)
                )
                scope_reports.append(
                    {
                        **entry,
                        "run_id": self.run_id,
                        "verdict": verdict_for(scope_gaps, scope_checks),
                        "gaps": [gap.to_json() for gap in scope_gaps],
                        "checks": scope_checks,
                    }
                )
        out.update(
            {
                "exchanges": exchanges,
                "threads": [
                    {"thread_id": thread_id, "exchange_ids": list(ids)}
                    for thread_id, ids in stitched.threads
                ],
                "gaps": [gap.to_json() for gap in gaps],
                "counts": {"exchanges": len(exchanges), "gaps_by_type": gap_counts(gaps)},
                "checks": checks,
            }
        )
        out.update(self._structure())
        return out, scope_reports

    # -- run structure (spec 050 §3.12) ---------------------------------------

    def _structure_gaps(self) -> None:
        """The run's segment, seal, epoch and manifest gaps, and the segment graph's."""
        verifier = self.verifier
        for run_id in verifier.run_ids_of(self.run_id):
            for gap, scopes in verifier.run_gaps.get(run_id, ()):
                self._add(gap, scopes)
        graph = verifier.graphs.get(self.run_id)
        if graph is not None:
            for gap in graph.gaps:
                segment = verifier.segments.get(gap.segment_id or "")
                self._add(gap, () if segment is None else segment.scope_ids)
        for window in self.windows:
            source = verifier.sources[window.key]
            for low, high, reason in source.manifestless:
                first = max(low, window.low)
                last = min(source.top if high is None else high, window.high)
                if first > last:
                    continue
                self._add(
                    Gap("manifest_gap", "unverified", source_id=window.key[0],
                        source_epoch=window.key[1], first_sequence=first, last_sequence=last,
                        reason=reason),
                    () if window.scope_id is None else (window.scope_id,),
                )  # fmt: skip

    def _structure(self) -> dict[str, Any]:
        """``run_state``, ``segments``, ``run_aliases``, ``deadline_at`` and ``evaluated_at``
        for a run with segments (absent for a pre-P1 capture), and ``attempts``: the full
        position set of every records-input attempt of the run."""
        verifier = self.verifier
        out: dict[str, Any] = {}
        run_ids = verifier.run_ids_of(self.run_id)
        attempts = _attempts(r for i in run_ids for r in verifier.run_records.get(i, ()))
        if attempts:
            out["attempts"] = attempts
        by_id = {s.segment_id: s for i in run_ids for s in verifier.run_segments.get(i, ())}
        present = sorted(by_id.values(), key=lambda segment: segment.segment_id)
        graph = verifier.graphs.get(self.run_id)
        if not present and graph is None:
            return out
        if graph is not None and graph.run_state is not None:
            out["run_state"] = graph.run_state
        segments = [segment.to_json() for segment in present]
        known = {segment.segment_id for segment in present}
        for node in () if graph is None else graph.segments:
            if node.segment_id not in known:  # named by the graph, never seen: missing
                known.add(node.segment_id)
                segments.append(
                    {"segment_id": node.segment_id, "predecessors": list(node.predecessors),
                     "state": "missing"}
                )  # fmt: skip
        out["segments"] = segments
        out["run_aliases"] = [] if graph is None else sorted(graph.run_aliases)
        if graph is not None and graph.id_basis_conflicts:
            out["id_basis_conflicts"] = [c.to_json() for c in graph.id_basis_conflicts]
        if graph is not None and graph.deadline_at is not None:
            out["deadline_at"] = format_datetime(graph.deadline_at)
        if verifier.evaluated_at is not None:
            out["evaluated_at"] = verifier.evaluated_at
        return out

    def _authentication(self, bodies: dict[str, _Bodies]) -> None:
        """049 §7.9 (G6, RR1a; decision 20): in the production profile every record of the
        run carries the Node's stamp, read back from a trusted location. Imported span
        files authenticate nothing; a stored object's stamp is its persisted descriptor's,
        read from the configured store. Each failure is ``unverified``."""
        verifier = self.verifier
        for key in sorted({window.key for window in self.windows}):
            unstamped = key in verifier.unstamped_sources or any(
                exchange.source == key and exchange.exchange_id in verifier.unstamped_exchanges
                for exchange in self.observed
            )
            if verifier.trusted_source and not unstamped:
                continue
            scopes = {window.scope_id for window in self.windows if window.key == key}
            scopes |= {
                scope
                for exchange in self.observed
                if exchange.source == key
                for scope in self._scopes_of(exchange.exchange_id)
            }
            self._add(
                Gap(
                    "source_unauthenticated",
                    "unverified",
                    source_id=key[0],
                    source_epoch=key[1],
                    reason="unstamped_record" if verifier.trusted_source else "imported_telemetry",
                ),
                sorted(scope for scope in scopes if scope is not None),
            )
        for exchange in self.members:
            body = bodies[exchange.exchange_id]
            sides: list[tuple[Side, ObjectResult | None]] = [
                ("request", body.request), ("response", body.response),
            ]  # fmt: skip
            for side, result in sides:
                if result is None or result.verification != "verified":
                    continue
                # Every object the verdict consumes: the side's object and, for a split
                # side, each part it was reassembled from (Sol P0-A #3).
                if not result.source_authenticated:
                    reason = "unstamped_object"
                elif not result.parts_authenticated:
                    reason = "unstamped_part"
                else:
                    continue
                self._add(
                    Gap(
                        "source_unauthenticated",
                        "unverified",
                        exchange_id=exchange.exchange_id,
                        object_role=side,
                        reason=reason,
                    ),
                    self._scopes_of(exchange.exchange_id),
                )

    def _scopes_of(self, exchange_id: str | None) -> tuple[str, ...]:
        if exchange_id is None:
            return ()
        return tuple(sorted(self.scopes_of.get(exchange_id, ())))

    def _scope_members(self, scope: _Scope) -> list[str]:
        """Exchange ids of this run that any observation tags with ``scope``."""

        return [
            exchange.exchange_id
            for exchange in self.members
            if scope.scope_id in self.scopes_of.get(exchange.exchange_id, ())
        ]

    # -- bytes ---------------------------------------------------------------

    def _bodies(self, exchange: ExchangeObs) -> _Bodies:
        if exchange.exchange_id in self.verifier.conflicts:
            self._gap(exchange, "digest_mismatch", reason="conflicting_duplicate")
        if len(self.verifier.claims[(exchange.source, exchange.source_sequence)]) > 1:
            self._gap(exchange, "digest_mismatch", reason="sequence_conflict")
        request, skipped = self._body(
            exchange, "request", exchange.request_sha256, exchange.request_ref
        )
        response: ObjectResult | None = None
        if exchange.response_sha256 is not None or (
            # 049 §2.4 rule 8: a side stored nothing (its digest is then absent); with
            # content disabled the check is skipped, otherwise the side is not stored.
            exchange.store_status in ("partial", "failed") and exchange.response_ref is None
            and exchange.response_state in _RESPONSE_EXPECTED
        ):  # fmt: skip
            response, response_skipped = self._body(
                exchange, "response", exchange.response_sha256, exchange.response_ref
            )
            skipped = skipped or response_skipped
        elif exchange.store_status == "disabled":
            pass  # content not recorded by configuration: no object is expected
        elif exchange.response_state in _RESPONSE_EXPECTED or exchange.http_status is not None:
            # The exchange received a response (its state, or a recorded HTTP status, says
            # so); a record without its digest proves only the request (sol1 #4, sol2 #4).
            self._gap(exchange, "missing_object", side="response", reason="response_not_recorded")
        if exchange.truncated:
            sides: list[Side | None] = []
            if request.truncated:
                sides.append("request")
            if response is not None and response.truncated:
                sides.append("response")
            for side in sides or [None]:
                self._gap(exchange, "truncated", side=side)
        return _Bodies(request, response, skipped)

    def _body(
        self, exchange: ExchangeObs, side: Side, digest: str | None, ref: str | None
    ) -> tuple[ObjectResult, bool]:
        """Fetch and verify one body; the bool says the check was skipped."""

        reader = self.verifier.reader
        if reader is None or exchange.store_status == "disabled":
            return ObjectResult("not_checked", sha256=digest), True
        if ref is None:
            if not exchange.truncated:
                self._gap(exchange, "missing_object", side=side, reason="not_stored")
            return ObjectResult("not_stored", sha256=digest), False
        object_id = object_id_from_ref(ref)
        if object_id is None or digest is None:  # a ref always comes with its digest
            self._gap(exchange, "missing_object", side=side, reason="invalid_ref")
            return ObjectResult("missing", sha256=digest), False
        result = reader.fetch(
            object_id,
            role=_ROLES[side],
            expected_sha256=digest,
            binding={
                "source_id": exchange.source_id,
                "source_epoch": exchange.source_epoch,
                "source_sequence": exchange.source_sequence,
                "run_id": exchange.run_id,
                "operation_id": exchange.exchange_id,
            },
            id_key=self.verifier.key,
        )
        if result.verification == "missing":
            self._gap(exchange, "missing_object", side=side, reason=result.reason)
        elif result.verification == "digest_mismatch":
            self._gap(exchange, "digest_mismatch", side=side, reason=result.reason)
        elif result.split is not None and result.data is not None:
            # 049 §7.5: a retain_original split side reassembles to its original digest;
            # the reassembled original is what the side's parse reads.
            rebuilt = reader.reassemble(
                object_id,
                result.data,
                result.split,
                binding={
                    "source_id": exchange.source_id,
                    "source_epoch": exchange.source_epoch,
                    "source_sequence": exchange.source_sequence,
                    "run_id": exchange.run_id,
                    "operation_id": exchange.exchange_id,
                },
                id_key=self.verifier.key,
            )
            if rebuilt.gap_type is not None:
                self._gap(exchange, rebuilt.gap_type, side=side, reason=rebuilt.reason)
            else:
                result = dataclasses.replace(
                    result, data=rebuilt.data, parts_authenticated=rebuilt.authenticated
                )
        return result, False

    def _gap(
        self,
        exchange: ExchangeObs,
        gap_type: Literal["missing_object", "digest_mismatch", "truncated"],
        *,
        side: Side | None = None,
        reason: str | None = None,
    ) -> None:
        self._add(
            Gap(
                gap_type,
                "partial",
                exchange_id=exchange.exchange_id,
                object_role=side,
                reason=reason,
            ),
            self._scopes_of(exchange.exchange_id),
        )

    # -- stitching -----------------------------------------------------------

    def _exchange(
        self, exchange: ExchangeObs, bodies: _Bodies
    ) -> tuple[dict[str, Any], StitchView]:
        objects = {"request": bodies.request.to_json()}
        if bodies.response is not None:
            objects["response"] = bodies.response.to_json()
        entry: dict[str, Any] = {
            "exchange_id": exchange.exchange_id,
            "source_id": exchange.source_id,
            "source_epoch": exchange.source_epoch,
            "source_sequence": exchange.source_sequence,
            "api": exchange.api,
            "started_at": format_ns(exchange.start_ns),
            "ended_at": format_ns(exchange.end_ns),
            "response_state": exchange.response_state,
            "parse_status": "not_checked",
            "thread_id": "",
            "tool_call_ids_consumed": [],
            "tool_call_ids_emitted": [],
            "objects": objects,
        }
        if exchange.trace_id is not None:
            entry["trace_id"] = exchange.trace_id
        if exchange.span_id is not None:
            entry["span_id"] = exchange.span_id
        if exchange.scope_id is not None:
            entry["scope_id"] = exchange.scope_id
        view = self._parse(exchange, bodies, entry)
        # Spec 048 §7: a model parsed from the body, else the span's value, is
        # reported as is only when allowlisted, otherwise as its m- digest.
        model = expose_model(entry.pop("model", None), self.verifier.allowlist)
        if model is None and exchange.model is not None:
            span_model = exchange.model
            model = (
                span_model
                if HASHED_MODEL_RE.fullmatch(span_model)
                else expose_model(span_model, self.verifier.allowlist)
            )
        if model is not None:
            entry["model"] = model
        response_id = entry.get("response_id") or exchange.response_id
        if response_id is not None:
            entry["response_id"] = response_id
        return entry, view

    def _parse(self, exchange: ExchangeObs, bodies: _Bodies, entry: dict[str, Any]) -> StitchView:
        request, response = bodies.request, bodies.response
        api = cast("WireApi", exchange.api)
        unparsed = StitchView(
            exchange.exchange_id, api, parsed=False, response_id=exchange.response_id
        )
        if request.data is None or (response is not None and response.data is None):
            return unparsed
        keys = extract_stitch_keys(
            api,
            request.data,
            request.media_type or "application/octet-stream",
            request.content_encoding,
            request.truncated,
            response.data if response is not None else None,
            response.media_type if response is not None else None,
            response.content_encoding if response is not None else None,
            response.truncated if response is not None else False,
            id_key=self.verifier.key,
            response_cut=exchange.response_state != "complete",
        )
        status = keys.request_parse_status
        response_status = keys.response_parse_status
        if response_status == "truncated" and response is not None and not response.truncated:
            # 049 §2.6, §6.2 R4: a response the transport did not finish whose bytes do not
            # prove their own end is truncated (a gap: partial), streamed or not.
            reason = (
                "stream_closed_early"
                if exchange.response_state == "closed_early"
                else "transport_incomplete"
            )
            self._gap(exchange, "truncated", side="response", reason=reason)
        if status == "ok" and response_status not in ("ok", "not_parsed"):
            http_error = exchange.http_status is not None and exchange.http_status >= _HTTP_ERROR
            status = "ok" if http_error and response_status != "truncated" else response_status
        entry["parse_status"] = status
        if status != "ok":
            if status != "truncated":
                self._add(
                    Gap(
                        "unparsed_exchange",
                        "unverified",
                        exchange_id=exchange.exchange_id,
                        reason=status,
                    ),
                    self._scopes_of(exchange.exchange_id),
                )
            return unparsed
        entry["model"] = keys.response_model or keys.model
        if keys.response_id is not None:
            entry["response_id"] = keys.response_id
        if keys.previous_response_id is not None:
            entry["previous_response_id"] = keys.previous_response_id
        emitted = tuple(call_id for call_id, _ in keys.tool_calls)
        entry["input_message_count"] = len(keys.input_digests)
        entry["output_message_count"] = len(keys.output_digests)
        entry["tool_call_ids_consumed"] = list(keys.tool_call_ids_consumed)
        entry["tool_call_ids_emitted"] = list(emitted)
        continuation = keys.input_digests + continuation_digests(api, keys.output_digests)
        return StitchView(
            exchange.exchange_id,
            exchange.api,
            parsed=True,
            request=keys.input_digests,
            continuation=continuation,
            consumed=keys.tool_call_ids_consumed,
            emitted=emitted,
            response_id=keys.response_id or exchange.response_id,
            previous_response_id=keys.previous_response_id,
        )

    # -- checks --------------------------------------------------------------

    @staticmethod
    def _checks(
        gaps: Iterable[Gap],
        bodies: Sequence[_Bodies],
        views: Sequence[StitchView],
        has_members: bool,
    ) -> dict[str, Check]:
        failing = {gap.gap_type for gap in gaps if gap.effect != "info"}

        def check(failed: bool, skipped: bool = False, applicable: bool = True) -> Check:
            if failed:
                return "failed"
            if not applicable:
                return "not_applicable"
            return "skipped" if skipped else "passed"

        return {
            "sequence": check("sequence_gap" in failing),
            "loss": check("loss" in failing),
            "tail": check("tail_unverified" in failing),
            "bytes": check(
                bool(failing & _BYTE_GAPS),
                any(body.skipped for body in bodies),
                has_members,
            ),
            "stitching": check(
                bool(failing & _STITCH_GAPS),
                not all(view.parsed for view in views),
                has_members,
            ),
        }
