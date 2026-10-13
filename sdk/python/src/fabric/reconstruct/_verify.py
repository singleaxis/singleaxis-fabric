# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline run reconstruction and integrity verdict (specs 042 §9, 043 §6-§7).

The verifier is read-only and the only component that parses messages. It
normalizes exchange, loss and heartbeat spans, accounts for every allocated
sequence per ``(source_id, source_epoch)``, verifies stored bytes against
the span digests and descriptors, derives message digests and tool-call ids
from those bytes, stitches exchanges into threads and states a verdict for
a declared scope. The verdict is an integrity statement about the *record*;
it never judges the agent.
"""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from fabric._model_names import HASHED_MODEL_RE, expose_model, parse_model_allowlist
from fabric._version import __version__
from fabric.reconstruct._inputs import (
    ExchangeObs,
    HeartbeatObs,
    LossObs,
    ReconstructInputError,
    SpanFormat,
    object_id_from_ref,
    observe,
    read_span_file,
)
from fabric.reconstruct._objects import ObjectResult, StoreReader
from fabric.reconstruct._report import (
    SCHEMA_VERSION,
    Check,
    Gap,
    format_datetime,
    format_ns,
    gap_counts,
    sort_gaps,
    verdict_for,
)
from fabric.reconstruct._stitch import WireApi, continuation_digests, extract_stitch_keys
from fabric.reconstruct._stitch_check import StitchView, stitch_run

SourceKey = tuple[str, int]
Segment = tuple[int, int, str | None]
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


# --------------------------------------------------------------------------
# Per-source sequence accounting
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _Source:
    key: SourceKey
    sequences: set[int] = field(default_factory=set)
    losses: set[LossObs] = field(default_factory=set)
    heartbeat: int = -1
    final: int | None = None
    top: int = -1
    missing: list[tuple[int, int]] = field(default_factory=list)
    segments: dict[tuple[int, int], list[Segment]] = field(default_factory=dict)

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
        for first, last in self.missing:
            self.segments[(first, last)] = _segments(first, last, ordered)

    def tail_problem(self) -> str | None:
        """Why this epoch's end is unknown; ``None`` when a final heartbeat ended it.

        A ``final`` heartbeat is written by a clean close and names the last
        sequence the epoch allocated. It ends the epoch only if nothing seen
        for the epoch lies beyond it (spec 042 §9.5, rev 5).
        """

        if self.final is None:
            return "no_final_heartbeat"
        if self.top > self.final:
            return "activity_after_final_heartbeat"
        return None

    def to_json(self, exchanges: int) -> dict[str, Any]:
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
                for loss in sorted(
                    self.losses, key=lambda x: (x.first_sequence, x.last_sequence, x.reason)
                )
            ],
        }
        if self.final is not None:
            out["final_heartbeat_sequence"] = self.final
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
Marker = tuple[SourceKey, str, int]  # (source, run id, last_sequence)


@dataclass(slots=True)
class _Scope:
    """One ``fabric.wire.run()`` block entry, keyed by its scope id (spec 043 §6).

    Markers pair by scope id only, never by run id or parity: exactly one
    distinct ``run_start`` and one ``run_end`` on one source epoch, naming
    the same run, with ``a <= b``, close the scope over ``[a + 1, b]``. A
    missing marker leaves it ``open``; anything else is a ``conflict``.
    ``problem`` is ``None`` only for a closed scope whose tagged exchanges
    (of any run) all carry its run id and lie on its source inside its
    window.
    """

    scope_id: str
    starts: set[Marker] = field(default_factory=set)
    ends: set[Marker] = field(default_factory=set)
    exchanges: list[ExchangeObs] = field(default_factory=list)
    state: ScopeState = "open"
    key: SourceKey = ("", 0)
    start: int | None = None
    end: int | None = None
    problem: str | None = None

    def finalize(self) -> None:
        if len(self.starts) == 1 and len(self.ends) == 1:
            ((start_key, run_id, low),) = self.starts
            ((end_key, end_run, high),) = self.ends
            if start_key == end_key and run_id == end_run and low <= high:
                self.state, self.key, self.start, self.end = "closed", start_key, low, high
                if any(
                    exchange.run_id != run_id
                    or exchange.source != start_key
                    or not low < exchange.source_sequence <= high
                    for exchange in self.exchanges
                ):
                    self.problem = "exchange_outside_run_markers"
                return
        if (self.starts and self.ends) or len(self.starts) > 1 or len(self.ends) > 1:
            self.state, self.problem = "conflict", "scope_conflict"
        else:
            self.state, self.problem = "open", "run_not_closed"
        markers = self.starts | self.ends
        self.key = min([key for key, _, _ in markers] + [x.source for x in self.exchanges])
        starts = {last for key, _, last in self.starts if key == self.key}
        ends = {last for key, _, last in self.ends if key == self.key}
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
) -> dict[str, Any]:
    """Reconstruct runs from span files and an optional customer store.

    ``model_allowlist`` extends the built-in model allowlist (spec 043 §7):
    exact names or ``prefix*`` entries. Returns a
    ``fabric.run-reconstruction/v1`` document. Raises
    :class:`ReconstructInputError` for unusable input or options.
    """

    paths = list(span_paths)
    if not paths:
        raise ReconstructInputError("at least one span file is required")
    allowlist = _allowlist(model_allowlist)
    reader = StoreReader(store, tenant_id) if store is not None else None
    span_files: list[dict[str, Any]] = []
    verifier = _Verifier(reader, allowlist)
    for path in paths:
        fmt, records = read_span_file(path)
        span_files.append(_span_file_entry(path, fmt, len(records)))
        for record in records:
            verifier.add(observe(record))
    verifier.finalize()
    inputs: dict[str, Any] = {"span_files": span_files}
    if reader is not None:
        inputs["store"] = {"kind": reader.kind, "tenant_id": reader.tenant_id}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": format_datetime(generated_at or datetime.now(tz=UTC)),
        "verifier": {"name": "fabric.reconstruct", "version": __version__},
        "inputs": inputs,
        "sources": [
            verifier.sources[key].to_json(verifier.exchange_count[key])
            for key in sorted(verifier.sources)
        ],
        "runs": verifier.build_runs(set(run_ids) if run_ids is not None else None),
    }


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
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "path": str(path)[:4096],
        "sha256": "sha256:" + digest.hexdigest(),
        "format": fmt,
        "records": count,
    }


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------


class _Verifier:
    def __init__(self, reader: StoreReader | None, allowlist: Sequence[str] = ()) -> None:
        self.reader = reader
        self.allowlist = tuple(allowlist)
        self.exchanges: dict[str, ExchangeObs] = {}
        self.conflicts: set[str] = set()
        self.sources: dict[SourceKey, _Source] = {}
        self.exchange_count: dict[SourceKey, int] = defaultdict(int)
        self.claims: dict[tuple[SourceKey, int], set[str]] = defaultdict(set)
        self.scopes: dict[str, _Scope] = {}
        self.run_scopes: dict[str, set[str]] = defaultdict(set)
        self._heartbeats: set[HeartbeatObs] = set()

    def _scope(self, scope_id: str, run_id: str) -> _Scope:
        self.run_scopes[run_id].add(scope_id)
        if scope_id not in self.scopes:
            self.scopes[scope_id] = _Scope(scope_id)
        return self.scopes[scope_id]

    def _source(self, key: SourceKey) -> _Source:
        if key not in self.sources:
            self.sources[key] = _Source(key)
        return self.sources[key]

    def add(self, obs: ExchangeObs | LossObs | HeartbeatObs | None) -> None:
        if isinstance(obs, ExchangeObs):
            known = self.exchanges.get(obs.exchange_id)
            if known is None:
                self.exchanges[obs.exchange_id] = obs
                source = self._source(obs.source)
                source.sequences.add(obs.source_sequence)
                self.exchange_count[obs.source] += 1
                self.claims[(obs.source, obs.source_sequence)].add(obs.exchange_id)
                if obs.scope_id is not None:
                    self._scope(obs.scope_id, obs.run_id).exchanges.append(obs)
            elif known != obs:
                self.conflicts.add(obs.exchange_id)
        elif isinstance(obs, LossObs):
            self._source((obs.source_id, obs.source_epoch)).losses.add(obs)
        elif isinstance(obs, HeartbeatObs) and obs not in self._heartbeats:
            # Deduplicated by logical identity (source, epoch, kind, run id,
            # scope id, last sequence), never by span id: a retried export
            # re-sends the same record under a new span id and must not count
            # twice.
            self._heartbeats.add(obs)
            key = (obs.source_id, obs.source_epoch)
            source = self._source(key)
            source.heartbeat = max(source.heartbeat, obs.last_sequence)
            if obs.kind == "final":
                source.final = max(obs.last_sequence, -1 if source.final is None else source.final)
            elif obs.scope_id is not None and obs.run_id is not None:
                scope = self._scope(obs.scope_id, obs.run_id)
                marks = scope.starts if obs.kind == "run_start" else scope.ends
                marks.add((key, obs.run_id, obs.last_sequence))

    def finalize(self) -> None:
        for source in self.sources.values():
            source.finalize()
        for scope in self.scopes.values():
            scope.finalize()

    def build_runs(self, wanted: set[str] | None) -> list[dict[str, Any]]:
        members: dict[str, list[ExchangeObs]] = defaultdict(list)
        for exchange in self.exchanges.values():
            members[exchange.run_id].append(exchange)
        runs: list[dict[str, Any]] = []
        for run_id in sorted(set(members) | set(self.run_scopes)):
            if wanted is not None and run_id not in wanted:
                continue
            scopes = [self.scopes[scope_id] for scope_id in self.run_scopes.get(run_id, ())]
            run = _Run(self, run_id, members.get(run_id, []), scopes)
            if run.windows:
                runs.append(run.build())
        return runs


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


def _by_source(exchanges: Iterable[ExchangeObs]) -> dict[SourceKey, list[int]]:
    out: dict[SourceKey, list[int]] = defaultdict(list)
    for exchange in exchanges:
        out[exchange.source].append(exchange.source_sequence)
    return out


class _Run:
    def __init__(
        self,
        verifier: _Verifier,
        run_id: str,
        members: list[ExchangeObs],
        scopes: Sequence[_Scope],
    ) -> None:
        self.verifier = verifier
        self.run_id = run_id
        self.members = sorted(
            members, key=lambda x: (x.start_ns, x.source_id, x.source_epoch, x.source_sequence)
        )
        self.order = {exchange.exchange_id: i for i, exchange in enumerate(self.members)}
        self.scopes = sorted(
            scopes, key=lambda x: (x.key, -2 if x.start is None else x.start, x.scope_id)
        )
        self.gaps: list[Gap] = []
        self.windows: list[_Window] = []
        if self.scopes:
            self._scoped()
        else:
            self._unscoped()
        self.windows.sort(key=lambda w: (w.key, w.low, w.high, w.scope_id or ""))

    # -- completeness (spec 042 §9.5 rule b, spec 043 §6) ----------------------

    def _unscoped(self) -> None:
        """A run without scopes: only the epoch's final heartbeat proves its end."""

        for key, own in sorted(_by_source(self.members).items()):
            problem = self.verifier.sources[key].tail_problem()
            closed_by: Literal["final_heartbeat"] | None = (
                "final_heartbeat" if problem is None else None
            )
            self.windows.append(_Window(key, min(own), max(own), None, closed_by))
            self._near_gaps(key, min(own), max(own))
            self._tail(key, problem)

    def _scoped(self) -> None:
        """A run with scopes is complete only if every scope is closed and clean.

        A closed scope's window ``[a + 1, b]`` is proven by its markers:
        ``a`` was allocated before entry and ``b + 1`` after exit, so only
        sequences inside it matter, and any missing one is ``partial`` (it
        cannot be attributed to a particular concurrent scope, so it counts
        against every scope whose window holds it). An open or conflicting
        scope, or a scoped exchange outside its scope, is ``unverified``; so
        is an exchange of the run that started outside every scope.
        """

        for scope in self.scopes:
            own = [x for x in self.members if x.scope_id == scope.scope_id]
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
        unscoped = [x for x in self.members if x.scope_id is None]
        for key, own_sequences in sorted(_by_source(unscoped).items()):
            low, high = min(own_sequences), max(own_sequences)
            self.windows.append(_Window(key, low, high))
            self._near_gaps(key, low, high)
            self._tail(key, "exchange_outside_run_markers")

    def _open_scope(self, scope: _Scope, own: Sequence[ExchangeObs]) -> None:
        """An unproven scope: bounds come from its exchanges and whatever markers exist."""

        key = scope.key
        on_key = [x.source_sequence for x in own if x.source == key]
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
        elsewhere = [x for x in own if x.source != key]
        for other, sequences in sorted(_by_source(elsewhere).items()):
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
        for first, last in source.missing:
            if first > top or last < low:
                continue
            for seg_low, seg_high, reason in source.segments[(first, last)]:
                clipped_low, clipped_high = max(seg_low, low), min(seg_high, top)
                if clipped_low <= clipped_high:
                    self._sequence_gap(key, clipped_low, clipped_high, reason, effect)

    def _near_gaps(self, key: SourceKey, low: int, high: int) -> None:
        """Spec 042 §9.5 rule (b) for a window bounded only by its exchanges.

        A missing sequence inside the window, or adjacent to it (it may be
        the run's own first or last call), is ``partial``. One after the
        window may be the run's lost later call: ``unverified``, even under a
        final heartbeat (which proves only that nothing beyond it exists).
        """

        source = self.verifier.sources[key]
        for first, last in source.missing:
            effect: Literal["partial", "unverified"]
            if first <= high + 1 and last >= low - 1:
                effect = "partial"
            elif last >= low:
                effect = "unverified"
            else:
                continue
            for seg_low, seg_high, reason in source.segments[(first, last)]:
                self._sequence_gap(key, seg_low, seg_high, reason, effect)

    def _sequence_gap(
        self,
        key: SourceKey,
        low: int,
        high: int,
        reason: str | None,
        effect: Literal["partial", "unverified"],
    ) -> None:
        unexplained = "unattributed" if effect == "unverified" else None
        self.gaps.append(
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
            self.gaps.append(
                Gap(
                    "tail_unverified",
                    "unverified",
                    source_id=key[0],
                    source_epoch=key[1],
                    reason=problem,
                )
            )

    def build(self) -> dict[str, Any]:
        bodies = {exchange.exchange_id: self._bodies(exchange) for exchange in self.members}
        exchanges, views = [], []
        for exchange in self.members:
            entry, view = self._exchange(exchange, bodies[exchange.exchange_id])
            exchanges.append(entry)
            views.append(view)
        stitched = stitch_run(views)
        self.gaps.extend(stitched.gaps)
        for entry in exchanges:
            entry["thread_id"] = stitched.thread_of[entry["exchange_id"]]
            continued = stitched.continues.get(entry["exchange_id"])
            if continued is not None:
                entry["continues_exchange_id"] = continued
        gaps = sort_gaps(self.gaps, self.order)
        checks = self._checks(gaps, bodies, views)
        out: dict[str, Any] = {
            "run_id": self.run_id,
            "verdict": verdict_for(gaps, checks),
            "declared_scope": {
                "windows": [
                    window.to_json(self.verifier.sources[window.key].heartbeat)
                    for window in self.windows
                ],
            },
        }
        if self.scopes:
            counts: dict[str, int] = defaultdict(int)
            for exchange in self.members:
                if exchange.scope_id is not None:
                    counts[exchange.scope_id] += 1
            out["scopes"] = [scope.to_json(counts[scope.scope_id]) for scope in self.scopes]
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
        return out

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
        if exchange.response_sha256 is not None:
            response, response_skipped = self._body(
                exchange, "response", exchange.response_sha256, exchange.response_ref
            )
            skipped = skipped or response_skipped
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
        self, exchange: ExchangeObs, side: Side, digest: str, ref: str | None
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
        if object_id is None:
            self._gap(exchange, "missing_object", side=side, reason="invalid_ref")
            return ObjectResult("missing", sha256=digest), False
        result = reader.fetch(
            object_id, role=_ROLES[side], operation_id=exchange.exchange_id, expected_sha256=digest
        )
        if result.verification == "missing":
            self._gap(exchange, "missing_object", side=side, reason=result.reason)
        elif result.verification == "digest_mismatch":
            self._gap(exchange, "digest_mismatch", side=side, reason=result.reason)
        return result, False

    def _gap(
        self,
        exchange: ExchangeObs,
        gap_type: Literal["missing_object", "digest_mismatch", "truncated"],
        *,
        side: Side | None = None,
        reason: str | None = None,
    ) -> None:
        self.gaps.append(
            Gap(
                gap_type,
                "partial",
                exchange_id=exchange.exchange_id,
                object_role=side,
                reason=reason,
            )
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
        # Spec 043 §7: a model parsed from the body, else the span's value, is
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
        )
        status = keys.request_parse_status
        response_status = keys.response_parse_status
        if status == "ok" and response_status not in ("ok", "not_parsed"):
            http_error = exchange.http_status is not None and exchange.http_status >= _HTTP_ERROR
            status = "ok" if http_error and response_status != "truncated" else response_status
        entry["parse_status"] = status
        if status != "ok":
            if status != "truncated":
                self.gaps.append(
                    Gap(
                        "unparsed_exchange",
                        "unverified",
                        exchange_id=exchange.exchange_id,
                        reason=status,
                    )
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

    def _checks(
        self, gaps: Iterable[Gap], bodies: dict[str, _Bodies], views: Sequence[StitchView]
    ) -> dict[str, Check]:
        failing = {gap.gap_type for gap in gaps if gap.effect != "info"}

        def check(failed: bool, skipped: bool = False, applicable: bool = True) -> Check:
            if not applicable:
                return "not_applicable"
            if failed:
                return "failed"
            return "skipped" if skipped else "passed"

        has_members = bool(self.members)
        return {
            "sequence": check("sequence_gap" in failing),
            "loss": check("loss" in failing),
            "tail": check("tail_unverified" in failing),
            "bytes": check(
                bool(failing & _BYTE_GAPS),
                any(body.skipped for body in bodies.values()),
                has_members,
            ),
            "stitching": check(
                bool(failing & _STITCH_GAPS),
                not all(view.parsed for view in views),
                has_members,
            ),
        }
