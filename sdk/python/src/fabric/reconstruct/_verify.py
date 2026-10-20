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
from collections import defaultdict
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from fabric._model_names import HASHED_MODEL_RE, expose_model, parse_model_allowlist
from fabric._sequence import encode_opaque_id
from fabric._version import __version__
from fabric.reconstruct._ids import report_run_id, report_source_id, report_tenant_id
from fabric.reconstruct._inputs import (
    ExchangeObs,
    HeartbeatObs,
    LossObs,
    MalformedMarkerObs,
    ReconstructInputError,
    SpanFormat,
    list_span_inputs,
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
    run_verdict,
    sort_gaps,
    verdict_for,
)
from fabric.reconstruct._stitch import WireApi, continuation_digests, extract_stitch_keys
from fabric.reconstruct._stitch_check import StitchView, stitch_run

SourceKey = tuple[str, int]
Segment = tuple[int, int, str | None]
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
    # Sequences claimed by conflicting observations (one exchange id seen with
    # different values, or one sequence claimed by several exchange ids). No
    # window holding one can be complete, whichever run the claims name.
    conflicted: set[int] = field(default_factory=set)

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
        for the epoch lies beyond it (spec 047 §9.5, rev 5).
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
    """One ``fabric.wire.run()`` block entry, keyed by its scope id (spec 048 §6).

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
    id_key: bytes | None = None,
    wait_for_objects_s: float = 0.0,
    profile: Profile | None = None,
    trusted_source: bool = False,
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
    Raises :class:`ReconstructInputError` for unusable input or options.
    """

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
    span_files: list[dict[str, Any]] = []
    verifier = _Verifier(reader, allowlist, id_key)
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
            verifier.add(observation)
    verifier.finalize()
    verifier.trusted_source = trusted_source
    verifier.production = (
        profile == "production" if profile is not None else verifier.stamp_observed
    )
    inputs: dict[str, Any] = {
        "span_files": span_files,
        "telemetry_origin": "trusted_readback" if trusted_source else "imported",
        "profile": "production" if verifier.production else "local",
    }
    if reader is not None:
        tenant = report_tenant_id(reader.tenant_id, id_key)
        inputs["store"] = {"kind": reader.kind, "tenant_id": tenant}
    wanted = None if run_ids is None else {report_run_id(value, id_key) for value in run_ids}
    runs, scopes = verifier.build_runs(wanted)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": format_datetime(generated_at or datetime.now(tz=UTC)),
        "verifier": {"name": "fabric.reconstruct", "version": __version__},
        "inputs": inputs,
        "sources": [
            verifier.sources[key].to_json(verifier.exchange_count[key])
            for key in sorted(verifier.sources)
        ],
        "runs": runs,
        "scopes": scopes,
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
# Collection
# --------------------------------------------------------------------------


class _Verifier:
    def __init__(
        self, reader: StoreReader | None, allowlist: Sequence[str] = (), key: bytes | None = None
    ) -> None:
        self.reader = reader
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

    def _scope(self, scope_id: str, run_id: str) -> _Scope:
        self.run_scopes[run_id].add(scope_id)
        if scope_id not in self.scopes:
            self.scopes[scope_id] = _Scope(scope_id)
        return self.scopes[scope_id]

    def _source(self, key: SourceKey) -> _Source:
        if key not in self.sources:
            self.sources[key] = _Source(key)
        return self.sources[key]

    def _labels(
        self, obs: ExchangeObs | LossObs | HeartbeatObs | MalformedMarkerObs | None
    ) -> ExchangeObs | LossObs | HeartbeatObs | MalformedMarkerObs | None:
        """Source and run ids in their report form (decision J1), before any accounting, so
        legacy clear and pseudonymous records of one source or run are one."""
        if obs is None:
            return None
        if isinstance(obs, MalformedMarkerObs):
            heartbeat = self._labels(obs.heartbeat)
            return MalformedMarkerObs(obs.scope_id, cast("HeartbeatObs | None", heartbeat))
        changes: dict[str, Any] = {"source_id": report_source_id(obs.source_id, self.key)}
        run_id = getattr(obs, "run_id", None)
        if run_id is not None:
            changes["run_id"] = report_run_id(run_id, self.key)
        return dataclasses.replace(obs, **changes)

    def _stamp(self, obs: ExchangeObs | LossObs | HeartbeatObs) -> None:
        """Note whether ``obs`` carries the Node's stamp (049 §7.9); any unstamped copy of a
        record counts, whichever copy the accounting keeps."""
        if obs.authenticated:
            self.stamp_observed = True
        elif isinstance(obs, ExchangeObs):
            self.unstamped_exchanges.add(obs.exchange_id)
        else:
            self.unstamped_sources.add((obs.source_id, obs.source_epoch))

    def add(self, obs: ExchangeObs | LossObs | HeartbeatObs | MalformedMarkerObs | None) -> None:
        obs = self._labels(obs)
        if obs is not None and not isinstance(obs, MalformedMarkerObs):
            self._stamp(obs)
        if isinstance(obs, MalformedMarkerObs):
            self.malformed_scopes.add(obs.scope_id)
            self.add(obs.heartbeat)
        elif isinstance(obs, ExchangeObs):
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
        for (key, sequence), ids in self.claims.items():
            if len(ids) > 1 or not ids.isdisjoint(self.conflicts):
                self.sources[key].conflicted.add(sequence)
        for scope in self.scopes.values():
            scope.finalize()
            if scope.scope_id in self.malformed_scopes:  # a malformed marker names it
                scope.state, scope.problem = "conflict", "malformed_record"

    def build_runs(
        self, wanted: set[str] | None
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """The reported runs and, in run order, the per-scope verdicts of their scopes."""

        observed: dict[str, list[ExchangeObs]] = defaultdict(list)
        for observations in self.observations.values():
            for exchange in observations:
                observed[exchange.run_id].append(exchange)
        runs: list[dict[str, Any]] = []
        scopes: list[dict[str, Any]] = []
        # An epoch that allocated sequences (its heartbeats say so) of which no exchange and
        # no scope marker arrived (a killed fork worker, wire/_forks.py) is reported as its
        # source-fallback run, every sequence missing: a loss, never silence.
        seen = {x.source for xs in observed.values() for x in xs}
        seen |= {scope.key for scope in self.scopes.values()}
        silent = {
            encode_opaque_id(f"source:{key[0]}:{key[1]}"): key
            for key, source in self.sources.items()
            if key not in seen and source.top >= 0
        }
        for run_id in sorted(set(observed) | set(self.run_scopes) | set(silent)):
            if wanted is not None and run_id not in wanted:
                continue
            members = [self.scopes[scope_id] for scope_id in self.run_scopes.get(run_id, ())]
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
        self._conflicted(key, low, top)

    def _near_gaps(self, key: SourceKey, low: int, high: int) -> None:
        """Spec 047 §9.5 rule (b) for a window bounded only by its exchanges.

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
        self._conflicted(key, low - 1, high + 1)

    def _conflicted(self, key: SourceKey, low: int, high: int) -> None:
        """A sequence with conflicting claims inside a window invalidates it (partial)."""

        for sequence in sorted(self.verifier.sources[key].conflicted):
            if low <= sequence <= high:
                self._add(
                    Gap(
                        "digest_mismatch",
                        "partial",
                        source_id=key[0],
                        source_epoch=key[1],
                        first_sequence=sequence,
                        last_sequence=sequence,
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
        for gap in stitched.gaps:
            self._add(gap, self._scopes_of(gap.exchange_id))
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
        return out, scope_reports

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
        )
        status = keys.request_parse_status
        response_status = keys.response_parse_status
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
