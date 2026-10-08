# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline run reconstruction and integrity verdict (spec 042 §9).

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

from fabric._version import __version__
from fabric.reconstruct._inputs import (
    ExchangeObs,
    HeartbeatObs,
    LossObs,
    ReconstructInputError,
    SpanFormat,
    model_value,
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


@dataclass(slots=True)
class _Marks:
    """A run's ``run_start`` / ``run_end`` markers on one source epoch (distinct records)."""

    starts: set[int] = field(default_factory=set)
    ends: set[int] = field(default_factory=set)

    def open_reason(self, own: Sequence[int]) -> str | None:
        """``None`` when the markers close the run around all of its exchanges.

        Each ``fabric.wire.run()`` block writes one ``run_start`` and one
        ``run_end``. Sorted starts and ends must pair up (equal numbers, each
        start at or before its end); a missing ``run_end`` leaves the run's
        end unknown however many other markers arrived.
        """

        starts, ends = sorted(self.starts), sorted(self.ends)
        if not starts or len(starts) != len(ends):
            return "run_not_closed"
        if any(start > end for start, end in zip(starts, ends, strict=True)):
            return "run_not_closed"
        if own and (min(own) <= starts[0] or max(own) > ends[-1]):
            return "exchange_outside_run_markers"
        return None


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
) -> dict[str, Any]:
    """Reconstruct runs from span files and an optional customer store.

    Returns a ``fabric.run-reconstruction/v1`` document. Raises
    :class:`ReconstructInputError` for unusable input or options.
    """

    paths = list(span_paths)
    if not paths:
        raise ReconstructInputError("at least one span file is required")
    reader = StoreReader(store, tenant_id) if store is not None else None
    span_files: list[dict[str, Any]] = []
    verifier = _Verifier(reader)
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
    def __init__(self, reader: StoreReader | None) -> None:
        self.reader = reader
        self.exchanges: dict[str, ExchangeObs] = {}
        self.conflicts: set[str] = set()
        self.sources: dict[SourceKey, _Source] = {}
        self.exchange_count: dict[SourceKey, int] = defaultdict(int)
        self.claims: dict[tuple[SourceKey, int], set[str]] = defaultdict(set)
        self.markers: dict[str, dict[SourceKey, _Marks]] = defaultdict(lambda: defaultdict(_Marks))
        self._heartbeats: set[HeartbeatObs] = set()

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
            elif known != obs:
                self.conflicts.add(obs.exchange_id)
        elif isinstance(obs, LossObs):
            self._source((obs.source_id, obs.source_epoch)).losses.add(obs)
        elif isinstance(obs, HeartbeatObs) and obs not in self._heartbeats:
            # Deduplicated by logical identity (source, epoch, kind, run id,
            # last sequence), never by span id: a retried export re-sends the
            # same record under a new span id and must not count twice.
            self._heartbeats.add(obs)
            key = (obs.source_id, obs.source_epoch)
            source = self._source(key)
            source.heartbeat = max(source.heartbeat, obs.last_sequence)
            if obs.kind == "final":
                source.final = max(obs.last_sequence, -1 if source.final is None else source.final)
            elif obs.kind == "run_start" and obs.run_id is not None:
                self.markers[obs.run_id][key].starts.add(obs.last_sequence)
            elif obs.kind == "run_end" and obs.run_id is not None:
                self.markers[obs.run_id][key].ends.add(obs.last_sequence)

    def finalize(self) -> None:
        for source in self.sources.values():
            source.finalize()

    def build_runs(self, wanted: set[str] | None) -> list[dict[str, Any]]:
        members: dict[str, list[ExchangeObs]] = defaultdict(list)
        for exchange in self.exchanges.values():
            members[exchange.run_id].append(exchange)
        runs: list[dict[str, Any]] = []
        for run_id in sorted(set(members) | set(self.markers)):
            if wanted is not None and run_id not in wanted:
                continue
            run = _Run(self, run_id, members.get(run_id, []), self.markers.get(run_id, {}))
            if run.windows:
                runs.append(run.build())
        return runs


# --------------------------------------------------------------------------
# One run
# --------------------------------------------------------------------------


def _closed_by(window: _Window) -> dict[str, str]:
    """The evidence that proves the window's end, when there is one."""

    if window.tail_problem is not None:
        return {}
    return {"closed_by": "run_markers" if window.marked else "final_heartbeat"}


@dataclass(slots=True)
class _Window:
    """One source epoch a run used, and why its end is (or is not) known.

    ``marked`` says the run left ``run_start`` / ``run_end`` markers on this
    source; then they alone bound the run (rule a). Without markers the
    epoch's final heartbeat must (rule b). ``tail_problem`` is ``None`` only
    when that evidence exists.
    """

    key: SourceKey
    low: int
    high: int
    marked: bool
    tail_problem: str | None


@dataclass(slots=True)
class _Bodies:
    request: ObjectResult
    response: ObjectResult | None
    skipped: bool


class _Run:
    def __init__(
        self,
        verifier: _Verifier,
        run_id: str,
        members: list[ExchangeObs],
        markers: dict[SourceKey, _Marks],
    ) -> None:
        self.verifier = verifier
        self.run_id = run_id
        self.members = sorted(
            members, key=lambda x: (x.start_ns, x.source_id, x.source_epoch, x.source_sequence)
        )
        self.order = {exchange.exchange_id: i for i, exchange in enumerate(self.members)}
        self.gaps: list[Gap] = []
        self.windows = self._windows(markers)

    def _windows(self, markers: dict[SourceKey, _Marks]) -> list[_Window]:
        sequences: dict[SourceKey, list[int]] = defaultdict(list)
        for exchange in self.members:
            sequences[exchange.source].append(exchange.source_sequence)
        windows: list[_Window] = []
        for key in sorted(set(sequences) | set(markers)):
            own = sequences.get(key, [])
            marks = markers.get(key)
            source = self.verifier.sources[key]
            if marks is None:
                # A run that wrote markers anywhere is bounded only by markers
                # (rule a); without any, by the epoch's final heartbeat (rule b).
                problem = "no_run_markers_on_source" if markers else source.tail_problem()
                windows.append(_Window(key, min(own), max(own), False, problem))
                continue
            problem = marks.open_reason(own)
            starts = [start + 1 for start in marks.starts]
            # With only run_end markers the run's start is unknown.
            low = min([*own, *starts]) if own or starts else max(min(marks.ends), 0)
            high = max([*own, *marks.ends], default=low)
            if problem is None and low > high:
                continue  # a closed run that allocated nothing on this source
            windows.append(_Window(key, low, max(low, high), True, problem))
        return windows

    def build(self) -> dict[str, Any]:
        self._completeness()
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
        return {
            "run_id": self.run_id,
            "verdict": verdict_for(gaps, checks),
            "declared_scope": {
                "windows": [
                    {
                        "source_id": window.key[0],
                        "source_epoch": window.key[1],
                        "first_sequence": window.low,
                        "last_sequence": window.high,
                        "heartbeat_sequence": self.verifier.sources[window.key].heartbeat,
                        **_closed_by(window),
                    }
                    for window in self.windows
                ],
            },
            "exchanges": exchanges,
            "threads": [
                {"thread_id": thread_id, "exchange_ids": list(ids)}
                for thread_id, ids in stitched.threads
            ],
            "gaps": [gap.to_json() for gap in gaps],
            "counts": {"exchanges": len(exchanges), "gaps_by_type": gap_counts(gaps)},
            "checks": checks,
        }

    # -- completeness ------------------------------------------------------

    def _completeness(self) -> None:
        """Spec 042 §9.5 (rev 5): only proven ends make a run complete.

        A missing sequence inside a window, or adjacent to it (it may be the
        run's own first or last call), is ``partial``. A missing sequence
        after the window counts against the run unless the window's end is
        proven: by the run's own closed markers (then later sequences belong
        to other work) or, without markers, by the epoch's final heartbeat
        (then every sequence up to it is checked, and one missing there may
        be the run's lost call, so it is ``unverified``). Without either the
        tail is ``unverified``.
        """

        for window in self.windows:
            key, low, high = window.key, window.low, window.high
            source = self.verifier.sources[key]
            bounded_by_markers = window.marked and window.tail_problem is None
            for first, last in source.missing:
                effect: Literal["partial", "unverified"]
                if first <= high + 1 and last >= low - 1:
                    effect = "partial"
                elif not bounded_by_markers and last >= low:
                    effect = "unverified"  # may be the run's lost later call
                else:
                    continue
                unexplained = "unattributed" if effect == "unverified" else None
                for seg_low, seg_high, reason in source.segments[(first, last)]:
                    self.gaps.append(
                        Gap(
                            "loss" if reason is not None else "sequence_gap",
                            effect,
                            source_id=key[0],
                            source_epoch=key[1],
                            first_sequence=seg_low,
                            last_sequence=seg_high,
                            reason=reason or unexplained,
                        )
                    )
            if window.tail_problem is not None:
                self.gaps.append(
                    Gap(
                        "tail_unverified",
                        "unverified",
                        source_id=key[0],
                        source_epoch=key[1],
                        reason=window.tail_problem,
                    )
                )

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
        view = self._parse(exchange, bodies, entry)
        # A parsed body may carry any text under "model"; only a value that
        # passes the capture pattern is copied into the report.
        model = model_value(entry.get("model")) or exchange.model
        if model is not None:
            entry["model"] = model
        else:
            entry.pop("model", None)
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
