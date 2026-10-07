# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline run reconstruction and integrity verdict (spec 042 §10).

The verifier is read-only. It normalizes exchange and loss/watermark spans,
merges them with stored ``fabric.llm-exchange/v1`` records, accounts for
every allocated source sequence, verifies stored bytes, stitches exchanges
into threads and states a verdict for a declared scope. The verdict is an
integrity statement about the *record*; it never judges the agent.

A run is reported per ``(run_id, source_id, source_epoch)``: ``run_sequence``
is allocated per source, so exchanges that share a run id across processes
or capture components are verified as separate run entries with the same
``run_id``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Literal

from fabric._version import __version__
from fabric.reconstruct._inputs import (
    A_EXCHANGE_ID,
    L_RECORD_KIND,
    DigestList,
    ExchangeObs,
    LossObs,
    ReconstructInputError,
    SpanFormat,
    SpanRecord,
    exchange_from_record,
    exchange_from_span,
    id_list,
    loss_from_span,
    object_id_from_ref,
    read_span_file,
)
from fabric.reconstruct._objects import RECORD_ROLE, ObjectResult, StoreReader
from fabric.reconstruct._report import (
    MAX_GAP_SEQUENCES,
    SCHEMA_VERSION,
    Check,
    Gap,
    format_datetime,
    format_ns,
    gap_counts,
    sort_gaps,
    verdict_for,
)
from fabric.reconstruct._stitch_check import stitch_run

Scope = Literal["bytes", "metadata"]
SourceKey = tuple[str, int]
RunKey = tuple[str, str, int]


_RECOVERABLE_LOSS = frozenset({"span_dropped", "span_export_failed"})
_BYTE_GAPS = frozenset({"missing_object", "truncated"})
_STITCH_GAPS = frozenset(
    {"unmatched_tool_call", "unresolved_previous_response", "unparsed_exchange", "prefix_break"}
)
_UNSTORED = frozenset({"failed", "dropped"})
_STORED = frozenset({"stored", "truncated"})


# --------------------------------------------------------------------------
# Collected state
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _Source:
    source_id: str
    epoch: int
    component: str | None = None
    exchange_sequences: set[int] = field(default_factory=set)
    losses: list[LossObs] = field(default_factory=list)
    watermarks: list[LossObs] = field(default_factory=list)
    high_water: int = -1
    missing: list[tuple[int, int]] = field(default_factory=list)
    explained: set[int] = field(default_factory=set)

    def observed(self) -> set[int]:
        records = {record.source_sequence for record in (*self.losses, *self.watermarks)}
        return self.exchange_sequences | records

    def finalize(self) -> None:
        observed = self.observed()
        declared = [
            record.high_water_sequence
            for record in (*self.losses, *self.watermarks)
            if record.high_water_sequence is not None
        ]
        self.high_water = max([*observed, *declared], default=-1)
        self.missing = _complement(observed, self.high_water)
        self.explained = {item.source_sequence for loss in self.losses for item in loss.affected}

    def unexplained(self) -> list[tuple[int, int]]:
        return _subtract_points(self.missing, self.explained)

    def to_json(self) -> dict[str, Any]:
        cumulative = [
            record.cumulative_total
            for record in (*self.losses, *self.watermarks)
            if record.cumulative_total is not None
        ]
        out: dict[str, Any] = {"source_id": self.source_id, "source_epoch": self.epoch}
        if self.component is not None:
            out["component"] = self.component
        out["observed_records"] = len(self.observed())
        out["high_water_sequence"] = self.high_water
        out["missing_sequences"] = [[first, last] for first, last in self.missing]
        if self.watermarks:
            out["watermark_sequence"] = max(mark.source_sequence for mark in self.watermarks)
        out["cumulative_lost"] = max(cumulative, default=0)
        return out


@dataclass(slots=True)
class _ExchangeState:
    obs: ExchangeObs
    gaps: list[Gap] = field(default_factory=list)
    objects: dict[str, ObjectResult] = field(default_factory=dict)
    record_result: ObjectResult | None = None


def _complement(observed: set[int], high_water: int) -> list[tuple[int, int]]:
    """Inclusive ranges of ``[0, high_water]`` not in ``observed``."""

    missing: list[tuple[int, int]] = []
    cursor = 0
    for value in sorted(item for item in observed if 0 <= item <= high_water):
        if value > cursor:
            missing.append((cursor, value - 1))
        cursor = value + 1
    if cursor <= high_water:
        missing.append((cursor, high_water))
    return missing


def _subtract_points(spans: Sequence[tuple[int, int]], points: set[int]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    ordered = sorted(points)
    for first, last in spans:
        cursor = first
        for point in ordered:
            if point < cursor or point > last:
                continue
            if point > cursor:
                out.append((cursor, point - 1))
            cursor = point + 1
        if cursor <= last:
            out.append((cursor, last))
    return out


def _clip(spans: Iterable[tuple[int, int]], low: int, high: int) -> list[tuple[int, int]]:
    """Intersect inclusive ranges with ``[low, high]``."""

    out: list[tuple[int, int]] = []
    for first, last in spans:
        start, end = max(first, low), min(last, high)
        if start <= end:
            out.append((start, end))
    return out


def _listing(first: int, last: int) -> tuple[int, ...]:
    return tuple(range(first, min(last, first + MAX_GAP_SEQUENCES - 1) + 1))


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def reconstruct(
    span_paths: Sequence[str | os.PathLike[str]],
    *,
    store: Any | None = None,
    tenant_id: str | None = None,
    scope: Literal["bytes", "metadata"] = "bytes",
    run_ids: Collection[str] | None = None,
    scan_store: bool = False,
    recompute_digests: bool = False,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Reconstruct runs from span files (and an optional store).

    Returns a ``fabric.run-reconstruction/v1`` document. Raises
    :class:`ReconstructInputError` for unusable input or options.
    """

    if scope not in ("bytes", "metadata"):
        raise ReconstructInputError(f"scope must be 'bytes' or 'metadata', not {scope!r}")
    paths = list(span_paths)
    if not paths:
        raise ReconstructInputError("at least one span file is required")
    stitcher = _load_stitcher() if recompute_digests else None
    reader = StoreReader(store, tenant_id) if store is not None else None
    if scan_store and reader is None:
        raise ReconstructInputError("--scan-store requires a store")
    if recompute_digests and reader is None:
        raise ReconstructInputError("--recompute-digests requires a store")
    span_files: list[dict[str, Any]] = []
    spans: list[SpanRecord] = []
    for path in paths:
        fmt, records = read_span_file(path)
        span_files.append(_span_file_entry(path, fmt, len(records)))
        spans.extend(records)
    verifier = _Verifier(reader, scope, stitcher)
    verifier.ingest(spans)
    if scan_store and reader is not None:
        verifier.scan(reader)
    verifier.verify_objects()
    runs = verifier.build_runs(set(run_ids) if run_ids is not None else None)
    inputs: dict[str, Any] = {"span_files": span_files}
    if reader is not None:
        inputs["store"] = {"kind": reader.kind, "tenant_id": reader.tenant_id}
    inputs.update(
        {"scope": scope, "recompute_digests": recompute_digests, "scan_store": scan_store}
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": format_datetime(generated_at or datetime.now(tz=UTC)),
        "verifier": {"name": "fabric.reconstruct", "version": __version__},
        "inputs": inputs,
        "sources": [verifier.sources[key].to_json() for key in sorted(verifier.sources)],
        "runs": runs,
    }


def _span_file_entry(path: str | os.PathLike[str], fmt: SpanFormat, count: int) -> dict[str, Any]:
    location = Path(path)
    digest = hashlib.sha256()
    with location.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "path": str(path)[:4096],
        "sha256": "sha256:" + digest.hexdigest(),
        "format": fmt,
        "records": count,
    }


def _load_stitcher() -> ModuleType:
    try:
        module = importlib.import_module("fabric.wire._stitch")
    except Exception as exc:
        raise ReconstructInputError(
            "--recompute-digests needs fabric.wire._stitch, which is unavailable"
        ) from exc
    if not callable(getattr(module, "extract_stitch_keys", None)):
        raise ReconstructInputError("fabric.wire._stitch has no extract_stitch_keys()")
    return module


# --------------------------------------------------------------------------
# Verifier
# --------------------------------------------------------------------------


class _Verifier:
    def __init__(
        self, reader: StoreReader | None, scope: Scope, stitcher: ModuleType | None
    ) -> None:
        self.reader = reader
        self.scope = scope
        self.stitcher = stitcher
        self.exchanges: dict[str, _ExchangeState] = {}
        self.losses: dict[str, LossObs] = {}
        self.sources: dict[SourceKey, _Source] = {}
        self._record_ids: set[str] = set()

    @property
    def check_bytes(self) -> bool:
        return self.scope == "bytes"

    # -- ingestion ------------------------------------------------------

    def ingest(self, spans: Iterable[SpanRecord]) -> None:
        for span in spans:
            if A_EXCHANGE_ID in span.attributes:
                self._ingest_exchange_span(span)
            elif L_RECORD_KIND in span.attributes:
                loss = loss_from_span(span)
                if loss is not None:
                    self.losses.setdefault(loss.record_id, loss)
        if self.reader is None:
            return
        for state in list(self.exchanges.values()):
            if state.obs.exchange_ref is not None:
                self._load_record(self.reader, state, object_id_from_ref(state.obs.exchange_ref))

    def _ingest_exchange_span(self, span: SpanRecord) -> None:
        obs = exchange_from_span(span)
        if obs is None:
            return
        existing = self.exchanges.get(obs.exchange_id)
        if existing is None:
            self.exchanges[obs.exchange_id] = _ExchangeState(obs)
            return
        if existing.obs.fingerprint() != obs.fingerprint():
            existing.gaps.append(
                Gap(
                    "digest_mismatch",
                    "partial",
                    exchange_id=obs.exchange_id,
                    reason="conflicting_duplicate",
                )
            )

    def _load_record(
        self, reader: StoreReader, state: _ExchangeState, object_id: str | None
    ) -> None:
        result = reader.fetch(
            object_id,
            role=RECORD_ROLE,
            expected_sha256=state.obs.exchange_sha256,
            expected_length=None,
        )
        state.record_result = replace(result, data=None)
        if object_id is not None:
            self._record_ids.add(object_id)
        record = self._parse_record(result)
        if record is None:
            if result.verification == "verified":
                state.record_result = replace(
                    result,
                    verification="digest_mismatch",
                    gap_type="digest_mismatch",
                    reason="record_invalid",
                )
            return
        if record.exchange_id != state.obs.exchange_id:
            state.record_result = replace(
                result,
                verification="digest_mismatch",
                gap_type="digest_mismatch",
                reason="record_invalid",
            )
            return
        state.obs, disagree = _merge(state.obs, record)
        if disagree:
            state.gaps.append(
                Gap(
                    "digest_mismatch",
                    "partial",
                    exchange_id=state.obs.exchange_id,
                    reason="span_record_disagree",
                )
            )

    @staticmethod
    def _parse_record(result: ObjectResult) -> ExchangeObs | None:
        if result.verification != "verified" or result.data is None:
            return None
        try:
            document = json.loads(result.data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(document, Mapping):
            return None
        return exchange_from_record(document, "store")

    def scan(self, reader: StoreReader) -> None:
        for object_id in reader.scan_record_ids():
            if object_id in self._record_ids:
                continue
            sha, length = reader.descriptor_digest(object_id)
            result = reader.fetch(
                object_id, role=RECORD_ROLE, expected_sha256=sha, expected_length=length
            )
            record = self._parse_record(result)
            if record is None:
                continue
            self._record_ids.add(object_id)
            result = replace(result, data=None)
            existing = self.exchanges.get(record.exchange_id)
            if existing is not None and not existing.obs.has_record:
                existing.record_result = result
                existing.obs, disagree = _merge(existing.obs, record)
                if disagree:
                    existing.gaps.append(
                        Gap(
                            "digest_mismatch",
                            "partial",
                            exchange_id=record.exchange_id,
                            reason="span_record_disagree",
                        )
                    )
            elif existing is None:
                self.exchanges[record.exchange_id] = _ExchangeState(record, record_result=result)

    # -- objects ----------------------------------------------------------

    def verify_objects(self) -> None:
        loss_ids = {loss.record_id for loss in self.losses.values()}
        for state in self.exchanges.values():
            self._verify_exchange_objects(state, loss_ids)
            self._recompute(state)
            for role, result in list(state.objects.items()):
                if result.data is not None:
                    state.objects[role] = replace(result, data=None)

    def _verify_exchange_objects(self, state: _ExchangeState, loss_ids: set[str]) -> None:
        obs = state.obs
        if obs.store_status == "disabled":
            for role in ("request", "response"):
                state.objects[role] = ObjectResult("not_stored")
            if self.check_bytes:
                state.gaps.append(
                    Gap(
                        "missing_object",
                        "unverified",
                        exchange_id=obs.exchange_id,
                        reason="store_disabled",
                    )
                )
            return
        self._record_object(state)
        for role, body in (("request", obs.request), ("response", obs.response)):
            if body is None:
                continue
            if body.status in _UNSTORED:
                state.objects[role] = ObjectResult("not_stored", object_id=body.object_id)
                if self.check_bytes and not set(obs.loss_record_ids) & loss_ids:
                    state.gaps.append(
                        Gap(
                            "missing_object",
                            "partial",
                            exchange_id=obs.exchange_id,
                            object_role="request" if role == "request" else "response",
                            reason="store_failure_unreported",
                        )
                    )
                continue
            if body.object_id is None and body.status is None:
                continue
            self._body_object(state, role, body)
        if self.check_bytes and obs.truncated and not obs.has_record:
            state.gaps.append(
                Gap("truncated", "partial", exchange_id=obs.exchange_id, reason="span_truncated")
            )

    def _record_object(self, state: _ExchangeState) -> None:
        obs = state.obs
        result = state.record_result
        if result is not None:
            if not self.check_bytes:
                if result.verification != "verified":
                    result = replace(result, verification="not_checked")
                state.objects["record"] = result
                return
            state.objects["record"] = result
            if result.gap_type is not None:
                state.gaps.append(
                    Gap(
                        result.gap_type,
                        "partial",
                        exchange_id=obs.exchange_id,
                        object_role="record",
                        reason=result.reason,
                    )
                )
            return
        if obs.exchange_ref is not None:
            state.objects["record"] = ObjectResult(
                "not_checked",
                object_id=object_id_from_ref(obs.exchange_ref),
                ref=obs.exchange_ref,
                sha256=obs.exchange_sha256,
            )
        elif (
            self.check_bytes
            and self.reader is not None
            and obs.store_status in ("stored", "partial")
        ):
            state.gaps.append(
                Gap(
                    "missing_object",
                    "partial",
                    exchange_id=obs.exchange_id,
                    object_role="record",
                    reason="record_ref_absent",
                )
            )

    def _body_object(self, state: _ExchangeState, role: str, body: Any) -> None:
        obs = state.obs
        if obs.has_record:
            expected_length = body.stored_byte_length
        else:
            expected_length = None if obs.truncated else body.observed_byte_length
        if self.reader is None or not (self.check_bytes or self.stitcher is not None):
            state.objects[role] = ObjectResult(
                "not_checked",
                object_id=body.object_id,
                ref=body.ref,
                sha256=body.stored_sha256,
                byte_length=body.stored_byte_length,
            )
            return
        result = self.reader.fetch(
            body.object_id,
            role=f"model.exchange.{role}",
            expected_sha256=body.stored_sha256,
            expected_length=expected_length,
        )
        if self.stitcher is None:
            result = replace(result, data=None)
        if not self.check_bytes:
            state.objects[role] = replace(result, verification="not_checked")
            return
        state.objects[role] = result
        object_role: Literal["request", "response"] = "request" if role == "request" else "response"
        if result.gap_type is not None:
            state.gaps.append(
                Gap(
                    result.gap_type,
                    "partial",
                    exchange_id=obs.exchange_id,
                    object_role=object_role,
                    reason=result.reason,
                )
            )
        if body.status == "truncated":
            state.gaps.append(
                Gap(
                    "truncated",
                    "partial",
                    exchange_id=obs.exchange_id,
                    object_role=object_role,
                    reason="body_truncated",
                )
            )

    def _recompute(self, state: _ExchangeState) -> None:
        """Re-derive stitch keys from verified stored bytes (--recompute-digests)."""

        obs = state.obs
        stitcher = self.stitcher
        request = state.objects.get("request")
        response = state.objects.get("response")
        if stitcher is None or not obs.has_record or obs.api is None or obs.request is None:
            return
        if request is None or request.data is None:
            return
        if obs.request.status not in _STORED:
            return
        if obs.response is not None and (
            obs.response.status not in _STORED or response is None or response.data is None
        ):
            # A failed or dropped response body is already reported by its
            # store_failure / buffer_overflow loss. Re-deriving keys without
            # it would wipe the record's real output digests and emitted ids.
            return
        response_bytes = response.data if response is not None else None
        try:
            keys = stitcher.extract_stitch_keys(
                obs.api,
                request.data,
                obs.request.media_type or "application/octet-stream",
                _encoding(obs.request.content_encoding),
                obs.request.status == "truncated",
                response_bytes,
                obs.response.media_type if obs.response else None,
                _encoding(obs.response.content_encoding if obs.response else None),
                bool(obs.response and obs.response.status == "truncated"),
            )
            recomputed = _apply_keys(obs, keys)
        except Exception:
            state.gaps.append(
                Gap(
                    "unparsed_exchange",
                    "unverified",
                    exchange_id=obs.exchange_id,
                    reason="recompute_failed",
                )
            )
            return
        if _stitch_view(recomputed) != _stitch_view(obs):
            state.gaps.append(
                Gap(
                    "digest_mismatch",
                    "partial",
                    exchange_id=obs.exchange_id,
                    reason="recomputed_keys_disagree",
                )
            )
        state.obs = recomputed

    # -- runs -------------------------------------------------------------

    def build_runs(self, wanted: set[str] | None) -> list[dict[str, Any]]:
        placed = [state for state in self.exchanges.values() if state.obs.placeable()]
        for state in placed:
            obs = state.obs
            source = self._source(str(obs.source_id), int(obs.source_epoch or 0))
            source.exchange_sequences.add(int(obs.source_sequence or 0))
            source.component = source.component or obs.component
        for loss in sorted(self.losses.values(), key=lambda item: item.source_sequence):
            source = self._source(loss.source_id, loss.source_epoch)
            source.component = source.component or loss.component
            (source.losses if loss.kind == "loss" else source.watermarks).append(loss)
        for source in self.sources.values():
            source.finalize()
        members: dict[RunKey, list[_ExchangeState]] = {}
        for state in placed:
            obs = state.obs
            key = (str(obs.run_id), str(obs.source_id), int(obs.source_epoch or 0))
            members.setdefault(key, []).append(state)
        for loss in self.losses.values():
            run_ids = {item.run_id for item in loss.affected if item.run_id is not None}
            if loss.run_id is not None:
                run_ids.add(loss.run_id)
            for run_id in run_ids:
                members.setdefault((run_id, loss.source_id, loss.source_epoch), [])
        runs = []
        for key in sorted(members):
            if wanted is not None and key[0] not in wanted:
                continue
            runs.append(_RunBuilder(self, key, members[key]).build())
        return runs

    def _source(self, source_id: str, epoch: int) -> _Source:
        key = (source_id, epoch)
        source = self.sources.get(key)
        if source is None:
            source = self.sources[key] = _Source(source_id, epoch)
        return source


def _encoding(value: str | None) -> str | None:
    return None if value in (None, "identity") else value


def _apply_keys(obs: ExchangeObs, keys: Any) -> ExchangeObs:
    input_digests = tuple(str(item) for item in keys.input_digests)
    output_digests = tuple(str(item) for item in keys.output_digests)
    emitted = tuple(str(call[0]) for call in keys.tool_calls)
    return replace(
        obs,
        input=DigestList(len(input_digests), 0, input_digests),
        output=DigestList(len(output_digests), 0, output_digests),
        tool_call_ids_consumed=id_list(list(keys.tool_call_ids_consumed)) or (),
        tool_call_ids_emitted=id_list(list(emitted)) or (),
        response_id=keys.response_id,
        previous_response_id=keys.previous_response_id,
    )


def _stitch_view(obs: ExchangeObs) -> tuple[Any, ...]:
    return (
        obs.input.total,
        obs.input.digests,
        obs.output.total,
        obs.output.digests,
        tuple(dict.fromkeys(obs.tool_call_ids_consumed)),
        tuple(dict.fromkeys(obs.tool_call_ids_emitted)),
        obs.response_id,
        obs.previous_response_id,
    )


def _merge(span: ExchangeObs, record: ExchangeObs) -> tuple[ExchangeObs, bool]:
    """Merge a span with its stored record; report any disagreement."""

    disagree = any(
        theirs is not None and theirs != ours
        for theirs, ours in (
            (span.source_id, record.source_id),
            (span.source_epoch, record.source_epoch),
            (span.source_sequence, record.source_sequence),
            (span.run_id, record.run_id),
            (span.run_sequence, record.run_sequence),
            (
                span.request.stored_sha256 if span.request else None,
                record.request.stored_sha256 if record.request else None,
            ),
            (
                span.response.stored_sha256 if span.response else None,
                record.response.stored_sha256 if record.response else None,
            ),
        )
    )
    disagree = disagree or not _window_agrees(span.input, record.input)
    disagree = disagree or not _window_agrees(span.output, record.output)
    merged = replace(
        record,
        origin="span_and_store" if span.origin != "store" else "store",
        trace_id=record.trace_id or span.trace_id,
        span_id=span.span_id or record.span_id,
        start_ns=span.start_ns,
        end_ns=span.end_ns,
        exchange_ref=span.exchange_ref,
        exchange_sha256=span.exchange_sha256,
    )
    return merged, disagree


def _window_agrees(window: DigestList, full: DigestList) -> bool:
    if window.total is not None and full.total is not None and window.total != full.total:
        return False
    return all(
        full.at(window.offset + index) in (None, digest)
        for index, digest in enumerate(window.digests)
    )


# --------------------------------------------------------------------------
# Per-run evaluation
# --------------------------------------------------------------------------


class _RunBuilder:
    def __init__(self, verifier: _Verifier, key: RunKey, members: list[_ExchangeState]) -> None:
        self.verifier = verifier
        self.run_id, self.source_id, self.epoch = key
        self.source = verifier.sources[(self.source_id, self.epoch)]
        self.gaps: list[Gap] = []
        self.states = self._ordered(members)
        self.exchanges = [state.obs for state in self.states]
        self.run_close = max(
            (mark for mark in self.source.watermarks if mark.run_id == self.run_id),
            key=lambda mark: mark.source_sequence,
            default=None,
        )
        sequences = [int(obs.source_sequence or 0) for obs in self.exchanges] or [
            item.source_sequence
            for loss in self.source.losses
            for item in loss.affected
            if item.run_id == self.run_id
        ]
        self.first = min(sequences, default=None)
        self.last = max(sequences, default=None)

    def _ordered(self, members: list[_ExchangeState]) -> list[_ExchangeState]:
        ordered = sorted(
            members,
            key=lambda state: (
                state.obs.run_sequence,
                state.obs.source_sequence,
                state.obs.exchange_id,
            ),
        )
        kept: list[_ExchangeState] = []
        for state in ordered:
            if kept and kept[-1].obs.run_sequence == state.obs.run_sequence:
                self.gaps.append(
                    Gap(
                        "digest_mismatch",
                        "partial",
                        exchange_id=state.obs.exchange_id,
                        reason="conflicting_duplicate",
                    )
                )
                continue
            kept.append(state)
            self.gaps.extend(state.gaps)
        return kept

    def build(self) -> dict[str, Any]:
        proved, through = self._tail()
        self._sequence_gaps(proved)
        self._loss_gaps()
        stitched = stitch_run(self.exchanges)
        self.gaps.extend(stitched.gaps)
        if not proved:
            self.gaps.append(
                Gap(
                    "tail_unverified",
                    "unverified",
                    source_id=self.source_id,
                    source_epoch=self.epoch,
                    reason="no_watermark" if not self.source.watermarks else "tail_not_covered",
                )
            )
        checks = self._checks(proved, stitched.skipped)
        run_sequence_of = {obs.exchange_id: int(obs.run_sequence or 0) for obs in self.exchanges}
        gaps = sort_gaps(self.gaps, run_sequence_of)
        threads = [
            {"thread_id": thread_id, "exchange_ids": list(exchange_ids)}
            for thread_id, exchange_ids in stitched.threads
        ]
        return {
            "run_id": self.run_id,
            "run_id_basis": self._basis(),
            "verdict": verdict_for(gaps, checks),
            "declared_scope": {
                "capture_surfaces": self._surfaces(),
                "bytes": self.verifier.check_bytes,
                "through": (
                    [
                        {
                            "source_id": self.source_id,
                            "source_epoch": self.epoch,
                            "through_source_sequence": through,
                        }
                    ]
                    if proved and through is not None
                    else []
                ),
            },
            "exchanges": [
                self._exchange_json(state, stitched.thread_of, stitched.continues)
                for state in self.states
            ],
            "threads": threads,
            "gaps": [gap.to_json() for gap in gaps],
            "counts": {"exchanges": len(self.states), "gaps_by_type": gap_counts(gaps)},
            "checks": checks,
        }

    # -- sequence, loss and tail ----------------------------------------

    def _tail(self) -> tuple[bool, int | None]:
        # A run-close watermark proves the tail only if nothing of the run
        # came after it (a reused id or a task outliving its run scope).
        if self.run_close is not None and (
            self.last is None or self.run_close.source_sequence > self.last
        ):
            mark = self.run_close
            return True, (
                mark.high_water_sequence
                if mark.high_water_sequence is not None
                else mark.source_sequence
            )
        if self.last is None:
            return False, None
        unexplained = self.source.unexplained()
        marks = sorted(
            self.source.watermarks,
            key=lambda mark: (
                mark.high_water_sequence
                if mark.high_water_sequence is not None
                else mark.source_sequence,
                mark.source_sequence,
            ),
            reverse=True,
        )
        for mark in marks:
            high = (
                mark.high_water_sequence
                if mark.high_water_sequence is not None
                else mark.source_sequence
            )
            if high < self.last:
                break
            if not _clip(unexplained, self.last + 1, high):
                return True, high
        return False, None

    def _sequence_gaps(self, tail_proved: bool) -> None:
        if self.first is not None and self.last is not None:
            unexplained = self.source.unexplained()
            window = _clip(unexplained, self.first + 1, self.last - 1)
            if not tail_proved:
                window += _clip(unexplained, self.last + 1, self.source.high_water)
            for first, last in window:
                self.gaps.append(
                    Gap(
                        "sequence_gap",
                        "partial",
                        source_id=self.source_id,
                        source_epoch=self.epoch,
                        sequences=_listing(first, last),
                        reason="source_sequence_missing",
                    )
                )
        observed = {int(obs.run_sequence or 0) for obs in self.exchanges}
        explained = {
            item.run_sequence
            for loss in self.source.losses
            for item in loss.affected
            if item.run_id == self.run_id and item.run_sequence is not None
        }
        declared = [
            self.run_close.run_high_water
            if self.run_close is not None and self.run_close.run_high_water is not None
            else -1
        ]
        high = max([*observed, *explained, *declared], default=-1)
        missing = _subtract_points(_complement(observed, high), explained)
        for first, last in missing:
            self.gaps.append(
                Gap(
                    "sequence_gap",
                    "partial",
                    source_id=self.source_id,
                    source_epoch=self.epoch,
                    run_sequences=_listing(first, last),
                    reason="run_sequence_missing",
                )
            )

    def _loss_gaps(self) -> None:
        recovered = self.source.exchange_sequences
        for loss in self.source.losses:
            items = [item for item in loss.affected if item.run_id == self.run_id]
            if items:
                recoverable = loss.reason in _RECOVERABLE_LOSS and all(
                    item.source_sequence in recovered for item in items
                )
                self._loss_gap(loss, items, "info" if recoverable else "partial")
                continue
            if loss.fully_attributed() or self.first is None or self.last is None:
                continue
            if loss.source_sequence <= self.first:
                continue
            inside = any(self.first <= item.source_sequence <= self.last for item in loss.affected)
            if (
                self.run_close is not None
                and self.run_close.source_sequence < loss.source_sequence
                and not inside
            ):
                continue
            unattributed = [item for item in loss.affected if item.run_id is None]
            recoverable = (
                loss.reason in _RECOVERABLE_LOSS
                and not loss.affected_truncated
                and len(loss.affected) >= loss.count
                and all(item.source_sequence in recovered for item in loss.affected)
            )
            self._loss_gap(loss, unattributed, "info" if recoverable else "partial")

    def _loss_gap(
        self, loss: LossObs, items: Sequence[Any], effect: Literal["info", "partial"]
    ) -> None:
        self.gaps.append(
            Gap(
                "loss_record",
                effect,
                source_id=self.source_id,
                source_epoch=self.epoch,
                sequences=tuple(sorted({item.source_sequence for item in items}))[
                    :MAX_GAP_SEQUENCES
                ],
                run_sequences=tuple(
                    sorted({item.run_sequence for item in items if item.run_sequence is not None})
                )[:MAX_GAP_SEQUENCES],
                loss_record_id=loss.record_id,
                reason=loss.reason,
            )
        )

    # -- checks and output ------------------------------------------------

    def _checks(self, tail_proved: bool, stitching_skipped: bool) -> dict[str, Check]:
        def failing(types: Collection[str], *, object_only: bool = False) -> bool:
            return any(
                gap.gap_type in types
                and gap.effect != "info"
                and (not object_only or gap.object_role is not None)
                for gap in self.gaps
            )

        if not self.verifier.check_bytes:
            bytes_check: Check = "not_applicable"
        elif self.verifier.reader is None:
            bytes_check = "skipped"
        elif failing(_BYTE_GAPS) or failing({"digest_mismatch"}, object_only=True):
            bytes_check = "failed"
        else:
            bytes_check = "passed"
        if not self.exchanges:
            stitching: Check = "not_applicable"
        elif stitching_skipped:
            stitching = "skipped"
        elif failing(_STITCH_GAPS):
            stitching = "failed"
        else:
            stitching = "passed"
        return {
            "sequence": "failed" if failing({"sequence_gap"}) else "passed",
            "loss": "failed" if failing({"loss_record"}) else "passed",
            "tail": "passed" if tail_proved else "failed",
            "bytes": bytes_check,
            "stitching": stitching,
        }

    def _basis(self) -> str:
        for obs in self.exchanges:
            if obs.run_id_basis is not None:
                return obs.run_id_basis
        if self.run_id.startswith("trace:"):
            return "trace"
        if self.run_id.startswith("source:"):
            return "source"
        return "explicit"

    def _surfaces(self) -> list[str]:
        surfaces = sorted({str(obs.fidelity) for obs in self.exchanges if obs.fidelity})
        if surfaces:
            return surfaces
        return ["gateway_normalized" if self.source.component == "gateway" else "exact_wire"]

    def _exchange_json(
        self,
        state: _ExchangeState,
        thread_of: Mapping[str, str],
        continues: Mapping[str, str],
    ) -> dict[str, Any]:
        obs = state.obs
        out: dict[str, Any] = {
            "exchange_id": obs.exchange_id,
            "run_sequence": obs.run_sequence,
            "source_id": obs.source_id,
            "source_epoch": obs.source_epoch,
            "source_sequence": obs.source_sequence,
            "fidelity": obs.fidelity,
            "api": obs.api,
        }
        optional: dict[str, Any] = {
            "trace_id": obs.trace_id,
            "span_id": obs.span_id if obs.trace_id else None,
            "started_at": format_ns(obs.start_ns) if obs.start_ns else obs.started_at,
            "ended_at": format_ns(obs.end_ns) if obs.end_ns else obs.ended_at,
            "model": obs.model,
            "response_id": obs.response_id,
            "previous_response_id": obs.previous_response_id,
        }
        out.update({key: value for key, value in optional.items() if value is not None})
        out["response_state"] = obs.response_state
        out["thread_id"] = thread_of[obs.exchange_id]
        if obs.exchange_id in continues:
            out["continues_exchange_id"] = continues[obs.exchange_id]
        out["input_message_count"] = obs.input.total or 0
        out["output_message_count"] = obs.output.total or 0
        out["tool_call_ids_consumed"] = list(obs.tool_call_ids_consumed)
        out["tool_call_ids_emitted"] = list(obs.tool_call_ids_emitted)
        out["origin"] = obs.origin
        out["objects"] = {
            role: state.objects[role].to_json()
            for role in ("request", "response", "record")
            if role in state.objects
        }
        return out
