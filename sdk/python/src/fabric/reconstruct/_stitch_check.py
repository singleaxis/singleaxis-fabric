# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Thread stitching and tool-call matching within one run (spec 042 §10.5).

Exchanges are visited in ``run_sequence`` order. A Responses API call with
``previous_response_id`` continues the exchange that produced that response.
Any other call continues the earlier exchange whose request digests plus
continuation digests form the longest prefix of its own request digests.
A partial overlap is a ``prefix_break``: history was rewritten. It is
recorded and never judged. When only OTLP digest windows are available and
a candidate cannot be compared on any index, the stitching check is skipped
rather than guessed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from fabric.reconstruct._inputs import DigestList, ExchangeObs
from fabric.reconstruct._report import Gap

_SINGLE_CONTINUATION = frozenset({"openai.chat_completions", "openai.completions"})
_PARSED_OK = frozenset({"ok", "truncated"})


@dataclass(slots=True)
class StitchResult:
    threads: list[tuple[str, list[str]]] = field(default_factory=list)
    continues: dict[str, str] = field(default_factory=dict)
    thread_of: dict[str, str] = field(default_factory=dict)
    gaps: list[Gap] = field(default_factory=list)
    skipped: bool = False


@dataclass(slots=True)
class _Continuation:
    """The digests the next request in a thread is expected to start with."""

    exchange: ExchangeObs
    length: int
    full: tuple[str, ...] | None
    request: DigestList
    output: DigestList
    output_count: int

    def at(self, index: int) -> str | None:
        if index < (self.request.total or 0):
            return self.request.at(index)
        return self.output.at(index - (self.request.total or 0))


def _continuation(exchange: ExchangeObs) -> _Continuation | None:
    request = exchange.input
    if request.total is None or exchange.api == "openai.embeddings":
        return None
    outputs = exchange.output.total or 0
    take = min(1, outputs) if exchange.api in _SINGLE_CONTINUATION else outputs
    length = request.total + take
    if length == 0:
        return None
    full: tuple[str, ...] | None = None
    if request.complete and exchange.output.offset == 0 and len(exchange.output.digests) >= take:
        full = request.digests + exchange.output.digests[:take]
    return _Continuation(exchange, length, full, request, exchange.output, take)


def _compare(candidate: _Continuation, request: DigestList) -> str:
    """``match``, ``mismatch`` or ``unknown`` (no comparable index)."""

    if request.total is None or candidate.length > request.total:
        return "mismatch" if request.total is not None else "unknown"
    if candidate.full is not None and request.complete:
        return "match" if request.digests[: candidate.length] == candidate.full else "mismatch"
    overlap = 0
    for index in range(candidate.length):
        theirs = candidate.at(index)
        ours = request.at(index)
        if theirs is None or ours is None:
            continue
        if theirs != ours:
            return "mismatch"
        overlap += 1
    return "match" if overlap else "unknown"


def _common_prefix(candidate: _Continuation, request: DigestList) -> int:
    """Leading digests shared by a candidate continuation and a request."""

    limit = min(candidate.length, request.total or 0)
    shared = 0
    for index in range(limit):
        theirs = candidate.at(index)
        ours = request.at(index)
        if theirs is None or ours is None:
            if shared:
                break
            continue
        if theirs != ours:
            break
        shared += 1
    return shared


class _Threads:
    def __init__(self, result: StitchResult) -> None:
        self._result = result
        self._members: dict[str, list[str]] = {}

    def new(self, exchange_id: str) -> None:
        thread_id = f"thread-{len(self._result.threads)}"
        members = [exchange_id]
        self._members[thread_id] = members
        self._result.threads.append((thread_id, members))
        self._result.thread_of[exchange_id] = thread_id

    def join(self, exchange_id: str, earlier_id: str) -> None:
        thread_id = self._result.thread_of[earlier_id]
        self._members[thread_id].append(exchange_id)
        self._result.thread_of[exchange_id] = thread_id


def stitch_run(exchanges: Sequence[ExchangeObs]) -> StitchResult:
    """Assign threads and stitching gaps; ``exchanges`` sorted by run_sequence."""

    result = StitchResult()
    threads = _Threads(result)
    candidates: list[_Continuation] = []
    by_response_id: dict[str, ExchangeObs] = {}
    for exchange in exchanges:
        _place(exchange, candidates, by_response_id, threads, result)
        continuation = _continuation(exchange)
        if continuation is not None:
            candidates.append(continuation)
        if exchange.response_id is not None:
            by_response_id[exchange.response_id] = exchange
        if not set(exchange.parse_statuses) <= _PARSED_OK or not exchange.parse_statuses:
            result.gaps.append(
                Gap(
                    "unparsed_exchange",
                    "unverified",
                    exchange_id=exchange.exchange_id,
                    reason=_unparsed_reason(exchange.parse_statuses),
                )
            )
    gaps, unprovable = _tool_call_gaps(exchanges)
    result.gaps.extend(gaps)
    if unprovable:
        result.skipped = True
    return result


def _unparsed_reason(statuses: Sequence[str]) -> str:
    for status in statuses:
        if status not in _PARSED_OK:
            return status
    return "parse_status_unknown"


def _place(
    exchange: ExchangeObs,
    candidates: Sequence[_Continuation],
    by_response_id: dict[str, ExchangeObs],
    threads: _Threads,
    result: StitchResult,
) -> None:
    if exchange.api == "openai.embeddings":
        threads.new(exchange.exchange_id)
        return
    if exchange.previous_response_id is not None:
        previous = by_response_id.get(exchange.previous_response_id)
        if previous is None:
            result.gaps.append(
                Gap(
                    "unresolved_previous_response",
                    "partial",
                    exchange_id=exchange.exchange_id,
                    previous_response_id=exchange.previous_response_id,
                )
            )
            threads.new(exchange.exchange_id)
            return
        result.continues[exchange.exchange_id] = previous.exchange_id
        threads.join(exchange.exchange_id, previous.exchange_id)
        return
    best: _Continuation | None = None
    unknown = False
    for candidate in candidates:
        outcome = _compare(candidate, exchange.input)
        if outcome == "unknown":
            unknown = True
        elif outcome == "match" and (best is None or candidate.length >= best.length):
            best = candidate
    if best is not None:
        result.continues[exchange.exchange_id] = best.exchange.exchange_id
        threads.join(exchange.exchange_id, best.exchange.exchange_id)
        return
    if unknown:
        result.skipped = True
    closest: _Continuation | None = None
    closest_shared = 0
    for candidate in candidates:
        shared = _common_prefix(candidate, exchange.input)
        if shared >= 1 and shared >= closest_shared:
            closest, closest_shared = candidate, shared
    if closest is None:
        threads.new(exchange.exchange_id)
        return
    result.gaps.append(
        Gap(
            "prefix_break",
            "info",
            exchange_id=exchange.exchange_id,
            reason="history_rewritten",
        )
    )
    threads.join(exchange.exchange_id, closest.exchange.exchange_id)


def _tool_call_gaps(exchanges: Sequence[ExchangeObs]) -> tuple[list[Gap], bool]:
    """Tool-call matching gaps, and whether matching could not be proven.

    Span-only exchanges carry at most 64 ids per OTLP array. When a consumed
    list is capped, ids outside the window cannot be checked; when an emitted
    list is capped, a later "unmatched" id may have been emitted by it. Both
    make the check unprovable (``skipped``) instead of a false pass or a
    false ``partial``.
    """
    gaps: list[Gap] = []
    emitted: dict[str, str] = {}
    carried: set[str] = set()
    matched: set[str] = set()
    unprovable = False
    emitted_capped = False
    for exchange in exchanges:
        if exchange.consumed_ids_capped:
            unprovable = True
        for call_id in exchange.tool_call_ids_consumed:
            if call_id in emitted:
                matched.add(call_id)
                continue
            if call_id in carried:
                continue
            first = exchange.run_sequence == 0
            if emitted_capped and not first:
                unprovable = True
                continue
            gaps.append(
                Gap(
                    "unmatched_tool_call",
                    "info" if first else "partial",
                    exchange_id=exchange.exchange_id,
                    tool_call_id=call_id,
                    reason="consumed_before_run" if first else "consumed_not_emitted",
                )
            )
        carried.update(exchange.tool_call_ids_consumed)
        for call_id in exchange.tool_call_ids_emitted:
            emitted.setdefault(call_id, exchange.exchange_id)
        emitted_capped = emitted_capped or exchange.emitted_ids_capped
    for call_id, exchange_id in emitted.items():
        if call_id not in matched:
            gaps.append(
                Gap(
                    "unmatched_tool_call",
                    "info",
                    exchange_id=exchange_id,
                    tool_call_id=call_id,
                    reason="emitted_not_consumed",
                )
            )
    return gaps, unprovable
