# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Thread stitching and tool-call matching within one run (spec 042 §9 step 6).

Exchanges are visited in run order with message digests derived from the
stored bytes. A Responses API call with ``previous_response_id`` continues
the exchange that produced that response. Any other call continues the
earlier exchange whose request digests plus continuation digests form the
longest prefix of its own request digests. A partial overlap is a
``prefix_break``: history was rewritten. It is recorded and never judged.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from fabric.reconstruct._report import Gap


@dataclass(frozen=True, slots=True)
class StitchView:
    """What stitching needs from one exchange; ``parsed`` False = own thread."""

    exchange_id: str
    api: str
    parsed: bool
    request: tuple[str, ...] = ()
    continuation: tuple[str, ...] = ()
    consumed: tuple[str, ...] = ()
    emitted: tuple[str, ...] = ()
    response_id: str | None = None
    previous_response_id: str | None = None


@dataclass(slots=True)
class StitchResult:
    threads: list[tuple[str, list[str]]] = field(default_factory=list)
    continues: dict[str, str] = field(default_factory=dict)
    thread_of: dict[str, str] = field(default_factory=dict)
    gaps: list[Gap] = field(default_factory=list)

    def new(self, exchange_id: str) -> None:
        thread_id = f"thread-{len(self.threads)}"
        self.threads.append((thread_id, [exchange_id]))
        self.thread_of[exchange_id] = thread_id

    def join(self, exchange_id: str, earlier_id: str, *, continues: bool = True) -> None:
        thread_id = self.thread_of[earlier_id]
        for candidate, members in self.threads:
            if candidate == thread_id:
                members.append(exchange_id)
        self.thread_of[exchange_id] = thread_id
        if continues:
            self.continues[exchange_id] = earlier_id


def _common_prefix(left: Sequence[str], right: Sequence[str]) -> int:
    shared = 0
    for theirs, ours in zip(left, right, strict=False):
        if theirs != ours:
            break
        shared += 1
    return shared


def stitch_run(views: Sequence[StitchView]) -> StitchResult:
    """Assign threads and stitching gaps; ``views`` are in run order."""

    result = StitchResult()
    candidates: list[StitchView] = []
    by_response_id: dict[str, str] = {}
    for view in views:
        _place(view, candidates, by_response_id, result)
        if view.parsed and view.continuation and view.api != "openai.embeddings":
            candidates.append(view)
        if view.response_id is not None:
            by_response_id[view.response_id] = view.exchange_id
    result.gaps.extend(_tool_call_gaps(views))
    return result


def _place(
    view: StitchView,
    candidates: Sequence[StitchView],
    by_response_id: dict[str, str],
    result: StitchResult,
) -> None:
    if not view.parsed or view.api == "openai.embeddings":
        result.new(view.exchange_id)
        return
    if view.previous_response_id is not None:
        previous = by_response_id.get(view.previous_response_id)
        if previous is None:
            result.gaps.append(
                Gap(
                    "unresolved_previous_response",
                    "partial",
                    exchange_id=view.exchange_id,
                    previous_response_id=view.previous_response_id,
                )
            )
            result.new(view.exchange_id)
        else:
            result.join(view.exchange_id, previous)
        return
    best: StitchView | None = None
    for candidate in candidates:
        length = len(candidate.continuation)
        if view.request[:length] == candidate.continuation and (
            best is None or length >= len(best.continuation)
        ):
            best = candidate
    if best is not None:
        result.join(view.exchange_id, best.exchange_id)
        return
    closest: StitchView | None = None
    closest_shared = 0
    for candidate in candidates:
        shared = _common_prefix(candidate.continuation, view.request)
        if shared >= 1 and shared >= closest_shared:
            closest, closest_shared = candidate, shared
    if closest is None:
        result.new(view.exchange_id)
        return
    result.gaps.append(
        Gap("prefix_break", "info", exchange_id=view.exchange_id, reason="history_rewritten")
    )
    result.join(view.exchange_id, closest.exchange_id, continues=False)


def _tool_call_gaps(views: Sequence[StitchView]) -> list[Gap]:
    """Tool-call matching gaps.

    After an exchange whose bytes could not be parsed, an id that seems
    never emitted may have been emitted by it: no ``consumed_not_emitted``
    is claimed then (the stitching check is already ``skipped``).
    """
    gaps: list[Gap] = []
    emitted: dict[str, str] = {}
    carried: set[str] = set()
    matched: set[str] = set()
    blind = False
    for index, view in enumerate(views):
        for call_id in view.consumed:
            if call_id in emitted:
                matched.add(call_id)
            elif call_id not in carried and not blind:
                first = index == 0
                gaps.append(
                    Gap(
                        "unmatched_tool_call",
                        "info" if first else "partial",
                        exchange_id=view.exchange_id,
                        tool_call_id=call_id,
                        reason="consumed_before_run" if first else "consumed_not_emitted",
                    )
                )
        carried.update(view.consumed)
        blind = blind or not view.parsed
        for call_id in view.emitted:
            emitted.setdefault(call_id, view.exchange_id)
    gaps.extend(
        Gap(
            "unmatched_tool_call",
            "info",
            exchange_id=exchange_id,
            tool_call_id=call_id,
            reason="emitted_not_consumed",
        )
        for call_id, exchange_id in emitted.items()
        if call_id not in matched
    )
    return gaps
