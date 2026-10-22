# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 WP-12 unit suite: ``fr3/`` tokens and the run-identity rules against the
WP-00 ``resume-token-v2`` vectors, every seal-trigger row of §3.6, continuation
``run_start`` markers, the outcome hook, ``end_run`` refusals, fail-open/strict, and the
privacy canaries (a clear run id never reaches a marker, a token or a baggage value).

The run table is driven on a real allocator and the real seal accumulator; markers are
collected from the marker queue and every one is validated as a capture/v1 1.3.0 spool
marker (schema plus semantic checks)."""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import pytest

import fabric._loss
import fabric._sequence
from fabric import _segments, wire
from fabric._capture_types import COUNTERS, STRICT_ENV, Marker, RecordsMisuseError
from fabric._seal import SegmentSeals, seal_digest
from fabric._segments import (
    NO_MANIFEST_DIGEST,
    IdentityRule,
    SegmentTable,
    format_token,
    parse_token,
    resolve_identity,
    split_tokens,
)
from fabric._sequence import SourceAllocator, current_run_scope, run_scope
from fabric.wire._spool import SCHEMA, marker_doc, valid_header

from .test_wire_helpers import CAPTURE, load_validator

REPO = Path(__file__).resolve().parents[3]
VECTORS = json.loads(
    (REPO / "contracts/coverage/v1/fixtures/vectors/resume-token-v2.json").read_text("utf-8")
)
VALIDATOR = load_validator()
SCHEMAS = {
    rel: json.loads((CAPTURE / rel).read_text("utf-8")) for rel in VALIDATOR.SCHEMAS.values()
}
KEY = b"fabric-test-id-key-not-a-secret"
SOURCE = "s-" + "a" * 32
DIGEST = "sha256:" + "ab" * 32
CLEAR = "customer-run-7781-CANARY"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    COUNTERS.reset()
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)
    COUNTERS.reset()


class _Queue:
    """The marker queue (``LossEmitter.queue_marker``) as a list."""

    def __init__(self) -> None:
        self.markers: list[Marker] = []
        self.lock = threading.Lock()

    def queue_marker(self, marker: Marker) -> bool:
        with self.lock:
            self.markers.append(marker)
        return True

    def note_activity(self, allocator: Any) -> None:
        return None

    def kind(self, kind: str) -> list[Marker]:
        return [m for m in self.markers if m.kind == kind]


class Rig:
    def __init__(
        self, *, key: bytes | None = KEY, mode: str = "pseudonymous", production: bool = False,
        forced_at: int = 1_000_000,
    ) -> None:  # fmt: skip
        self.allocator = SourceAllocator(SOURCE)
        self.queue = _Queue()
        self.seals = SegmentSeals(self.queue.queue_marker, forced_at=forced_at)
        self.seals.bind_source(lambda: (self.allocator.source_id, self.allocator.epoch))
        self.table = SegmentTable()
        loss: Any = self.queue
        self.table.bind(allocator=self.allocator, loss=loss, seals=self.seals, key=key,
                        production=production, identity_mode=cast("Any", mode))  # fmt: skip
        self.allocator.attach(segments=self.table, seals=self.seals)

    @contextlib.contextmanager
    def block(self, run_id: Any = None, **kwargs: Any) -> Iterator[Any]:
        plan = self.table.prepare(run_id, outermost=current_run_scope() is None, **kwargs)
        with run_scope("fabric-run", emitted=plan.run_id) as scope:
            self.table.enter(plan, scope)
            status = "ok"
            try:
                yield scope
            except BaseException as exc:
                status = wire._scope_status(exc)
                raise
            finally:
                self.table.exit(scope, status)  # type: ignore[arg-type]

    def write(self, count: int = 1) -> list[Any]:
        """``count`` positions allocated and settled (written) in the current context."""
        out = []
        for index in range(count):
            allocation = self.allocator.allocate()
            self.allocator.settle(allocation.segment_id, allocation.sequence,
                                  "sha256:" + f"{index:064x}")  # fmt: skip
            out.append(allocation)
        return out

    def issue(self, branches: int = 0) -> tuple[str, ...]:
        scope = current_run_scope()
        assert scope is not None
        return self.table.issue(scope, branches)

    def seal_of(self, segment: str) -> Marker:
        (seal,) = [m for m in self.queue.kind("segment_seal") if m.segment_id == segment]
        return seal

    def check_markers(self) -> None:
        """Every queued marker is a valid capture/v1 1.3.0 spool marker."""
        for order, marker in enumerate(self.queue.markers):
            doc = {**marker_doc(marker), "schema_version": SCHEMA, "order": order,
                   "written_at_unix_nano": 1000 + order}  # fmt: skip
            assert valid_header(doc, 0), doc
            VALIDATOR.validate_document(doc, SCHEMAS)


def _parsed(token: str) -> dict[str, Any] | None:
    parsed = parse_token(token)
    if parsed is None:
        return None
    return {"version": parsed.version, "correlation_id": parsed.correlation_id,
            "segment_id": parsed.segment_id, "source_id": parsed.source_id,
            "epoch": parsed.epoch, "last_sequence": parsed.last_sequence,
            "manifest_digest": parsed.manifest_digest, "branch_id": parsed.branch_id}  # fmt: skip


# --- tokens: the v2 grammar (resume-token-v2.json) -------------------------------------------


@pytest.mark.parametrize("case", VECTORS["tokens"], ids=lambda c: c["name"])
def test_token_grammar_vectors(case: dict[str, Any]) -> None:
    assert _parsed(case["token"]) == case["parsed"]


@pytest.mark.parametrize("case", VECTORS["issue"], ids=lambda c: c["name"])
def test_token_issue_vectors(case: dict[str, Any]) -> None:
    assert format_token(case["correlation_id"], case["entry"], case["branch_id"]) == case["token"]


@pytest.mark.parametrize("case", VECTORS["carriers"], ids=lambda c: c["name"])
def test_carrier_vectors(case: dict[str, Any]) -> None:
    tokens = split_tokens(case["value"], carrier=case["carrier"])
    assert tokens == case["tokens"]
    assert [parse_token(t) is not None for t in tokens] == case["valid"]


def test_non_string_tokens_never_parse() -> None:
    assert parse_token(None) is None
    assert parse_token(b"fr3/x") is None
    assert format_token("r-" + "1" * 32, "not-an-entry") is None
    entry = f"seg-{'1' * 32}/{SOURCE}/7/3/{DIGEST}"
    assert format_token("r-" + "1" * 32, entry + "/br-" + "2" * 32) is None  # one branch only


# --- run identity: rules 1-5 (resume-token-v2.json) -------------------------------------------


def _rule(inputs: dict[str, Any]) -> IdentityRule:
    key = inputs["key"].encode("utf-8") if inputs["key"] else None
    return IdentityRule(key=key, mode=inputs["identity_mode"], production=False)


@pytest.mark.parametrize("case", VECTORS["run_identity"], ids=lambda c: c["name"])
def test_run_identity_vectors(case: dict[str, Any]) -> None:
    inputs, expected = case["inputs"], case["expected"]
    rule = _rule(inputs)
    run_id = inputs["run_id"]
    if inputs["run_id_emitted"]:
        run_id = rule._ids.mint(run_id)  # an EmittedId of this rule's issuer
    identity = resolve_identity(inputs["tokens"], run_id, map_run=rule.run,
                                mint=lambda: inputs["minted"])  # fmt: skip
    assert identity.run_id == expected["run_id"]
    assert identity.id_basis == expected["id_basis"]
    assert list(identity.predecessors) == expected["predecessors"]
    assert list(identity.branch_ids) == expected["branch_ids"]
    assert identity.tokens_rejected == expected["tokens_rejected"]


def test_rule_5_mints_a_csprng_emitted_id_without_caller_input() -> None:
    rule = IdentityRule(key=KEY, mode="pseudonymous", production=False)
    first, second = rule.mint_run(), rule.mint_run()
    assert first != second and fabric._sequence.RUN_PSEUDONYM_RE.fullmatch(first)
    assert rule.mine(first) and isinstance(first, fabric._sequence.EmittedId)
    assert rule.run(first) == first  # passes through, never mapped again
    assert rule.run(str(first)) != first  # a plain string is always mapped (decision 22)


def test_the_production_profile_without_a_key_derives_nothing_from_the_run_id() -> None:
    rule = IdentityRule(key=None, mode="pseudonymous", production=True,
                        fallback=lambda: "source:s-x:7")  # fmt: skip
    assert rule.run(CLEAR) == "source:s-x:7"
    assert rule.link(CLEAR) is None and rule.v2("sess", CLEAR) is None


@pytest.mark.parametrize("case", VECTORS["end_run"], ids=lambda c: c["name"])
def test_end_run_vectors(case: dict[str, Any]) -> None:
    inputs, expected = case["inputs"], case["expected"]
    rig = Rig(key=inputs["key"].encode("utf-8"), mode=inputs["identity_mode"])
    status = rig.table.end(inputs["run_id"], "completed", inputs["tokens"], None)
    assert status == expected["status"]
    if status != "ended":
        assert rig.queue.markers == []  # a refusal emits nothing
        return
    (start,) = rig.queue.kind("run_start")
    (end,) = rig.queue.kind("run_end")
    (seal,) = rig.queue.kind("segment_seal")
    assert start.run_id == end.run_id == seal.run_id == expected["run_id"]
    assert start.id_basis == expected["id_basis"]
    assert list(start.predecessors) == expected["predecessors"]
    assert list(start.branch_ids) == expected["branch_ids"]
    assert end.outcome == "completed" and end.scope_status == "ok"
    assert start.scope_id == end.scope_id and start.segment_id == end.segment_id
    assert seal.segment_id == start.segment_id and seal.terminal is True
    assert seal.seal is not None and seal.seal.seal_digest == seal_digest([])  # zero-width
    rig.check_markers()


# --- seal triggers (§3.6 table) ------------------------------------------------------------------


def test_the_root_segment_and_its_terminal_seal_at_the_outermost_exit() -> None:
    rig = Rig()
    with rig.block(CLEAR, session_id="sess-clear", user_id="user-clear", links=["l-1"]):
        first = rig.write(3)
    (start,) = rig.queue.kind("run_start")
    (end,) = rig.queue.kind("run_end")
    segment = first[0].segment_id
    assert {a.segment_id for a in first} == {segment} and start.segment_id == segment
    assert start.predecessors == ("none",) and start.id_basis == "caller"
    assert start.run_id == fabric._sequence.run_pseudonym(CLEAR, KEY)
    assert start.session_id and start.session_id.startswith("sess-")
    assert start.user_id and start.user_id.startswith("usr-")
    assert start.links == (fabric._sequence.run_pseudonym("l-1", KEY),)
    assert start.resumable is False
    assert end.segment_id == segment and end.scope_status == "ok"
    seal = rig.seal_of(segment)
    assert seal.terminal is True and seal.resumable is False
    assert seal.seal is not None and seal.seal.last_sequence == 2
    assert seal.seal.manifest_digest == NO_MANIFEST_DIGEST  # no manifest chain in this rig
    entries = [(a.sequence, "sha256:" + f"{i:064x}") for i, a in enumerate(first)]
    assert seal.seal.seal_digest == seal_digest(entries)
    rig.check_markers()


def test_resume_token_seals_resumable_and_the_next_allocation_continues() -> None:
    rig = Rig()
    with rig.block("trip") as scope:
        (before,) = rig.write()
        (token,) = rig.issue()
        (after,) = rig.write()
    parsed = parse_token(token)
    assert parsed is not None and parsed.version == 3
    assert parsed.correlation_id == fabric._sequence.run_pseudonym("trip", KEY)
    assert parsed.segment_id == before.segment_id != after.segment_id
    seal = rig.seal_of(before.segment_id)
    assert seal.terminal is False and seal.resumable is True and not seal.branch_ids
    assert seal.seal is not None and parsed.last_sequence == seal.seal.last_sequence == 0
    starts = rig.queue.kind("run_start")
    continuation = [m for m in starts if m.segment_id == after.segment_id]
    assert len(continuation) == 1 and continuation[0].scope_id == scope.scope_id
    assert continuation[0].predecessors == (parsed.entry,)  # local continuation
    assert continuation[0].last_sequence == after.sequence - 1
    # The run is now resumable: the outermost exit seals non-terminal.
    assert rig.seal_of(after.segment_id).terminal is False
    rig.check_markers()


def test_branch_tokens_list_their_branch_ids_on_the_seal() -> None:
    rig = Rig()
    with rig.block("fan-out"):
        (allocation,) = rig.write()
        tokens = rig.issue(3)
    parsed = [parse_token(t) for t in tokens]
    branches = tuple(p.branch_id for p in parsed if p is not None)
    assert len(set(branches)) == 3 and all(b and b.startswith("br-") for b in branches)
    seal = rig.seal_of(allocation.segment_id)
    assert seal.branch_ids == branches and seal.resumable is True
    assert seal.seal is not None and seal.seal.branch_ids == branches
    rig.check_markers()


def test_a_token_with_no_open_segment_seals_a_zero_width_one() -> None:
    rig = Rig()
    with rig.block("idle"):
        (first,) = rig.issue()
        (second,) = rig.issue()
    one, two = parse_token(first), parse_token(second)
    assert one is not None and two is not None and one.segment_id != two.segment_id
    starts = {m.segment_id: m for m in rig.queue.kind("run_start")}
    assert starts[two.segment_id].predecessors == (one.entry,)
    assert rig.seal_of(two.segment_id).seal.seal_digest == seal_digest([])  # type: ignore[union-attr]


def test_a_final_block_seals_a_resumable_run_terminal() -> None:
    rig = Rig()
    with rig.block("resumable", resumable=True, open_deadline_s=3600):
        (open_one,) = rig.write()
    assert rig.seal_of(open_one.segment_id).terminal is False
    (start,) = rig.queue.kind("run_start")
    assert start.resumable is True and start.open_deadline_s == 3600
    with rig.block("resumable", final=True):
        (closing,) = rig.write()
    assert rig.seal_of(closing.segment_id).terminal is True
    (reentry,) = [m for m in rig.queue.kind("run_start") if m.segment_id == closing.segment_id]
    assert reentry.predecessors[0].startswith(f"{open_one.segment_id}/")  # local continuation
    assert reentry.id_basis == "caller" and reentry.resumable is None  # root-only flag
    rig.check_markers()


def test_a_terminal_exit_without_an_open_segment_seals_a_zero_width_segment() -> None:
    rig = Rig()
    with rig.block("short") as scope:
        pass
    (seal,) = rig.queue.kind("segment_seal")
    (end,) = rig.queue.kind("run_end")
    assert seal.terminal is True and end.segment_id == seal.segment_id
    assert end.scope_id == scope.scope_id


def test_post_terminal_reentry_is_counted_and_continues_from_the_terminal() -> None:
    rig = Rig()
    with rig.block("once"):
        (first,) = rig.write()
    with rig.block("once"):
        (second,) = rig.write()
    assert rig.table.stats()["post_terminal_allocations"] == 1
    starts = {m.segment_id: m for m in rig.queue.kind("run_start")}
    assert starts[second.segment_id].predecessors[0].startswith(f"{first.segment_id}/")


def test_final_seals_every_open_segment_non_terminal() -> None:
    rig = Rig()
    with rig.block("long-running"):
        (allocation,) = rig.write()
        rig.table.on_final()
        assert rig.allocator.allocate().segment_id is None  # nothing accounted after final
    seal = rig.seal_of(allocation.segment_id)
    assert seal.terminal is False
    assert len(rig.queue.kind("segment_seal")) == 1  # the exit after final seals nothing


def test_a_forced_seal_continues_the_run_in_a_new_local_segment() -> None:
    rig = Rig(forced_at=3)
    with rig.block("huge"):
        written = rig.write(5)
    first, later = written[0].segment_id, written[-1].segment_id
    assert first != later
    assert {a.segment_id for a in written[:3]} == {first}  # the third position triggers it
    assert rig.seal_of(first).terminal is False
    assert rig.seal_of(later).terminal is True
    assert rig.table.stats()["forced_seals"] == 1
    starts = {m.segment_id: m for m in rig.queue.kind("run_start")}
    assert starts[later].predecessors[0].startswith(f"{first}/")
    rig.check_markers()


def test_a_seal_waits_for_every_outstanding_position() -> None:
    rig = Rig()
    with rig.block("slow"):
        pending = rig.allocator.allocate()
    assert rig.queue.kind("segment_seal") == []  # one position in flight
    rig.allocator.settle(pending.segment_id, pending.sequence, "loss:queue_full")
    seal = rig.seal_of(pending.segment_id)  # type: ignore[arg-type]
    assert seal.seal is not None
    assert seal.seal.seal_digest == seal_digest([(pending.sequence, "loss:queue_full")])


# --- blocks, nesting and concurrency --------------------------------------------------------------


def test_nested_blocks_of_one_run_share_its_segment_and_seal_once() -> None:
    rig = Rig()
    with rig.block("nested") as outer:
        (a,) = rig.write()
        with rig.block("nested") as inner:
            (b,) = rig.write()
        (c,) = rig.write()
    assert a.segment_id == b.segment_id == c.segment_id
    starts = rig.queue.kind("run_start")
    assert [m.scope_id for m in starts] == [outer.scope_id, inner.scope_id]
    assert starts[1].segment_id == a.segment_id and starts[1].predecessors == ()
    ends = rig.queue.kind("run_end")
    assert len(ends) == 2 and len(rig.queue.kind("segment_seal")) == 1
    rig.check_markers()


def test_asyncio_gather_and_to_thread_share_the_open_segment() -> None:
    rig = Rig()

    async def task() -> str | None:
        await asyncio.sleep(0)
        return rig.allocator.allocate().segment_id

    async def main() -> list[str | None]:
        gathered = await asyncio.gather(*(task() for _ in range(8)))
        threaded = await asyncio.gather(
            *(asyncio.to_thread(lambda: rig.allocator.allocate().segment_id) for _ in range(4))
        )
        return [*gathered, *threaded]

    with rig.block("fan-in"):
        segments = asyncio.run(main())
        copied = contextvars.copy_context()
        with ThreadPoolExecutor(2) as pool:
            in_context = pool.submit(copied.run, lambda: rig.allocator.allocate().segment_id)
            bare = pool.submit(lambda: rig.allocator.allocate().segment_id)
            segments.append(in_context.result())
            outside = bare.result()
    assert len(set(segments)) == 1 and segments[0] is not None
    assert outside is None  # a pool without a copied context runs outside the run (delta 3)


def test_concurrent_blocks_of_one_run_count_depth_across_threads() -> None:
    rig = Rig()
    barrier = threading.Barrier(4)
    seen: list[str | None] = []

    def worker() -> None:
        with rig.block("shared"):
            barrier.wait()
            seen.append(rig.write()[0].segment_id)
            barrier.wait()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(seen)) == 1
    assert len(rig.queue.kind("segment_seal")) == 1  # only the last exit was outermost
    assert rig.queue.kind("segment_seal")[0].terminal is True


# --- tokens into a run (rules 1-3 at block entry) ---------------------------------------------


def test_a_block_resumed_from_a_token_takes_its_correlation_id() -> None:
    a, b = Rig(), Rig(key=b"another-key-of-16-bytes")  # B rotated its key
    with a.block("trip"):
        a.write()
        (token,) = a.issue()
    with b.block("trip", resume=[token]):
        (resumed,) = b.write()
    (start,) = b.queue.kind("run_start")
    assert start.run_id == fabric._sequence.run_pseudonym("trip", KEY)  # A's, verbatim
    assert start.id_basis == "token" and start.predecessors == (parse_token(token).entry,)  # type: ignore[union-attr]
    assert b.seal_of(resumed.segment_id).terminal is False  # opened from a token: resumable


def test_fan_in_with_differing_runs_needs_a_caller_run_id() -> None:
    a, b, c = Rig(), Rig(), Rig()
    with a.block():
        (left,) = a.issue()
    with b.block():
        (right,) = b.issue()
    with c.block(resume=[left, right]):
        pass
    with c.block("join-run", resume=[left, right]):
        pass
    conflict, joined = c.queue.kind("run_start")
    assert conflict.id_basis == "token_conflict"
    assert conflict.run_id == min(parse_token(t).correlation_id for t in (left, right))  # type: ignore[union-attr,type-var]
    assert joined.id_basis == "caller_join"
    assert joined.run_id == fabric._sequence.run_pseudonym("join-run", KEY)


def test_malformed_tokens_are_dropped_counted_and_never_raise(
    caplog: pytest.LogCaptureFixture,
) -> None:
    rig = Rig()
    with rig.block("x", resume=["fr3/nope", "fr1/old", 42]):
        pass
    (start,) = rig.queue.kind("run_start")
    assert start.predecessors == ("none",) and start.id_basis == "caller"
    assert rig.table.stats()["tokens_rejected"] == 2
    assert COUNTERS.api_misuse == 1  # the non-string entry
    assert "fr3/nope" not in caplog.text


def test_a_token_joining_an_open_segment_seals_it_and_names_both() -> None:
    rig, other = Rig(), Rig()
    with other.block("trip"):
        (token,) = other.issue()
    with rig.block("trip") as scope:
        (local,) = rig.write()
        with rig.block("trip", resume=token):
            (joined,) = rig.write()
    assert local.segment_id != joined.segment_id
    start = next(m for m in rig.queue.kind("run_start") if m.segment_id == joined.segment_id)
    assert start.predecessors[0].startswith(f"{local.segment_id}/")
    assert start.predecessors[1] == parse_token(token).entry  # type: ignore[union-attr]
    assert scope.closed


# --- the run outcome (D30) ------------------------------------------------------------------------


def test_the_outermost_run_end_carries_the_last_outcome() -> None:
    rig = Rig()
    with rig.block("outcome") as outer:
        with rig.block("outcome"):
            assert rig.table.set_outcome("failed", "error", None)
        assert rig.table.set_outcome("completed", "goal_reached", "outcome")  # mapped
    inner_end, outer_end = rig.queue.kind("run_end")
    assert inner_end.outcome is None and inner_end.stop_reason is None
    assert outer_end.scope_id == outer.scope_id
    assert outer_end.outcome == "completed" and outer_end.stop_reason == "goal_reached"
    assert rig.table.set_outcome("completed", None, None) is False  # no open run
    rig.check_markers()


def test_a_raising_block_reports_its_scope_status() -> None:
    rig = Rig()
    with pytest.raises(KeyError), rig.block("raises") as scope:
        raise KeyError("x")
    with pytest.raises(asyncio.CancelledError), rig.block("cancelled"):
        raise asyncio.CancelledError
    error, cancelled = rig.queue.kind("run_end")
    assert error.scope_id == scope.scope_id and error.scope_status == "error"
    assert cancelled.scope_status == "cancelled"


# --- privacy canaries --------------------------------------------------------------------------


def _text(markers: list[Marker]) -> str:
    return json.dumps([marker_doc(m) for m in markers])


def test_a_clear_run_id_never_reaches_a_marker_or_a_token() -> None:
    rig = Rig()
    rig.table.set_environment("env-run-CANARY-55", None)
    with rig.block(CLEAR, parent_run_id="parent-CANARY", resumed_from="older-CANARY"):
        rig.write()
        tokens = rig.issue(2)
    with rig.block():  # FABRIC_RUN_ID joins this one
        rig.write()
        tokens += rig.issue()
    text = _text(rig.queue.markers) + " ".join(tokens)
    assert "CANARY" not in text
    baggage = "fabric.resume=" + "%2C".join(tokens)
    assert "CANARY" not in baggage
    assert all(
        parse_token(t) is not None
        for t in split_tokens(baggage.split("=", 1)[1], carrier="baggage")
    )


def test_clear_mode_emits_the_clear_id_and_carries_it_in_the_token() -> None:
    rig = Rig(mode="clear")
    with rig.block("clear-run-1"):
        (token,) = rig.issue()
    with rig.block("orders/42"):
        (hashed,) = rig.issue()
    assert parse_token(token).correlation_id == "clear-run-1"  # type: ignore[union-attr]
    assert parse_token(hashed).correlation_id.startswith("h-")  # type: ignore[union-attr]


# --- fail-open and strict (R9) -------------------------------------------------------------


def test_arguments_outside_their_rules_are_dropped_as_misuse() -> None:
    rig = Rig()
    with rig.block("args", open_deadline_s=5, resumable="yes", links="not-a-list", session_id=7):
        pass
    (start,) = rig.queue.kind("run_start")
    assert start.open_deadline_s is None and start.resumable is False and start.links == ()
    assert start.session_id is None
    assert COUNTERS.api_misuse == 4


def test_the_public_api_fails_open_without_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _segments.resume_token() is None
    assert _segments.resume_tokens(2) == ()
    assert _segments.end_run(None, "completed", resume=["fr3/x"]) == "not_capturing"
    assert _segments.set_run_outcome("completed") is False
    assert _segments.resume_tokens(0) == ()
    assert _segments.end_run(None, "won", resume=[]) == "failed"  # type: ignore[arg-type]
    assert COUNTERS.api_misuse == 2
    monkeypatch.setenv(STRICT_ENV, "1")
    with pytest.raises(RecordsMisuseError):
        _segments.resume_tokens(65)
    with pytest.raises(RecordsMisuseError):
        _segments.set_run_outcome("completed", "bored")  # type: ignore[arg-type]


# --- fork hooks (driven in process; the real fork runs in test_segments_run.py) ----------------


def test_the_fork_hooks_seal_the_parent_and_declare_the_child() -> None:
    rig = Rig()
    with rig.block("forked") as scope:
        (before,) = rig.write()
        rig.table.before_fork()
        child, preds = rig.table._fork[scope.run_id]
        assert not rig.allocator._lock.acquire(blocking=False)  # held across the fork
        rig.table.after_fork_in_parent()
        assert rig.queue.kind("segment_seal")[0].segment_id == before.segment_id  # S
        (after,) = rig.write()
    starts = {m.segment_id: m for m in rig.queue.kind("run_start")}
    assert starts[after.segment_id].declared_branches == (child,)
    assert starts[after.segment_id].predecessors == preds
    assert preds[0].startswith(f"{before.segment_id}/")
    assert rig.table.stats()["fork_branches"] == 1
    rig.check_markers()


def test_the_child_continues_in_the_minted_segment_with_fresh_scope_ids() -> None:
    rig = Rig()
    with rig.block("forked") as outer, rig.block("forked") as inner:
        (before,) = rig.write()
        old_scopes = (outer.scope_id, inner.scope_id)
        rig.table.before_fork()
        child, preds = rig.table._fork[outer.run_id]
        rig.allocator._lock = threading.Lock()  # what _sequence's child hook does
        rig.allocator.epoch, rig.allocator._next = rig.allocator.epoch + 1, 0
        rig.table.after_fork_in_child()
        assert (outer.scope_id, inner.scope_id) != old_scopes
        assert all(s not in old_scopes for s in (outer.scope_id, inner.scope_id))
        (in_child,) = rig.write()
        assert in_child.segment_id == child
    starts = [m for m in rig.queue.kind("run_start") if m.segment_id == child]
    assert [m.scope_id for m in starts] == [inner.scope_id, outer.scope_id]
    assert starts[0].predecessors == preds and starts[1].predecessors == ()
    assert starts[0].last_sequence == -1
    seal = rig.seal_of(child)
    assert seal.terminal is False  # a fork child's inherited block exit is non-terminal
    assert before.segment_id not in {m.segment_id for m in rig.queue.kind("segment_seal")}
    rig.check_markers()


def test_a_fork_outside_any_run_changes_nothing() -> None:
    rig = Rig()
    rig.table.before_fork()
    rig.table.after_fork_in_parent()
    rig.table.after_fork_in_child()
    assert rig.queue.markers == [] and rig.table.stats()["fork_branches"] == 0


def test_an_epoch_change_seals_the_open_segment_and_continues() -> None:
    rig = Rig()
    with rig.block("long"):
        (first,) = rig.write()
        rig.allocator.seal()  # final: the epoch ends, later positions use a new one
        (second,) = rig.write()
    assert first.segment_id != second.segment_id and first.epoch != second.epoch
    assert rig.seal_of(first.segment_id).terminal is False
    assert rig.seal_of(first.segment_id).epoch == first.epoch
    assert rig.seal_of(second.segment_id).terminal is True


# --- edges ---------------------------------------------------------------------------------------


def test_the_protocol_block_hooks_take_the_emitted_run_id() -> None:
    rig = Rig()
    with run_scope("fabric-run", emitted="r-" + "5" * 32) as scope:
        rig.table.on_block_enter(scope)
        rig.write()
        rig.table.on_block_exit(scope)
    (start,) = rig.queue.kind("run_start")
    assert start.run_id == "r-" + "5" * 32 and start.id_basis == "caller"


def test_unknown_scopes_and_a_closed_table_account_nothing() -> None:
    rig = Rig()
    with run_scope("fabric-run", emitted="r-" + "6" * 32):
        assert rig.allocator.allocate().segment_id is None  # a scope the table never saw
    with rig.block("closing") as scope:
        rig.table.on_final()
        assert rig.table.issue(scope, 0) == ()
        assert rig.table.end(None, "completed", [], None) == "not_capturing"
        assert rig.table.set_outcome("completed", None, None) is False
    unbound = SegmentTable()
    assert not unbound.active and unbound.get("r-x") is None
    unbound.on_final()
    with run_scope("fabric-run", emitted="r-" + "7" * 32) as other:
        unbound.exit(other)
        unbound.enter(unbound.prepare("x"), other)


def test_joins_are_bounded() -> None:
    rig = Rig()
    tokens: list[str] = []
    for _ in range(70):
        with rig.block():
            tokens += rig.issue()
    assert len({parse_token(t).correlation_id for t in tokens}) == 70  # type: ignore[union-attr]
    links = [f"link-{n}" for n in range(20)]
    with rig.block("join", resume=tokens, links=links):
        pass
    start = rig.queue.kind("run_start")[-1]
    assert len(start.predecessors) == 64 and start.id_basis == "caller_join"
    assert rig.table.stats()["predecessors_dropped"] == 6
    rig.check_markers()


def test_environment_intake_never_raises() -> None:
    _segments.intake_environment(None, {"FABRIC_RUN_ID": "x"})
    rig = Rig()
    rig.table.set_environment(None, ["fr3/bad"])
    with rig.block():
        pass
    with rig.block():  # consumed once
        pass
    assert rig.table.stats()["tokens_rejected"] == 1
