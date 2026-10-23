# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The segment graph (spec 050 §3.12; spec 049 §2.10): per-run graphs from run markers and
seals, the run-identity merge (``id_basis``, X49), rules G1-G10 in order, run states,
deadlines and clocks.

Input: one :class:`SegmentNode` per segment the record names (``_verify.segment_nodes``).
Output: one :class:`RunGraph` per run, keyed by its canonical run id, holding

- ``segments``: the run's present segments (sorted by segment id), then a ``missing`` node
  (state ``missing``, no predecessors) for every predecessor a present segment names that
  the record does not hold;
- ``run_state`` and ``rule``: the first G rule that fires decides the state (049 §2.10);
- ``gaps``: the gaps of that rule only. G6 (per-segment integrity: sequences, seals,
  epochs, manifests, authentication) is the verifier's and reported by ``_verify``;
- ``run_aliases`` and ``id_basis_conflicts``: the run-identity merge (below);
- ``deadline_at`` and ``open_run_deadline_s`` for a run decided by its deadline (``open``,
  ``unterminated``, ``deadline_uncertain``); ``resumable``; the one terminal segment.

**Run grouping (050 §3.12 R1).** Segments group by ``fabric.run.id``. A segment whose
``id_basis`` is ``caller_join`` merges the runs of its present predecessors into its own
run; ``legacy`` (and a segment without ``id_basis``: rev 6.4 behaviour) merges its own run
into its predecessors' run. Merging is transitive (union-find over the runs of joined
segments, visited predecessors first, so the latest joiner names the merged run). The
merged run ids are the canonical run's ``run_aliases``. Any other basis never merges: a
predecessor in another run is G1 ``segment_conflict``. A ``token_conflict`` segment is G1,
and is listed in ``id_basis_conflicts`` with its own run id and its present predecessors'.
A merged run keeps one root per merged run: G1's "more than one root" counts the roots of
each ``fabric.run.id``, and the earliest root fixes the merged run's deadline.

**Rule order (049 §2.10).** G1 conflict; G2 named predecessor missing; G3 non-root without a
predecessor entry; G4 post-terminal activity (clock-compared); G5 terminated; G7 a terminal
but G5 fails; G8 ``not_resumable_unclosed``; G9 ``open``; G10 ``unterminated``; and
``deadline_uncertain`` when the clocks cannot decide G9 against G10.

**Branch ids (049 X46).** A consumed ``br-`` id must be issued by the seal of a predecessor
the consumer names; when those predecessors are present and sealed, an id none of them issued
is G1 ``segment_conflict`` (``branch_not_issued``). A missing or unsealed issuer is G2, or
G7 (``predecessor_unsealed``) once a terminal exists.

**Declared branches before a terminal.** A declared fork child, or the consumer of an
issued ``br-`` id, that is not present fails the run only once a terminal exists (G5/G7,
``segment_missing``). Before that it is pending work of a run that is still going (LR-1
asserts a lost branch against a terminated run). A *named* predecessor that is missing (a
lost middle) is G2 in every state.

**Clocks.** Times are UTC nanoseconds. G4 compares a segment outside the terminal's closure
with the terminal by seal time (start time while unsealed) within the sum of the two
segments' declared ``clock.uncertainty_ns``: inside that window it is ``clock_uncertain``
(``unverified``). The deadline is the root ``run_start`` time plus the root's
``fabric.run.open_deadline_s``, else its manifest's ``limits.open_run_deadline_s``, else 7
days. U is the root's declared uncertainty plus the verifier's. An unknown declared
uncertainty (no manifest) counts as 0; the verifier reports the missing manifest itself.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from ._inputs import PREDECESSOR_RE
from ._report import Effect, Gap, GapType

RunState = Literal[
    "terminated", "open", "unterminated", "conflicted", "not_resumable_unclosed",
    "deadline_uncertain",
]  # fmt: skip
SegmentState = Literal["sealed", "unsealed", "missing", "conflict"]
#: The rule that decided a run state; ``clock`` is the deadline that U cannot decide.
Rule = Literal["G1", "G2", "G3", "G4", "G5", "G7", "G8", "G9", "G10", "clock"]
# The gap types §3.12 adds to the report (`run_open` has effect `info`).
P1_GAP_TYPES: tuple[str, ...] = (
    "segment_missing", "segment_conflict", "post_terminal_activity", "run_unterminated",
    "run_open", "seal_mismatch", "unsealed_segment", "unsealed_epoch", "manifest_gap",
    "clock_uncertain",
)  # fmt: skip
#: 049 decision 14: the open-run deadline when neither the root nor its manifest sets one.
DEFAULT_OPEN_RUN_DEADLINE_S = 604_800
#: 050 §3.12 ``--max-clock-uncertainty`` default (300 s).
DEFAULT_MAX_CLOCK_UNCERTAINTY_NS = 300_000_000_000
ROOT: tuple[str, ...] = ("none",)
_MERGING_BASES = frozenset({"caller_join", "legacy", None})
_NS_PER_S = 1_000_000_000
_NS_PER_US = 1_000
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class SegmentNode:
    """One segment as its opening ``run_start`` and its ``segment_seal`` describe it.

    ``branch_ids`` are the ``br-`` ids the segment *consumes* (its run_start's
    ``fabric.run.branch_ids``; the report's ``consumes_branch_ids``); ``issued_branch_ids``
    are the ids its seal *mints* (``fabric.segment.branch_ids``; the report's
    ``branch_ids``). ``resumable`` is the seal's flag, ``start_resumable`` the run_start's.
    ``last_sequence``, ``manifest_digest`` and ``sealed_ns`` are the seal's (``None`` while
    unsealed); ``start_ns`` and ``open_deadline_s`` the run_start's. ``state`` is the
    verifier's segment state; ``None`` derives ``sealed``/``unsealed`` from
    ``last_sequence``. ``clock_uncertainty_ns`` and ``manifest_open_run_deadline_s`` come
    from the manifest of the segment's source epoch."""

    segment_id: str
    run_id: str
    source_id: str
    epoch: int
    predecessors: tuple[str, ...]
    id_basis: str | None = None
    branch_ids: tuple[str, ...] = ()
    declared_branches: tuple[str, ...] = ()
    start_ns: int | None = None
    last_sequence: int | None = None  # from the seal; None while unsealed
    terminal: bool | None = None
    resumable: bool | None = None
    clock_uncertainty_ns: int | None = None
    issued_branch_ids: tuple[str, ...] = ()
    manifest_digest: str | None = None
    state: SegmentState | None = None
    start_resumable: bool | None = None
    open_deadline_s: int | None = None
    manifest_open_run_deadline_s: int | None = None
    sealed_ns: int | None = None

    @property
    def seal_state(self) -> SegmentState:
        """``state``, else ``sealed`` when the seal is known, else ``unsealed``."""
        if self.state is not None:
            return self.state
        return "unsealed" if self.last_sequence is None else "sealed"

    @property
    def is_root(self) -> bool:
        return self.predecessors == ROOT


@dataclass(frozen=True, slots=True)
class IdBasisConflict:
    """A ``token_conflict`` segment and the run ids its tokens named (the report's
    ``id_basis_conflicts[]`` item)."""

    segment_id: str
    run_ids: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {"segment_id": self.segment_id, "run_ids": list(self.run_ids)}


@dataclass(frozen=True, slots=True)
class RunGraph:
    """One run: its segments, state, aliases and the graph gaps."""

    run_id: str
    segments: tuple[SegmentNode, ...]
    run_state: RunState | None
    run_aliases: tuple[str, ...] = ()
    id_basis_conflicts: tuple[IdBasisConflict, ...] = ()
    gaps: tuple[Gap, ...] = ()
    deadline_at: datetime | None = None
    resumable: bool | None = None
    open_run_deadline_s: int | None = None
    rule: Rule | None = None  # the G rule that decided ``run_state``
    terminal_segment_id: str | None = None  # the one terminal segment, when there is one

    def member_run_ids(self) -> tuple[str, ...]:
        """The canonical run id and its aliases: every ``fabric.run.id`` of the run."""
        return (self.run_id, *self.run_aliases)


@dataclass(frozen=True, slots=True)
class Entry:
    """A parsed predecessor entry ``<seg>/<source>/<epoch>/<last_sequence>/sha256:<hex>``."""

    segment_id: str
    source_id: str
    epoch: int
    last_sequence: int
    manifest_digest: str


def parse_entry(entry: str) -> Entry | None:
    """The fields of a predecessor entry (049 §2.10, X41); ``None`` for ``none`` or junk."""
    match = PREDECESSOR_RE.fullmatch(entry)
    if match is None:
        return None
    return Entry(match["segment_id"], match["source_id"], int(match["epoch"]),
                 int(match["last_sequence"]), match["manifest_digest"])  # fmt: skip


def _entries(node: SegmentNode) -> list[Entry]:
    parsed = (parse_entry(p) for p in node.predecessors if p != "none")
    return [entry for entry in parsed if entry is not None]


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def build_run_graphs(
    segments: Sequence[SegmentNode], *, evaluated_at: datetime, clock_uncertainty_ns: int = 0,
    max_clock_uncertainty_ns: int = DEFAULT_MAX_CLOCK_UNCERTAINTY_NS,
) -> list[RunGraph]:  # fmt: skip
    """Group ``segments`` into runs and apply G1-G10: one graph per run, by run id.

    ``evaluated_at`` decides G9 against G10 (a naive datetime reads as UTC);
    ``clock_uncertainty_ns`` is the verifier's declared uncertainty, added to the root's;
    ``max_clock_uncertainty_ns`` bounds the sum. ``[]`` for a capture without segments. A
    segment id given twice keeps its first node (the verifier reports the conflict)."""
    nodes: dict[str, SegmentNode] = {}
    for node in segments:
        nodes.setdefault(node.segment_id, node)
    if not nodes:
        return []
    if evaluated_at.tzinfo is None:
        evaluated_at = evaluated_at.replace(tzinfo=UTC)
    canonical = _merge_runs(nodes)
    members: dict[str, list[SegmentNode]] = defaultdict(list)
    aliases: dict[str, set[str]] = defaultdict(set)
    for node in nodes.values():
        run_id = canonical[node.run_id]
        members[run_id].append(node)
        if node.run_id != run_id:
            aliases[run_id].add(node.run_id)
    clocks = _Clocks(_ns_of(evaluated_at), clock_uncertainty_ns, max_clock_uncertainty_ns)
    return [
        _RunBuilder(run_id, members[run_id], tuple(sorted(aliases[run_id])), nodes,
                    clocks).build()
        for run_id in sorted(members)
    ]  # fmt: skip


def _merge_runs(nodes: Mapping[str, SegmentNode]) -> dict[str, str]:
    """Run id -> canonical run id (050 §3.12 R1): ``caller_join`` pulls its predecessors'
    runs into its own; ``legacy`` (or no basis) joins its predecessors' run."""
    parent: dict[str, str] = {node.run_id: node.run_id for node in nodes.values()}

    def find(run_id: str) -> str:
        while parent[run_id] != run_id:
            parent[run_id] = parent[parent[run_id]]
            run_id = parent[run_id]
        return run_id

    def union(winner: str, loser: str) -> None:
        win, lose = find(winner), find(loser)
        if win != lose:
            parent[lose] = win

    for segment_id in _topological(nodes):
        node = nodes[segment_id]
        if node.id_basis not in _MERGING_BASES:
            continue
        for entry in _entries(node):
            predecessor = nodes.get(entry.segment_id)
            if predecessor is None or predecessor.run_id == node.run_id:
                continue
            if node.id_basis == "caller_join":
                union(node.run_id, predecessor.run_id)
            else:
                union(predecessor.run_id, node.run_id)
    return {run_id: find(run_id) for run_id in parent}


def _successors(nodes: Mapping[str, SegmentNode]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {segment_id: set() for segment_id in nodes}
    for node in nodes.values():
        for entry in _entries(node):
            if entry.segment_id in nodes:
                out[entry.segment_id].add(node.segment_id)
    return out


def _topological(nodes: Mapping[str, SegmentNode]) -> list[str]:
    """Segment ids, predecessors first (Kahn, ties by id); segments on a cycle last."""
    successors = _successors(nodes)
    indegree = dict.fromkeys(nodes, 0)
    for following in successors.values():
        for segment_id in following:
            indegree[segment_id] += 1
    ready = sorted(s for s, n in indegree.items() if n == 0)
    out: list[str] = []
    while ready:
        current = ready.pop(0)
        out.append(current)
        for successor in successors[current]:
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)
        ready.sort()
    done = set(out)
    return out + sorted(s for s in nodes if s not in done)


def _on_cycles(successors: Mapping[str, set[str]]) -> list[str]:
    """The nodes on a cycle: members of a strongly connected component of more than one
    node, or with an edge to themselves (iterative Tarjan)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    out: list[str] = []
    for start in sorted(successors):
        if start in index:
            continue
        work: list[tuple[str, list[str], int]] = [(start, sorted(successors[start]), 0)]
        index[start] = low[start] = len(index)
        stack.append(start)
        on_stack.add(start)
        while work:
            current, children, position = work[-1]
            if position < len(children):
                work[-1] = (current, children, position + 1)
                child = children[position]
                if child not in index:
                    index[child] = low[child] = len(index)
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, sorted(successors[child]), 0))
                elif child in on_stack:
                    low[current] = min(low[current], index[child])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[current])
            if low[current] != index[current]:
                continue
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == current:
                    break
            if len(component) > 1 or current in successors[current]:
                out.extend(component)
    return sorted(out)


def _ns_of(value: datetime) -> int:
    return (value - _EPOCH) // timedelta(microseconds=1) * _NS_PER_US


def _datetime_of(ns: int) -> datetime:
    return _EPOCH + timedelta(microseconds=ns // _NS_PER_US)


@dataclass(frozen=True, slots=True)
class _Clocks:
    evaluated_ns: int
    verifier_ns: int
    bound_ns: int


@dataclass(frozen=True, slots=True)
class _Decision:
    rule: Rule
    state: RunState
    gaps: tuple[Gap, ...] = ()
    deadline_at: datetime | None = None
    deadline_s: int | None = None


# --------------------------------------------------------------------------
# One run
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _RunBuilder:
    run_id: str
    members: list[SegmentNode]
    aliases: tuple[str, ...]
    everything: Mapping[str, SegmentNode]
    clocks: _Clocks
    present: dict[str, SegmentNode] = field(default_factory=dict)
    entries: dict[str, list[Entry]] = field(default_factory=dict)
    missing: dict[str, SegmentNode] = field(default_factory=dict)
    successors: dict[str, set[str]] = field(default_factory=dict)
    conflicts: list[IdBasisConflict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.members.sort(key=lambda node: node.segment_id)
        self.present = {node.segment_id: node for node in self.members}
        self.successors = _successors(self.present)
        for node in self.members:
            self.entries[node.segment_id] = _entries(node)
            for entry in self.entries[node.segment_id]:
                named = entry.segment_id
                if named not in self.everything and named not in self.missing:
                    self.missing[named] = SegmentNode(
                        named, self.run_id, entry.source_id, entry.epoch, (), state="missing"
                    )

    def build(self) -> RunGraph:
        terminals = [node for node in self.members if node.terminal]
        decision = self._decide(terminals)
        return RunGraph(
            run_id=self.run_id,
            segments=(*self.members, *(self.missing[key] for key in sorted(self.missing))),
            run_state=decision.state,
            run_aliases=self.aliases,
            id_basis_conflicts=tuple(self.conflicts),
            gaps=tuple(dict.fromkeys(decision.gaps)),
            deadline_at=decision.deadline_at,
            resumable=self._resumable(),
            open_run_deadline_s=decision.deadline_s,
            rule=decision.rule,
            terminal_segment_id=terminals[0].segment_id if len(terminals) == 1 else None,
        )

    def _decide(self, terminals: list[SegmentNode]) -> _Decision:
        """049 §2.10: the first rule that fires decides the run state."""
        conflicted: tuple[tuple[Rule, Any], ...] = (
            ("G1", self._g1), ("G2", self._g2), ("G3", self._g3), ("G4", self._g4),
        )  # fmt: skip
        for rule, check in conflicted:
            gaps = check()
            if gaps is not None:
                return _Decision(rule, "conflicted", tuple(gaps))
        if terminals:
            failures = self._g5_failures(terminals)
            if failures:
                return _Decision("G7", "conflicted", tuple(failures))
            return _Decision("G5", "terminated")
        if not self._resumable():
            return _Decision("G8", "not_resumable_unclosed")
        return self._deadline()

    def _gap(self, gap_type: GapType, effect: Effect, node: SegmentNode, reason: str) -> Gap:
        return Gap(gap_type, effect, source_id=node.source_id, source_epoch=node.epoch,
                   segment_id=node.segment_id, reason=reason)  # fmt: skip

    def _root(self) -> SegmentNode | None:
        """The run's root: its earliest root by start time. A run merged by ``caller_join``
        has one root per merged run; the earliest one fixes the deadline (the earliest
        deadline: a later segment never extends it)."""
        roots = [node for node in self.members if node.is_root]
        timed = sorted(roots, key=lambda n: (n.start_ns is None, n.start_ns or 0, n.segment_id))
        return timed[0] if timed else None

    def _resumable(self) -> bool:
        """049 §2.10 X42: a root ``run_start`` flag OR any seal flag of the run's graph."""
        return any(node.resumable or (node.is_root and node.start_resumable)
                   for node in self.members)  # fmt: skip

    # -- G1: cycles, roots, entries, branch replay, identity ------------------

    def _g1(self) -> list[Gap] | None:
        """A conflicting segment (the verifier's own G1 findings: a record above the seal,
        a second seal or source; no new gap), a ``token_conflict`` or cross-run predecessor,
        an entry that disagrees with the segment it names, two roots of one run id, a
        cycle, or a ``br-`` id consumed twice."""
        gaps = self._entry_conflicts()
        conflicting = any(node.seal_state == "conflict" for node in self.members)
        # More than one root of one run id (each merged run keeps its own root).
        roots: dict[str, list[SegmentNode]] = defaultdict(list)
        for node in self.members:
            if node.is_root:
                roots[node.run_id].append(node)
        for run_id in sorted(roots):
            if len(roots[run_id]) > 1:
                gaps.extend(self._gap("segment_conflict", "partial", node, "multiple_roots")
                            for node in roots[run_id])  # fmt: skip
        gaps.extend(self._gap("segment_conflict", "partial", self.present[segment_id], "cycle")
                    for segment_id in _on_cycles(self.successors))  # fmt: skip
        consumers: dict[str, list[SegmentNode]] = defaultdict(list)
        for node in self.members:
            for branch in dict.fromkeys(node.branch_ids):
                consumers[branch].append(node)
            gaps.extend(self._branches_not_issued(node))
        for branch in sorted(consumers):
            if len(consumers[branch]) > 1:
                gaps.extend(self._gap("segment_conflict", "partial", node, "branch_replayed")
                            for node in consumers[branch])  # fmt: skip
        return gaps if gaps or conflicting else None

    def _branches_not_issued(self, node: SegmentNode) -> list[Gap]:
        """049 X46: a consumed ``br-`` id is bound to the sealed segment that issued it, which
        the consumer names as a predecessor (its token's entry). When every predecessor it
        names is present and sealed, an id none of their seals issued is a conflict (a root
        consuming a branch id has no issuer at all). A named predecessor that is missing
        (G2), conflicting (G1) or unsealed (G7, or the run's ``unsealed_segment``) leaves
        the issuer unknown: those rules keep the run from completing."""
        if not node.branch_ids:
            return []
        named = [self.present.get(entry.segment_id) for entry in self.entries[node.segment_id]]
        if any(issuer is None or issuer.seal_state != "sealed" for issuer in named):
            return []
        issued = {branch for issuer in named if issuer is not None
                  for branch in issuer.issued_branch_ids}  # fmt: skip
        if set(node.branch_ids) <= issued:
            return []
        return [self._gap("segment_conflict", "partial", node, "branch_not_issued")]

    def _entry_conflicts(self) -> list[Gap]:
        """G1 by identity and entries: ``token_conflict`` segments, predecessors in another
        run, and entries that disagree with the segment they name."""
        gaps: list[Gap] = []
        for node in self.members:
            if node.id_basis == "token_conflict":
                gaps.append(self._gap("segment_conflict", "partial", node, "token_conflict"))
                self._list_conflict(node)
                continue
            for entry in self.entries[node.segment_id]:
                named = self.present.get(entry.segment_id)
                if named is None and entry.segment_id in self.everything:
                    gaps.append(self._gap("segment_conflict", "partial", node,
                                          "predecessor_in_other_run"))  # fmt: skip
                elif named is not None and _disagrees(entry, named):
                    gaps.append(self._gap("segment_conflict", "partial", node,
                                          "predecessor_mismatch"))  # fmt: skip
        return gaps

    def _list_conflict(self, node: SegmentNode) -> None:
        run_ids = {node.run_id}
        for entry in self.entries[node.segment_id]:
            named = self.everything.get(entry.segment_id)
            if named is not None:
                run_ids.add(named.run_id)
        if len(run_ids) > 1:
            self.conflicts.append(IdBasisConflict(node.segment_id, tuple(sorted(run_ids))))

    # -- G2, G3: missing segments ---------------------------------------------

    def _g2(self) -> list[Gap] | None:
        gaps = [self._gap("segment_missing", "partial", self.missing[segment_id],
                          "predecessor_missing")
                for segment_id in sorted(self.missing)]  # fmt: skip
        return gaps or None

    def _g3(self) -> list[Gap] | None:
        gaps = [self._gap("segment_missing", "partial", node, "no_predecessor_entry")
                for node in self.members if not node.predecessors]  # fmt: skip
        return gaps or None

    # -- G4: post-terminal activity --------------------------------------------

    def _g4(self) -> list[Gap] | None:
        """A segment continuing a terminal (certain), or one outside the terminal's closure
        that sealed (or, unsealed, started) after it, by the two segments' clocks."""
        gaps: list[Gap] = []
        for terminal in (node for node in self.members if node.terminal):
            after = self._descendants(terminal.segment_id)
            gaps.extend(self._gap("post_terminal_activity", "partial", self.present[s],
                                  "continues_terminal")
                        for s in sorted(after))  # fmt: skip
            if terminal.sealed_ns is None:
                continue
            closure = self._ancestors(terminal.segment_id)
            for node in self.members:
                if node.segment_id in closure or node.segment_id in after:
                    continue
                sealed = node.seal_state == "sealed" and node.sealed_ns is not None
                when = node.sealed_ns if sealed else node.start_ns
                if when is None:
                    continue
                window = (node.clock_uncertainty_ns or 0) + (terminal.clock_uncertainty_ns or 0)
                late = when - terminal.sealed_ns
                if late > window:
                    reason = "sealed_after_terminal" if sealed else "started_after_terminal"
                    gaps.append(self._gap("post_terminal_activity", "partial", node, reason))
                elif window > 0 and late >= -window:
                    gaps.append(self._gap("clock_uncertain", "unverified", node,
                                          "terminal_order_uncertain"))  # fmt: skip
        return gaps or None

    def _descendants(self, segment_id: str) -> set[str]:
        out: set[str] = set()
        todo = list(self.successors[segment_id])
        while todo:
            current = todo.pop()
            if current not in out and current != segment_id:
                out.add(current)
                todo.extend(self.successors[current])
        return out

    def _ancestors(self, segment_id: str) -> set[str]:
        """``segment_id`` and every present segment in its predecessor closure."""
        out = {segment_id}
        todo = [segment_id]
        while todo:
            for entry in self.entries[todo.pop()]:
                if entry.segment_id in self.present and entry.segment_id not in out:
                    out.add(entry.segment_id)
                    todo.append(entry.segment_id)
        return out

    # -- G5 / G7: termination --------------------------------------------------

    def _g5_failures(self, terminals: list[SegmentNode]) -> list[Gap]:
        """``[]`` when G5 holds for the one terminal T: every present segment is in T's
        predecessor closure or in a declared fork child's closure, all of them sealed, and
        every ``br-`` id issued in them has one present, sealed consumer. Else the G7 gaps
        (``predecessor_unsealed``: a segment of T's closure without its seal)."""
        if len(terminals) > 1:
            return [self._gap("segment_conflict", "partial", node, "multiple_terminals")
                    for node in terminals]  # fmt: skip
        closure = self._ancestors(terminals[0].segment_id)
        # 049 G5: every segment of T's predecessor closure is sealed. An ancestor whose seal
        # never arrived is reported whether or not any of its records survived.
        unsealed = [self._gap("segment_missing", "partial", self.present[segment_id],
                              "predecessor_unsealed")
                    for segment_id in sorted(closure)
                    if self.present[segment_id].seal_state != "sealed"]  # fmt: skip
        forked, gaps = self._fork_closures(closure)
        gaps[:0] = unsealed
        joined = closure | forked
        gaps.extend(self._gap("segment_missing", "partial", node, "branch_not_joined")
                    for node in self.members if node.segment_id not in joined)  # fmt: skip
        for node in self.members:
            if node.segment_id not in joined:
                continue
            for branch in node.issued_branch_ids:
                consumers = [n for n in self.members if branch in n.branch_ids]
                if not consumers:
                    gaps.append(self._gap("segment_missing", "partial", node,
                                          "branch_consumer_missing"))  # fmt: skip
                elif consumers[0].seal_state != "sealed":
                    gaps.append(self._gap("segment_missing", "partial", consumers[0],
                                          "branch_unsealed"))  # fmt: skip
        return gaps

    def _fork_closures(self, closure: set[str]) -> tuple[set[str], list[Gap]]:
        """The closures rooted at the fork children declared in ``closure`` (and, in turn,
        in those closures), and the G7 gaps of absent or unsealed fork-closure segments."""
        out: set[str] = set()
        gaps: list[Gap] = []
        seen: set[str] = set()
        todo = sorted({child for s in closure for child in self.present[s].declared_branches})
        while todo:
            child = todo.pop(0)
            if child in seen:
                continue
            seen.add(child)
            if child not in self.present:
                declarer = next(n for n in self.members if child in n.declared_branches)
                gaps.append(self._gap("segment_missing", "partial", declarer,
                                      "fork_child_missing"))  # fmt: skip
                continue
            for segment_id in sorted({child} | self._descendants(child)):
                member = self.present[segment_id]
                fresh = segment_id not in closure and segment_id not in out
                if fresh and member.seal_state != "sealed":
                    gaps.append(self._gap("segment_missing", "partial", member,
                                          "branch_unsealed"))  # fmt: skip
                out.add(segment_id)
                todo.extend(sorted(set(member.declared_branches) - seen))
        return out, gaps

    # -- G9 / G10: deadline and clocks -----------------------------------------

    def _deadline(self) -> _Decision:
        """A resumable run without a terminal: ``open`` before its deadline, ``unterminated``
        after it, ``deadline_uncertain`` when U exceeds the bound or ``evaluated_at`` lies
        within U of the deadline (049 §2.10, RR3b)."""
        root = self._root()
        if root is None or root.start_ns is None:
            # Unreachable from the verifier: G1-G3 leave a root, whose run_start has a time.
            gap = self._gap("clock_uncertain", "unverified", root or self.members[0],
                            "no_root_time")  # fmt: skip
            return _Decision("clock", "deadline_uncertain", (gap,))
        seconds = (
            root.open_deadline_s or root.manifest_open_run_deadline_s
            or DEFAULT_OPEN_RUN_DEADLINE_S
        )  # fmt: skip
        deadline_ns = root.start_ns + seconds * _NS_PER_S
        at = _datetime_of(deadline_ns)
        uncertainty = (root.clock_uncertainty_ns or 0) + self.clocks.verifier_ns
        late = self.clocks.evaluated_ns - deadline_ns
        if uncertainty > self.clocks.bound_ns:
            reason = "uncertainty_exceeds_bound"
        elif uncertainty > 0 and abs(late) <= uncertainty:
            reason = "deadline_within_uncertainty"
        elif late < 0:
            gap = self._gap("run_open", "info", root, "before_deadline")
            return _Decision("G9", "open", (gap,), at, seconds)
        else:
            gap = self._gap("run_unterminated", "partial", root, "deadline_passed")
            return _Decision("G10", "unterminated", (gap,), at, seconds)
        gap = self._gap("clock_uncertain", "unverified", root, reason)
        return _Decision("clock", "deadline_uncertain", (gap,), at, seconds)


def _disagrees(entry: Entry, named: SegmentNode) -> bool:
    """049 G1: a predecessor entry that disagrees with the segment it names: its source
    epoch always; its last sequence and manifest digest once the segment is sealed."""
    if (entry.source_id, entry.epoch) != (named.source_id, named.epoch):
        return True
    if named.last_sequence is not None and entry.last_sequence != named.last_sequence:
        return True
    return named.manifest_digest is not None and entry.manifest_digest != named.manifest_digest


__all__ = [
    "DEFAULT_MAX_CLOCK_UNCERTAINTY_NS", "DEFAULT_OPEN_RUN_DEADLINE_S", "P1_GAP_TYPES", "Entry",
    "IdBasisConflict", "Rule", "RunGraph", "RunState", "SegmentNode", "SegmentState",
    "build_run_graphs", "parse_entry",
]  # fmt: skip
