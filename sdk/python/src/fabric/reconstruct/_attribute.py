# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Effect -> tool call attribution and the four chain verdicts (spec 056 §4.2, §4.5).

A zero-code agent never tells Fabric which tool call a subprocess belongs to. The link is
derived offline from evidence the record already holds: the model exchanges and the effect
records (``exec.subprocess``, spec 053 §5.1) sit on one ordered sequence in one process.

**Open window of a tool call T.** T is issued by exchange ``X_i`` (its response holds T).
Its result is fed back by the first later exchange ``X_j`` whose request holds a result
item for T's id. The window opens at the end of ``X_i``'s span and closes at the start of
``X_j``'s span, or at the end of the run window when no ``X_j`` was captured.

**Candidates of an effect E**: the tool calls issued on E's segment and epoch, earlier in
sequence than E, whose window holds E's start time. The issuing exchange and E share one
process and one clock, so the window opens exactly at its end; the close is widened by the
epoch's declared clock uncertainty only when it is another epoch's exchange (a resumed
run) or the run window's end. An effect inside such a margin is a candidate of both
sides. Host events keep both clocks' uncertainties (``_host.py``).

**Rules**, first that applies wins (:func:`attribute_effect`):

- A0 reported: E names a parent attempt (``fabric.step.parent_id``) -> ``caused_by`` that
  attempt, ``reported``, ``certain``;
- A1 output match: E's stdout (trailing ASCII whitespace removed, at least 16 UTF-8 bytes)
  is a substring of exactly one candidate's fed-back result; with digests only, equal
  SHA-256 -> ``output_match``, ``certain``. A1 needs the output **and every candidate's
  result**; in metadata-only mode, or when either side was withheld, it does not apply
  and never falls back to a weaker match. Two or more matches stay ``ambiguous``: one
  ``output_match`` link per match, each ``tentative``;
- A2 single window: exactly one candidate -> ``sequence_bracket``, ``tentative``;
- A3 several windows: one ``ambiguous`` link per candidate, each listing them all;
- A4 no window: no link; E is listed in ``attribution.unattributed_effects``.

**S0 startup effects** (revision 11, :func:`startup_effects`): an effect with no reported
parent that the agent process ran before its first model call of the run (a lower
sequence than every exchange of the run on its epoch), with no unverified position below
it, is decided before A1-A4: it is listed in ``attribution.startup_effects``, never
attributed to a call and never a reason of the ``effects`` chain. A client library that
probes the platform at import does this in every run.

No rule ever picks the most likely of several candidates (§4.1).

**Hook programs** (spec 057 §4.3, WP7-10; field finding F2). An exec record the capture
worker classified as a listed hook program (``fabric.hook.program_label``) is not an
effect of any tool call: it is the customer's hook running around one. A0-A4 and S0 skip
it (its decision is ``hook_program``, it is never counted under ``links``, never
unattributed), so a hook can never satisfy "this tool call had an effect"; spec 057 shows
it as a hook row (``_security.py``) gating the call its window names. A tool call whose
window holds a hook program that did not block it, but no effect, stays
``none_in_window``, and the ``effects`` chain is ``partial(none_in_window)``: the call was
dispatched (its hook ran) and its effect was not where the enabled channels look (a remote
sandbox, an unhooked client). A deny that gates such a call moves it to ``control_denied``
(F5), and when no such call is left ``none_in_window`` the reason goes with it
(``_apply_security``). An exec record that is not classified (no list, or a program
the list does not name) is an effect exactly as before: Fabric never guesses by name.

**Host events** (§4.3, rules H1-H4) are joined by ``_host.py`` (WP6-05) through the
:class:`HostJoin` interface: this module composes its links and facts into the
``corroboration`` chain and the attribution summary, and never joins host events itself.

The rules read a **normalized input** (the ``input`` object of the rule fixtures under
``contracts/coverage/v1/fixtures/action-record/rules/``, whose README defines every field).
:class:`ActionReader` builds it from a verified run while the verifier holds the run's
bodies, so every fact comes from verified records and bytes. Nothing here judges the
agent: a link says how two records are related and how that was established.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from fabric import _classify
from fabric.reconstruct import _derive, _security
from fabric.reconstruct._evidence import EVIDENCE_TYPES, decode_evidence
from fabric.reconstruct._fields_model import _response_body
from fabric.reconstruct._inputs import pseudonym
from fabric.reconstruct._report import (
    LIST_MAX,
    Check,
    Gap,
    attribution_json,
    chain,
    chained_run_verdict,
    decisions_chain,
    link_counts,
    not_observed,
)
from fabric.reconstruct._stitch import (
    _decode,
    _load_json,
    _UnparsedError,
    extract_stitch_keys,
)
from fabric.reconstruct.dialects import TOOL_RESULT_FLAG
from fabric.reconstruct.dialects.tool_result import tool_results

__all__ = [
    "EFFECT_POINTS",
    "MIN_MATCH_BYTES",
    "ActionReader",
    "ActionRun",
    "Attribution",
    "Decision",
    "HostJoin",
    "HostJoiner",
    "ToolCall",
    "action_rows",
    "attribute",
    "attribute_effect",
    "candidates",
    "output_matches",
    "sha256_text",
    "startup_effects",
    "tool_calls",
]

#: Spec 056 revision 11, rule S0: an effect the process ran before its first model call.
STARTUP: Final = "S0"
#: Spec 057 WP7-10: a listed hook program, never an effect (no A rule applies).
HOOK_PROGRAM: Final = "hook_program"
#: Spec 057 WP7-13: the widest listed control network the reader enumerates to match the
#: sensor's keyed peer ids (a /16); a wider one is matched by the emitter (WP7-11), not here.
MAX_ENUMERATED_ADDRESSES: Final = 1 << 16
#: Spec 056 §4.2 A1: the shortest output that can match a result by substring.
MIN_MATCH_BYTES: Final = 16
#: The effect capture points whose records are effects (spec 056 §2 "Effect"; M2 adds the
#: remote sandbox calls of §4.4.1, attributed exactly as subprocesses).
EXEC_POINT: Final = "exec.subprocess"
REMOTE_SANDBOX_POINT: Final = "remote.sandbox"
EFFECT_POINTS: Final = frozenset({EXEC_POINT, REMOTE_SANDBOX_POINT})
#: Non-model HTTP (053 §5.4) is recorded but is not an effect in spec 056: no rule
#: attributes it to a tool call or joins a host ``connect`` to it. The action view lists
#: its requests as recorded and unattributed, so none reads as silently missing.
HTTP_POINT: Final = "http.nonmodel"
#: The body role whose text A1 compares with the tool result, per effect capture point.
OUTPUT_ROLES: Final = {EXEC_POINT: "terminal.stdout", REMOTE_SANDBOX_POINT: "remote.result"}
# The evidence type a remote sandbox record carries (§7.3.3 (k)); the action view reads it.
_SANDBOX_EVIDENCE: Final = {
    name: EVIDENCE_TYPES[name] for name in ("fabric.sandbox.observation/v1",)
}
# Trailing whitespace A1 removes: ASCII only, so the rule is the same in every language.
_TRAILING_WHITESPACE: Final = " \t\n\r\x0b\x0c"
_NOT_OBSERVED_REASONS: Final = ("channel_disabled", "no_effect_channel", "none_in_window")
# The M2 attribution summary objects the action view repeats (spec 056 §4.5).
_M2_SUMMARY: Final = ("sandbox_events_unlinked", "remote_sandbox_calls")

CallId = Callable[[str], str]


def _same(value: str) -> str:
    return value


def sha256_text(text: str) -> str:
    """``sha256:`` + hex of the text's UTF-8 bytes (A1's digest form)."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


# --------------------------------------------------------------------------
# The host join interface (spec 056 §4.3; implemented by _host.py, WP6-05)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HostJoin:
    """What the host join hands back for one run, read from the same normalized input.

    ``links``: per effect attempt uid, its ``corroborated_by`` links (H1, H2; an ambiguous
    anchor is one link per candidate). ``sensor_events``: the run report's
    ``sensor_events`` (every host event a link names, time order, with the ``part_of``
    links whose subject it is: H3 and H5 to an attempt, H4 to the run). ``counts``:
    decisions per basis (``process_anchor``, ``process_lineage``, ``sandbox_report``) and
    state, as ``attribution.links`` counts them. ``unexplained``: unexplained host event
    ids in time order (the report keeps the first 64); ``unexplained_count`` is their full
    count when ``unexplained`` holds only the first ones (``None``: ``len(unexplained)``).
    ``anchor_missing``: an effect with a pid has no resolved anchor. ``source_gap``: a
    host source does not verify for the whole run window. ``lineage_truncated``: events an
    H3 bound left unlinked. ``trace_*``: which rule decided each anchor and host event, and why each
    source is a host source (fixtures only, never reported). M2: ``sandbox_events_unlinked``
    counts sandbox-scope events no H5 link names (``None``: no event carries a scope);
    ``remote_sandbox_calls`` are ``(event_id, time_ns, margin)`` of the agent's connections
    to a declared sandbox peer while ``remote.sandbox`` is not active (``None``: no peer
    declared); ``unauthenticated``: a host source lacks the Node's stamp in the production
    profile. ``_host.attribution_join`` builds one from a ``_host.HostJoin``, and
    ``_host.host_joiner`` is the :data:`HostJoiner` for a real export."""

    links: Mapping[str, Sequence[Mapping[str, Any]]] = field(default_factory=dict)
    sensor_events: Sequence[Mapping[str, Any]] = ()
    counts: Mapping[str, Mapping[str, int]] = field(default_factory=dict)
    unexplained: Sequence[str] = ()
    unexplained_count: int | None = None
    anchor_missing: bool = False
    source_gap: bool = False
    lineage_truncated: int = 0
    trace_anchors: Mapping[str, str] = field(default_factory=dict)
    trace_host_events: Mapping[str, str] = field(default_factory=dict)
    trace_host_sources: Mapping[str, Mapping[str, Any]] | None = None
    sandbox_events_unlinked: int | None = None
    remote_sandbox_calls: Sequence[tuple[str, int, int]] | None = None
    unauthenticated: bool = False
    # Row data (ids, pids, times) of unexplained events ``sensor_events`` does not list:
    # the actions view shows them; the report does not carry them.
    unexplained_events: Sequence[Mapping[str, Any]] = ()


#: Called once per annotated run with its normalized input; ``None`` when no host source
#: is configured for the run (``corroboration`` is then ``not_observed(not_configured)``).
HostJoiner = Callable[[Mapping[str, Any]], HostJoin | None]


# --------------------------------------------------------------------------
# §4.2: tool-call windows and the A rules
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolCall:
    """One tool call of a captured response with its open window (nanoseconds)."""

    raw_id: str  # the id as the input names it (the report's p- pseudonym on a real run)
    id: str  # the link target id: call_id(raw_id)
    name: str | None
    issued: Mapping[str, Any]  # the exchange whose response holds the call
    fed: Mapping[str, Any] | None  # the first later exchange whose request holds its result
    result: Mapping[str, Any] | None  # that request's result item {id, text?, sha256?}
    open_ns: int
    close_ns: int


def _epoch(inp: Mapping[str, Any], item: Mapping[str, Any]) -> tuple[str, int]:
    agent = inp["agent"]
    return (
        str(item.get("source_id", agent["source_id"])),
        int(item.get("source_epoch", agent["source_epoch"])),
    )


def _position(inp: Mapping[str, Any], item: Mapping[str, Any]) -> tuple[Any, str, int]:
    """Segment and epoch: where sequence order is exact (spec 050 §3.3)."""
    return (item.get("segment_id", inp["run"].get("segment_id")), *_epoch(inp, item))


def tool_calls(inp: Mapping[str, Any], call_id: CallId = _same) -> list[ToolCall]:
    """Every tool call of a captured response, in issue order, with its open window.

    "Later" is sequence order on the issuing exchange's epoch; an exchange of another
    epoch (a resumed run) is later only when it starts after the issuing exchange ended,
    and is considered after every same-epoch one."""
    exchanges = sorted(
        inp["exchanges"], key=lambda x: (x["sequence"], x["start_ns"], x["exchange_id"])
    )
    fed_by: dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = defaultdict(list)
    for exchange in exchanges:
        for result in exchange.get("tool_results", ()):
            fed_by[str(result["id"])].append((exchange, result))
    window_end = int(inp["run"]["window"][1])
    calls: list[ToolCall] = []
    for exchange in exchanges:
        epoch = _epoch(inp, exchange)
        for call in exchange.get("tool_calls", ()):
            raw = str(call["id"])
            same = [
                pair for pair in fed_by.get(raw, ())
                if _epoch(inp, pair[0]) == epoch and pair[0]["sequence"] > exchange["sequence"]
            ]  # fmt: skip
            other = sorted(
                (
                    pair for pair in fed_by.get(raw, ())
                    if _epoch(inp, pair[0]) != epoch and pair[0]["start_ns"] >= exchange["end_ns"]
                ),
                key=lambda pair: (pair[0]["start_ns"], pair[0]["sequence"]),
            )  # fmt: skip
            found = (same + other)[:1]
            fed, result = found[0] if found else (None, None)
            calls.append(
                ToolCall(
                    raw_id=raw,
                    id=call_id(raw),
                    name=call.get("name") if isinstance(call.get("name"), str) else None,
                    issued=exchange,
                    fed=fed,
                    result=result,
                    open_ns=int(exchange["end_ns"]),
                    close_ns=int(fed["start_ns"]) if fed is not None else window_end,
                )
            )
    return calls


def _margin(inp: Mapping[str, Any], effect: Mapping[str, Any]) -> int:
    """The declared clock uncertainty of the effect's epoch (the window margin)."""
    value = effect.get("clock_uncertainty_ns", inp["agent"].get("clock_uncertainty_ns", 0))
    return max(int(value or 0), 0)


def candidates(
    inp: Mapping[str, Any], effect: Mapping[str, Any], calls: Sequence[ToolCall]
) -> list[ToolCall]:
    """§4.2 conditions 1-3: same segment and epoch, later in sequence than the issuing
    exchange, start inside the window widened by the clock margin on both sides."""
    margin = _margin(inp, effect)
    where = _position(inp, effect)
    start = int(effect["start_ns"])
    found = []
    for call in calls:
        if _position(inp, call.issued) != where or effect["sequence"] <= call.issued["sequence"]:
            continue
        # One process, one clock (0.11.2, spec 056 rev 8): the issuing exchange is on the
        # effect's epoch, so its end needs no margin; the close needs one only when it is
        # another epoch's exchange or the run window's end.
        same_close = call.fed is not None and _position(inp, call.fed) == where
        if call.open_ns <= start < call.close_ns + (0 if same_close else margin):
            found.append(call)
    return found


def output_matches(
    inp: Mapping[str, Any], effect: Mapping[str, Any], found: Sequence[ToolCall]
) -> list[ToolCall] | None:
    """§4.2 A1: the candidates whose fed-back result contains the effect's output, or
    ``None`` when A1 does not apply (metadata-only mode; the output or any candidate's
    result withheld). With both texts the rule is the substring test; with only digests on
    either side it is digest equality. It never falls back to a weaker match."""
    if inp.get("content_mode") == "metadata_only" or not found:
        return None
    results = [call.result for call in found]
    if any(result is None for result in results):
        return None
    texts = [result for result in results if result is not None]
    text = effect.get("stdout")
    if isinstance(text, str) and all(isinstance(r.get("text"), str) for r in texts):
        output = text.rstrip(_TRAILING_WHITESPACE)
        if len(output.encode("utf-8", "surrogatepass")) < MIN_MATCH_BYTES:
            return []
        return [call for call in found if call.result and output in call.result["text"]]
    digest = effect.get("stdout_sha256") or (sha256_text(text) if isinstance(text, str) else None)
    if digest is None or not all("text" in r or "sha256" in r for r in texts):
        return None
    return [
        call
        for call in found
        if call.result is not None
        and (call.result.get("sha256") or sha256_text(call.result["text"])) == digest
    ]


def _caused_by(
    target: str, method: str, confidence: str, state: str, pool: Sequence[str] = ()
) -> dict[str, Any]:
    link: dict[str, Any] = {
        "type": "caused_by",
        "target": {"namespace": "call", "id": target},
        "provenance": "inferred",
        "method": method,
        "confidence": confidence,
        "state": state,
    }
    if state == "ambiguous":
        link["candidates"] = list(pool)
    return link


@dataclass(frozen=True, slots=True)
class Decision:
    """Which rule decided one effect, its links and whether A1 was evaluated for it."""

    rule: str  # A0, A1, A1-ambiguous, A2, A3, A4, S0 (startup) or hook_program (057)
    links: list[dict[str, Any]]
    evaluated: bool

    @property
    def basis(self) -> str:
        if self.rule == "A0":
            return "reported"
        if self.rule in ("A4", STARTUP, HOOK_PROGRAM):
            return "none"
        return str(self.links[0]["method"])

    @property
    def state(self) -> str:
        if self.rule in ("A4", STARTUP, HOOK_PROGRAM):
            return "unresolved"
        return str(self.links[0]["state"])


def startup_effects(inp: Mapping[str, Any], effects: Iterable[Mapping[str, Any]]) -> set[str]:
    """Spec 056 revision 11: the attempt uids of the effects the agent process ran before
    its first model call of the run. An effect is one when it has no reported parent (A0
    or an explicit tool-call scope), the run has an exchange on its epoch, its sequence is
    lower than every such exchange's, and no unverified position (``effect_sequence_gaps``)
    lies below it: a lost position could have been a model call. A run with no exchange on
    the effect's epoch (a tool-worker process, rev 6) has none: there is no first call."""
    first: dict[tuple[str, int], int] = {}
    for exchange in inp.get("exchanges", ()):
        key = _epoch(inp, exchange)
        first[key] = min(first.get(key, int(exchange["sequence"])), int(exchange["sequence"]))
    lowest_gap = min((int(gap[0]) for gap in inp.get("effect_sequence_gaps", ())), default=None)
    found: set[str] = set()
    for effect in effects:
        if (effect.get("reported_parent_attempt") or effect.get("reported_parent_call")
                or effect.get("hook_program")):  # fmt: skip
            continue
        sequence = int(effect["sequence"])
        bound = first.get(_epoch(inp, effect))
        if bound is None or sequence >= bound:
            continue
        if lowest_gap is not None and lowest_gap < sequence:
            continue
        found.add(str(effect["attempt_uid"]))
    return found


def attribute_effect(
    inp: Mapping[str, Any], effect: Mapping[str, Any], calls: Sequence[ToolCall]
) -> Decision:
    """Rules A0-A4 in order for one effect. An ambiguous decision links every candidate,
    each link listing them all; no rule picks the most likely one (§4.1)."""
    parent = effect.get("reported_parent_attempt")
    if isinstance(parent, str) and parent:
        link = {
            "type": "caused_by",
            "target": {"namespace": "attempt", "id": parent},
            "provenance": "reported",
            "confidence": "certain",
            "state": "resolved",
        }
        return Decision("A0", [link], evaluated=False)
    found = candidates(inp, effect, calls)
    if not found:
        return Decision("A4", [], evaluated=False)
    matched = output_matches(inp, effect, found)
    if matched is not None and len(matched) == 1:
        link = _caused_by(matched[0].id, "output_match", "certain", "resolved")
        return Decision("A1", [link], evaluated=True)
    if matched:
        pool = [call.id for call in matched]
        # Ambiguous is never certain (§4.1): each match is a tentative candidate.
        links = [_caused_by(i, "output_match", "tentative", "ambiguous", pool) for i in pool]
        return Decision("A1-ambiguous", links, evaluated=True)
    if len(found) == 1:
        link = _caused_by(found[0].id, "sequence_bracket", "tentative", "resolved")
        return Decision("A2", [link], evaluated=matched is not None)
    pool = [call.id for call in found]
    links = [_caused_by(i, "sequence_bracket", "tentative", "ambiguous", pool) for i in pool]
    return Decision("A3", links, evaluated=matched is not None)


# --------------------------------------------------------------------------
# §4.5: one run's links, chains and attribution summary
# --------------------------------------------------------------------------


@dataclass(slots=True)
class Attribution:
    """The spec 056 result for one run: the links on each effect step of the projection,
    the report's ``sensor_events``, ``chains`` and ``attribution``, and a per-record trace
    of which rule decided (fixtures only; never reported)."""

    projection_links: dict[str, list[dict[str, Any]]]
    sensor_events: list[dict[str, Any]]
    chains: dict[str, dict[str, Any]]
    attribution: dict[str, Any]
    trace: dict[str, dict[str, Any]]
    calls: list[ToolCall] = field(default_factory=list)
    decisions: dict[str, Decision] = field(default_factory=dict)
    # Unexplained host events no ``sensor_events`` entry lists (actions view only).
    unexplained_events: list[dict[str, Any]] = field(default_factory=list)
    # Spec 057: per hook-program effect or control contact attempt uid, the tool calls
    # whose open window holds it (the §4.2 conditions; spec 057 joins them by window).
    windows: dict[str, list[str]] = field(default_factory=dict)
    # Spec 057 WP7-10 (F2): the calls in whose window an unblocked hook program ran; one of
    # them left ``none_in_window`` is what lowers the effects chain (``_apply_security``
    # re-reads it after F5 has moved denied calls to ``control_denied``).
    hook_dispatched: frozenset[str] = frozenset()

    def expected(self) -> dict[str, Any]:
        """The rule fixture ``expected`` shape of this result."""
        return {
            "projection_links": [
                {"attempt_id": uid, "links": links}
                for uid, links in self.projection_links.items() if links
            ],
            "sensor_events": self.sensor_events,
            "chains": self.chains,
            "attribution": self.attribution,
            "trace": self.trace,
        }  # fmt: skip


def _effect_channels_active(inp: Mapping[str, Any]) -> bool:
    return any(state == "active" for state in (inp.get("effect_channels") or {}).values())


def _exec_active(inp: Mapping[str, Any]) -> bool:
    return (inp.get("effect_channels") or {}).get(EXEC_POINT) == "active"


def attribute(  # noqa: PLR0912, PLR0915 - one branch per rule outcome and chain reason
    inp: Mapping[str, Any], call_id: CallId = _same, host: HostJoin | None = None
) -> Attribution:
    """Rules A0-A4 for every effect of the run, the tool calls without an effect, and the
    four chains; ``host`` is the run's host join (``None``: no host source configured).

    ``call_id`` maps the input's tool-call ids to link target ids: identity on a real run
    (the verifier already names calls by their ``p-`` pseudonym), the keyed ``p-`` v2
    pseudonym for a rule fixture (whose input holds provider ids)."""
    calls = tool_calls(inp, call_id)
    effects = sorted(inp.get("effects", ()), key=lambda e: e["sequence"])  # stable
    counts: dict[str, dict[str, int]] = {}
    trace: dict[str, dict[str, Any]] = {
        "effects": {},
        "anchors": {},
        "host_events": {},
        "tool_calls": {},
    }
    links: dict[str, list[dict[str, Any]]] = {e["attempt_uid"]: [] for e in effects}
    decisions: dict[str, Decision] = {}
    attributed: set[str] = set()
    unattributed: list[Mapping[str, Any]] = []
    startup: list[Mapping[str, Any]] = []
    before_first_call = startup_effects(inp, effects)
    evaluated = ambiguous = False
    windows: dict[str, list[str]] = {}
    dispatched: set[str] = set()  # calls in whose window an unblocked hook program ran
    for effect in effects:
        uid = effect["attempt_uid"]
        if effect.get("hook_program"):
            # Spec 057 WP7-10 (F2): a listed hook program is never an effect.
            decisions[uid] = Decision(HOOK_PROGRAM, [], evaluated=False)
            trace["effects"][uid] = HOOK_PROGRAM
            found = candidates(inp, effect, calls)
            windows[uid] = [call.id for call in found]
            if effect.get("hook_outcome") != "blocked":
                dispatched.update(call.id for call in found)
            continue
        if uid in before_first_call:
            # Revision 11: counted and listed, never attributed, never a chain reason.
            decisions[uid] = Decision(STARTUP, [], evaluated=False)
            trace["effects"][uid] = STARTUP
            startup.append(effect)
            continue
        decision = attribute_effect(inp, effect, calls)
        decisions[uid] = decision
        trace["effects"][uid] = decision.rule
        links[uid] += decision.links
        counts.setdefault(decision.basis, link_counts())[decision.state] += 1
        evaluated = evaluated or decision.evaluated
        ambiguous = ambiguous or decision.state == "ambiguous"
        for link in decision.links:
            attributed.update([link["target"]["id"], *link.get("candidates", ())])
        reported_call = effect.get("reported_parent_call")
        if isinstance(reported_call, str):
            # A0: the explicit tool_call() scope names the tool call it executes.
            attributed.add(call_id(reported_call))
        if decision.rule == "A4":
            unattributed.append(effect)

    sensor_events: list[dict[str, Any]] = []
    unexplained_events: list[dict[str, Any]] = []
    unexplained: Sequence[str] = ()
    unexplained_count: int | None = None
    truncated = 0
    remote_calls: Sequence[tuple[str, int, int]] = ()
    if host is not None:
        for uid, joined in host.links.items():
            links.setdefault(uid, []).extend(dict(link) for link in joined)
        for basis, by_state in host.counts.items():
            merged = counts.setdefault(basis, link_counts())
            for state, number in by_state.items():
                merged[state] = merged.get(state, 0) + int(number)
        sensor_events = [dict(event) for event in host.sensor_events]
        unexplained_events = [dict(event) for event in host.unexplained_events]
        unexplained = list(host.unexplained)
        unexplained_count = host.unexplained_count
        truncated = host.lineage_truncated
        trace["anchors"].update(host.trace_anchors)
        trace["host_events"].update(host.trace_host_events)
        if host.trace_host_sources is not None:
            trace["host_sources"] = {k: dict(v) for k, v in host.trace_host_sources.items()}
        remote_calls = tuple(host.remote_sandbox_calls or ())

    # §4.2 notes: a tool call with no attributed effect is not a gap; it is counted by why.
    # M2 (§4.4.1): a call in whose window the agent called a declared sandbox provider
    # while remote.sandbox was not active had its effect on a disabled channel. Any other
    # call's effect is a local one, on exec.subprocess: with that hook off the call is
    # channel_disabled even while remote.sandbox is active (§6.2 variant (c)).
    active = _effect_channels_active(inp)
    exec_active = _exec_active(inp)
    exec_disabled_calls = 0
    in_process = set(inp.get("in_process_tools", ()))
    not_observed_counts = dict.fromkeys(_NOT_OBSERVED_REASONS, 0)
    margin = max(int(inp["agent"].get("clock_uncertainty_ns", 0) or 0), 0)
    for call in calls:
        if call.id in attributed:
            trace["tool_calls"][call.id] = "attributed"
            continue
        sandboxed = any(
            call.open_ns - margin - other <= at < call.close_ns + margin + other
            for _, at, other in remote_calls
        )
        if sandboxed:
            reason = "channel_disabled"
        elif not exec_active:
            reason = "channel_disabled"
            exec_disabled_calls += 1
        elif call.name is not None and call.name in in_process:
            reason = "no_effect_channel"
        else:
            reason = "none_in_window"
        not_observed_counts[reason] += 1
        trace["tool_calls"][call.id] = reason
    # Spec 057 WP7-10 (F2): a call its hook program shows was dispatched, with no effect.
    hook_only = any(trace["tool_calls"].get(c.id) == "none_in_window" for c in calls
                    if c.id in dispatched)  # fmt: skip
    for contact in inp.get("control_contacts", ()):
        windows[contact["attempt_uid"]] = [call.id for call in candidates(inp, contact, calls)]

    chains = {
        "decisions": _decisions(inp),
        "actions": _actions(inp, calls),
        "effects": (
            chain(
                [
                    *(["sequence_gap"] if inp.get("effect_sequence_gaps") else []),
                    *inp.get("effect_record_gaps", ()),
                    *(["unattributed_effect"] if unattributed else []),
                    *(["ambiguous_attribution"] if ambiguous else []),
                    *(["remote_sandbox"] if remote_calls else []),
                    # Only remote.sandbox is active: a call it did not explain had its
                    # effect on the disabled exec.subprocess channel.
                    *(["channel_disabled"] if exec_disabled_calls else []),
                    *(["none_in_window"] if hook_only else []),
                ]
            )
            if active
            else not_observed(
                "channel_disabled" if inp.get("effect_channels") else "not_instrumented"
            )
        ),
        "corroboration": (
            _corroboration(host, bool(unexplained))
            if host is not None
            else not_observed("not_configured")
        ),
    }
    output_match: dict[str, str] = (
        {"state": "applied"}
        if evaluated
        else {
            "state": "not_applicable",
            "reason": (
                "privacy_policy"
                if inp.get("content_mode") == "metadata_only" or inp.get("output_withheld")
                else "not_exposed"
            ),
        }
    )
    summary = attribution_json(
        counts=counts,
        unattributed=[
            {"attempt_uid": e["attempt_uid"], "event_id": e["event_id"]} for e in unattributed
        ],
        effects_not_observed=not_observed_counts,
        output_match=output_match,
        unexplained=unexplained,
        unexplained_count=unexplained_count,
        lineage_truncated=truncated,
        startup=[{"attempt_uid": e["attempt_uid"], "event_id": e["event_id"]} for e in startup],
    )
    # M2 summary objects (§4.5): present when an event carries a sensor scope or sandbox
    # peers are declared, so M1 reports are unchanged.
    scoped = any("scope" in event for event in inp.get("host_events", ()))
    unlinked = host.sandbox_events_unlinked if host is not None else None
    if unlinked is not None or scoped:
        summary["sandbox_events_unlinked"] = {"count": unlinked or 0}
    declared_peers = host is not None and host.remote_sandbox_calls is not None
    if declared_peers or "sandbox_peers" in inp:
        summary["remote_sandbox_calls"] = {
            "count": len(remote_calls),
            "event_ids": [event_id for event_id, _, _ in remote_calls[:LIST_MAX]],
        }
    return Attribution(
        projection_links=links,
        sensor_events=sensor_events,
        chains=chains,
        attribution=summary,
        trace=trace,
        calls=calls,
        decisions=decisions,
        unexplained_events=unexplained_events,
        windows=windows,
        hook_dispatched=frozenset(dispatched),
    )


def _corroboration(host: HostJoin, unexplained: bool) -> dict[str, Any]:
    """``corroboration``: ``partial`` with its reasons; else, with a host source whose
    records lack the Node's stamp in the production profile,
    ``unverified(source_unauthenticated)`` (053 §6.2.10; partial beats unverified); else
    ``complete``."""
    reasons = [
        *(["source_gap"] if host.source_gap else []),
        *(["anchor_missing"] if host.anchor_missing else []),
        *(["unexplained_host_event"] if unexplained else []),
    ]
    if not reasons and host.unauthenticated:
        return {"verdict": "unverified", "reasons": ["source_unauthenticated"]}
    return chain(reasons)


def _decisions(inp: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"verdict": inp["exchange_verdict"]}
    if inp.get("exchange_reasons"):
        out["reasons"] = list(dict.fromkeys(inp["exchange_reasons"]))
    return out


def _actions(inp: Mapping[str, Any], calls: Sequence[ToolCall]) -> dict[str, Any]:
    """``actions``: every tool call has its result in a later captured request, or the
    run declared it outstanding at a normal end; no exchange it needs is missing."""
    if not calls:
        return not_observed()
    outstanding = set(inp.get("declared_outstanding", ()))
    missing = any(call.fed is None and call.raw_id not in outstanding for call in calls)
    return chain(
        [
            *(["tool_result_missing"] if missing else []),
            *(["exchange_gap"] if inp.get("exchange_gaps") else []),
        ]
    )


# --------------------------------------------------------------------------
# Reading a verified run (the verifier's hook, _verify._Run.build)
# --------------------------------------------------------------------------

_A_POINT = "fabric.capture.point"
_A_LIFECYCLE = "fabric.step.lifecycle_state"
_A_PARENT = "fabric.step.parent_id"
_A_HOOK_LABEL = "fabric.hook.program_label"
_A_HOOK_OUTCOME = "fabric.hook.outcome"
_A_CONTROL_KIND = "fabric.control.kind"
_A_CONTROL_LABEL = "fabric.control.engine.name"
_CONTROL_RESPONSE_ROLE = "control.exchange.response"
_MAX_EXTRACT_BYTES = 1 << 20  # the control.exchange.* role cap
_PROCESS_KEYS: Final = (
    ("pid", "fabric.process.pid"),
    ("parent_pid", "fabric.process.parent_pid"),
    ("process_start_ns", "fabric.process.start_ns"),
)
# Gaps that say an exchange the action chain needs is missing or unreadable (§4.5
# ``exchange_gap``): unparsed, a result without its call, or unreadable bytes.
_EXCHANGE_GAPS: Final = frozenset(
    {"unparsed_exchange", "unmatched_tool_call", "missing_object", "digest_mismatch", "truncated"}
)
# Gaps that leave positions of an effect channel's epoch unverified (``sequence_gap``).
_POSITION_GAPS: Final = frozenset({"sequence_gap", "loss", "tail_unverified"})
# Gaps of a records object or a segment seal that make an effect record unverifiable.
_RECORD_GAPS: Final = frozenset(
    {"missing_object", "digest_mismatch", "seal_mismatch", "unsealed_segment"}
)
_LABEL_MAX = 48
_RESPONSES_RESULTS: Final = frozenset({"function_call_output", "custom_tool_call_output"})


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _point_id(attrs: Mapping[str, Any]) -> str | None:
    value = attrs.get(_A_POINT)
    return value.split("@", 1)[0] if isinstance(value, str) else None


def _text_of(content: Any) -> str | None:
    """A tool result's content as text: a string, or the text parts of a list joined by
    newlines; ``None`` for any other shape (A1 then does not apply to it)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            part.get("text") for part in content
            if isinstance(part, Mapping) and isinstance(part.get("text"), str)
        ]  # fmt: skip
        return "\n".join(str(part) for part in parts) if parts else None
    return None


def tool_result_texts(  # noqa: PLR0912 - one branch per wire shape
    api: str, document: Any
) -> list[tuple[str, str | None]]:
    """``(provider id, result text)`` of every tool-result item of one request body:
    chat ``role: tool`` messages, Responses ``function_call_output`` items, Anthropic
    ``tool_result`` blocks."""
    out: list[tuple[str, str | None]] = []
    if not isinstance(document, Mapping):
        return out
    if api == "openai.chat_completions":
        for message in document.get("messages") or ():
            if isinstance(message, Mapping) and message.get("role") == "tool":
                call = message.get("tool_call_id")
                if isinstance(call, str) and call:
                    out.append((call, _text_of(message.get("content"))))
    elif api == "openai.responses":
        items = document.get("input")
        for item in items if isinstance(items, list) else ():
            if isinstance(item, Mapping) and item.get("type") in _RESPONSES_RESULTS:
                call = item.get("call_id")
                if isinstance(call, str) and call:
                    out.append((call, _text_of(item.get("output"))))
    elif api == "anthropic.messages":
        for message in document.get("messages") or ():
            content = message.get("content") if isinstance(message, Mapping) else None
            for block in content if isinstance(content, list) else ():
                if isinstance(block, Mapping) and block.get("type") == "tool_result":
                    call = block.get("tool_use_id")
                    if isinstance(call, str) and call:
                        out.append((call, _text_of(block.get("content"))))
    return out


def _cell(value: Any) -> str:
    if isinstance(value, Mapping) and value.get("t") == "str" and isinstance(value.get("v"), str):
        return str(value["v"])
    return "…"


def _bounded(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _LABEL_MAX else text[: _LABEL_MAX - 1] + "…"


def argv_label(data: bytes) -> str | None:
    """A short label of a ``terminal.argv`` body for the action view: the shell command
    or the argument list, whitespace collapsed and cut at 48 characters."""
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(document, Mapping):
        return None
    if document.get("form") == "shell":
        return _bounded(_cell(document.get("command")))
    args = document.get("args")
    if document.get("form") == "argv" and isinstance(args, list):
        return _bounded(" ".join(_cell(arg) for arg in args))
    return None


@dataclass(slots=True)
class ActionRun:
    """One annotated run as the ``actions`` view reads it: its normalized input (without
    output or result text) and its attribution."""

    run_id: str
    input: dict[str, Any]
    result: Attribution
    security: _security.SecurityResult | None = None


def _apply_security(result: Attribution, security: _security.SecurityResult) -> None:
    """Spec 057 §6.4 on the 056 result, in place: the fifth chain ``controls``; and, when
    it is observed, ``attribution.effects_not_observed.control_denied`` (F5: a tool call a
    deny gates, with no attributed effect where the enabled channels would have seen one,
    takes that reason instead of ``none_in_window`` or ``no_effect_channel``)."""
    result.chains["controls"] = security.chain
    if not security.observed:
        return
    counts = result.attribution["effects_not_observed"]
    counts["control_denied"] = 0
    for call_id in security.denied_calls:
        reason = result.trace["tool_calls"].get(call_id)
        if reason in ("none_in_window", "no_effect_channel"):
            counts[reason] -= 1
            counts["control_denied"] += 1
            result.trace["tool_calls"][call_id] = "control_denied"
    # Spec 057 WP7-10 (F2): the effects chain's ``none_in_window`` reason names a call a
    # hook program shows was dispatched and that still has no effect. A deny that gates
    # every such call (F5 above) leaves none: the reason goes with it, so the chain never
    # states a reason ``effects_not_observed`` does not count.
    effects = result.chains.get("effects", {})
    if "none_in_window" in effects.get("reasons", ()) and not any(
        result.trace["tool_calls"].get(call_id) == "none_in_window"
        for call_id in result.hook_dispatched
    ):
        result.chains["effects"] = chain(r for r in effects["reasons"] if r != "none_in_window")


class ActionReader:
    """The verifier's spec 056 hook: per reported run, while its bodies are in memory,
    builds the normalized input from verified records and bytes, attributes its effects,
    adds ``chains``, ``attribution`` (and with a host join ``sensor_events``) to the run's
    report entry and bounds the run verdict by the chains.

    A run is annotated when it has an effect record, a manifest row of an effect capture
    point, or a host joiner is configured. ``every_run`` (the ``actions`` view) also
    attributes every other run for display, but leaves its report entry, and so its
    verdict and the exit code, as the report command leaves it: pre-056 runs are reported
    exactly as before by both. ``links`` collects the links the step projection adds to
    effect steps; ``runs`` keeps each attributed run when ``keep_runs``. Output and result
    text never outlive the run's attribution. Across the runs it notes which host events
    some run lists or counts, so :meth:`unattributed_host_events` can name the rest."""

    def __init__(
        self,
        *,
        in_process_tools: Iterable[str] = (),
        host_joiner: HostJoiner | None = None,
        clock_uncertainty_ns: int = 0,
        every_run: bool = False,
        keep_runs: bool = False,
        classification: _classify.Classification | None = None,
        policy_digest: str | None = None,
        id_key: bytes | None = None,
        derivation: _derive.Derivation | None = None,
    ) -> None:
        # Spec 057 WP7-10/WP7-13: the capture policy's classification lists
        # (``--capture-policy``) and that policy's digest; they apply only to a run one of
        # whose manifests names the digest. Offline only: the lists never leave the reader.
        self.classification = classification
        self.policy_digest = policy_digest
        self.id_key = id_key  # keys the ``hst-`` ids of the listed control addresses
        self.in_process_tools = tuple(sorted(set(in_process_tools)))
        # Spec 057 P1: the opt-in wire derivation rules; none by default (§9.1).
        self.derivation = derivation if derivation is not None else _derive.Derivation()
        #: G16: each model call's offered grant id, by exchange id (the step projection).
        self.offered_grants: dict[str, str] = {}
        self.host_joiner = host_joiner
        self.clock_uncertainty_ns = max(int(clock_uncertainty_ns), 0)
        self.every_run = every_run
        self.keep_runs = keep_runs
        self.links: dict[str, list[dict[str, Any]]] = {}
        self.runs: list[ActionRun] = []
        # Spec 056 §4.3 "Host events in no run": per host event id, across the joined runs.
        self._host_in_run: set[str] = set()
        self._host_other_process: set[str] = set()
        self._host_out_of_scope: set[str] = set()
        self._host_event_list: list[Any] | None = None
        # Spec 056 §4.3 "One event, several runs": per host event id, every run's H4
        # ``part_of`` run link to it, with the run's attribution and report entry.
        self._run_claims: dict[str, list[tuple[str, dict[str, Any], Attribution, dict[str, Any]]]]
        self._run_claims = defaultdict(list)
        self._index: tuple[Any, _security.ControlIndex] | None = None
        self._sensor_cache: tuple[Any, dict[str, Any], dict[str, Any]] | None = None

    @property
    def declared_host_sources(self) -> tuple[str, ...]:
        """The source ids the host joiner declares (``--host-source KIND=SOURCE_ID``): host
        sources by the §7.3.3 (l) rule even with nothing in the export."""
        return tuple(getattr(self.host_joiner, "declared_ids", ()))

    def add_host_evidence(self, evidence: Any, *, production: bool, trusted: bool) -> None:
        """The host records and markers the verifier split out of the export (spec 056
        §7.3.3 (l)), handed to a host joiner that reads them (``_host.HostPlan``); a plain
        joiner callable has its own evidence, and without a joiner they are not joined."""
        add = getattr(self.host_joiner, "add_evidence", None)
        if add is not None:
            add(evidence, production=production, trusted=trusted)
            self._host_event_list = None

    def _host_configured(self) -> bool:
        if self.host_joiner is None:
            return False
        return bool(getattr(self.host_joiner, "configured", True))

    def annotate(
        self,
        report: dict[str, Any],
        run: Any,
        bodies: Mapping[str, Any],
        gaps: Sequence[Gap],
        checks: Mapping[str, Check],
    ) -> None:
        """Annotate one run's report entry (``run`` is the verifier's ``_Run``)."""
        reader = _RunReader(self, report, run, bodies)
        sec = reader.security(gaps)
        # Spec 057 §6.4: a run with a security record or an active security capture point
        # is annotated too; any other run keeps the report it had (§9.1).
        annotated = bool(reader.channels) or self._host_configured() or _security.present(sec)
        annotated = annotated or bool(sec["active_points"])
        if not (self.every_run or annotated):
            return
        inp = reader.build(gaps, checks)
        joiner = self.host_joiner if self._host_configured() else None
        host = joiner(inp) if joiner is not None else None
        if host is not None:
            self._note_host_events(host.trace_host_events)
        result = attribute(inp, host=host)
        _derive.add_rows(sec, inp, result.calls, self.derivation)
        for exchange in inp["exchanges"]:
            if isinstance(exchange.get("offered_grant_id"), str):
                self.offered_grants[exchange["exchange_id"]] = exchange["offered_grant_id"]
        if host is not None:
            self._sensor_rows(inp, result, host, reader._classification())
        security = _security.analyse(inp, result, sec, self._control_index(run.verifier))
        _apply_security(result, security)
        self._claim_run_links(report, result)
        if self.keep_runs:
            self.runs.append(ActionRun(report["run_id"], _lean(inp), result, security))
        if not annotated:
            return  # shown by the view; the report entry stays the pre-056 one
        report["chains"] = result.chains
        report["attribution"] = result.attribution
        if host is not None:
            report["sensor_events"] = result.sensor_events
        report["security_context"] = security.context
        report["verdict"] = chained_run_verdict(report["verdict"], result.chains)
        for uid, links in result.projection_links.items():
            if links:
                self.links[uid] = links
        for uid, links in security.projection_links.items():
            self.links[uid] = [*self.links.get(uid, ()), *links]

    # -- spec 057 WP7-10/WP7-13: classification of host records (offline) -------------

    def _sensor_tables(
        self, table: _classify.Classification
    ) -> tuple[dict[str, _classify.HookProgram], dict[str, _classify.ControlAddress]]:
        """The lists as the host records can be matched to them, built once: per listed
        hook ``path`` its bare SHA-256 (the sensor's ``exe_sha256``), and per listed
        control address its keyed ``hst-`` id (the sensor's peer id). A sensor never
        reports a basename or an address in clear, so ``basename`` entries match
        in-process records only, a network wider than :data:`MAX_ENUMERATED_ADDRESSES`
        is not matched here, and without the id key no address is."""
        if self._sensor_cache is None or self._sensor_cache[0] is not table:
            from fabric.reconstruct._host import peer_id  # noqa: PLC0415 - host join only

            digests = {hashlib.sha256(path.encode("utf-8", "surrogateescape")).hexdigest(): hook
                       for path, hook in table.hook_paths.items()}  # fmt: skip
            peers: dict[str, _classify.ControlAddress] = {}
            for entry in table.control_addresses if self.id_key is not None else ():
                if entry.network.num_addresses > MAX_ENUMERATED_ADDRESSES:
                    continue
                for address in entry.network:
                    found = peer_id(str(address), self.id_key)
                    if found is not None:
                        peers.setdefault(found, entry)
            self._sensor_cache = (table, digests, peers)
        return self._sensor_cache[1], self._sensor_cache[2]

    def _sensor_rows(self, inp: dict[str, Any], result: Attribution, host: Any,
                     table: _classify.Classification | None) -> None:  # fmt: skip
        """Host events of this run the customer's lists classify, added to the input for
        ``_security.analyse``: ``sensor_hooks`` (an ``exec`` whose executable digest is a
        listed hook path's, unless it is the process of an in-process effect, which is
        classified there) and ``sensor_contacts`` (a ``connect`` to a listed control
        address). A connect in the time bracket of an HTTP contact with the same label and
        kind is that contact seen twice: it is counted on the contact (``host_connects``),
        never a second row. Each row's window is every tool call open at the event's time
        (056 §4.2 by time: a host source has its own positions)."""
        if table is None:
            return
        digests, peers = self._sensor_tables(table)
        if not digests and not peers:
            return
        traced = host.trace_host_events
        outside = ("outside_run", "H4-other-process", "H4-other-lineage", "H4-earlier-process")
        anchored = {link["target"]["id"] for links in result.projection_links.values()
                    for link in links if link.get("type") == "corroborated_by"}  # fmt: skip
        margin = max(int(inp["agent"].get("clock_uncertainty_ns", 0) or 0), 0)
        contacts = inp.get("control_contacts", [])
        hooks: list[dict[str, Any]] = []
        connects: list[dict[str, Any]] = []
        for event in sorted(self._host_events(), key=lambda e: (e.time_ns, e.event_id)):
            rule = traced.get(event.event_id)
            if rule is None or rule in outside or event.result == "failed":
                continue
            row: dict[str, Any] = {
                "attempt_uid": event.event_id, "event_id": event.event_id,
                "source_id": event.source_id or event.source, "source_epoch": event.epoch or 0,
                "sequence": event.sequence or 0, "start_ns": event.time_ns, "via": event.source,
            }  # fmt: skip
            if event.event_class == "exec" and event.exe_sha256 in digests:
                if event.event_id in anchored:
                    continue
                row["hook_program"] = digests[event.exe_sha256].label
                hooks.append(row)
            elif event.event_class == "connect" and event.peer_id in peers:
                entry = peers[event.peer_id]
                same = [
                    c
                    for c in contacts
                    if c.get("label") == entry.label
                    and c["control_kind"] == entry.control_kind
                    and c["start_ns"] - margin <= event.time_ns <= c["end_ns"] + margin
                ]
                if same:
                    same[0]["host_connects"] = same[0].get("host_connects", 0) + 1
                    continue
                row.update(control_kind=entry.control_kind, label=entry.label)
                connects.append(row)
            else:
                continue
            result.windows[event.event_id] = [
                call.id
                for call in result.calls
                if call.open_ns - margin <= event.time_ns < call.close_ns + margin
            ]
        if hooks:
            inp["sensor_hooks"] = hooks
        if connects:
            inp["sensor_contacts"] = connects

    def _control_index(self, verifier: Any) -> _security.ControlIndex:
        """Every control record of the input, once per verifier (052 §4.9 rule 3)."""
        if self._index is None or self._index[0] is not verifier:
            self._index = (verifier, _security.ControlIndex.build(verifier.records))
        return self._index[1]

    def _host_events(self) -> list[Any]:
        """The host events a host joiner reads (``_host.HostPlan``), one per event id; the
        verifier hands the export's over before the first run is annotated."""
        if self._host_event_list is None:
            evidence = getattr(self.host_joiner, "evidence", None)
            events = getattr(evidence, "events", None) or ()
            self._host_event_list = list({e.event_id: e for e in events}.values())
        return self._host_event_list

    def _note_host_events(self, traced: Mapping[str, str]) -> None:
        """One run's host join (its rule per event id): an event it links, lists as
        unexplained or counts is in a run; ``H4-other-process`` is another process with
        the agent's pids, ``H4-other-lineage`` its descendant and ``H4-earlier-process`` a
        process that started before the agent; an event of its sources
        it did not trace lay in its window outside the agent's scope; ``outside_run``
        says nothing."""
        for event in self._host_events():
            rule = traced.get(event.event_id)
            if rule is None:
                self._host_out_of_scope.add(event.event_id)
            elif rule in ("H4-other-process", "H4-other-lineage", "H4-earlier-process"):
                self._host_other_process.add(event.event_id)
            elif rule != "outside_run":
                self._host_in_run.add(event.event_id)

    def _claim_run_links(self, report: dict[str, Any], result: Attribution) -> None:
        """Note every H4 ``part_of`` run link of one annotated run, per host event id."""
        for event in result.sensor_events:
            for link in event.get("links", ()):
                if link["target"]["namespace"] == "run" and link["method"] == "process_anchor":
                    claim = (report["run_id"], link, result, report)
                    self._run_claims[event["event_id"]].append(claim)

    def resolve_shared_run_links(self) -> None:
        """Spec 056 §4.3 "One event, several runs", once every run is annotated. Each run
        joins its host events alone, so when the agents' identities are not proven (no
        known start, no ``certain`` anchor) H4's pid comparison can link one process to
        more than one run: back-to-back containers report the same ``pid_ns`` and
        ``ns_pid``, and their windows overlap by the clock margins. No rule picks one: each
        such link becomes ``ambiguous`` with every claiming run as a candidate, and its
        run's ``corroboration`` is ``partial(ambiguous_attribution)``. A run whose link is
        ``certain`` (the event's start tick is the agent's known one) when no other run's
        is keeps it; the others' become ``ambiguous``."""
        for claims in self._run_claims.values():
            runs = sorted({run_id for run_id, _, _, _ in claims})
            if len(runs) == 1:  # one run's own links
                continue
            certain = {run_id for run_id, link, _, _ in claims if link["confidence"] == "certain"}
            keep = next(iter(certain)) if len(certain) == 1 else None
            for run_id, link, result, report in claims:
                if run_id == keep or link["state"] == "ambiguous":
                    continue
                link.update(confidence="tentative", state="ambiguous", candidates=runs[:64])
                counts = result.attribution["links"].setdefault("process_anchor", link_counts())
                counts["resolved"] -= 1
                counts["ambiguous"] += 1
                corroboration = result.chains["corroboration"]
                if corroboration["verdict"] != "not_observed":
                    reasons = [*corroboration.get("reasons", ()), "ambiguous_attribution"]
                    if corroboration["verdict"] == "unverified":
                        reasons = ["ambiguous_attribution"]  # partial beats unverified
                    result.chains["corroboration"] = chain(reasons)
                if "chains" in report:  # the report entry, not only the actions view
                    report["chains"] = result.chains
                    report["verdict"] = chained_run_verdict(report["verdict"], result.chains)

    def unattributed_host_events(self) -> list[dict[str, Any]] | None:
        """Spec 056 §4.3 "Host events in no run", once every run is annotated: each host
        event no run lists (linked or unexplained) or counts (sandbox-scope, unlinked),
        in time order, with its reason: ``other_process`` (inside a run's window with the
        agent's pids but another process, or its descendant), ``out_of_scope`` (inside a
        run's window, outside the agent's scope) or ``no_run`` (inside no run's window,
        the clock margins applied; every event when no run was reconstructed). ``None``
        without a host source. Captured activity is never dropped silently."""
        if not self._host_configured():
            return None
        out: list[dict[str, Any]] = []
        for event in sorted(self._host_events(), key=lambda e: (e.time_ns, e.event_id)):
            if event.event_id in self._host_in_run:
                continue
            if event.event_id in self._host_other_process:
                reason = "other_process"
            elif event.event_id in self._host_out_of_scope:
                reason = "out_of_scope"
            else:
                reason = "no_run"
            out.append({
                "event_id": event.event_id, "source": event.source,
                "event_class": event.event_class, "pid": event.pid,
                "time_ns": event.time_ns, "reason": reason,
            })  # fmt: skip
        return out


def _lean(inp: Mapping[str, Any]) -> dict[str, Any]:
    """The input without output or result text (what the view keeps)."""
    out = dict(inp)
    out["exchanges"] = [
        {**x, "tool_results": [{k: v for k, v in r.items() if k != "text"}
                               for r in x.get("tool_results", ())]}
        for x in inp.get("exchanges", ())
    ]  # fmt: skip
    out["effects"] = [{k: v for k, v in e.items() if k != "stdout"} for e in inp.get("effects", ())]
    return out


class _RunReader:
    """Builds one run's normalized input from the verifier's state (duck-typed: ``run`` is
    ``_verify._Run``, ``bodies`` its ``_Bodies`` per exchange id)."""

    def __init__(
        self, owner: ActionReader, report: Mapping[str, Any], run: Any, bodies: Mapping[str, Any]
    ) -> None:
        self.owner = owner
        self.report = report
        self.run = run
        self.verifier = run.verifier
        self.bodies = bodies
        run_ids = self.verifier.run_ids_of(run.run_id)
        self.records = sorted(
            (record for i in run_ids for record in self.verifier.run_records.get(i, ())),
            key=lambda r: (r.source_id, r.source_epoch, r.source_sequence),
        )
        self.effect_records = [
            r for r in self.records if _point_id(r.span.attributes) in EFFECT_POINTS
        ]
        self.http_records = [r for r in self.records if _point_id(r.span.attributes) == HTTP_POINT]
        # Spec 057 WP7-13: requests to a listed control endpoint (the hook labels them)
        controlled = {r.attempt_uid for r in self.http_records
                      if isinstance(r.span.attributes.get(_A_CONTROL_KIND), str)}  # fmt: skip
        self.control_records = [r for r in self.http_records if r.attempt_uid in controlled]
        self.http_records = [r for r in self.http_records if r.attempt_uid not in controlled]
        self.keys = sorted({x.source for x in run.members} | {r.source for r in self.records})
        self.channels = self._channels()
        self.withheld_privacy = False

    # -- manifests ---------------------------------------------------------------

    def _manifests(self) -> list[Any]:
        return [m for key in self.keys if key in self.verifier.sources
                for m in self.verifier.sources[key].manifests]  # fmt: skip

    def _channels(self) -> dict[str, str]:
        """Per effect capture point: ``active`` when a record of it exists or a manifest row
        says so, else the last manifest row's state (``disabled``, ...)."""
        out: dict[str, str] = {}
        for manifest in self._manifests():
            for row in manifest.document.get("capture_points", ()):
                if isinstance(row, Mapping) and row.get("id") in EFFECT_POINTS:
                    point, state = str(row["id"]), str(row.get("state"))
                    if out.get(point) != "active":
                        out[point] = "active" if state == "active" else "disabled"
        for record in self.effect_records:
            out[str(_point_id(record.span.attributes))] = "active"
        return out

    def security(self, gaps: Sequence[Gap]) -> dict[str, Any]:
        """Spec 057: the run's security records (``_security.extract``), the security
        capture points its manifests declare active, and the position gaps on the epochs
        that hold its security records (the ``controls`` chain's ``sequence_gap``)."""
        sec = _security.extract(self.records)
        active: set[str] = set()
        for manifest in self._manifests():
            for row in manifest.document.get("capture_points", ()):
                if (isinstance(row, Mapping) and row.get("id") in _security.SECURITY_POINTS
                        and row.get("state") == "active"):  # fmt: skip
                    active.add(str(row["id"]))
            # Spec 057 §6.4: a loaded classification list is an active derivation rule.
            for row in manifest.document.get("classifications", ()):
                if (isinstance(row, Mapping) and row.get("state") == "loaded"
                        and row.get("id") in _security.CLASSIFY_POINTS):  # fmt: skip
                    active.add(str(row["id"]))
        if self.run.members:  # spec 057 §6.4: a derivation rule applied to this run's calls
            active.update(self.owner.derivation.active)
        sec["active_points"] = sorted(active)
        keys = {(item["source_id"], item["source_epoch"])
                for name in ("controls", "hooks", "grants", "extensions")
                for item in sec[name]}  # fmt: skip
        if active:
            keys |= set(self.keys)  # an active point's epoch: a lost record may be one
        sec["sequence_gaps"] = [
            [g.first_sequence, g.last_sequence] for g in gaps
            if g.gap_type in _POSITION_GAPS and (g.source_id, g.source_epoch) in keys
            and g.first_sequence is not None and g.last_sequence is not None
        ]  # fmt: skip
        return sec

    def _clock(self, key: tuple[str, int]) -> int:
        declared = self.verifier._clock_uncertainty(key) if key in self.verifier.sources else None
        return int(declared or 0) + self.owner.clock_uncertainty_ns

    # -- the input -----------------------------------------------------------------

    def build(self, gaps: Sequence[Gap], checks: Mapping[str, Check]) -> dict[str, Any]:
        exchanges = self._exchanges()
        effects = self._effects()
        times = [t for x in exchanges for t in (x["start_ns"], x["end_ns"])]
        times += [t for r in self.records for t in (r.span.start_ns, r.span.end_ns)]
        first_key = self.keys[0] if self.keys else ("", 0)
        agent: dict[str, Any] = {
            "source_id": first_key[0],
            "source_epoch": first_key[1],
            "clock_uncertainty_ns": self._clock(first_key),
        }
        parents = {e["parent_pid"] for e in effects if "parent_pid" in e}
        if len(parents) == 1:
            agent["pid"] = parents.pop()  # the agent's pid at spawn (os.getpid())
        hosts = {e["host_id"] for e in effects if "host_id" in e}
        if len(hosts) == 1:
            agent["host_id"] = hosts.pop()
        record_positions = {(r.source_id, r.source_epoch, r.source_sequence) for r in self.records}
        decision_gaps = [g for g in gaps if not _record_gap(g, record_positions)]
        decisions = decisions_chain(decision_gaps, checks)
        if not exchanges and decisions["verdict"] == "complete":
            # An effects-only process (a tool worker) whose epoch verifies made no model
            # call: its decisions were not observed, never ``complete`` (§4.5). A gap keeps
            # its partial or unverified verdict: a lost position may have been a model call.
            decisions = not_observed()
        inp: dict[str, Any] = {
            "run": {
                "run_id": self.report["run_id"],
                "window": [min(times), max(times)] if times else [0, 0],
            },
            "agent": agent,
            "content_mode": self._content_mode(),
            "exchange_verdict": decisions["verdict"],
            "effect_channels": self.channels,
            "endpoint_peers": {},
            "host_sources": [],
            "exchanges": exchanges,
            "effects": effects,
            "host_events": [],
        }
        if decisions.get("reasons"):
            inp["exchange_reasons"] = decisions["reasons"]
        if self.withheld_privacy:
            # Only the effects whose output PROTECT withheld lose A1 (they carry no
            # stdout); the flag names the reason when A1 applied to no effect at all.
            inp["output_withheld"] = True
        exchange_gaps = sorted({
            g.gap_type for g in gaps
            if g.gap_type in _EXCHANGE_GAPS
            and (g.exchange_id is not None or g.gap_type == "unmatched_tool_call")
            and g.reason != "emitted_not_consumed"  # a call without its result: tool_result_missing
        })  # fmt: skip
        if exchange_gaps:
            inp["exchange_gaps"] = exchange_gaps
        effect_keys = {(e["source_id"], e["source_epoch"]) for e in effects}
        if any(self.channels.get(p) == "active" for p in EFFECT_POINTS):
            effect_keys |= set(self.keys)  # an active channel's epoch: a lost record may be one
        positions = [
            [g.first_sequence, g.last_sequence] for g in gaps
            if g.gap_type in _POSITION_GAPS and (g.source_id, g.source_epoch) in effect_keys
            and g.first_sequence is not None and g.last_sequence is not None
        ]  # fmt: skip
        if positions:
            inp["effect_sequence_gaps"] = positions
        record_gaps = self._record_gaps(gaps)
        if record_gaps:
            inp["effect_record_gaps"] = record_gaps
        if self.owner.in_process_tools:
            inp["in_process_tools"] = list(self.owner.in_process_tools)
        if self.owner.keep_runs and self.http_records:
            inp["http_requests"] = self._http_requests()  # the view only; no rule reads it
        if self.control_records:
            inp["control_contacts"] = self._control_contacts()
        return inp

    def _classification(self) -> _classify.Classification | None:
        """The reader's ``--capture-policy`` lists, when one of the run's manifests names
        that policy's digest (a list applies only to runs captured under it)."""
        table, digest = self.owner.classification, self.owner.policy_digest
        if table is None or digest is None:
            return None
        named = {(m.document.get("capture_policy") or {}).get("policy_digest")
                 for m in self._manifests()}  # fmt: skip
        return table if digest in named else None

    def _control_contacts(self) -> list[dict[str, Any]]:
        """Spec 057 §4.4 (WP7-13): one contact per request to a listed control endpoint:
        its position and time, the list's kind and label, the HTTP status and, offline
        only, the decision a configured ``decision_pointer`` and ``decision_map`` extract
        from its retained ``control.exchange.response`` body (``configured_extract``).
        Without a pointer, or when nothing maps, the decision is ``unknown``; a listed
        pointer whose body was not retained is ``body_not_retained``."""
        by_attempt: dict[str, list[Any]] = defaultdict(list)
        for record in self.control_records:
            by_attempt[record.attempt_uid].append(record)
        table = self._classification()
        out: list[dict[str, Any]] = []
        for uid, records in by_attempt.items():
            first = records[0]
            attrs = {k: v for r in records for k, v in r.span.attributes.items()}
            item: dict[str, Any] = {
                "attempt_uid": uid, "event_id": first.event_id,
                "source_id": first.source_id, "source_epoch": first.source_epoch,
                "sequence": first.source_sequence, "start_ns": first.span.start_ns,
                "end_ns": max(r.span.end_ns for r in records),
                "control_kind": str(attrs[_A_CONTROL_KIND]),
                "evidence_event_ids": [r.event_id for r in records][:8],
            }  # fmt: skip
            if first.segment_id is not None:
                item["segment_id"] = first.segment_id
            if isinstance(label := attrs.get(_A_CONTROL_LABEL), str):
                item["label"] = label
            status = next((v for r in reversed(records)
                           if (v := _int(r.span.attributes.get("http.response.status_code")))
                           is not None), None)  # fmt: skip
            if status is not None:
                item["status"] = status
            entry = self._control_entry(table, item)
            if entry is not None and entry.decision_pointer is not None:
                data = self._joined_body(records, _CONTROL_RESPONSE_ROLE)
                if data is None:
                    item["body_not_retained"] = True
                elif (decision := _extract(data, entry)) is not None:
                    item["decision"] = decision
            out.append(item)
        return out

    @staticmethod
    def _control_entry(
        table: _classify.Classification | None, item: Mapping[str, Any]
    ) -> _classify.ControlHost | None:
        """The ``control_hosts`` entry a contact names: the one entry with its label and
        kind (two entries sharing both name no single entry: nothing is extracted)."""
        if table is None:
            return None
        found = [
            e
            for e in table.control_hosts.values()
            if e.label == item.get("label") and e.control_kind == item["control_kind"]
        ]
        return found[0] if len(found) == 1 else None

    def _joined_body(self, records: Sequence[Any], role: str) -> bytes | None:
        """Every verified body of ``role`` the attempt's records carry, in record order
        (a streamed response's pieces); ``None`` when none is retained or one is not."""
        parts: list[bytes] = []
        for record in records:
            if not self._names(record, role):
                continue
            data = self._body(record, role)
            if data is None:
                return None
            parts.append(data)
        return b"".join(parts) if parts else None

    def _http_requests(self) -> list[dict[str, Any]]:
        """One row per recorded non-model HTTP request (attempt): its first record's
        position and time, the method and the last status code. Shown by the action view
        as recorded and unattributed; never attributed (``HTTP_POINT``)."""
        by_attempt: dict[str, list[Any]] = defaultdict(list)
        for record in self.http_records:
            by_attempt[record.attempt_uid].append(record)
        out: list[dict[str, Any]] = []
        for uid, records in by_attempt.items():
            first = records[0]
            item: dict[str, Any] = {
                "attempt_uid": uid, "event_id": first.event_id,
                "source_id": first.source_id, "source_epoch": first.source_epoch,
                "sequence": first.source_sequence, "start_ns": first.span.start_ns,
            }  # fmt: skip
            method = next((v for r in records
                           if isinstance(v := r.span.attributes.get("http.request.method"), str)),
                          None)  # fmt: skip
            if method is not None:
                item["method"] = method
            status = next((v for r in reversed(records)
                           if (v := _int(r.span.attributes.get("http.response.status_code")))
                           is not None), None)  # fmt: skip
            if status is not None:
                item["status"] = status
            host = next((v for r in records
                         if isinstance(v := r.span.attributes.get("fabric.network.host_id"), str)),
                        None)  # fmt: skip
            if host is not None:
                item["host_id"] = host
            out.append(item)
        return out

    def _content_mode(self) -> str:
        """The run's content mode as its manifests declare it. A body PROTECT withheld by
        policy does not make the whole run metadata-only: A1 is withheld per side."""
        if any(m.document.get("content_capture") == "metadata_only" for m in self._manifests()):
            return "metadata_only"
        return "retain_original"

    def _record_gaps(self, gaps: Sequence[Gap]) -> list[str]:
        """Gap types that make an effect record unverifiable: its own object's, or its
        segment's seal (``seal_mismatch``, ``unsealed_segment``)."""
        positions = {(r.source_id, r.source_epoch, r.source_sequence) for r in self.effect_records}
        segments = {r.segment_id for r in self.effect_records if r.segment_id is not None}
        found: list[str] = []
        for gap in gaps:
            if gap.gap_type not in _RECORD_GAPS or gap.exchange_id is not None:
                continue
            at = (gap.source_id, gap.source_epoch, gap.first_sequence)
            if at in positions or (gap.segment_id is not None and gap.segment_id in segments):
                found.append(gap.gap_type)
        return list(dict.fromkeys(found))

    # -- exchanges -------------------------------------------------------------------

    def _exchanges(self) -> list[dict[str, Any]]:
        entries = {e["exchange_id"]: e for e in self.report.get("exchanges", ())}
        out: list[dict[str, Any]] = []
        for exchange in self.run.members:
            entry = entries.get(exchange.exchange_id, {})
            item: dict[str, Any] = {
                "exchange_id": exchange.exchange_id,
                "source_id": exchange.source_id,
                "source_epoch": exchange.source_epoch,
                "sequence": exchange.source_sequence,
                "start_ns": exchange.start_ns,
                "end_ns": max(exchange.end_ns, exchange.start_ns),
            }
            if exchange.segment_id is not None:
                item["segment_id"] = exchange.segment_id
            endpoint = exchange.endpoint_id
            if isinstance(endpoint, str):
                item["endpoint_id"] = endpoint
            if isinstance(entry.get("model"), str):
                item["model"] = entry["model"]
            calls, results = self._tool_io(exchange, entry)
            item["tool_calls"], item["tool_results"] = calls, results
            if self.owner.derivation.active:
                item.update(self._derived(exchange))
            out.append(item)
        return out

    def _derived(self, exchange: Any) -> dict[str, Any]:
        """Spec 057 P1: what the derivation rules read from the exchange's verified request
        and response documents (``_derive.exchange_facts``)."""
        bodies = self.bodies.get(exchange.exchange_id)
        request: Any = getattr(bodies, "request", None)
        response: Any = getattr(bodies, "response", None)
        document: Any = None
        if _verified(request):
            try:
                document = _load_json(_decode(request.data, request.content_encoding), strict=True)
            except _UnparsedError:
                document = None
        parsed: Any = None
        stream = False
        if _verified(response):
            try:
                raw = _decode(response.data, response.content_encoding)
                parsed, stream = _response_body(exchange.api, raw, response.media_type)
            except Exception:  # an unparsed or cut response yields no row
                parsed = None
        endpoint = exchange.endpoint_id if isinstance(exchange.endpoint_id, str) else None
        return _derive.exchange_facts(
            self.owner.derivation, api=str(exchange.api), exchange_id=exchange.exchange_id,
            endpoint_id=endpoint, request=document, response=parsed, stream=stream,
            key=self.verifier.key,
        )  # fmt: skip

    def _tool_io(
        self, exchange: Any, entry: Mapping[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """The exchange's tool calls (``{id, name}``, from its verified response) and tool
        results (``{id, text?}``, from its verified request). Ids are the report's ``p-``
        pseudonyms; text is kept only for an untruncated, verified request body."""
        emitted = [i for i in entry.get("tool_call_ids_emitted", ()) if isinstance(i, str)]
        consumed = [i for i in entry.get("tool_call_ids_consumed", ()) if isinstance(i, str)]
        if not emitted and not consumed:
            return [], []
        bodies = self.bodies.get(exchange.exchange_id)
        request = getattr(bodies, "request", None)
        response = getattr(bodies, "response", None)
        names: dict[str, str | None] = {}
        if emitted and request is not None and request.data is not None:
            keys = extract_stitch_keys(
                exchange.api, request.data, request.media_type or "application/octet-stream",
                request.content_encoding, request.truncated,
                response.data if response is not None else None,
                response.media_type if response is not None else None,
                response.content_encoding if response is not None else None,
                response.truncated if response is not None else False,
                id_key=self.verifier.key,
                response_cut=exchange.response_state != "complete",
            )  # fmt: skip
            names = dict(keys.tool_calls)
        texts: dict[str, str] = {}
        flags: dict[str, bool] = {}
        if consumed and request is not None and request.data is not None and not request.truncated:
            try:
                document = _load_json(_decode(request.data, request.content_encoding))
            except _UnparsedError:
                document = None
            for raw, text in tool_result_texts(str(exchange.api), document):
                if text is not None:
                    texts.setdefault(pseudonym(raw, self.verifier.key), text)
            if self.owner.derivation.wants(TOOL_RESULT_FLAG):  # spec 057 WP7-6, F14
                for found in tool_results(str(exchange.api), document):
                    if found.is_error is not None:
                        call = pseudonym(found.call_id, self.verifier.key)
                        flags.setdefault(call, found.is_error)
        calls = [{"id": i, "name": names.get(i)} for i in emitted]
        results = [{"id": i, **({"text": texts[i]} if i in texts else {}),
                    **({"is_error": flags[i]} if i in flags else {})}
                   for i in consumed]  # fmt: skip
        return calls, results

    # -- effects ---------------------------------------------------------------------

    def _effects(self) -> list[dict[str, Any]]:
        by_attempt: dict[str, list[Any]] = defaultdict(list)
        for record in self.effect_records:
            by_attempt[record.attempt_uid].append(record)
        return [self._effect(uid, records) for uid, records in by_attempt.items()]

    def _effect(  # noqa: PLR0912 - one branch per optional effect field
        self, uid: str, records: Sequence[Any]
    ) -> dict[str, Any]:
        """One attempt's normalized effect (README §1 ``normalized_effect``): its start
        record's identity and time, the first value of each process key, the last verified
        ``terminal.stdout`` body, and a reported parent (A0) when a record names one."""
        start = next(
            (r for r in records if r.span.attributes.get(_A_LIFECYCLE) == "running"), records[0]
        )
        effect: dict[str, Any] = {
            "attempt_uid": uid,
            "event_id": start.event_id,
            "source_id": start.source_id,
            "source_epoch": start.source_epoch,
            "sequence": start.source_sequence,
            "start_ns": start.span.start_ns,
            "clock_uncertainty_ns": self._clock(start.source),
        }
        if start.segment_id is not None:
            effect["segment_id"] = start.segment_id
        for name, key in _PROCESS_KEYS:
            value = next(
                (v for r in records if (v := _int(r.span.attributes.get(key))) is not None), None
            )
            if value is not None:
                effect[name] = value
        point = _point_id(start.span.attributes)
        if point != EXEC_POINT:
            effect["capture_point"] = point  # M2: a remote.sandbox effect (no pid)
        for name, key in (("host_id", "fabric.execution.host_id"),
                          ("pid_ns", "fabric.process.pid_ns"),
                          ("created_sandbox_id", "fabric.sandbox.created_id"),
                          ("sandbox_id", "fabric.execution.sandbox_id")):  # fmt: skip
            found = next((v for r in records if isinstance(v := r.span.attributes.get(key), str)),
                         None)  # fmt: skip
            if found is not None:
                effect[name] = found
        parent = next((v for r in records if isinstance(v := r.span.attributes.get(_A_PARENT), str)
                       and v), None)  # fmt: skip
        if parent is not None:
            effect["reported_parent_attempt"] = parent
        last = records[-1].span.attributes
        for name, key in (("exit_code", "fabric.process.exit_code"),
                          ("signal", "fabric.process.signal")):  # fmt: skip
            value = _int(last.get(key))
            if value is not None:
                effect[name] = value
        # Spec 057 WP7-10: a listed hook program (the capture worker's label, never a path)
        label = next((v for r in records
                      if isinstance(v := r.span.attributes.get(_A_HOOK_LABEL), str) and v),
                     None)  # fmt: skip
        if label is not None:
            effect["hook_program"] = label
            outcome = next((v for r in reversed(records)
                            if isinstance(v := r.span.attributes.get(_A_HOOK_OUTCOME), str)),
                           None)  # fmt: skip
            if outcome is not None:
                effect["hook_outcome"] = outcome
            effect["end_ns"] = max(r.span.end_ns for r in records)
        # Spec 056 §4.3 exec chains: the hook saw the child reaped, so its pid was free, by
        # the end of the first record carrying its exit code or signal.
        exited = next((r.span.end_ns for r in records
                       if _int(r.span.attributes.get("fabric.process.exit_code")) is not None
                       or _int(r.span.attributes.get("fabric.process.signal")) is not None),
                      None)  # fmt: skip
        if exited is not None:
            effect["exit_observed_ns"] = exited
        self._stdout(effect, records, OUTPUT_ROLES.get(str(point), "terminal.stdout"))
        if self.owner.keep_runs:
            self._label(effect, start, records, point)
        return effect

    def _label(
        self, effect: dict[str, Any], start: Any, records: Sequence[Any], point: str | None
    ) -> None:
        """The action view's label: an exec's argv, a remote sandbox call's evidence."""
        if point != EXEC_POINT:
            self._sandbox_label(effect, records)
            return
        data = self._body(start, "terminal.argv")
        label = argv_label(data) if data is not None else None
        if label is not None:
            effect["label"] = label

    def _sandbox_label(self, effect: dict[str, Any], records: Sequence[Any]) -> None:
        """A remote sandbox effect's view label (§4.6: ``remote e2b commands_run exit 0``)
        from its records' ``fabric.sandbox.observation/v1`` evidence: provider and call of
        the first record whose evidence decodes, the exit code of the last that has one. For
        the view only: attribution never reads them."""
        items = [item for record in records for item in self._sandbox_items(record)]
        if not items:
            return
        effect["label"] = f"{items[0]['provider']} {items[0]['call']}"
        codes = [item["exit_code"] for item in items if "exit_code" in item]
        if codes and "exit_code" not in effect:
            effect["exit_code"] = codes[-1]

    def _sandbox_items(self, record: Any) -> list[dict[str, Any]]:
        """The items of ``record``'s verified sandbox observation, when its type schema
        accepts every item; else none."""
        if self.verifier.reader is None:
            return []
        for object_id in _object_ids(record.span.attributes):
            result = self.verifier.record_object(record, object_id)
            descriptor = result.descriptor
            if descriptor is None or descriptor.get("role") != "record.evidence":
                continue
            if result.verification != "verified":
                continue
            data = self.verifier.record_object(record, object_id, data=True).data
            if data is None:
                continue
            decoded = decode_evidence(
                bytes(data), evidence_types=_SANDBOX_EVIDENCE, provenance="observed",
                capture_point=REMOTE_SANDBOX_POINT,
            )  # fmt: skip
            if decoded.status == "ok" and not decoded.item_errors:
                return list(json.loads(bytes(data))["items"])
        return []

    def _stdout(self, effect: dict[str, Any], records: Sequence[Any], role: str) -> None:
        """The last verified body of the output role A1 compares (``terminal.stdout``, or
        ``remote.result`` for a remote sandbox call), as ``stdout``."""
        for record in reversed(records):
            if not self._names(record, role):
                continue
            data = self._body(record, role)
            if data is None:
                return
            try:
                effect["stdout"] = data.decode("utf-8")
            except UnicodeDecodeError:
                effect["stdout_sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
            return

    def _names(self, record: Any, role: str) -> bool:
        """Whether ``record`` names an object of ``role`` (descriptor read, bytes not)."""
        for object_id in _object_ids(record.span.attributes):
            result = self.verifier.record_object(record, object_id)
            if result.descriptor is not None and result.descriptor.get("role") == role:
                return True
        return False

    def _body(self, record: Any, role: str) -> bytes | None:
        """The verified bytes of ``record``'s object of ``role``; ``None`` when it is
        descriptor-only (noting a privacy-policy withholding), missing or unverified."""
        if self.verifier.reader is None:
            return None
        for object_id in _object_ids(record.span.attributes):
            result = self.verifier.record_object(record, object_id)
            descriptor = result.descriptor
            if descriptor is None or descriptor.get("role") != role:
                continue
            if result.verification == "not_stored":
                if result.reason == "privacy_policy":
                    self.withheld_privacy = True
                return None
            if result.verification != "verified":
                return None
            data = self.verifier.record_object(record, object_id, data=True).data
            return bytes(data) if data is not None else None
        return None


def _pointer(document: Any, pointer: str) -> tuple[bool, Any]:  # noqa: PLR0911 - one per RFC 6901 miss
    """RFC 6901: ``(True, value)`` at ``pointer`` in ``document``, else ``(False, None)``.
    An array index is decimal without a leading zero; ``-`` names nothing."""
    if pointer == "":
        return True, document
    if not pointer.startswith("/"):
        return False, None
    node = document
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return False, None
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                return False, None
            index = int(token)
            if index >= len(node):
                return False, None
            node = node[index]
        else:
            return False, None
    return True, node


def _extract(data: bytes, entry: _classify.ControlHost) -> str | None:
    """Spec 057 §4.4 (OD-7) offline decision extraction: the literal at the entry's JSON
    Pointer in a retained JSON response, mapped through its ``decision_map`` by exact
    type and value; ``None`` when the body is not JSON (or over 1 MiB), the pointer names
    nothing, or the literal is not mapped. No vendor parser, no text search."""
    if entry.decision_pointer is None or len(data) > _MAX_EXTRACT_BYTES:
        return None
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    found, value = _pointer(document, entry.decision_pointer)
    if not found or isinstance(value, (dict, list, float)) or value is None:
        return None
    return entry.decision_of(value)


def _verified(side: Any) -> bool:
    """An exchange side whose verified, untruncated bytes are in memory."""
    return (
        side is not None
        and side.data is not None
        and not side.truncated
        and getattr(side, "verification", "verified") == "verified"
    )


def _object_ids(attrs: Mapping[str, Any]) -> list[str]:
    value = attrs.get("fabric.content.object_ids")
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _record_gap(gap: Gap, positions: set[tuple[str, int, int]]) -> bool:
    """A gap that is provably about one records-input record's object (never about an
    exchange): it does not count against the ``decisions`` chain."""
    return (
        gap.exchange_id is None
        and gap.gap_type in ("missing_object", "digest_mismatch")
        and gap.first_sequence is not None
        and gap.first_sequence == gap.last_sequence
        and (gap.source_id, gap.source_epoch, gap.first_sequence) in positions
    )


# --------------------------------------------------------------------------
# §4.6: the action view's rows
# --------------------------------------------------------------------------


def _link_text(link: Mapping[str, Any]) -> str:
    method = link.get("method") or link.get("provenance", "")
    text = f"{method} · {link.get('confidence', '')}"
    return text + " · ambiguous" if link.get("state") == "ambiguous" else text


def action_rows(run: ActionRun) -> dict[str, Any]:  # noqa: PLR0912, PLR0915 - one per row kind
    """The ``actions`` view of one run as data: a header (chain verdicts), one row per
    model call, tool result, effect and linked host event in time order, and the
    unattributed effects, tool calls without an effect and unexplained host events. M2:
    one ``sandbox`` row per effect groups the host events rule H5 linked to it (count,
    first and last time, and each event); a remote sandbox effect's row names its capture
    point and sandbox id. It is a rendering of the report and the projection links; it
    adds no contract."""
    inp, result = run.input, run.result
    labels = {call.id: f"T{index}" for index, call in enumerate(result.calls, start=1)}
    by_raw = {call.raw_id: labels[call.id] for call in result.calls}
    names = {call.id: call.name for call in result.calls}
    fed_here: dict[str, list[str]] = defaultdict(list)  # results first fed by an exchange
    flagged: dict[str, list[str]] = defaultdict(list)  # of those, the ones with is_error
    for call in result.calls:
        if call.fed is not None:
            fed_here[call.fed["exchange_id"]].append(labels[call.id])
            if call.result is not None and call.result.get("is_error") is True:
                flagged[call.fed["exchange_id"]].append(labels[call.id])
    security = run.security
    in_force = security.call_grants if security is not None else {}
    by_raw_id = {call.raw_id: call.id for call in result.calls}
    events: list[tuple[int, int, int, dict[str, Any]]] = []
    for exchange in inp["exchanges"]:
        row: dict[str, Any] = {"kind": "model_call", "exchange_id": exchange["exchange_id"],
                               "sequence": exchange["sequence"]}  # fmt: skip
        if "model" in exchange:
            row["model"] = exchange["model"]
        if "offered_grant_id" in exchange:  # G16
            row["offered_grant_id"] = exchange["offered_grant_id"]
        fed = fed_here.get(exchange["exchange_id"], [])
        calls = []
        for c in exchange.get("tool_calls", ()):
            entry: dict[str, Any] = {"call": by_raw.get(c["id"], c["id"]), "name": c.get("name")}
            grant = in_force.get(by_raw_id.get(c["id"], c["id"]))
            if grant is not None:
                entry["grant_in_force"] = dict(grant)
            offered = exchange.get("offered_tools")
            hosted = exchange.get("hosted_tool_calls", ())
            if (isinstance(offered, list) and c["id"] not in hosted
                    and c.get("name") not in offered):  # fmt: skip
                entry["not_offered"] = True  # F12: set membership on the literal names
            calls.append(entry)
        if fed:
            row["results"] = fed
        if flagged.get(exchange["exchange_id"]):
            row["result_errors"] = flagged[exchange["exchange_id"]]
        if calls:
            row["tool_calls"] = calls
        events.append((exchange["start_ns"], 0, exchange["sequence"], row))
    for effect in inp["effects"]:
        uid = effect["attempt_uid"]
        if effect.get("hook_program"):
            continue  # spec 057 §4.3: shown as its hook row, never as an effect
        row = {"kind": "effect", "attempt_uid": uid, "event_id": effect["event_id"],
               "sequence": effect["sequence"]}  # fmt: skip
        for key in ("label", "pid", "exit_code", "signal", "capture_point", "sandbox_id",
                    "created_sandbox_id"):  # fmt: skip
            if key in effect:
                row[key] = effect[key]
        decision = result.decisions.get(uid)
        if decision is not None:
            row["rule"] = decision.rule
            row["caused_by"] = [
                {"target": labels.get(link["target"]["id"], link["target"]["id"]),
                 "namespace": link["target"]["namespace"], "link": _link_text(link)}
                for link in decision.links
            ]  # fmt: skip
        events.append((effect["start_ns"], 1, effect["sequence"], row))
    effect_rows = {row["attempt_uid"]: row for *_, row in events if row["kind"] == "effect"}
    for uid, links in result.projection_links.items():
        for link in links:
            if link["type"] == "corroborated_by" and uid in effect_rows:
                effect_rows[uid].setdefault("corroborated_by", []).append(
                    {"event_id": link["target"]["id"], "link": _link_text(link)}
                )
    unexplained = set(result.attribution["unexplained_host_events"]["event_ids"])
    created = {e["attempt_uid"]: e.get("created_sandbox_id") for e in inp["effects"]}
    sandboxes: dict[str, dict[str, Any]] = {}  # M2 (§4.6): H5 events grouped per effect
    for event in result.sensor_events:
        reported = [link for link in event.get("links", ())
                    if link.get("method") == "sandbox_report"]  # fmt: skip
        if reported:
            uid = reported[0]["target"]["id"]
            group = sandboxes.setdefault(uid, {
                "kind": "sandbox", "attempt_uid": uid, "sandbox_id": created.get(uid),
                "count": 0, "first_ns": event["time_ns"], "last_ns": event["time_ns"],
                "link": _link_text(reported[0]), "events": [],
            })  # fmt: skip
            group["count"] += 1
            group["first_ns"] = min(group["first_ns"], event["time_ns"])
            group["last_ns"] = max(group["last_ns"], event["time_ns"])
            group["events"].append({k: event[k] for k in ("event_id", "source", "event_class",
                                                          "pid", "time_ns")})  # fmt: skip
            continue
        row = {"kind": "host", "event_id": event["event_id"], "source": event["source"],
               "event_class": event["event_class"], "pid": event["pid"]}  # fmt: skip
        part_of = [{"target": link["target"]["id"], "namespace": link["target"]["namespace"],
                    "link": _link_text(link)} for link in event.get("links", ())]  # fmt: skip
        anchors = [
            {"attempt_uid": uid, "link": _link_text(link)}
            for uid, links in result.projection_links.items() for link in links
            if link["type"] == "corroborated_by" and link["target"]["id"] == event["event_id"]
        ]  # fmt: skip
        if part_of:
            row["part_of"] = part_of
        if anchors:
            row["anchors"] = anchors
        if event["event_id"] in unexplained:
            row["unexplained"] = True
        events.append((event["time_ns"], 2, 0, row))
    # Unexplained events no link names (an os.system child, a process Fabric does not
    # hook): a row each, at their time, with pid, parent pid and time (host records carry
    # no argv), so a reader sees what ran, not only a count.
    listed = {event["event_id"] for event in result.sensor_events}
    for event in result.unexplained_events:
        if event["event_id"] in listed:
            continue
        row = {"kind": "host", "event_id": event["event_id"], "source": event["source"],
               "event_class": event["event_class"], "pid": event["pid"],
               "time_ns": event["time_ns"], "unexplained": True}  # fmt: skip
        for key in ("ppid", "syscall"):
            if key in event:
                row[key] = event[key]
        events.append((event["time_ns"], 2, 0, row))
    for group in sandboxes.values():
        events.append((group["first_ns"], 3, 0, group))
    for request in inp.get("http_requests", ()):
        row = {"kind": "http", "attempt_uid": request["attempt_uid"],
               "event_id": request["event_id"], "sequence": request["sequence"],
               "attributed": False}  # fmt: skip
        for key in ("method", "status", "host_id"):
            if key in request:
                row[key] = request[key]
        events.append((request["start_ns"], 1, request["sequence"], row))
    if security is not None:
        positions = {x["exchange_id"]: (x["start_ns"], x["sequence"]) for x in inp["exchanges"]}
        events += _security.view_events(security, labels, positions)
    events.sort(key=lambda item: item[:3])
    ordered = [row for *_, row in events]
    if security is not None:
        ordered = _security.with_no_effect_rows(ordered, security, labels)
    rows: list[dict[str, Any]] = []
    preamble: list[dict[str, Any]] = []
    numbers: dict[str, int] = {}
    for row in ordered:
        # Spec 057 §6.2: grant and extension lines before the first step are a preamble.
        if not rows and row["kind"] in ("grant", "extension"):
            preamble.append(row)
            continue
        row["n"] = number = len(rows) + 1
        if row["kind"] == "effect":
            numbers[row["attempt_uid"]] = number
        rows.append(row)
    for row in rows:
        if row["kind"] == "sandbox" and row["attempt_uid"] in numbers:
            row["refs"] = [numbers[row["attempt_uid"]]]
        if row["kind"] == "host":
            refs = [numbers[a["attempt_uid"]] for a in row.get("anchors", ())
                    if a["attempt_uid"] in numbers]  # fmt: skip
            refs += [numbers[p["target"]] for p in row.get("part_of", ())
                     if p["namespace"] == "attempt" and p["target"] in numbers]  # fmt: skip
            if refs:
                row["refs"] = refs
    unattributed = [
        {k: v for k, v in effect.items() if k in ("attempt_uid", "event_id", "sequence", "label")}
        for effect in inp["effects"]
        if result.decisions.get(effect["attempt_uid"]) is not None
        and result.decisions[effect["attempt_uid"]].rule == "A4"
    ]
    startup = [
        {k: v for k, v in effect.items() if k in ("attempt_uid", "event_id", "sequence", "label")}
        for effect in inp["effects"]
        if (decision := result.decisions.get(effect["attempt_uid"])) is not None
        and decision.rule == STARTUP
    ]
    without = [
        {"call": labels[call_id], "name": names.get(call_id), "reason": reason}
        for call_id, reason in result.trace["tool_calls"].items() if reason != "attributed"
    ]  # fmt: skip
    extra: dict[str, Any] = {}
    if security is not None:
        _security.resolve_refs(rows)
        if preamble:
            extra["preamble"] = preamble
        if security.facts:
            extra["facts"] = _security.fact_rows(security, [*preamble, *rows])
    return {
        "run_id": run.run_id,
        "chains": result.chains,
        **extra,
        "rows": rows,
        "unattributed_effects": unattributed,
        **({"startup_effects": startup} if startup else {}),
        "tool_calls_without_effect": without,
        "unexplained_host_events": result.attribution["unexplained_host_events"],
        **{key: result.attribution[key] for key in _M2_SUMMARY if key in result.attribution},
        "output_match": result.attribution["output_match"],
        # Recorded by http.nonmodel, never attributed nor joined to host connects (spec
        # 056 defines no rule for it; docs/action-reconstruction.md, Known limitations).
        "http_requests_unattributed": len(inp.get("http_requests", ())),
        "complete": all(c["verdict"] in ("complete", "not_observed")
                        for c in result.chains.values()),
    }  # fmt: skip
