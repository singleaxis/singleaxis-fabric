# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The coverage report (spec 058 §12): for one deployment, what is recorded, what stays
invisible, and the one command or line that fixes each gap.

The rows come from the integration rows registry
(``contracts/coverage/v1/registry/integration-rows-v1.json``, shipped as ``_rows_data``):
questions a user asks, each with the capture points that can answer it. ``fabric plan``
predicts each row's state from what it probed (:func:`predict`, §12.3); ``fabric verify``
starts from the same prediction and replaces it with what the run's records show (§12.4,
in ``_read``). The reader's reasons are put in words by :func:`words` from the reasons
catalogue (``contracts/diagnostics/v1/reasons-v1.json``, WP8-18).

Pure functions over data: no I/O, no import of the reader or the capture path."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ._reasons_data import REASONS
from ._rows_data import ROWS

#: Switches that need no command: on with the SDK, derived by the reader, or code.
_NO_FIX = frozenset({"always", "derived", "code"})


@dataclass(frozen=True)
class Row:
    """One coverage row: the question, its state, and the evidence or the fix."""

    question: str
    state: str  # recorded | fix | needs code | invisible | partial | not observed
    note: str
    row_id: str | None = None

    def to_json(self) -> dict[str, str]:
        out = {"row": self.question, "state": self.state, "note": self.note}
        if self.row_id:
            out["id"] = self.row_id
        return out

    def line(self) -> str:
        return f"  {self.question:<46} {self.state:<12} {self.note}"


@dataclass(frozen=True)
class Context:
    """What a prediction depends on (§12.3 step 1).

    ``runtime``: ``python``, ``node`` or ``other``. ``libraries``: the agent's installed
    (or declared) distributions and packages, lower-case; ``None`` when they could not be
    read (a library condition is then assumed met). ``switches``: which switch of the
    registry is on (``capture.exec``, ``capture.http_hosts``, ``capture.mcp``,
    ``sensor``, ``env:NAME``). ``sensor_point``: the host capture point that can load
    here (``host.ebpf``, ``host.auditd``) or ``None``, with ``sensor_reason`` saying why
    not and ``sensor_note`` adding to the evidence."""

    runtime: str
    libraries: frozenset[str] | None = None
    node_major: int | None = None
    switches: Mapping[str, bool] = field(default_factory=dict)
    sensor_point: str | None = None
    sensor_reason: str | None = None
    sensor_note: str | None = None


def rows() -> list[dict[str, Any]]:
    """The registry's rows, in report order."""
    return list(ROWS["rows"])


def row(row_id: str) -> dict[str, Any]:
    return next(r for r in ROWS["rows"] if r["id"] == row_id)


def question(row_id: str) -> str:
    return str(row(row_id)["question"])


def _has(libraries: frozenset[str] | None, wanted: Iterable[str]) -> bool:
    wanted = list(wanted)
    return not wanted or libraries is None or any(name in libraries for name in wanted)


def _detected(libraries: frozenset[str] | None, wanted: Iterable[str]) -> bool:
    """Only a library actually seen: an unread package list shows no optional row."""
    return libraries is not None and any(name in libraries for name in wanted)


def _applies(point: Mapping[str, Any], ctx: Context) -> bool:
    runtime = point["runtime"]
    if runtime not in ("any", ctx.runtime):
        return False
    if point["switch"] == "sensor" and point["id"] != ctx.sensor_point:
        return False
    return _has(ctx.libraries, point.get("libraries", ()))


def _enabled(point: Mapping[str, Any], ctx: Context) -> bool:
    switch = point["switch"]
    return switch == "always" or bool(ctx.switches.get(switch))


def invisible_entry(entry: Mapping[str, Any], runtime: str) -> Mapping[str, Any]:
    items = entry["invisible"]
    return next((i for i in items if i["runtime"] == runtime),
                next((i for i in items if i["runtime"] == "*"), items[0]))  # fmt: skip


def invisible_note(entry: Mapping[str, Any], runtime: str, text: str | None = None) -> str:
    item = invisible_entry(entry, runtime)
    note = f"{item['reason']}: {text or item['text']}"
    if item.get("alternative"):
        note += f"; instead: {item['alternative']}"
    return note


def predict_row(entry: Mapping[str, Any], ctx: Context, states: Mapping[str, str]) -> Row:
    """§12.3 steps 2 and 3 for one row: the built capture points that can run here, then
    ``recorded`` (one is on), ``fix`` (one is off: its command), ``needs code`` (only a
    records API can), else ``invisible`` with the registry's reason and alternative."""
    points = [p for p in entry["capture_points"] if p["built"] and _applies(p, ctx)]
    answering = [p for p in points if not p.get("supporting")]
    on: list[str] = []
    for point in answering:
        if point["switch"] == "derived":
            if states.get(point["from_row"]) == "recorded":
                on.append(point.get("evidence") or point["id"])
        elif point["switch"] != "code" and _enabled(point, ctx):
            on.append(point.get("evidence") or point["id"])
    rid = entry["id"]
    if on:
        if entry["id"] == "host" and ctx.sensor_note:
            on.append(ctx.sensor_note)
        return Row(entry["question"], "recorded", "; ".join(dict.fromkeys(on)), rid)
    off = [p for p in answering if p["switch"] not in _NO_FIX]
    if off:
        return Row(entry["question"], "fix", str(off[0]["fix"]), rid)
    code = [p for p in answering if p["switch"] == "code"]
    if code:
        return Row(entry["question"], "needs code", str(code[0]["code"]), rid)
    derived = [p for p in answering if p["switch"] == "derived"]
    upstream = states.get(derived[0]["from_row"]) if derived else None
    if upstream in ("fix", "needs code"):
        return Row(entry["question"], upstream,
                   f"follows {question(derived[0]['from_row'])}", rid)  # fmt: skip
    if rid == "host" and ctx.sensor_reason:
        return Row(entry["question"], "invisible", ctx.sensor_reason, rid)
    return Row(entry["question"], "invisible", invisible_note(entry, ctx.runtime), rid)


def limit_rows(entry: Mapping[str, Any], ctx: Context) -> list[Row]:
    """§12.3 step 4: a library-specific limit of this runtime is its own invisible row."""
    out = []
    for limit in entry.get("limits", ()):
        if limit["runtime"] != ctx.runtime:
            continue
        if "libraries" in limit and not _detected(ctx.libraries, limit["libraries"]):
            continue
        below = limit.get("node_below")
        if below is not None and (ctx.node_major is None or ctx.node_major >= below):
            continue
        out.append(Row(limit["question"], "invisible",
                       f"{limit['reason']}: {limit['text']}; fix: {limit['fix']}",
                       f"{entry['id']}.{limit['id']}"))  # fmt: skip
    return out


def predict(ctx: Context, *, skip: Iterable[str] = ()) -> list[Row]:
    """The predicted coverage report (§12.3): every row in registry order, each with its
    limits after it. A row with ``show_libraries`` appears only when one of them is
    present; ``skip`` leaves rows out (the caller reports them its own way)."""
    skipped = set(skip)
    states: dict[str, str] = {}
    out: list[Row] = []
    for entry in rows():
        shown = entry.get("show_libraries")
        if shown and not _detected(ctx.libraries, shown):
            continue
        predicted = predict_row(entry, ctx, states)
        states[entry["id"]] = predicted.state
        if entry["id"] not in skipped:
            out.append(predicted)
        out.extend(limit_rows(entry, ctx))
    return out


def point(row_id: str, point_id: str) -> Mapping[str, Any]:
    """One capture point entry of one row."""
    return next(p for p in row(row_id)["capture_points"] if p["id"] == point_id)


# ---------------------------------------------------------------- reasons in words (WP8-18)


def _reason_index() -> dict[str, Mapping[str, Any]]:
    return {str(entry["reason"]): entry for entry in REASONS["reasons"]}


_INDEX = _reason_index()


def reason_words(reason: str, chain: str | None = None) -> tuple[str, str] | None:
    """``(text, fix)`` of ``reason``, as ``chain`` means it when the catalogue says the
    chain changes its meaning; ``None`` for a reason the catalogue does not know."""
    entry = _INDEX.get(reason)
    if entry is None:
        return None
    override = (entry.get("chains") or {}).get(chain or "")
    if override:
        return str(override["text"]), str(override["fix"])
    return str(entry["text"]), str(entry["fix"])


def known_reasons() -> frozenset[str]:
    return frozenset(_INDEX)


def note_words(name: str) -> tuple[str, str]:
    note = REASONS["notes"][name]
    return str(note["text"]), str(note["fix"])


def words(reason: str, chain: str | None = None) -> str:
    """One reason in a line: its name, what it means and its fix."""
    found = reason_words(reason, chain)
    if found is None:
        return f"{reason} (see `python -m fabric.reconstruct --json` for this reason)"
    return f"{reason}: {found[0]}; fix: {found[1]}"


def chain_reasons(run: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(chain, reason)`` of every chain of a run that is not complete, without repeats,
    in report order; the decisions chain's reasons are the run's gaps (its own)."""
    out: list[tuple[str, str]] = []
    for name, chain in (run.get("chains") or {}).items():
        if chain.get("verdict") in ("complete", "not_observed", None):
            continue
        out += [(name, str(reason)) for reason in chain.get("reasons") or ()]
    return list(dict.fromkeys(out))


def explain(reasons: Sequence[tuple[str, str]]) -> list[str]:
    """One line per reason, in words with its fix; a reason two chains share is said once
    unless a chain gives it its own meaning."""
    lines: list[str] = []
    seen: set[tuple[str, str]] = set()
    for chain, reason in reasons:
        found = reason_words(reason, chain) or (reason, "")
        if (reason, found[0]) in seen:
            continue
        seen.add((reason, found[0]))
        lines.append(f"{chain}: {words(reason, chain)}")
    return lines
