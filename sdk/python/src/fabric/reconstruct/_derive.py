# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 P1 in the reader: the opt-in wire derivation rules (WP7-4, WP7-5, WP7-6).

The rules run offline over bytes the record already holds (B2) and only when the reader is
asked to (``--derive``, ``--tool-result-markers``); a reader without them reports every
run exactly as before (§9.1). :class:`Derivation` is that choice. Per exchange,
:func:`exchange_facts` reads the verified request and response documents once (the
offered grant, the safety rows); per run, :func:`add_rows` turns them into the rows the
security analysis joins:

- ``wire.offered_grant``: one ``basis=offered`` grant snapshot for the first model call
  of a run segment and again whenever the offered digest changes (G01-G04, G07, G13-G15;
  trigger ``derived``, boundary ``llm_wire``, provenance observed), and the
  ``offered_grant_id`` of every model call (G16), so a de-duplicated snapshot still
  resolves per call. F12 reads each exchange's offered names.
- ``wire.safety_map``: one ``provider_safety`` control per map row a response yields
  (derivation ``literal``, phase ``observation``, gated kind ``model_call``, engine the
  endpoint id), joined to its model call by ``exchange_id`` (observed, certain), with the
  exchange as its evidence (D47).
- ``wire.tool_result_flag``: each tool result's structured error flag (F14, counted once
  per tool call, where it was first fed back).
- ``wire.tool_result_marker``: one control per tool result whose text a configured marker
  matches (derivation ``configured_marker``, provenance inferred, confidence certain),
  gating the call the result answers by its provider id (``provider_id``, certain), placed
  under that call and with the request that carried the result as its evidence. A result
  is matched once, where it was first fed back; a result that matches nothing gives
  nothing, never ``allow``.

Every derived control carries the two D11 constants (B5). No row is ever an evaluation of
the call: each is a literal field or the customer's own declared text (§3.8).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from fabric.reconstruct._controls import AUTHENTICATION, ENFORCED_BY_FABRIC
from fabric.reconstruct.dialects import (
    OFFERED_GRANT,
    RULES,
    SAFETY_MAP,
    TOOL_RESULT_FLAG,
    TOOL_RESULT_MARKER,
)
from fabric.reconstruct.dialects.offered_grant import offered
from fabric.reconstruct.dialects.safety_map import safety_rows
from fabric.reconstruct.dialects.tool_result import MarkerTable

__all__ = ["DERIVE_CHOICES", "Derivation", "add_rows", "exchange_facts"]

#: ``--derive`` values: one rule, or ``wire`` for the three rules that need no list.
DERIVE_CHOICES: Final = ("wire", OFFERED_GRANT, SAFETY_MAP, TOOL_RESULT_FLAG)
_WIRE_RULES: Final = frozenset({OFFERED_GRANT, SAFETY_MAP, TOOL_RESULT_FLAG})
_INVARIANTS: Final = {"fabric.control.enforced_by_fabric": ENFORCED_BY_FABRIC,
                      "fabric.control.authentication": AUTHENTICATION}  # fmt: skip


@dataclass(frozen=True, slots=True)
class Derivation:
    """The derivation rules the reader applies: ``rules`` (of ``wire.offered_grant``,
    ``wire.safety_map``, ``wire.tool_result_flag``) and the denial-marker table."""

    rules: frozenset[str] = frozenset()
    markers: MarkerTable | None = None

    @classmethod
    def build(cls, rules: Iterable[str] = (), markers: object = None) -> Derivation:
        chosen: set[str] = set()
        for rule in rules:
            chosen |= _WIRE_RULES if rule == "wire" else {rule} & _WIRE_RULES
        table = MarkerTable.load(markers) if markers is not None else None
        return cls(frozenset(chosen), table)

    @property
    def active(self) -> tuple[str, ...]:
        """The rules that apply, in manifest order (the marker rule when a marker loaded)."""
        on = set(self.rules)
        if self.markers is not None and self.markers.markers:
            on.add(TOOL_RESULT_MARKER)
        return tuple(rule for rule in RULES if rule in on)

    def wants(self, rule: str) -> bool:
        return rule in self.active

    def inputs(self) -> dict[str, Any] | None:
        """The report's ``inputs.derivation``: the rules and the marker list's digest,
        size and refusals (never a marker string); ``None`` when nothing was asked."""
        if not self.rules and self.markers is None:
            return None
        out: dict[str, Any] = {"rules": list(self.active)}
        if self.markers is not None:
            out["tool_result_markers"] = self.markers.summary()
        return out


def exchange_facts(
    derivation: Derivation, *, api: str, exchange_id: str, endpoint_id: str | None,
    request: Any, response: Any, stream: bool, key: bytes | None,
) -> dict[str, Any]:  # fmt: skip
    """What the request and response documents of one exchange give the rules (``None``
    for a side that is not a verified, parsed document). Kept on the exchange of the
    normalized input; the offered digest is used only to de-duplicate and never shown."""
    out: dict[str, Any] = {}
    if derivation.wants(OFFERED_GRANT) and request is not None:
        found = offered(api, request, exchange_id=exchange_id, endpoint_id=endpoint_id, key=key)
        if found is not None:
            choice = found.tool_choice
            out["offered"] = {
                "digest": found.digest, "count": found.count, "tool_choice": choice["mode"],
                "allowed_count": choice["allowed_count"], "parallel": choice["parallel"],
                "instructions_digest": found.document.get("instructions_digest"),
            }  # fmt: skip
            if found.grant_id is not None:
                out["offered"]["grant_id"] = found.grant_id
            out["offered_tools"] = sorted(found.names)
    if derivation.wants(SAFETY_MAP) and response is not None:
        rows = safety_rows(api, response, stream=stream)
        if rows:
            out["safety"] = [{"row": r.row_id, "signal": r.signal, "stage": r.stage,
                              "decision": r.decision,
                              **({"reason_code": r.reason_code} if r.reason_code else {})}
                             for r in rows]  # fmt: skip
    return out


def _at(item: Mapping[str, Any], uid: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "attempt_uid": uid, "event_id": uid, "source_id": item["source_id"],
        "source_epoch": item["source_epoch"], "sequence": item["sequence"],
        "start_ns": item["start_ns"], "derived": True,
    }  # fmt: skip
    if "segment_id" in item:
        out["segment_id"] = item["segment_id"]
    return out


def _derived_control(at: dict[str, Any], **fields: Any) -> dict[str, Any]:
    at.update(phase="observation", attrs=dict(_INVARIANTS), invariant_conflict=False, **fields)
    return at


def _grants(inp: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Offered snapshots: the first model call of each run segment, then each change of
    the offered digest; every exchange carries its ``offered_grant_id``."""
    out: list[dict[str, Any]] = []
    last: dict[tuple[Any, ...], tuple[str, str | None]] = {}
    exchanges = sorted(inp.get("exchanges", ()), key=lambda x: (x["start_ns"], x["sequence"]))
    for exchange in exchanges:
        found = exchange.get("offered")
        if found is None:
            continue
        grant_id = found.get("grant_id")
        if grant_id is not None:
            exchange["offered_grant_id"] = grant_id
        segment = (exchange.get("segment_id"), exchange["source_id"], exchange["source_epoch"])
        before = last.get(segment)
        if before is not None and before[0] == found["digest"]:
            continue
        last[segment] = (found["digest"], grant_id)
        item = _at(exchange, f"{exchange['exchange_id']}#offered_grant")
        item.update(basis="offered", trigger="derived", source_boundary="llm_wire",
                    provenance="observed", exchange_id=exchange["exchange_id"],
                    counts={"tools_offered": found["count"]},
                    tool_choice=found["tool_choice"])  # fmt: skip
        for name in ("allowed_count", "parallel"):
            if found.get(name) is not None:
                item[name] = found[name]
        if found.get("instructions_digest") is not None:  # G15: C20 of the same request
            item["instructions_digest"] = found["instructions_digest"]
        if grant_id is not None:
            item["id"] = grant_id
        if before is not None and before[1] is not None:
            item["previous_id"] = before[1]
        out.append(item)
    return out


def _safety(inp: Mapping[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for exchange in inp.get("exchanges", ()):
        exchange_id = str(exchange["exchange_id"])
        for n, row in enumerate(exchange.get("safety", ()), start=1):
            item = _derived_control(
                _at(exchange, f"{exchange_id}#safety.{n}"), kind="provider_safety",
                decision=row["decision"], stage=row["stage"], signal=row["signal"],
                derivation="literal", gated_kind="model_call", evidence_ref=[exchange_id],
                map_row=row["row"], view_after=exchange_id,
                preset_link={"type": "gates",
                             "target": {"namespace": "exchange", "id": exchange_id},
                             "provenance": "observed", "method": "exchange_id",
                             "confidence": "certain", "state": "resolved"},
            )  # fmt: skip
            if isinstance(exchange.get("endpoint_id"), str):
                item["engine_name"] = exchange["endpoint_id"]
            if "reason_code" in row:
                item["reason_code"] = row["reason_code"]
            out.append(item)
    return out


def _markers(table: MarkerTable, calls: Sequence[Any]) -> list[dict[str, Any]]:
    """One row per tool call whose first-fed result a marker matches (``calls`` are the
    056 tool calls: ``fed`` is the first request carrying the result, ``result`` its item
    with the verified text)."""
    out: list[dict[str, Any]] = []
    for call in calls:
        if call.fed is None or call.result is None:
            continue
        marker = table.match(call.result.get("text"))
        if marker is None:
            continue
        fed = str(call.fed["exchange_id"])
        item = _derived_control(
            _at(call.issued, f"{fed}#marker.{call.id}"), kind=marker.kind,
            decision=marker.decision, stage="unknown", derivation="configured_marker",
            gated_kind="tool_call", gated_tool_call_id=call.id, engine_name=marker.label,
            evidence_ref=[fed], view_after=str(call.issued["exchange_id"]),
            preset_link={"type": "gates", "target": {"namespace": "call", "id": call.id},
                         "provenance": "inferred", "method": "provider_id",
                         "confidence": "certain", "state": "resolved"},
        )  # fmt: skip
        if marker.reason_code is not None:
            item["reason_code"] = marker.reason_code
        out.append(item)
    return out


def add_rows(
    sec: dict[str, Any], inp: Mapping[str, Any], calls: Sequence[Any], derivation: Derivation
) -> None:
    """The derived grant and control rows of one run, added to its security input ``sec``
    (in place); the exchanges of ``inp`` gain their ``offered_grant_id``."""
    if derivation.wants(OFFERED_GRANT):
        sec["grants"] = [*sec["grants"], *_grants(inp)]
    if derivation.wants(SAFETY_MAP):
        sec["controls"] = [*sec["controls"], *_safety(inp)]
    if derivation.markers is not None and derivation.wants(TOOL_RESULT_MARKER):
        sec["controls"] = [*sec["controls"], *_markers(derivation.markers, calls)]


def flag_of(result: Any) -> bool | None:
    """A tool result's structured error flag as the input keeps it."""
    flag = result.get("is_error") if isinstance(result, Mapping) else None
    return flag if isinstance(flag, bool) else None
