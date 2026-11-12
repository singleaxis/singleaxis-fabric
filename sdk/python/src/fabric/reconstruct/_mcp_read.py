# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-7 and WP7-8 in the reader: the MCP messages of one run, from either
capture point, for the ``mcp.jsonrpc`` derivation rule (``--derive mcp.jsonrpc``).

- **Streamable HTTP** (``http.nonmodel``, WP7-7): each request's ``network.request`` body
  and its ``network.response`` body (one JSON body, or a ``text/event-stream`` whose
  ``message`` events are JSON bodies) are read with the frozen ``jsonrpc2`` dialect. One
  host's requests are one session, and an ``initialize`` request starts a new one (the
  ``Mcp-Session-Id`` header is never recorded). The messages of a response are placed at
  the request's first record, after the request (a stream opened there).
- **stdio** (``mcp.client``, WP7-8): each record's ``mcp.*`` body is one message, its
  direction ``fabric.mcp.direction``, its session the evidence item's ``session_ref``.
  Each session also yields a ``process_launch`` extension row: the server process the
  library launched, its ``src-`` launch reference and pid, with the exec record of that
  process (same pid) as evidence when the exec hook recorded it.

**Listed hosts and ``body_not_retained``** (§6.4). Without retained bodies nothing about
MCP can be derived. A ``mcp.client`` session whose bodies were not retained, or a request
to a host listed with ``--mcp-host`` whose bodies were not retained, makes the ``controls``
chain ``partial(body_not_retained)`` and yields no rows. An unlisted host's exchanges are
read when their bodies are JSON-RPC and are otherwise ignored.

Nothing here parses free text; the ``mcp`` layer reads literal members only (§3.8).
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from fabric._sequence import pseudonym_v2
from fabric.reconstruct.dialects import jsonrpc2
from fabric.reconstruct.dialects.mcp import Seen, SessionInfo

__all__ = ["MCP_POINT", "McpInput", "listed_host_ids", "read"]

MCP_POINT: Final = "mcp.client"
_REQUEST, _RESPONSE = "network.request", "network.response"
_MCP_ROLES: Final = ("mcp.request", "mcp.response", "mcp.notification")
_EVIDENCE_ROLE: Final = "record.evidence"
_CLIENT, _SERVER = "client_to_server", "server_to_client"
_NOT_RETAINED: Final = frozenset({"not_retained", "not_exposed"})


@dataclass(slots=True)
class McpInput:
    """One run's MCP messages in record order, their sessions, the launch rows of the
    stdio sessions, and whether any listed MCP traffic had no retained bodies."""

    messages: list[Seen] = field(default_factory=list)
    sessions: dict[str, SessionInfo] = field(default_factory=dict)
    launches: list[tuple[SessionInfo, dict[str, Any], list[str], int | None]] = field(
        default_factory=list
    )
    body_not_retained: bool = False


def listed_host_ids(hosts: Iterable[str], key: bytes | None) -> frozenset[str]:
    """The ``hst-`` ids of the ``--mcp-host`` hosts, keyed as the HTTP hook keys a rule's
    host (none without an id key: then nothing is listed)."""
    from fabric.hooks._config import parse_host  # noqa: PLC0415 - pure parsing
    from fabric.hooks._http import host_text  # noqa: PLC0415

    out: set[str] = set()
    for text in hosts:
        found = pseudonym_v2("hst", host_text(parse_host(text).host), key)
        if found is not None:
            out.add(found)
    return frozenset(out)


def _at(record: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "source_id": record.source_id, "source_epoch": record.source_epoch,
        "sequence": record.source_sequence, "start_ns": record.span.start_ns,
        "attempt_uid": record.attempt_uid,
    }  # fmt: skip
    if record.segment_id is not None:
        out["segment_id"] = record.segment_id
    return out


def _object_ids(attrs: Mapping[str, Any]) -> list[str]:
    value = attrs.get("fabric.content.object_ids")
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _objects(reader: Any, record: Any, role: str) -> list[tuple[dict[str, Any], bytes | None]]:
    """Every object of ``role`` the record names: its descriptor and verified bytes
    (``None`` when not retained, missing or unverified)."""
    out: list[tuple[dict[str, Any], bytes | None]] = []
    verifier = reader.verifier
    for object_id in _object_ids(record.span.attributes):
        result = verifier.record_object(record, object_id)
        descriptor = result.descriptor
        if descriptor is None or descriptor.get("role") != role:
            continue
        data = None
        if result.verification == "verified" and verifier.reader is not None:
            raw = verifier.record_object(record, object_id, data=True).data
            data = bytes(raw) if raw is not None else None
        out.append((dict(descriptor), data))
    return out


def _http(  # noqa: PLR0912, PLR0915 - one branch per body form and completeness state
    reader: Any, records: Sequence[Any], listed: frozenset[str], out: McpInput
) -> None:
    by_attempt: dict[str, list[Any]] = defaultdict(list)
    for record in records:
        by_attempt[record.attempt_uid].append(record)
    count: dict[str, int] = defaultdict(int)
    current: dict[str, str] = {}
    ordered = sorted(by_attempt.values(), key=lambda rs: (rs[0].source_id, rs[0].source_epoch,
                                                          rs[0].source_sequence))  # fmt: skip
    for group in ordered:
        first = group[0]
        host = next((v for r in group
                     if isinstance(v := r.span.attributes.get("fabric.network.host_id"), str)),
                    None)  # fmt: skip
        host_key = host or "unkeyed-host"
        request, pieces, response, media = None, [], [], None
        retained = True
        for record in group:
            for descriptor, data in _objects(reader, record, _REQUEST):
                if descriptor.get("stream_id") is None and descriptor.get("chunk_index") is None:
                    request = data
                    if data is None:
                        retained = False
                else:
                    pieces.append((int(descriptor.get("chunk_index") or 0), data))
            for descriptor, data in _objects(reader, record, _RESPONSE):
                response.append((int(descriptor.get("chunk_index") or 0), data))
                media = media or descriptor.get("media_type")
        # The evidence says how complete each body is (N44): a role that is off, a body
        # over its cap or a streamed request body is not retained.
        item = _evidence_item(reader, group[-1])
        states = (item.get("request_body"), item.get("response_body"))
        if any(state in _NOT_RETAINED for state in states):
            retained = False
        body: bytes | None = None
        if request is not None:
            try:
                locator = json.loads(request).get("body") or {}
            except (ValueError, AttributeError):
                locator = {}
            if locator.get("form") == "pieces":
                if any(d is None for _, d in pieces) or not pieces:
                    retained = False
                else:
                    body = b"".join(d for _, d in sorted(pieces) if d is not None)
        if any(d is None for _, d in response):
            retained = False
        if host in listed and not retained:
            out.body_not_retained = True
        if body is None:
            continue
        sent = jsonrpc2.from_json(body)
        if not sent:
            continue  # not JSON-RPC: another API on this host
        if any(m.kind == "request" and m.method == "initialize" for m in sent) or (
            host_key not in current
        ):  # fmt: skip
            count[host_key] += 1
            current[host_key] = f"http:{host_key}:{count[host_key]}"
            out.sessions[current[host_key]] = SessionInfo(
                "streamable_http", f"{host_key}#session.{count[host_key]}", None, host
            )
        session = current[host_key]
        at = _at(first)
        for message in sent:
            out.messages.append(Seen(message, _CLIENT, session, at, first.attempt_uid,
                                     first.event_id))  # fmt: skip
        if response and all(d is not None for _, d in response) and retained:
            data = b"".join(d for _, d in sorted(response) if d is not None)
            last = group[-1]
            for message in jsonrpc2.from_body(data, media):
                out.messages.append(Seen(message, _SERVER, session, at, first.attempt_uid,
                                         last.event_id))  # fmt: skip


def _evidence_item(reader: Any, record: Any) -> dict[str, Any]:
    for _, data in _objects(reader, record, _EVIDENCE_ROLE):
        if data is None:
            continue
        try:
            items = json.loads(data).get("items") or []
        except (ValueError, AttributeError):
            continue
        if items and isinstance(items[0], dict):
            return items[0]
    return {}


def _stdio(reader: Any, records: Sequence[Any], effects: Sequence[Mapping[str, Any]],
           key: bytes | None, out: McpInput) -> None:  # fmt: skip
    exec_by_pid = {e["pid"]: e["event_id"] for e in effects
                   if isinstance(e.get("pid"), int) and "capture_point" not in e}  # fmt: skip
    seen_sessions: set[str] = set()
    for record in records:
        attrs = record.span.attributes
        item = _evidence_item(reader, record)
        ref = item.get("session_ref")
        pid = attrs.get("fabric.process.pid")
        # Without an id key the worker drops the evidence ids: one source epoch's server
        # process (its pid, on every record) is then the session.
        session = (f"stdio:{ref}" if isinstance(ref, str)
                   else f"stdio:{record.source_id}:{record.source_epoch}:{pid}")  # fmt: skip
        if session not in out.sessions:
            server_ref = attrs.get("fabric.mcp.server_ref")
            info = SessionInfo(str(item.get("transport") or "stdio"),
                               ref if isinstance(ref, str) else session,
                               server_ref if isinstance(server_ref, str) else None)  # fmt: skip
            out.sessions[session] = info
        info = out.sessions[session]
        if session not in seen_sessions:
            seen_sessions.add(session)
            pid = attrs.get("fabric.process.pid")
            pid = pid if isinstance(pid, int) and not isinstance(pid, bool) else None
            evidence = [record.event_id]
            if pid is not None and pid in exec_by_pid:
                evidence.append(exec_by_pid[pid])
            out.launches.append((info, _at(record), evidence, pid))
        direction = attrs.get("fabric.mcp.direction")
        if direction not in (_CLIENT, _SERVER):
            continue
        bodies = [d for role in _MCP_ROLES for _, d in _objects(reader, record, role)]
        if not bodies or any(d is None for d in bodies):
            out.body_not_retained = True
            continue
        for data in bodies:
            for message in jsonrpc2.from_json(data):  # type: ignore[arg-type]
                out.messages.append(Seen(message, str(direction), session, _at(record),
                                         record.attempt_uid, record.event_id))  # fmt: skip


def read(reader: Any, *, http_records: Sequence[Any], mcp_records: Sequence[Any],
         effects: Sequence[Mapping[str, Any]], listed: frozenset[str],
         key: bytes | None) -> McpInput:  # fmt: skip
    """The MCP input of one run (``reader`` is the run's ``_RunReader``)."""
    out = McpInput()
    _http(reader, http_records, listed, out)
    _stdio(reader, mcp_records, effects, key, out)
    out.messages.sort(key=lambda s: (s.at["source_id"], s.at["source_epoch"], s.at["sequence"]))
    return out
