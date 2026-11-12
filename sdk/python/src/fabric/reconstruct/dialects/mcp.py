# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``mcp.jsonrpc`` (spec 057 §4.2, WP7-7, WP7-8): the MCP method layer over ``jsonrpc2``.

It reads the JSON-RPC messages of one MCP session, already split from stored bytes by the
``jsonrpc2`` dialect, and says which security context each one carries. It reads the same
messages whichever capture point recorded them: ``http.nonmodel`` bodies (Streamable
HTTP) or ``mcp.client`` records (the transport hook, stdio and Streamable HTTP). Nothing
here runs in the agent's request path (B2), and nothing interprets free text (§3.8): every
value is a literal member of a message with a public specification.

- ``initialize`` result: an extension ``mcp_server``, ``observed_via=mcp_initialize``
  (C25-C27);
- ``tools/list`` result: an extension ``observed_via=mcp_tools_list`` with the inventory
  digest (E15) and annotation counts (E20); a ``listed`` grant when the listed document
  changes;
- ``roots/list`` result: a ``listed`` grant counting the roots (never their values);
- ``tools/call`` and its answer: an MCP call row, ``ok``, ``tool_error`` (``isError``,
  F14) or ``protocol_error`` (a JSON-RPC error, N25);
- ``elicitation/create`` and its answer: control rows ``kind=elicitation``, the request
  (``escalate``) and the resolution (``accept`` -> ``allow``, ``decline`` -> ``deny``,
  ``cancel`` -> ``cancelled``), joined by JSON-RPC id;
- ``notifications/tools/list_changed``: an MCP row; F11 is stated when a later
  ``tools/list`` gives another digest.

A request is paired with its answer by direction and typed id inside one session (``"1"``
and ``1`` never alias; a server request and a client request with the same id are
different requests). A paginated ``tools/list`` is one listing: pages are joined until a
result has no ``nextCursor``.

Annotations are the server's assertion, never fact (§3.3). An answer nobody gave leaves
the elicitation request pending (F4). An ``action`` outside the three literals is
``unknown``; a missing field never becomes ``allow``.

The messages of the 2025-11-25 and earlier protocol revisions (the ``initialize``
handshake) are read. The 2026-07-28 revision's ``server/discover`` and
``input_required`` results are plain JSON-RPC to this layer and project nothing yet.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from fabric._rec_grant import SCHEMA_VERSION, grant_digest, grant_id, jcs
from fabric._sequence import pseudonym_v2
from fabric.reconstruct._controls import AUTHENTICATION, ENFORCED_BY_FABRIC
from fabric.reconstruct.dialects.jsonrpc2 import Message, typed_id

__all__ = ["RULE", "Derived", "Seen", "SessionInfo", "derive", "launch_row"]

#: The derivation rule, as the capture manifest names it (spec 057 §6.4).
RULE: Final = "mcp.jsonrpc"
CLIENT: Final = "client_to_server"
SERVER: Final = "server_to_client"
_NAME: Final = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._:/@-]{0,127}")  # E12 name
_VERSION: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")  # E12 version, C26
_PROTOCOL: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")  # C27
_HINTS: Final = (
    ("readOnlyHint", "read_only_hint", "read_only"),
    ("destructiveHint", "destructive_hint", "destructive"),
    ("idempotentHint", "idempotent_hint", "idempotent"),
    ("openWorldHint", "open_world_hint", "open_world"),
)
_ACTIONS: Final = {"accept": "allow", "decline": "deny", "cancel": "cancelled"}
_MAX_TEXT: Final = 1024
_MAX_TOOLS: Final = 4096
_MAX_PENDING: Final = 4096  # outstanding requests kept per session (053 §5.5)
_INVARIANTS: Final = {"fabric.control.enforced_by_fabric": ENFORCED_BY_FABRIC,
                      "fabric.control.authentication": AUTHENTICATION}  # fmt: skip


@dataclass(frozen=True, slots=True)
class SessionInfo:
    """One MCP session as its capture point knew it: the transport, the keyed session
    reference shown on rows (``mcps-``, or a reader-made label when no id key or clear
    session id exists), the keyed ``src-`` reference of the server's URL or launch
    command (E21) when the capture point knew it, and the keyed host id of an
    ``http.nonmodel`` rule."""

    transport: str
    ref: str
    server_ref: str | None = None
    host_id: str | None = None


@dataclass(frozen=True, slots=True)
class Seen:
    """One JSON-RPC message with where it was recorded: its direction, its session key,
    the position of the record that carried it (``source_id``, ``source_epoch``,
    ``sequence``, ``start_ns``, optionally ``segment_id``) and that record's attempt uid
    and event id (the evidence a derived row names, D47)."""

    message: Message
    direction: str
    session: str
    at: Mapping[str, Any]
    carrier: str
    evidence: str


@dataclass(slots=True)
class Derived:
    """What the layer derived from the sessions of one run."""

    extensions: list[dict[str, Any]] = field(default_factory=list)
    grants: list[dict[str, Any]] = field(default_factory=list)
    controls: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class _State:
    info: SessionInfo
    pending: dict[tuple[str, str, str | int], tuple[Message, dict[str, Any]]] = field(
        default_factory=dict
    )
    name: str | None = None
    version: str | None = None
    tools: list[dict[str, Any]] | None = None
    page: list[dict[str, Any]] = field(default_factory=list)
    roots: list[str] | None = None
    digest: str | None = None
    grant: str | None = None
    # Answers read before their request (an HTTP answer posted while the request's own
    # response stream was still open): paired when the request is read.
    early: dict[tuple[str, str, str | int], Seen] = field(default_factory=dict)


def _text(value: object, pattern: re.Pattern[str]) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def _tool(raw: object) -> dict[str, Any] | None:
    """One listed tool as the ``listed`` grant document holds it: its name, the SHA-256 of
    its RFC 8785 form and each annotation hint that is a literal boolean."""
    if not isinstance(raw, dict):
        return None
    name = raw.get("name")
    if not isinstance(name, str) or not 1 <= len(name) <= _MAX_TEXT:
        return None
    try:
        out: dict[str, Any] = {
            "name": name,
            "definition_sha256": hashlib.sha256(jcs(raw)).hexdigest(),
        }
    except Exception:
        out = {"name": name}
    annotations = raw.get("annotations")
    if isinstance(annotations, dict):
        for literal, key, _ in _HINTS:
            if isinstance(annotations.get(literal), bool):
                out[key] = annotations[literal]
    return out


class _Deriver:
    def __init__(self, sessions: Mapping[str, SessionInfo], key: bytes | None) -> None:
        self.sessions, self.key = sessions, key
        self.states: dict[str, _State] = {}
        self.out = Derived()
        self.counts: dict[str, int] = {}

    # -- positions -----------------------------------------------------------------

    def _at(self, seen: Seen) -> dict[str, Any]:
        n = self.counts[seen.carrier] = self.counts.get(seen.carrier, 0) + 1
        uid = f"{seen.carrier}#mcp.{n}"
        out: dict[str, Any] = {
            "attempt_uid": uid, "event_id": uid, "source_id": seen.at["source_id"],
            "source_epoch": seen.at["source_epoch"], "sequence": seen.at["sequence"],
            "start_ns": seen.at["start_ns"], "derived": True, "evidence_ref": [seen.evidence],
        }  # fmt: skip
        if "segment_id" in seen.at:
            out["segment_id"] = seen.at["segment_id"]
        return out

    # -- the walk --------------------------------------------------------------------

    def feed(self, seen: Seen) -> None:
        info = self.sessions.get(seen.session)
        if info is None:
            return
        state = self.states.get(seen.session)
        if state is None:
            state = self.states[seen.session] = _State(info)
        message = seen.message
        if message.kind == "request":
            ident = typed_id(message.id)
            if ident is None:
                return
            row = self._request(state, seen)
            key = (seen.direction, *ident)
            early = state.early.pop(key, None)
            if early is not None:
                self._answer(state, early, message, row)
            elif len(state.pending) < _MAX_PENDING:
                state.pending[key] = (message, row)
        elif message.kind == "notification":
            if message.method == "notifications/tools/list_changed" and seen.direction == SERVER:
                self.out.calls.append({**self._at(seen), "method": message.method,
                                       "session": info.ref, "outcome": "notification"})  # fmt: skip
        else:
            ident = typed_id(message.id)
            if ident is None:
                return
            asked = CLIENT if seen.direction == SERVER else SERVER
            found = state.pending.pop((asked, *ident), None)
            if found is not None:
                self._answer(state, seen, found[0], found[1])
            elif len(state.early) < _MAX_PENDING:
                state.early[(asked, *ident)] = seen

    def _request(self, state: _State, seen: Seen) -> dict[str, Any]:
        """The row a request opens (an MCP call, an elicitation request), else ``{}``."""
        message, info = seen.message, state.info
        if seen.direction == CLIENT and message.method == "tools/call":
            row = {**self._at(seen), "method": "tools/call", "session": info.ref,
                   "outcome": "pending"}  # fmt: skip
            params = message.params
            name = params.get("name") if isinstance(params, dict) else None
            if isinstance(name, str) and 1 <= len(name) <= _MAX_TEXT:
                row["tool"] = name
            self.out.calls.append(row)
            return row
        if seen.direction == SERVER and message.method == "elicitation/create":
            row = self._control(state, seen, phase="request", decision="escalate")
            row.update(answered=False, preset_link={
                "type": "part_of", "target": {"namespace": "external", "id": info.ref},
                "provenance": "observed", "method": "mcp_session", "confidence": "certain",
                "state": "resolved",
            })  # fmt: skip
            self.out.controls.append(row)
            return row
        return {}

    def _control(self, state: _State, seen: Seen, **fields: Any) -> dict[str, Any]:
        row = self._at(seen)
        row.update(kind="elicitation", stage="unknown", derivation="literal",
                   gated_kind="mcp_call", attrs=dict(_INVARIANTS), invariant_conflict=False,
                   provenance="observed", session=state.info.ref, **fields)  # fmt: skip
        if state.name is not None:
            row["engine_name"] = state.name
        return row

    def _answer(self, state: _State, seen: Seen, request: Message, opened: dict[str, Any]) -> None:
        answer, method = seen.message, request.method
        result = answer.result if answer.kind == "response" else None
        if seen.direction == SERVER:  # the server answered a client request
            if method == "initialize" and isinstance(result, dict):
                self._initialize(state, seen, result)
            elif method == "tools/list" and isinstance(result, dict):
                self._tools(state, seen, request, result)
            elif method == "tools/call" and opened:
                if answer.kind == "error":
                    opened["outcome"] = "protocol_error"
                elif isinstance(result, dict) and result.get("isError") is True:
                    opened["outcome"] = "tool_error"
                else:
                    opened["outcome"] = "ok"
                opened["answer_ref"] = seen.evidence
        elif method == "roots/list" and isinstance(result, dict):
            self._roots(state, seen, result)
        elif method == "elicitation/create" and opened:
            self._elicited(state, seen, answer, opened)

    # -- messages --------------------------------------------------------------------

    def _extension(self, state: _State, seen: Seen, via: str) -> dict[str, Any]:
        info = state.info
        row: dict[str, Any] = {
            **self._at(seen), "kind": "mcp_server", "observed_via": via,
            "signature_status": "unknown", "provenance": "observed", "session": info.ref,
            "source_kind": "process" if info.transport == "stdio" else "url",
        }  # fmt: skip
        if state.name is not None:
            row["name"] = state.name
        if state.version is not None:
            row["version"] = state.version
        if info.server_ref is not None:
            row["source_ref"] = info.server_ref
        if info.host_id is not None:
            row["host_id"] = info.host_id
        # E10: (kind, name, source ref). Over HTTP the server's URL is never recorded, so
        # the keyed host id stands in for it: two servers that report one name on two
        # hosts are two extensions, and a listing on one never "changes" the other (F11).
        source = info.server_ref or info.host_id
        ext_id = pseudonym_v2("ext", f"mcp_server/{state.name or ''}/{source or ''}", self.key)
        if ext_id is not None:
            row["id"] = ext_id
        else:  # no id key: the session still tells one server's rows from another's
            row["identity"] = ("mcp_server", state.name, info.ref)
        return row

    def _initialize(self, state: _State, seen: Seen, result: Mapping[str, Any]) -> None:
        server = result.get("serverInfo")
        if isinstance(server, dict):
            state.name = _text(server.get("name"), _NAME)
            state.version = _text(server.get("version"), _VERSION)
        row = self._extension(state, seen, "mcp_initialize")
        protocol = _text(result.get("protocolVersion"), _PROTOCOL)
        if protocol is not None:
            row["protocol_version"] = protocol
        self.out.extensions.append(row)

    def _tools(self, state: _State, seen: Seen, request: Message,
               result: Mapping[str, Any]) -> None:  # fmt: skip
        listed = result.get("tools")
        if not isinstance(listed, list):
            return
        params = request.params
        if not (isinstance(params, dict) and isinstance(params.get("cursor"), str)):
            state.page = []  # a request without a cursor starts a new listing
        for raw in listed:
            tool = _tool(raw)
            if tool is not None and len(state.page) < _MAX_TOOLS:
                state.page.append(tool)
        if isinstance(result.get("nextCursor"), str) and result["nextCursor"]:
            return  # more pages follow: the listing is not whole yet
        tools = sorted(state.page, key=lambda t: t["name"])
        state.page, state.tools = [], tools
        row = self._extension(state, seen, "mcp_tools_list")
        row["tools"] = len(tools)
        row["annotations"] = {
            label: sum(1 for t in tools if t.get(key) is True) for _, key, label in _HINTS
        }
        try:
            row["manifest_hash"] = hashlib.sha256(jcs(tools)).hexdigest()
        except Exception:
            row.pop("manifest_hash", None)
        self.out.extensions.append(row)
        self._grant(state, seen)

    def _roots(self, state: _State, seen: Seen, result: Mapping[str, Any]) -> None:
        listed = result.get("roots")
        if not isinstance(listed, list):
            return
        uris = [r["uri"] for r in listed if isinstance(r, dict) and isinstance(r.get("uri"), str)
                and 1 <= len(r["uri"]) <= _MAX_TEXT]  # fmt: skip
        state.roots = sorted(set(uris))
        self._grant(state, seen)

    def _grant(self, state: _State, seen: Seen) -> None:
        """A ``listed`` snapshot of what the server listed so far (its tools, the roots the
        client exposed to it), when that document differs from the last one made."""
        info = state.info
        source: dict[str, Any] = {"boundary": "mcp_wire"}
        document: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "basis": "listed",
                                    "source": source}  # fmt: skip
        if state.name is not None:
            source["name"] = state.name
            document["server"] = {"name": state.name}
            if state.version is not None:
                source["version"] = state.version
                document["server"]["version"] = state.version
        if state.tools is not None:
            document["tools_listed"] = state.tools
        if state.roots is not None:
            document["roots"] = state.roots
        try:
            digest = grant_digest(document)
        except Exception:
            return
        if digest == state.digest:
            return
        row: dict[str, Any] = {
            **self._at(seen), "basis": "listed", "trigger": "derived",
            "source_boundary": "mcp_wire", "provenance": "observed", "scope": info.ref,
            "counts": {}, "digest": digest,
        }  # fmt: skip
        if state.tools is not None:
            row["counts"]["tools_listed"] = len(state.tools)
        if state.roots is not None:
            row["counts"]["fs_rules"] = len(state.roots)
        if state.name is not None:
            row["server"] = state.name
        found = grant_id(digest, self.key)
        if found is not None:
            row["id"] = found
        if state.grant is not None:
            row["previous_id"] = state.grant
        state.digest, state.grant = digest, found
        self.out.grants.append(row)

    def _elicited(self, state: _State, seen: Seen, answer: Message,
                  opened: dict[str, Any]) -> None:  # fmt: skip
        opened["answered"] = True
        fields: dict[str, Any] = {"phase": "resolution", "decided_by": "human"}
        if answer.kind == "error":
            fields.update(decision="error", error_class="other")
        else:
            action = answer.result.get("action") if isinstance(answer.result, dict) else None
            decision = _ACTIONS.get(action) if isinstance(action, str) else None
            if decision is None:
                fields["decision"] = "unknown"  # a missing or other literal is never allow
            else:
                fields.update(decision=decision, reason_code=f"elicitation.{action}")
        row = self._control(state, seen, **fields)
        row.update(resolves_row=opened["attempt_uid"], preset_link={
            "type": "resolves", "target": {"namespace": "attempt", "id": opened["attempt_uid"]},
            "provenance": "observed", "method": "rpc_id", "confidence": "certain",
            "state": "resolved",
        })  # fmt: skip
        self.out.controls.append(row)


def derive(
    messages: Sequence[Seen], sessions: Mapping[str, SessionInfo], *, key: bytes | None
) -> Derived:
    """The rows of one run's MCP messages, given in the order they were recorded
    (``sessions`` by session key; ``key`` is the reader's id key, for ``grt-`` and
    ``ext-`` ids)."""
    deriver = _Deriver(sessions, key)
    for seen in messages:
        try:
            deriver.feed(seen)
        except Exception:  # noqa: S112 - one unreadable message yields nothing; the rest are read
            continue
    return deriver.out


def launch_row(info: SessionInfo, at: Mapping[str, Any], evidence: Sequence[str], *,
               pid: int | None, key: bytes | None) -> dict[str, Any]:  # fmt: skip
    """The ``process_launch`` extension row of a stdio session the transport hook saw the
    library launch (E11, E13, E14, E21): kind ``mcp_server``, source ``process``, its
    launch command's ``src-`` id, at the session's first record, with that record and the
    exec record of the same process as evidence. Its id is the ``ext-`` pseudonym of the
    kind and source (the server's name is not known at launch)."""
    row: dict[str, Any] = {
        "attempt_uid": f"{at['attempt_uid']}#mcp.launch", "source_id": at["source_id"],
        "source_epoch": at["source_epoch"], "sequence": at["sequence"],
        "start_ns": at["start_ns"], "derived": True, "evidence_ref": list(evidence)[:8],
        "kind": "mcp_server", "observed_via": "process_launch", "source_kind": "process",
        "signature_status": "unknown", "provenance": "observed", "session": info.ref,
    }  # fmt: skip
    row["event_id"] = row["attempt_uid"]
    if "segment_id" in at:
        row["segment_id"] = at["segment_id"]
    if info.server_ref is not None:
        row["source_ref"] = info.server_ref
    if pid is not None:
        row["pid"] = pid
    ext_id = pseudonym_v2("ext", f"mcp_server//{info.server_ref or ''}", key)
    if ext_id is not None:
        row["id"] = ext_id
    else:
        row["identity"] = ("mcp_server", None, info.ref)
    return row
