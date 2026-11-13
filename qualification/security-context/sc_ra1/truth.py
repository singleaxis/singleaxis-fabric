# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SC-RA-1 ground truth, computed from the harness's own ledgers, never from Fabric.

Inputs: the agent's ledger (each request it sent with its offered tools, tool choice and
parallel setting; each response it received; each tool result and its error flag; each
elicitation answer and root it gave; each stdio server it launched) and the fixture MCP
servers' ledgers (every JSON-RPC message they sent and received).

Output: the events spec 057 §10.2 says must each have exactly one record, with the values
the record must carry: offered and listed grants with their keyed ids, tool choice, F12,
F14, MCP servers, inventories and inventory changes (F11), MCP calls, elicitation requests
and answers, provider safety signals and stdio launches.

Every digest and id is computed here from the spec text, with this module's own code
(nothing is imported from ``fabric``): the grant digest of spec 057 §5.2
(``sha256(JCS(document))``, every list sorted by the JCS bytes of its items and
de-duplicated, ``request_ref`` dropped), RFC 8785 for the JSON this run holds (strings,
integers, booleans, null, arrays and objects; no floats occur in these documents), and
the keyed pseudonym function v2 of spec 049 §2.9 (``prefix-`` + the first 32 hex of
HMAC-SHA256(k_type, value), k_type = HMAC-SHA256(key, ``"fabric-id/v2/" + type``)), and the
keyed v1 operator label of spec 049 C35 for a configured endpoint's id (``lbl-`` + the first
32 hex of HMAC-SHA256(key, name)).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "fabric.grant-snapshot/v1"
_TYPES = {"grt": "grant", "src": "extension_source", "ext": "extension"}
_HINTS = (
    ("readOnlyHint", "read_only_hint", "read_only"),
    ("destructiveHint", "destructive_hint", "destructive"),
    ("idempotentHint", "idempotent_hint", "idempotent"),
    ("openWorldHint", "open_world_hint", "open_world"),
)
_ACTIONS = {"accept": "allow", "decline": "deny", "cancel": "cancelled"}


# ------------------------------------------------------------------- spec primitives
def jcs(value: Any) -> bytes:
    """RFC 8785 for the value shapes this run holds (no floats): object members sorted by
    their UTF-16 code units, no insignificant whitespace, strings as JSON escapes them."""

    def encode(v: Any) -> str:
        if isinstance(v, dict):
            items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return (
                "{"
                + ",".join(json.dumps(k, ensure_ascii=False) + ":" + encode(x) for k, x in items)
                + "}"
            )
        if isinstance(v, list):
            return "[" + ",".join(encode(x) for x in v) + "]"
        if isinstance(v, float):
            raise ValueError("SC-RA-1 documents carry no floats")
        return json.dumps(v, ensure_ascii=False)

    return encode(value).encode("utf-8")


def normalise(document: Mapping[str, Any]) -> dict[str, Any]:
    """Spec 057 §5.2: every list sorted and de-duplicated (by JCS bytes), at every depth;
    ``request_ref`` dropped."""

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            unique = {jcs(item): item for item in (walk(v) for v in value)}
            return [unique[k] for k in sorted(unique)]
        return value

    out: dict[str, Any] = walk(dict(document))
    out.pop("request_ref", None)
    return out


def grant_digest(document: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs(normalise(document))).hexdigest()


def label(value: str, key: bytes) -> str:
    """Spec 049 C35 and §4.2: a configured endpoint's emitted id, ``lbl-`` + the first 32 hex
    of HMAC-SHA256(key, name) (the keyed v1 label). The wire-derived offered document names
    its endpoint this way, since the reader sees only what was emitted."""
    return "lbl-" + hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


def pseudonym(prefix: str, value: str, key: bytes, id_type: str | None = None) -> str:
    """Function v2 of spec 049 §2.9 (``id_type`` defaults to the prefix's type)."""
    kind = id_type or _TYPES[prefix]
    k_type = hmac.new(key, f"fabric-id/v2/{kind}".encode(), hashlib.sha256).digest()
    return f"{prefix}-" + hmac.new(k_type, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]


# -------------------------------------------------------------- offered grant (§4.1, §5.2)
def _tool_entry(tool: Mapping[str, Any], dialect: str) -> dict[str, str]:
    if dialect == "anthropic":
        name, kind = tool["name"], "function" if "type" not in tool else "custom"
    else:
        name, kind = tool["function"]["name"], tool.get("type", "function")
    return {"name": name, "type": kind, "definition_sha256": hashlib.sha256(jcs(tool)).hexdigest()}


def tool_choice(  # noqa: PLR0911 - one return per row of the closed table
    dialect: str, literal: Any, offered: int, parallel: Any
) -> dict[str, Any]:
    """The closed normalisation table of spec 057 §4.1 (G13, G14)."""
    absent = literal == "<absent>"
    flag = parallel if isinstance(parallel, bool) else None
    if dialect == "anthropic":
        if absent:
            return {"mode": "auto" if offered else "none", "allowed_count": None, "parallel": None}
        modes = {"auto": "auto", "any": "required", "tool": "specific", "none": "none"}
        kind = literal.get("type") if isinstance(literal, dict) else None
        if kind not in modes:
            return {"mode": "unknown", "allowed_count": None, "parallel": None}
        disabled = literal.get("disable_parallel_tool_use")
        return {
            "mode": modes[kind],
            "allowed_count": 1 if kind == "tool" else None,
            "parallel": (not disabled) if isinstance(disabled, bool) else None,
        }
    if absent:
        return {"mode": "auto" if offered else "none", "allowed_count": None, "parallel": flag}
    if literal in ("auto", "none", "required"):
        return {"mode": literal, "allowed_count": None, "parallel": flag}
    if isinstance(literal, dict) and literal.get("type") == "allowed_tools":
        tools = (literal.get("allowed_tools") or literal).get("tools")
        count = len(tools) if isinstance(tools, list) else None
        return {"mode": "allowed_subset", "allowed_count": count, "parallel": flag}
    if isinstance(literal, dict) and literal.get("type"):
        return {"mode": "specific", "allowed_count": 1, "parallel": flag}
    return {"mode": "unknown", "allowed_count": None, "parallel": flag}


def instructions_digest(dialect: str, system: Any) -> str:
    """C20 as the reader defines it (spec 049 names C20 a "stable digest" without fixing
    the function; this follows the reader's documented form): SHA-256 of the compact,
    key-sorted JSON array of the system parts (Anthropic ``system``; Chat Completions
    system and developer messages)."""
    parts = [system] if dialect == "anthropic" else [{"role": "system", "content": system}]
    text = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def offered_document(request: Mapping[str, Any], endpoint_id: str, system: str) -> dict[str, Any]:
    tools = [_tool_entry(t, request["dialect"]) for t in request["tools"]]
    return {
        "schema_version": SCHEMA,
        "basis": "offered",
        "source": {"boundary": "llm_wire", "endpoint_id": endpoint_id},
        "tools_offered": tools,
        "tool_choice": tool_choice(
            request["dialect"], request["tool_choice"], len(tools), request["parallel_tool_calls"]
        ),
        "instructions_digest": instructions_digest(request["dialect"], system),
    }


# ------------------------------------------------------------------------------- events
@dataclass
class Truth:
    """What one session must show. Lists are in the order the events happened."""

    session: str
    model_calls: list[dict[str, Any]] = field(default_factory=list)  # per request
    offered: list[dict[str, Any]] = field(default_factory=list)  # snapshots
    f12_calls: list[int] = field(default_factory=list)  # model-call index naming un-offered
    f14_calls: list[int] = field(default_factory=list)  # model-call index feeding a flag
    safety: list[dict[str, Any]] = field(default_factory=list)
    extensions: list[dict[str, Any]] = field(default_factory=list)
    listed: list[dict[str, Any]] = field(default_factory=list)
    mcp_calls: list[dict[str, Any]] = field(default_factory=list)
    elicitations: list[dict[str, Any]] = field(default_factory=list)
    inventory_changes: int = 0
    launches: list[dict[str, Any]] = field(default_factory=list)
    answers_given: list[str] = field(default_factory=list)
    roots_given: int = 0

    def summary(self) -> dict[str, int]:
        return {
            "model_calls": len(self.model_calls),
            "offered_grants": len(self.offered),
            "tool_choice_restricted": sum(
                1 for o in self.offered if o["tool_choice"]["mode"] not in ("auto", "none")
            ),
            "f12": len(self.f12_calls),
            "f14_wire": len(self.f14_calls),
            "safety": len(self.safety),
            "extensions": len(self.extensions),
            "listed_grants": len(self.listed),
            "mcp_calls": len(self.mcp_calls),
            "mcp_tool_errors": sum(1 for c in self.mcp_calls if c["outcome"] == "tool_error"),
            "elicitation_rows": len(self.elicitations),
            "inventory_changes": self.inventory_changes,
            "launches": len(self.launches),
        }


def wire_truth(
    truth: Truth,
    ledger: Sequence[Mapping[str, Any]],
    endpoint_ids: Mapping[str, str],
    system: str,
    key: bytes,
    safety_rows: Sequence[Mapping[str, Any]],
) -> None:
    """Offered grants, tool choice, F12 and F14 from the agent's own requests and the
    responses it received (spec 057 §4.1)."""
    requests = [r for r in ledger if r["event"] == "model_request"]
    responses = {r["turn"]: r for r in ledger if r["event"] == "model_response"}
    flagged = {r["turn"] for r in ledger if r["event"] == "tool_result" and r.get("flag")}
    previous: str | None = None
    for i, request in enumerate(requests):
        endpoint = label(endpoint_ids[request["dialect"]], key)
        document = offered_document(request, endpoint, system)
        digest = grant_digest(document)
        gid = pseudonym("grt", digest, key)
        truth.model_calls.append(
            {
                "index": i,
                "offered_grant_id": gid,
                "tools": [t["name"] for t in document["tools_offered"]],
            }
        )
        if gid != previous:
            truth.offered.append(
                {
                    "id": gid,
                    "previous_id": previous,
                    "tools": len(document["tools_offered"]),
                    "tool_choice": document["tool_choice"],
                    "instructions": document["instructions_digest"],
                    "call": i,
                }
            )
        previous = gid
        response = responses.get(request["turn"], {})
        names = {t["name"] for t in document["tools_offered"]}
        if any(c["name"] not in names for c in response.get("tool_calls", ())):
            truth.f12_calls.append(i)
        if request["turn"] - 1 in flagged:
            truth.f14_calls.append(i)  # this request fed back a result with is_error: true
    for row in safety_rows:
        truth.safety.append({**row, "call": 0})


def _listed_tool(raw: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": raw["name"],
        "definition_sha256": hashlib.sha256(jcs(raw)).hexdigest(),
    }
    annotations = raw.get("annotations") or {}
    for literal, key, _ in _HINTS:
        if isinstance(annotations.get(literal), bool):
            out[key] = annotations[literal]
    return out


def mcp_truth(truth: Truth, messages: Sequence[Mapping[str, Any]], key: bytes) -> None:
    """MCP events from the fixture servers' own ledgers (spec 057 §4.2), per server."""
    servers = sorted({(m["server"], m["transport"]) for m in messages})
    for server, transport in servers:
        _server_truth(
            truth,
            [m for m in messages if (m["server"], m["transport"]) == (server, transport)],
            key,
        )


def _server_truth(  # noqa: PLR0912, PLR0915 - one branch per MCP message kind
    truth: Truth, messages: Sequence[Mapping[str, Any]], key: bytes
) -> None:
    asked: dict[Any, str] = {}  # client request id -> method
    server_asked: dict[Any, dict[str, Any]] = {}
    name = version = None
    tools: list[dict[str, Any]] | None = None
    roots: list[str] | None = None
    digest = inventory = None
    for entry in messages:
        message, direction = entry["message"], entry["direction"]
        server = entry["server"]
        if direction == "client_to_server" and "method" in message and "id" in message:
            asked[message["id"]] = message["method"]
            if message["method"] == "tools/call":
                truth.mcp_calls.append(
                    {
                        "server": server,
                        "tool": message["params"]["name"],
                        "id": message["id"],
                        "outcome": "pending",
                    }
                )
            continue
        if direction == "server_to_client" and "method" in message:
            if "id" not in message:
                if message["method"] == "notifications/tools/list_changed":
                    truth.mcp_calls.append(
                        {
                            "server": server,
                            "tool": None,
                            "method": message["method"],
                            "outcome": "notification",
                        }
                    )
                continue
            server_asked[message["id"]] = message
            if message["method"] == "elicitation/create":
                truth.elicitations.append(
                    {
                        "server": server,
                        "phase": "request",
                        "decision": "escalate",
                        "id": message["id"],
                    }
                )
            continue
        if direction == "client_to_server":  # the client answers the server's question
            question = server_asked.get(message.get("id"))
            result = message.get("result") or {}
            if question is None:
                continue
            if question["method"] == "elicitation/create":
                action = result.get("action")
                truth.elicitations.append(
                    {
                        "server": server,
                        "phase": "resolution",
                        "decision": _ACTIONS.get(str(action), "unknown"),
                        "action": action,
                        "reason_code": f"elicitation.{action}",
                        "id": message.get("id"),
                    }
                )
            elif question["method"] == "roots/list":
                roots = sorted({r["uri"] for r in result.get("roots", [])})
                digest = _listed(truth, server, name, version, tools, roots, digest, key)
            continue
        method = asked.get(message.get("id"))
        result = message.get("result")
        if method == "initialize" and isinstance(result, dict):
            info = result.get("serverInfo") or {}
            name, version = info.get("name"), info.get("version")
            truth.extensions.append(
                {
                    "server": server,
                    "observed_via": "mcp_initialize",
                    "name": name,
                    "version": version,
                }
            )
        elif method == "tools/list" and isinstance(result, dict):
            tools = sorted((_listed_tool(t) for t in result["tools"]), key=lambda t: t["name"])
            counts = {label: sum(1 for t in tools if t.get(k) is True) for _, k, label in _HINTS}
            listed = hashlib.sha256(jcs(tools)).hexdigest()
            changed = inventory is not None and listed != inventory
            truth.inventory_changes += int(changed)
            inventory = listed
            truth.extensions.append(
                {
                    "server": server,
                    "observed_via": "mcp_tools_list",
                    "name": name,
                    "tools": len(tools),
                    "annotations": counts,
                    "manifest_hash": listed,
                    "changed": changed,
                }
            )
            digest = _listed(truth, server, name, version, tools, roots, digest, key)
        elif method == "tools/call":
            call = next(
                c
                for c in reversed(truth.mcp_calls)
                if c.get("id") == message["id"]
                and c["server"] == server
                and c["outcome"] == "pending"
            )
            if "error" in message:
                call["outcome"] = "protocol_error"
            elif isinstance(result, dict) and result.get("isError") is True:
                call["outcome"] = "tool_error"
            else:
                call["outcome"] = "ok"


def _listed(
    truth: Truth,
    server: str,
    name: Any,
    version: Any,
    tools: list[dict[str, Any]] | None,
    roots: list[str] | None,
    last: str | None,
    key: bytes,
) -> str | None:
    """A ``listed`` snapshot when the document differs from the last one (§5.2)."""
    source: dict[str, Any] = {"boundary": "mcp_wire"}
    document: dict[str, Any] = {"schema_version": SCHEMA, "basis": "listed", "source": source}
    if name is not None:
        source["name"] = name
        document["server"] = {"name": name}
        if version is not None:
            source["version"] = version
            document["server"]["version"] = version
    if tools is not None:
        document["tools_listed"] = tools
    if roots is not None:
        document["roots"] = roots
    digest = grant_digest(document)
    if digest == last:
        return last
    previous = next((g["id"] for g in reversed(truth.listed) if g["server"] == server), None)
    counts = {}
    if tools is not None:
        counts["tools_listed"] = len(tools)
    if roots is not None:
        counts["fs_rules"] = len(roots)
    truth.listed.append(
        {
            "server": server,
            "id": pseudonym("grt", digest, key),
            "previous_id": previous,
            "counts": counts,
        }
    )
    return digest


def launch_truth(truth: Truth, ledger: Sequence[Mapping[str, Any]], key: bytes) -> None:
    """Each stdio server the agent launched: one ``process_launch`` extension whose source is
    the keyed id of the command line, and one exec record (spec 057 §4.2, WP7-8)."""
    for row in ledger:
        if row["event"] == "mcp_launch":
            truth.launches.append(
                {
                    "server": row["server"],
                    "source_ref": pseudonym("src", shlex.join(row["argv"]), key),
                }
            )
        elif row["event"] == "elicitation_answer":
            truth.answers_given.append(row["action"])
        elif row["event"] == "roots_given":
            truth.roots_given += 1
