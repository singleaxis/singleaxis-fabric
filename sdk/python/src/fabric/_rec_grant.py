# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``record_grant``: the grant snapshot record (spec 057 §5.2, WP7-1).

What the agent was given or allowed, **as the customer reports it**: a declared permission
configuration (the default basis), or an offered tool set for a model call Fabric does not
capture on the wire. Rules are recorded verbatim, in the runtime's own syntax; Fabric never
parses, interprets or applies them. Credential values are never read: a credential entry
carries a name, a kind and declared scopes only.

The record is a run annotation (step kind ``run``). Telemetry carries the shape only: the
keyed ``grt-`` id (G01), trigger, previous id, source boundary, basis, modes and counts
(G02-G09, G12-G14). The document itself is ``run.permissions`` content (G10), retained only
as the capture policy allows, after **structural pseudonymisation** (§7.2): every path or
glob becomes ``pth-``, every network host ``net-``, every credential name ``crd-`` and
every MCP ``server_ref`` (a launch command or URL, which can carry a token or a user path)
``src-``, the id ``fabric.mcp.server_ref`` and ``fabric.extension.source_ref`` carry
(keyed v2, deterministic under one key). Without an id key the document cannot be
pseudonymised and is withheld; it never falls back to clear.

``grant_digest = sha256(JCS(normalised clear document))`` (RFC 8785; every list sorted and
de-duplicated, ``request_ref`` dropped). It never reaches telemetry: the ``grt-`` id is its
keyed pseudonym. Every call is passive and fails open (051 R9).
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from decimal import Decimal
from typing import Any

from ._capture_types import misuse
from ._records_api import Body, current_records, emit, never_raises
from ._sequence import pseudonym_v2
from .records._handles import RecordHandle
from .records._vocab import (
    APPROVAL_POLICIES,
    EXECUTION_MODES,
    GRANT_BASES,
    GRANT_TRIGGERS,
    SANDBOX_KINDS,
    TOOL_CHOICE_MODES,
    normalise,
)

SCHEMA_VERSION = "fabric.grant-snapshot/v1"
MAX_LIST = 4096
MAX_OBJECTS = 256
MAX_TEXT = 1024
MAX_EXTENSION_NODES = 10_000
MAX_EXTENSION_DEPTH = 32
_LABEL64 = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PATH_REF = re.compile(r"pth-[0-9a-f]{32}")
_POINTER = re.compile(r"(/[^/]*)*")
_EXTENSION = re.compile(r"x-[a-z0-9-]+")
_GRANT_ID = re.compile(r"grt-[0-9a-f]{32}")
_SCOPES = frozenset({"managed", "user", "project", "local", "session", "unknown"})
_TRANSPORTS = frozenset({"stdio", "streamable_http", "sse", "other"})
_CREDENTIAL_KINDS = frozenset({"env", "file", "secret_store", "token", "other"})
_TOOL_TYPES = frozenset({"function", "custom", "provider_hosted", "mcp", "computer", "other"})
_NETWORK_DEFAULTS = frozenset({"allow", "deny", "unknown"})
# The boundaries a basis may name (the schema's per-basis rule), and the default for a
# document the application reports through this API.
_BOUNDARIES = {
    "offered": frozenset({"llm_wire", "api", "otlp", "other"}),
    "listed": frozenset({"mcp_wire", "otlp", "other"}),
    "declared": frozenset({"api", "otlp", "operator_snapshot", "other"}),
}
_DEFAULT_BOUNDARY = {"offered": "api", "listed": "other", "declared": "api"}
_DECLARED = frozenset({
    "execution_mode", "approval_policy", "permission_mode", "tools", "mcp_servers",
    "filesystem", "network", "sandbox", "credentials", "models", "limits",
})  # fmt: skip
_OFFERED = frozenset({"tools_offered", "tool_choice", "instructions_digest", "request_ref"})
_LISTED = frozenset({"server", "tools_listed", "roots", "request_ref"})
_BASIS_KEYS = {"declared": _DECLARED, "offered": _OFFERED, "listed": _LISTED}
# §7.2: the fields each pseudonymisation group replaces.
PATH_FIELDS: tuple[tuple[str, ...], ...] = (
    ("filesystem", "roots"), ("filesystem", "read"), ("filesystem", "write"),
    ("filesystem", "deny"), ("roots",),
)  # fmt: skip
HOST_FIELDS: tuple[tuple[str, ...], ...] = (("network", "allow"), ("network", "deny"))
GROUPS = ("paths", "hosts", "credentials", "sources")


# ===================================================================== JCS (RFC 8785)
class _NotJsonError(Exception):
    """A value JCS cannot serialise (internal; the caller drops the field)."""


def _number(value: int | float) -> str:  # noqa: PLR0911 - RFC 8785 §3.2.2.3 cases
    """ECMAScript Number serialisation (RFC 8785 §3.2.2.3)."""
    if type(value) is int:
        if abs(value) > 2**53:
            raise _NotJsonError
        return str(value)
    if not math.isfinite(value):
        raise _NotJsonError
    if value == 0:
        return "0"
    if float(value).is_integer() and abs(value) < 1e21:  # noqa: PLR2004 - RFC 8785
        return str(int(value))
    sign = "-" if value < 0 else ""
    digits, exponent = Decimal(repr(abs(value))).normalize().as_tuple()[1:]
    text = "".join(str(d) for d in digits)
    point = len(text) + int(exponent)
    if -6 < point <= 21:  # noqa: PLR2004 - the ECMAScript fixed-notation range
        if point <= 0:
            return f"{sign}0.{'0' * -point}{text}"
        if point >= len(text):
            return f"{sign}{text}{'0' * (point - len(text))}"
        return f"{sign}{text[:point]}.{text[point:]}"
    mantissa = text[0] + ("." + text[1:] if len(text) > 1 else "")
    power = point - 1
    return f"{sign}{mantissa}e{'+' if power > 0 else '-'}{abs(power)}"


_ESCAPES = {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}


def _string(value: str) -> str:
    out = ['"']
    for char in value:
        code = ord(char)
        if char in ('"', "\\"):
            out.append("\\" + char)
        elif code < 0x20:  # noqa: PLR2004 - control characters
            out.append(_ESCAPES.get(code, f"\\u{code:04x}"))
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _jcs(value: object) -> str:  # noqa: PLR0911 - one return per JSON type
    kind = type(value)
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if kind is int or kind is float:
        return _number(value)  # type: ignore[arg-type]
    if kind is str:
        return _string(value)  # type: ignore[arg-type]
    if kind is list or kind is tuple:
        return "[" + ",".join(_jcs(v) for v in value) + "]"  # type: ignore[attr-defined]
    if kind is dict:
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))  # type: ignore[attr-defined]
        return "{" + ",".join(_string(k) + ":" + _jcs(v) for k, v in items) + "}"
    raise _NotJsonError


def jcs(value: object) -> bytes:
    """The RFC 8785 canonical UTF-8 bytes of a JSON value (plain ``dict``/``list``/``str``/
    ``int``/``float``/``bool``/``None`` only; anything else raises)."""
    return _jcs(value).encode("utf-8", "surrogatepass")


def normalise_grant(document: Mapping[str, Any]) -> dict[str, Any]:
    """Every list sorted by the JCS bytes of its items and de-duplicated, at every depth;
    ``request_ref`` dropped, so two requests with the same offered set normalise equal."""

    def walk(value: Any) -> Any:
        if type(value) is dict:
            return {k: walk(v) for k, v in value.items()}
        if type(value) is list:
            items = {jcs(item): item for item in (walk(v) for v in value)}
            return [items[k] for k in sorted(items)]
        return value

    out: dict[str, Any] = walk(dict(document))
    out.pop("request_ref", None)
    return out


def grant_digest(document: Mapping[str, Any]) -> str:
    """G11: ``sha256:`` + hex of the JCS bytes of the normalised clear document."""
    return "sha256:" + hashlib.sha256(jcs(normalise_grant(document))).hexdigest()


def grant_id(digest: str, key: bytes | None) -> str | None:
    """G01: the keyed ``grt-`` pseudonym of the digest text; ``None`` without a key."""
    return pseudonym_v2("grt", digest, key)


def pseudonymise_grant(
    document: Mapping[str, Any], key: bytes, *, paths: bool = True, hosts: bool = True,
    credentials: bool = True, sources: bool = True,
) -> dict[str, Any]:  # fmt: skip
    """§7.2, in place of each value: every path or glob (filesystem rules and MCP roots)
    becomes ``pth-``, every network host or pattern ``net-``, every credential name
    ``crd-`` and every MCP ``server_ref`` ``src-`` (the E14/E21 source id); other fields
    stay as written. A group switched off stays clear."""
    out: dict[str, Any] = _copy(dict(document))

    def replace(path: Sequence[str], prefix: str) -> None:
        node: Any = out
        for part in path[:-1]:
            node = node.get(part) if type(node) is dict else None
        if type(node) is dict and type(node.get(path[-1])) is list:
            node[path[-1]] = [pseudonym_v2(prefix, v, key) for v in node[path[-1]]]

    if paths:
        for path in PATH_FIELDS:
            replace(path, "pth")
    if hosts:
        for path in HOST_FIELDS:
            replace(path, "net")
    if credentials:
        for item in out.get("credentials", ()):
            item["name"] = pseudonym_v2("crd", item["name"], key)
    if sources:
        for item in out.get("mcp_servers", ()):
            if "server_ref" in item:
                item["server_ref"] = pseudonym_v2("src", item["server_ref"], key)
    return out


def _resorted(document: dict[str, Any]) -> dict[str, Any]:
    """The pseudonymised lists sorted again, by their pseudonyms: a list left in the order
    of its clear values would reveal how those values sort (§7.2)."""
    for path in (*PATH_FIELDS, *HOST_FIELDS, ("credentials",), ("mcp_servers",)):
        node: Any = document
        for part in path[:-1]:
            node = node.get(part) if type(node) is dict else None
        if type(node) is dict and type(node.get(path[-1])) is list:
            node[path[-1]] = sorted(node[path[-1]], key=jcs)
    return document


def _copy(value: Any) -> Any:
    if type(value) is dict:
        return {k: _copy(v) for k, v in value.items()}
    if type(value) is list:
        return [_copy(v) for v in value]
    return value


def needs_key(document: Mapping[str, Any], groups: Mapping[str, bool]) -> bool:
    """Whether any value the enabled groups replace is present (no key: withheld)."""
    for path in (PATH_FIELDS if groups.get("paths", True) else ()) + (
        HOST_FIELDS if groups.get("hosts", True) else ()
    ):  # fmt: skip
        node: Any = document
        for part in path:
            node = node.get(part) if type(node) is dict else None
        if node:
            return True
    if groups.get("sources", True) and any(
        "server_ref" in item for item in document.get("mcp_servers", ())
    ):  # fmt: skip
        return True
    return bool(groups.get("credentials", True) and document.get("credentials"))


# ===================================================================== the document's shape
class _InvalidError(Exception):
    """One field outside the closed shape (internal: the field is dropped, counted)."""


def _text(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_TEXT:
        raise _InvalidError
    return value


def _label64(value: object) -> str:
    if type(value) is not str or not _LABEL64.fullmatch(value):
        raise _InvalidError
    return value


def _enum(value: object, allowed: frozenset[str]) -> str:
    if type(value) is not str or value not in allowed:
        raise _InvalidError
    return value


def _seq(value: object, limit: int = MAX_LIST) -> list[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise _InvalidError
    if len(value) > limit:
        raise _InvalidError
    return list(value)


def _text_list(value: object) -> list[str]:
    return [_text(v) for v in _seq(value)]


def _obj(value: object, required: set[str], optional: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _InvalidError
    keys = set(value.keys())
    if not required <= keys or keys - required - optional:
        raise _InvalidError
    return dict(value)


def _rules(value: object) -> list[dict[str, str]]:
    out = []
    for item in _seq(value):
        if type(item) is str:  # a bare rule string is the rule object's shorthand
            out.append({"rule": _text(item)})
        else:
            out.append({"rule": _text(_obj(item, {"rule"}, set())["rule"])})
    return out


def _tools(value: object) -> dict[str, Any]:
    row = _obj(value, set(), {"allow", "deny", "ask"})
    return {k: _rules(v) for k, v in row.items()}


def _mcp_server(value: object) -> dict[str, Any]:
    row = _obj(value, {"server"}, {"transport", "server_ref", "tools_allow", "tools_deny",
                                   "scope"})  # fmt: skip
    out: dict[str, Any] = {"server": _text(row["server"])}
    if "transport" in row:
        out["transport"] = _enum(row["transport"], _TRANSPORTS)
    if "server_ref" in row:
        out["server_ref"] = _text(row["server_ref"])
    for name in ("tools_allow", "tools_deny"):
        if name in row:
            out[name] = _text_list(row[name])
    if "scope" in row:
        out["scope"] = _enum(row["scope"], _SCOPES)
    return out


def _lists(value: object, names: set[str]) -> dict[str, Any]:
    row = _obj(value, set(), names)
    return {k: _text_list(v) for k, v in row.items()}


def _network(value: object) -> dict[str, Any]:
    row = _obj(value, set(), {"default", "allow", "deny"})
    out: dict[str, Any] = {}
    if "default" in row:
        out["default"] = _enum(row["default"], _NETWORK_DEFAULTS)
    for name in ("allow", "deny"):
        if name in row:
            out[name] = _text_list(row[name])
    return out


def _sandbox(value: object) -> dict[str, Any]:
    row = _obj(value, {"kind"}, {"name", "enabled"})
    out: dict[str, Any] = {"kind": _enum(row["kind"], SANDBOX_KINDS)}
    if "name" in row:
        out["name"] = _text(row["name"])
    if "enabled" in row:
        if type(row["enabled"]) is not bool:
            raise _InvalidError
        out["enabled"] = row["enabled"]
    return out


def _credential(value: object) -> dict[str, Any]:
    row = _obj(value, {"name"}, {"kind", "scopes"})  # never a value field (closed object)
    out: dict[str, Any] = {"name": _text(row["name"])}
    if "kind" in row:
        out["kind"] = _enum(row["kind"], _CREDENTIAL_KINDS)
    if "scopes" in row:
        out["scopes"] = _text_list(row["scopes"])
    return out


def _limit(value: object) -> dict[str, Any]:
    row = _obj(value, {"kind", "limit"}, {"window"})
    if type(row["limit"]) is not int or row["limit"] < 0:
        raise _InvalidError
    out: dict[str, Any] = {"kind": _label64(row["kind"]), "limit": row["limit"]}
    if "window" in row:
        out["window"] = _label64(row["window"])
    return out


def _tool_offered(value: object) -> dict[str, Any]:
    row = _obj(value, {"name", "type"}, {"definition_sha256"})
    out: dict[str, Any] = {"name": _text(row["name"]), "type": _enum(row["type"], _TOOL_TYPES)}
    if "definition_sha256" in row:
        if type(row["definition_sha256"]) is not str or not _SHA256.fullmatch(
            row["definition_sha256"]
        ):  # fmt: skip
            raise _InvalidError
        out["definition_sha256"] = row["definition_sha256"]
    return out


def _tool_choice(value: object) -> dict[str, Any]:
    row = _obj(value, {"mode"}, {"allowed_count", "parallel"})
    out: dict[str, Any] = {"mode": _enum(row["mode"], TOOL_CHOICE_MODES)}
    if "allowed_count" in row:
        count = row["allowed_count"]
        if count is not None and (type(count) is not int or count < 0):
            raise _InvalidError
        out["allowed_count"] = count
    if "parallel" in row:
        if row["parallel"] is not None and type(row["parallel"]) is not bool:
            raise _InvalidError
        out["parallel"] = row["parallel"]
    return out


def _tool_listed(value: object) -> dict[str, Any]:
    hints = {"read_only_hint", "destructive_hint", "idempotent_hint", "open_world_hint"}
    row = _obj(value, {"name"}, {"definition_sha256", *hints})
    out: dict[str, Any] = {"name": _text(row["name"])}
    if "definition_sha256" in row:
        if type(row["definition_sha256"]) is not str or not _SHA256.fullmatch(
            row["definition_sha256"]
        ):  # fmt: skip
            raise _InvalidError
        out["definition_sha256"] = row["definition_sha256"]
    for name in hints & row.keys():
        if type(row[name]) is not bool:
            raise _InvalidError
        out[name] = row[name]
    return out


def _server(value: object) -> dict[str, Any]:
    row = _obj(value, {"name"}, {"version"})
    return {k: _text(v) for k, v in row.items()}


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise _InvalidError
    return value


def _request_ref(value: object) -> dict[str, Any]:
    row = _obj(value, {"exchange_id"}, {"locator"})
    out: dict[str, Any] = {"exchange_id": _text(row["exchange_id"])}
    if "locator" in row:
        locator = row["locator"]
        if type(locator) is not str or len(locator) > MAX_TEXT or not _POINTER.fullmatch(locator):
            raise _InvalidError
        out["locator"] = locator
    return out


def _opaque(value: object) -> Any:
    """An ``x-<namespace>`` value: plain JSON, kept opaque; bounded in depth and size."""
    nodes = 0

    def walk(node: object, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_EXTENSION_NODES or depth > MAX_EXTENSION_DEPTH:
            raise _InvalidError
        kind = type(node)
        if node is None or kind is bool or kind is str or kind is int:
            if kind is int and abs(node) > 2**53:  # type: ignore[arg-type]
                raise _InvalidError
            return node
        if kind is float:
            if not math.isfinite(node):  # type: ignore[arg-type]
                raise _InvalidError
            return node
        if kind is list or kind is tuple:
            return [walk(v, depth + 1) for v in node]  # type: ignore[attr-defined]
        if kind is dict:
            if not all(type(k) is str for k in node):  # type: ignore[attr-defined]
                raise _InvalidError
            return {k: walk(v, depth + 1) for k, v in node.items()}  # type: ignore[attr-defined]
        raise _InvalidError

    return walk(value, 0)


_FIELD_CHECKS: dict[str, Any] = {
    "execution_mode": lambda v: _enum(v, EXECUTION_MODES),
    "approval_policy": lambda v: _enum(v, APPROVAL_POLICIES),
    "permission_mode": _label64,
    "tools": _tools,
    "mcp_servers": lambda v: [_mcp_server(i) for i in _seq(v, MAX_OBJECTS)],
    "filesystem": lambda v: _lists(v, {"roots", "read", "write", "deny"}),
    "network": _network,
    "sandbox": _sandbox,
    "credentials": lambda v: [_credential(i) for i in _seq(v, MAX_OBJECTS)],
    "models": lambda v: _lists(v, {"allow", "deny"}),
    "limits": lambda v: [_limit(i) for i in _seq(v, MAX_OBJECTS)],
    "tools_offered": lambda v: [_tool_offered(i) for i in _seq(v)],
    "tool_choice": _tool_choice,
    "instructions_digest": _digest,
    "server": _server,
    "tools_listed": lambda v: [_tool_listed(i) for i in _seq(v)],
    "roots": _text_list,
    "request_ref": _request_ref,
}


def _source(value: object, basis: str) -> dict[str, Any]:
    default = {"boundary": _DEFAULT_BOUNDARY[basis]}
    if value is None:
        return default
    try:
        row = _obj(value, {"boundary"}, {"name", "version", "endpoint_id", "path_ref"})
        out: dict[str, Any] = {"boundary": _enum(row["boundary"], _BOUNDARIES[basis])}
        for name in ("name", "version", "endpoint_id"):
            if name in row:
                out[name] = _text(row[name])
        if "path_ref" in row:
            if type(row["path_ref"]) is not str or not _PATH_REF.fullmatch(row["path_ref"]):
                raise _InvalidError
            out["path_ref"] = row["path_ref"]
        return out
    except _InvalidError:
        misuse("grant source")
        return default


def check_document(value: Mapping[str, Any]) -> dict[str, Any] | None:
    """The document in the closed ``fabric.grant-snapshot/v1`` shape: each field outside
    it (or outside its basis) is dropped and counted; ``None`` (counted) when a field the
    basis requires is missing. Never raises misuse except under strict mode."""
    basis = value.get("basis", "declared")
    if type(basis) is not str or basis not in GRANT_BASES:
        misuse("grant basis")
        return None
    out: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "basis": basis,
                           "source": _source(value.get("source"), basis)}  # fmt: skip
    allowed = _BASIS_KEYS[basis]
    for name, item in value.items():
        if name in ("schema_version", "basis", "source"):
            if name == "schema_version" and item != SCHEMA_VERSION:
                misuse("grant schema_version")
            continue
        if type(name) is str and _EXTENSION.fullmatch(name):
            try:
                out[name] = _opaque(item)
            except _InvalidError:
                misuse("grant extension field")
            continue
        if name not in allowed:
            misuse("grant field outside the basis")
            continue
        try:
            out[name] = _FIELD_CHECKS[name](item)
        except _InvalidError:
            misuse("grant field")
    if basis == "offered" and "tools_offered" not in out:
        misuse("an offered grant needs tools_offered")
        return None
    if basis == "listed" and "tools_listed" not in out and "roots" not in out:
        misuse("a listed grant needs tools_listed or roots")
        return None
    return out


# ===================================================================== the API
@dataclass(frozen=True, slots=True)
class GrantSnapshot:
    """A grant document (``fabric.grant-snapshot/v1``) built field by field; ``None``
    fields are left out. ``extensions`` holds the opaque ``x-<namespace>`` members."""

    basis: str = "declared"
    source: Mapping[str, Any] | None = None
    execution_mode: str | None = None
    approval_policy: str | None = None
    permission_mode: str | None = None
    tools: Mapping[str, Sequence[Any]] | None = None
    mcp_servers: Sequence[Mapping[str, Any]] | None = None
    filesystem: Mapping[str, Sequence[str]] | None = None
    network: Mapping[str, Any] | None = None
    sandbox: Mapping[str, Any] | None = None
    credentials: Sequence[Mapping[str, Any]] | None = None
    models: Mapping[str, Sequence[str]] | None = None
    limits: Sequence[Mapping[str, Any]] | None = None
    tools_offered: Sequence[Mapping[str, Any]] | None = None
    tool_choice: Mapping[str, Any] | None = None
    instructions_digest: str | None = None
    server: Mapping[str, Any] | None = None
    tools_listed: Sequence[Mapping[str, Any]] | None = None
    roots: Sequence[str] | None = None
    extensions: Mapping[str, Any] = field(default_factory=dict)

    def to_document(self) -> dict[str, Any]:
        out: dict[str, Any] = {"schema_version": SCHEMA_VERSION}
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name == "extensions":
                if isinstance(value, Mapping):
                    out.update(value)
            elif value is not None:
                out[item.name] = value
        return out


class GrantRef:
    """Ids only (052 E5): ``grant_id`` (the keyed ``grt-`` id, ``None`` without a key or
    when nothing was recorded), ``attempt_uid`` and ``recorded``. Pass it as ``previous=``
    to a later snapshot or as ``grant=`` to ``record_control``."""

    __slots__ = ("attempt_uid", "grant_id", "recorded")

    def __init__(self, grant_id: str | None, attempt_uid: str | None, recorded: bool) -> None:
        self.grant_id = grant_id
        self.attempt_uid = attempt_uid
        self.recorded = bool(recorded)

    def __repr__(self) -> str:
        return f"GrantRef(recorded={self.recorded})"

    @classmethod
    def unrecorded(cls) -> GrantRef:
        return cls(None, None, False)


def _plain(value: object) -> Any:
    """A caller mapping as plain ``dict``/``list`` values (``Mapping``/``Sequence`` copied),
    so the shape checks never call back into application objects beyond iteration."""
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _count(doc: Mapping[str, Any], *path: str) -> int | None:
    node: Any = doc
    for part in path:
        if type(node) is not dict or part not in node:
            return None
        node = node[part]
    return len(node) if type(node) is list else None


def _sum(*counts: int | None) -> int | None:
    present = [c for c in counts if c is not None]
    return sum(present) if present else None


_DECLARED_COUNTS = (
    "tools_allow", "tools_deny", "tools_ask", "mcp_servers", "fs_rules", "net_rules",
    "credentials", "model_rules",
)  # fmt: skip


def grant_attributes(doc: Mapping[str, Any]) -> dict[str, Any]:
    """The telemetry shape of a normalised document: basis, boundary, modes, counts."""
    attrs: dict[str, Any] = {
        "fabric.grant.basis": doc["basis"],
        "fabric.grant.source_boundary": doc["source"]["boundary"],
    }
    if "permission_mode" in doc:
        attrs["fabric.grant.permission_mode"] = doc["permission_mode"]
    if "execution_mode" in doc:  # G06: the 049 C30/C31 keys, set from a declared snapshot
        attrs["fabric.run.execution_mode"] = doc["execution_mode"]
    if "approval_policy" in doc:
        attrs["fabric.run.approval_policy"] = doc["approval_policy"]
    if "sandbox" in doc:
        attrs["fabric.grant.sandbox_kind"] = doc["sandbox"]["kind"]
    if "default" in doc.get("network", {}):
        attrs["fabric.grant.network_default"] = doc["network"]["default"]
    if "tool_choice" in doc:
        choice = doc["tool_choice"]
        attrs["fabric.grant.tool_choice"] = choice["mode"]
        if type(choice.get("allowed_count")) is int:
            attrs["fabric.grant.tool_choice.allowed_count"] = choice["allowed_count"]
        if type(choice.get("parallel")) is bool:
            attrs["fabric.grant.parallel_tools"] = choice["parallel"]
    counts = {
        "tools_allow": _count(doc, "tools", "allow"),
        "tools_deny": _count(doc, "tools", "deny"),
        "tools_ask": _count(doc, "tools", "ask"),
        "tools_offered": _count(doc, "tools_offered"),
        "tools_listed": _count(doc, "tools_listed"),
        "mcp_servers": _count(doc, "mcp_servers"),
        "fs_rules": _sum(
            *(_count(doc, "filesystem", n) for n in ("roots", "read", "write", "deny"))
        ),
        "net_rules": _sum(_count(doc, "network", "allow"), _count(doc, "network", "deny")),
        "credentials": _count(doc, "credentials"),
        "model_rules": _sum(_count(doc, "models", "allow"), _count(doc, "models", "deny")),
    }
    for name, value in counts.items():
        if value is not None:
            attrs[f"fabric.grant.{name}.count"] = value
    if doc["basis"] == "declared":  # C32: the sum of the declared counts
        total = _sum(*(counts[n] for n in _DECLARED_COUNTS))
        if total is not None:
            attrs["fabric.run.permissions.count"] = total
    return attrs


def pseudonymise_groups(records: Any) -> dict[str, bool]:
    """The capture policy's ``security_context.grant.pseudonymise`` switches (§7.2): each
    group on unless the policy sets it ``false``."""
    gate = getattr(getattr(records, "handle", None), "gate", None)
    configured = getattr(getattr(gate, "policy", None), "grant_pseudonymise", None) or {}
    return {group: configured.get(group, True) is not False for group in GROUPS}


def emit_grant(
    records: Any, document: Mapping[str, Any], *, trigger: object = "run_start",
    previous: object = None, attrs: Mapping[str, Any] | None = None,
) -> tuple[RecordHandle, str | None]:  # fmt: skip
    """One grant snapshot record on ``records`` from a checked document, as its handle and
    emitted ``grt-`` id; ``attrs`` adds run-annotation keys (``record_run_context``).
    Raises only misuse and faults."""
    from ._rec_controls import grant_id_of  # noqa: PLC0415 - the controls module imports none

    doc = normalise_grant(document)
    doc["source"] = document["source"]
    if "request_ref" in document:
        doc["request_ref"] = document["request_ref"]
    out: dict[str, Any] = dict(attrs or {})
    for name, value in grant_attributes(doc).items():
        out.setdefault(name, value)  # a run-context key the caller set wins
    out["fabric.grant.trigger"] = normalise(trigger, GRANT_TRIGGERS, "grant trigger")
    key = getattr(records, "_key", None)
    emitted = grant_id(grant_digest(doc), key)
    if emitted is not None:
        out["fabric.grant.id"] = emitted
    if previous is not None and (previous_id := grant_id_of(previous)) is not None:
        out["fabric.grant.previous_id"] = previous_id
    bodies: list[Body] = []
    if records.mode_of("run.permissions") != "omit":
        groups = pseudonymise_groups(records)
        if key is not None:
            stored = _resorted(pseudonymise_grant(doc, key, **groups))
            bodies.append(Body("run.permissions", stored, "application/json"))
        elif not needs_key(doc, groups):
            bodies.append(Body("run.permissions", doc, "application/json"))
        # else: no key, nothing to pseudonymise with: withheld, never clear (§7.3)
    handle = emit("run", attrs=out, records=records, name_hint="fabric.activity",
                  bodies=bodies, default_actor="unknown")  # fmt: skip
    return handle, emitted if handle.recorded else None


@never_raises(GrantRef.unrecorded)
def record_grant(
    document: Mapping[str, object] | GrantSnapshot, *, trigger: str = "run_start",
    previous: GrantRef | str | None = None,
) -> GrantRef:  # fmt: skip
    """Record one grant snapshot (§5.2): ``basis`` defaults to ``declared``; a caller may
    report ``offered`` for a model call Fabric does not capture on the wire. A field outside
    the closed shape is dropped and counted. Passive: returns ids only, never raises."""
    records = current_records()
    if records is None:
        return GrantRef.unrecorded()
    if isinstance(document, GrantSnapshot):
        raw: Any = document.to_document()
    elif isinstance(document, Mapping):
        raw = _plain(document)
    else:
        misuse("document must be a mapping or a GrantSnapshot")
        return GrantRef.unrecorded()
    checked = check_document(raw)
    if checked is None:
        return GrantRef.unrecorded()
    handle, emitted = emit_grant(records, checked, trigger=trigger, previous=previous)
    return GrantRef(emitted, handle.attempt_uid, handle.recorded)


__all__ = [
    "GROUPS", "SCHEMA_VERSION", "GrantRef", "GrantSnapshot", "check_document", "emit_grant",
    "grant_attributes", "grant_digest", "grant_id", "jcs", "needs_key", "normalise_grant",
    "pseudonymise_grant", "pseudonymise_groups", "record_grant",
]  # fmt: skip
