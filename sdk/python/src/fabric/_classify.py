# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The capture policy's classification lists as frozen tables (spec 057 §4.3, §4.4, §6.4,
WP7-9).

The ``security_context`` section of a deployment policy (``_security_policy.py`` checks
its shape when the policy is parsed) names the customer's own classification lists:
control endpoints by host (``control_hosts``) and by address (``control_addresses``),
hook programs (``hook_programs``), watched paths (``watched_paths``) and tool-result
denial markers (``tool_result_markers``). Classification is customer configuration,
never a built-in list of products (B9).

:func:`load` turns the section into a :class:`Classification` once, at install: each list
becomes an immutable lookup table keyed by the exact value it is matched on. Matching is
exact only (a dict or set lookup, B4): a host is ``host[:port]`` as configured, never a
suffix or a wildcard; a hook program is an exact executable path or an exact ``argv[0]``
basename; an address is an exact address or a CIDR (bit prefix of a configured network,
never a name pattern).

Each list has a :class:`ListStatus`: ``off`` (absent or empty), ``loaded`` or ``refused``
with a reason (``over_limit``: more than 256 entries; ``duplicate_entry``: two entries
match the same value; ``invalid_entry``: an entry the table cannot hold). A refused list
is not applied at all, and loading never raises: a refused list is a status, not an
install error. The capture manifest publishes every status with the list's digest and
entry count (``classifications``), never its contents; nothing here logs a value.

Which lists are applied where (this build): ``hook_programs`` by the exec hook (the
capture worker labels a classified child, spec 057 WP7-10) and by the reader for sensor
exec records; ``control_hosts`` by the ``http.nonmodel`` hook (the record's roles and
labels) and the reader (contact rows, ``decision_pointer`` extraction offline);
``control_addresses`` by the reader for sensor connects (WP7-13). ``watched_paths`` and
``tool_result_markers`` are loaded and published; their emitters are WP7-11 and WP7-6.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Literal

__all__ = [
    "LISTS", "MAX_ENTRIES", "REASONS", "STATES", "Classification", "ControlAddress",
    "ControlHost", "HookProgram", "ListStatus", "argv0_of", "from_policy", "list_digest",
    "load", "status_text", "statuses_from_text",
]  # fmt: skip

#: The classification lists in manifest order, each published as ``classify.<name>``.
LISTS: Final = (
    "control_hosts", "control_addresses", "hook_programs", "watched_paths",
    "tool_result_markers",
)  # fmt: skip
#: Spec 057 §4.4: at most 256 entries per list; a longer list is refused, never truncated.
MAX_ENTRIES: Final = 256
STATES: Final = ("off", "loaded", "refused")
REASONS: Final = ("over_limit", "duplicate_entry", "invalid_entry")
_DEFAULT_PORT: Final = 443  # FABRIC_WIRE_HTTP_HOSTS syntax: a host without a port is :443
_MAX_PORT: Final = 65535
_SHELL_PUNCTUATION: Final = frozenset("();<>|&")  # shlex punctuation_chars: operator tokens
_SHELL_UNSAFE: Final = ("`", "$(", "\n")  # substitution or a second line: not one command

ListState = Literal["off", "loaded", "refused"]


def list_digest(entries: Sequence[Any]) -> str:
    """``sha256:`` of a list's spec-029 canonical JSON (sorted keys, no whitespace,
    literal UTF-8): the list's identity in the manifest. Its contents never are."""
    canonical = json.dumps(list(entries), ensure_ascii=False, separators=(",", ":"),
                           sort_keys=True, allow_nan=False).encode("utf-8")  # fmt: skip
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class ListStatus:
    """One list's state in the manifest: ``classify.<name>``, its state, entry count,
    digest (``None`` when the list is absent) and refusal reason."""

    name: str
    state: ListState
    count: int
    sha256: str | None = None
    reason: str | None = None

    @property
    def id(self) -> str:
        return f"classify.{self.name}"

    def document(self) -> dict[str, Any]:
        """The ``capture-manifest-v1`` ``classifications`` row."""
        row: dict[str, Any] = {"id": self.id, "state": self.state, "count": self.count}
        if self.sha256 is not None:
            row["sha256"] = self.sha256
        if self.reason is not None:
            row["reason"] = self.reason
        return row


def status_text(row: Mapping[str, Any]) -> str:
    """A manifest row as its ``fabric.manifest.classifications`` string:
    ``<id>:<state>:<count>:<reason or ->:<sha256 or ->`` (the digest is last: it holds a
    colon)."""
    return (f"{row['id']}:{row['state']}:{row['count']}:{row.get('reason') or '-'}"
            f":{row.get('sha256') or '-'}")  # fmt: skip


def statuses_from_text(items: Sequence[str]) -> list[dict[str, Any]]:
    """The inverse of :func:`status_text` (a reader rebuilding the manifest document)."""
    rows: list[dict[str, Any]] = []
    for item in items:
        list_id, state, count, reason, digest = str(item).split(":", 4)
        row: dict[str, Any] = {"id": list_id, "state": state, "count": int(count)}
        if digest != "-":
            row["sha256"] = digest
        if reason != "-":
            row["reason"] = reason
        rows.append(row)
    return rows


@dataclass(frozen=True, slots=True)
class HookProgram:
    """A ``hook_programs`` entry: the customer's label and its exit map (exit code text →
    hook outcome). Without a map, or for a code the map does not name, the outcome is
    ``unknown`` and the exit code is still recorded (spec 057 §4.3)."""

    label: str
    exit_map: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def outcome(self, returncode: int | None) -> str:
        """The hook outcome a return code maps to (POSIX: a negative code is the signal,
        as Python reports it), else ``unknown``."""
        if type(returncode) is not int:
            return "unknown"
        return self.exit_map.get(str(returncode), "unknown")

    @property
    def mapped(self) -> bool:
        return bool(self.exit_map)


@dataclass(frozen=True, slots=True)
class ControlHost:
    """A ``control_hosts`` entry: the exact host and port, the customer's label and control
    kind, and the optional offline extraction (``decision_pointer``, ``decision_map``)."""

    host: str
    port: int
    label: str
    control_kind: str
    decision_pointer: str | None = None
    decision_map: tuple[tuple[object, str], ...] = ()

    def decision_of(self, value: object) -> str | None:
        """The configured decision of a literal value at the pointer: exact type and value
        (``1`` never matches ``True`` or ``"1"``), else ``None``."""
        for literal, decision in self.decision_map:
            if type(literal) is type(value) and literal == value:
                return decision
        return None


@dataclass(frozen=True, slots=True)
class ControlAddress:
    """A ``control_addresses`` entry: an exact address (a /32 or /128) or a CIDR."""

    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    label: str
    control_kind: str


_EMPTY: Final[Mapping[Any, Any]] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class Classification:
    """The frozen tables of one capture policy's ``security_context`` section."""

    hook_paths: Mapping[str, HookProgram] = _EMPTY
    hook_basenames: Mapping[str, HookProgram] = _EMPTY
    control_hosts: Mapping[tuple[str, int], ControlHost] = _EMPTY
    control_addresses: tuple[ControlAddress, ...] = ()
    watched_paths: tuple[Mapping[str, Any], ...] = ()
    tool_result_markers: tuple[Mapping[str, Any], ...] = ()
    statuses: tuple[ListStatus, ...] = ()

    @property
    def has_hook_programs(self) -> bool:
        return bool(self.hook_paths or self.hook_basenames)

    def hook_program(self, argv0: str | None, executable: str | None = None) -> HookProgram | None:
        """The hook program a child is, by exact match: the executable path (``executable``
        when the caller passed one, else ``argv[0]``) against the ``path`` entries, then
        the basename of ``argv[0]`` against the ``basename`` entries; else ``None``."""
        path = executable if type(executable) is str and executable else argv0
        if type(path) is str and (found := self.hook_paths.get(path)) is not None:
            return found
        if type(argv0) is str and argv0:
            return self.hook_basenames.get(argv0.rsplit("/", 1)[-1])
        return None

    def control_host(self, host: str, port: int) -> ControlHost | None:
        """The ``control_hosts`` entry of exactly this canonical host and port."""
        return self.control_hosts.get((host, port))

    def control_address(self, address: str) -> ControlAddress | None:
        """The ``control_addresses`` entry whose network holds ``address`` (the networks
        never overlap: an overlapping list is refused)."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        for entry in self.control_addresses:
            if ip.version == entry.network.version and ip in entry.network:
                return entry
        return None

    def status(self, name: str) -> ListStatus | None:
        return next((s for s in self.statuses if s.name == name), None)

    def manifest_rows(self) -> list[dict[str, Any]]:
        """Every list's ``classifications`` row, in :data:`LISTS` order."""
        return [status.document() for status in self.statuses]


class _Refused(Exception):  # noqa: N818 - a list status, never raised past load()
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _host(text: str) -> tuple[str, int]:
    """``host[:port]`` (the policy's checked pattern) as ``(host, port)``; a numeric name
    must be an IPv4 address, as ``FABRIC_WIRE_HTTP_HOSTS`` requires."""
    name, colon, port_text = text.partition(":")
    port = int(port_text) if colon else _DEFAULT_PORT
    if not 1 <= port <= _MAX_PORT:
        raise _Refused("invalid_entry")
    if name.replace(".", "").isdigit():
        try:
            name = str(ipaddress.IPv4Address(name))
        except ValueError:
            raise _Refused("invalid_entry") from None
    return name, port


def _put(table: dict[Any, Any], key: Any, value: Any) -> None:
    if key in table:
        raise _Refused("duplicate_entry")
    table[key] = value


def _hook_tables(entries: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, HookProgram], ...]:
    paths: dict[str, HookProgram] = {}
    basenames: dict[str, HookProgram] = {}
    for entry in entries:
        program = HookProgram(str(entry["label"]),
                              MappingProxyType(dict(entry.get("exit_map") or {})))  # fmt: skip
        if "path" in entry:
            _put(paths, str(entry["path"]), program)
        else:
            _put(basenames, str(entry["basename"]), program)
    return MappingProxyType(paths), MappingProxyType(basenames)


def _host_table(entries: Sequence[Mapping[str, Any]]) -> Mapping[tuple[str, int], ControlHost]:
    table: dict[tuple[str, int], ControlHost] = {}
    for entry in entries:
        host, port = _host(str(entry["host"]))
        pairs = tuple((pair["value"], str(pair["decision"]))
                      for pair in entry.get("decision_map") or ())  # fmt: skip
        _put(table, (host, port), ControlHost(
            host, port, str(entry["label"]), str(entry["control_kind"]),
            entry.get("decision_pointer"), pairs,
        ))  # fmt: skip
    return MappingProxyType(table)


def _address_table(entries: Sequence[Mapping[str, Any]]) -> tuple[ControlAddress, ...]:
    rows: list[ControlAddress] = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(str(entry["address"]), strict=True)
        except ValueError:
            raise _Refused("invalid_entry") from None
        for other in rows:
            if other.network.version == network.version and other.network.overlaps(network):
                raise _Refused("duplicate_entry")
        rows.append(ControlAddress(network, str(entry["label"]), str(entry["control_kind"])))
    return tuple(rows)


def _watch_table(entries: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    seen: dict[tuple[str, str], None] = {}
    for entry in entries:
        _put(seen, (str(entry["path"]), str(entry["match"])), None)
    return tuple(MappingProxyType(dict(entry)) for entry in entries)


def _marker_table(entries: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    return tuple(MappingProxyType(dict(entry)) for entry in entries)


def _entries(section: Mapping[str, Any], name: str) -> Sequence[Mapping[str, Any]] | None:
    value = section.get(name)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(e, Mapping) for e in value):
        raise _Refused("invalid_entry")
    return value


def load(section: Mapping[str, Any] | None) -> Classification | None:
    """The section's frozen tables and per-list statuses; ``None`` without a section.
    Never raises: a list that cannot be loaded is ``refused`` with its reason and is not
    applied; the other lists are unaffected."""
    if not isinstance(section, Mapping):
        return None
    built: dict[str, Any] = {}
    statuses: list[ListStatus] = []
    for name in LISTS:
        digest: str | None = None
        count = 0
        try:
            entries = _entries(section, name)
            if entries is None:
                statuses.append(ListStatus(name, "off", 0))
                continue
            count, digest = len(entries), list_digest(entries)
            if not entries:
                statuses.append(ListStatus(name, "off", 0, digest))
                continue
            if count > MAX_ENTRIES:
                raise _Refused("over_limit")
            if name == "hook_programs":
                built["hook_paths"], built["hook_basenames"] = _hook_tables(entries)
            elif name == "control_hosts":
                built["control_hosts"] = _host_table(entries)
            elif name == "control_addresses":
                built["control_addresses"] = _address_table(entries)
            elif name == "watched_paths":
                built["watched_paths"] = _watch_table(entries)
            else:
                built["tool_result_markers"] = _marker_table(entries)
            statuses.append(ListStatus(name, "loaded", count, digest))
        except _Refused as refused:
            statuses.append(ListStatus(name, "refused", count, digest, refused.reason))
        except Exception:
            statuses.append(ListStatus(name, "refused", count, digest, "invalid_entry"))
    return Classification(**built, statuses=tuple(statuses))


def from_policy(policy: Any) -> Classification | None:
    """:func:`load` of a validated ``DeploymentPolicy``'s section; never raises."""
    try:
        section = policy.to_dict().get("security_context")
    except Exception:
        return None
    return load(section)


def argv0_of(document: object) -> str | None:  # noqa: PLR0911 - one return per unnamed form
    """``argv[0]`` of an exec hook argv document (``terminal.argv``): the first ``str``
    cell of an argv, or the first word of a simple shell command (a shell string with
    ``;``, ``|``, ``&``, ``<`` or ``>`` names no single program); else ``None``. Pure;
    called on the capture worker, never the caller."""
    import shlex  # noqa: PLC0415 - the capture worker's, at first use

    if not isinstance(document, Mapping):
        return None
    if document.get("form") == "shell":
        cell = document.get("command")
        if not isinstance(cell, Mapping) or cell.get("t") != "str":
            return None
        command = str(cell.get("v"))
        if any(mark in command for mark in _SHELL_UNSAFE):
            return None
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            words = list(lexer)
        except ValueError:
            return None
        # one simple command only: an operator token (even written against a word, as in
        # ``a; b``) or a leading ``NAME=value`` assignment names no single program
        if not words or "=" in words[0] or any(set(w) <= _SHELL_PUNCTUATION for w in words):
            return None
        return words[0]
    cells = document.get("args")
    if not isinstance(cells, list) or not cells:
        return None
    first = cells[0]
    if isinstance(first, Mapping) and first.get("t") == "str":
        return str(first.get("v"))
    return None
