# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The optional ``security_context`` section of a deployment policy (spec 057 §8).

The customer's classification lists for security-context capture: control endpoints
(``control_hosts``, ``control_addresses``), hook programs, watched paths, tool-result
denial markers and the grant pseudonymisation switches. This module only checks the
section's shape when the policy is parsed, so the policy digest binds a well-formed
section; loading the lists into frozen tables and applying them is later work (spec 057
WP7-9). Classification is customer configuration, never a built-in list of products
(B9). A malformed section raises ``ValueError`` with fixed text (never a value), as every
other policy section does.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

MAX_ENTRIES = 256
MAX_TEXT = 1024  # a literal value or JSON Pointer
MAX_MAP = 64  # decision_map pairs, marker values, exit_map codes
MAX_MARKER = 4096  # an equals/prefix marker
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_REASON = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")
_HOST = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?")
_ADDRESS = re.compile(
    r"([0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?|[0-9A-Fa-f:]{2,39}(/[0-9]{1,3})?)"
)
_PATH = re.compile(r"/[ -~]{0,4095}")
_BASENAME = re.compile(r"[A-Za-z0-9._+-]{1,255}")
_POINTER = re.compile(r"(/([^~/]|~[01])*)*")
_EXIT_CODE = re.compile(r"0|-?[1-9][0-9]{0,9}")
CONTROL_KINDS = frozenset({"policy", "guardrail", "approval", "rate_limit", "budget", "other"})
HOOK_OUTCOMES = frozenset({"passed", "modified", "blocked", "escalated", "errored"})
WATCH_CLASSES = frozenset(
    {"permission_config", "hook_config", "extension_dir", "credential_file", "other"}
)
MARKER_KINDS = frozenset({
    "guardrail", "policy", "permission_request", "approval", "rate_limit", "budget", "other",
    "permission_check",
})  # fmt: skip
MARKER_DECISIONS = frozenset({"deny", "escalate"})  # a marker never states allow (OD-6)
EXTRACT_DECISIONS = frozenset({"allow", "deny", "modify", "escalate"})
SECTIONS = frozenset({
    "control_hosts", "control_addresses", "hook_programs", "watched_paths",
    "tool_result_markers", "grant",
})  # fmt: skip


def _fail() -> ValueError:
    return ValueError("invalid deployment policy security_context section")


def _object(value: object, required: set[str], optional: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not required <= value.keys():
        raise _fail()
    if value.keys() - required - optional:
        raise _fail()
    return dict(value)


def _match(pattern: re.Pattern[str], value: object) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _fail()
    return value


def _entries(value: object) -> Sequence[object]:
    if not isinstance(value, list) or len(value) > MAX_ENTRIES:
        raise _fail()
    return value


def _literal(value: object) -> object:
    if isinstance(value, bool) or (type(value) is int):
        return value
    if isinstance(value, str) and len(value) <= MAX_TEXT:
        return value
    raise _fail()


def _control_host(entry: object) -> dict[str, Any]:
    row = _object(entry, {"host", "label", "control_kind"}, {"decision_pointer", "decision_map"})
    _match(_HOST, row["host"])
    _match(_LABEL, row["label"])
    if row["control_kind"] not in CONTROL_KINDS:
        raise _fail()
    if ("decision_pointer" in row) != ("decision_map" in row):
        raise _fail()
    if "decision_pointer" in row:
        pointer = _match(_POINTER, row["decision_pointer"])
        if len(pointer) > MAX_TEXT:
            raise _fail()
        pairs = row["decision_map"]
        if not isinstance(pairs, list) or not 1 <= len(pairs) <= MAX_MAP:
            raise _fail()
        for pair in pairs:
            item = _object(pair, {"value", "decision"}, set())
            _literal(item["value"])
            if item["decision"] not in EXTRACT_DECISIONS:
                raise _fail()
    return row


def _control_address(entry: object) -> dict[str, Any]:
    row = _object(entry, {"address", "label", "control_kind"}, set())
    _match(_ADDRESS, row["address"])
    _match(_LABEL, row["label"])
    if row["control_kind"] not in CONTROL_KINDS:
        raise _fail()
    return row


def _hook_program(entry: object) -> dict[str, Any]:
    row = _object(entry, {"label"}, {"path", "basename", "exit_map"})
    _match(_LABEL, row["label"])
    if ("path" in row) == ("basename" in row):
        raise _fail()
    if "path" in row:
        _match(_PATH, row["path"])
    else:
        _match(_BASENAME, row["basename"])
    exit_map = row.get("exit_map")
    if exit_map is not None:
        if not isinstance(exit_map, Mapping) or len(exit_map) > MAX_MAP:
            raise _fail()
        for code, outcome in exit_map.items():
            _match(_EXIT_CODE, code)
            if outcome not in HOOK_OUTCOMES:
                raise _fail()
    return row


def _watched_path(entry: object) -> dict[str, Any]:
    row = _object(entry, {"path", "match", "label", "class"}, set())
    _match(_PATH, row["path"])
    _match(_LABEL, row["label"])
    if row["match"] not in ("exact", "prefix") or row["class"] not in WATCH_CLASSES:
        raise _fail()
    return row


def _marker(entry: object) -> dict[str, Any]:
    row = _object(entry, {"label"}, {"equals", "prefix", "json", "kind", "decision",
                                     "reason_code"})  # fmt: skip
    _match(_LABEL, row["label"])
    rules = [name for name in ("equals", "prefix", "json") if name in row]
    if len(rules) != 1:
        raise _fail()
    rule = rules[0]
    if rule == "json":
        spec = _object(row["json"], {"pointer", "values"}, set())
        if len(_match(_POINTER, spec["pointer"])) > MAX_TEXT:
            raise _fail()
        values = spec["values"]
        if not isinstance(values, list) or not 1 <= len(values) <= MAX_MAP:
            raise _fail()
        for value in values:
            _literal(value)
    elif not isinstance(row[rule], str) or not 1 <= len(row[rule]) <= MAX_MARKER:
        raise _fail()
    if "kind" in row and row["kind"] not in MARKER_KINDS:
        raise _fail()
    if "decision" in row and row["decision"] not in MARKER_DECISIONS:
        raise _fail()
    if "reason_code" in row:
        _match(_REASON, row["reason_code"])
    return row


def _grant(value: object) -> dict[str, Any]:
    row = _object(value, set(), {"pseudonymise"})
    if "pseudonymise" in row:
        switches = _object(row["pseudonymise"], set(), {"paths", "hosts", "credentials",
                                                          "sources"})  # fmt: skip
        if not all(isinstance(flag, bool) for flag in switches.values()):
            raise _fail()
    return row


_CHECKS = {
    "control_hosts": _control_host,
    "control_addresses": _control_address,
    "hook_programs": _hook_program,
    "watched_paths": _watched_path,
    "tool_result_markers": _marker,
}


def check_security_context(value: object) -> dict[str, Any]:
    """The section as given when its shape is valid, else ``ValueError`` (fixed text)."""
    section = _object(value, set(), set(SECTIONS))
    for name, check in _CHECKS.items():
        if name in section:
            for entry in _entries(section[name]):
                check(entry)
    if "grant" in section:
        _grant(section["grant"])
    return section


__all__ = ["MAX_ENTRIES", "SECTIONS", "check_security_context"]
