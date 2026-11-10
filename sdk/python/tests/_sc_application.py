# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A fixture application module for the no-auto-wrapping test (spec 057 §4.10.3, WP7-3).

Every name here is one an automatic wrapper keyed on names would pick: permission checks,
guards, authorisers, approval prompts and policy helpers, as functions, ``async``
functions, methods, static and class methods, and a callable object. Fabric must leave
every one of them exactly as defined: it wraps only what the customer decorates or wraps.
"""

from __future__ import annotations

from collections.abc import Mapping

ALLOWED_TOOLS = frozenset({"read_file", "list_dir"})
policy_table: dict[str, bool] = {"read_file": True, "shell": False}


def can_use(user: str, tool: str, args: Mapping[str, str]) -> bool:
    return tool in ALLOWED_TOOLS


def check_permission(user: str, action: str) -> bool:
    return action != "delete"


def is_allowed(tool: str) -> bool:
    return policy_table.get(tool, False)


def authorize(user: str, scope: str) -> None:
    if scope == "admin":
        raise PermissionError(scope)


def require_approval(action: str) -> str:
    return "pending"


def guardrail_check(text: str) -> bool:
    return "secret" not in text


def policy_decision(request: Mapping[str, str]) -> str:
    return "allow"


def validate_tool_call(name: str, arguments: Mapping[str, str]) -> bool:
    return bool(name)


async def async_permission_check(user: str) -> bool:
    return user != "guest"


class PermissionChecker:
    """A class whose methods carry check-like names."""

    def check(self, tool: str) -> bool:
        return tool in ALLOWED_TOOLS

    def allow(self, tool: str) -> bool:
        return True

    def deny(self, tool: str) -> bool:
        return False

    @staticmethod
    def has_permission(user: str) -> bool:
        return True

    @classmethod
    def from_policy(cls, policy: Mapping[str, bool]) -> PermissionChecker:
        return cls()


class _Gate:
    def __call__(self, tool: str) -> bool:
        return tool != "shell"


permission_gate = _Gate()
