# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hot-path endpoint matching (spec 047 §2): string compares only."""

from __future__ import annotations

from collections.abc import Sequence

from ._model import EndpointMatcher, WireApi

OPERATION_NAMES: dict[str, str] = {
    "openai.chat_completions": "chat", "openai.responses": "chat",
    "openai.completions": "text_completion", "openai.embeddings": "embeddings",
    "anthropic.messages": "chat",
}  # fmt: skip
_SUFFIXES: dict[str, tuple[tuple[str, WireApi], ...]] = {
    "openai": (
        ("/chat/completions", "openai.chat_completions"), ("/responses", "openai.responses"),
        ("/completions", "openai.completions"), ("/embeddings", "openai.embeddings"),
    ),
    "anthropic": (("/messages", "anthropic.messages"),),
}  # fmt: skip
_DEFAULT_PORTS = {"https": 443, "http": 80}


def api_for_path(dialect: str, path: str) -> WireApi | None:
    """Map a request path (no query string) to its wire API, if recognized."""
    return next((api for suffix, api in _SUFFIXES.get(dialect, ()) if path.endswith(suffix)), None)


class EndpointIndex:
    """Lowercased hosts per matcher, scanned in order (a handful of matchers at most)."""

    __slots__ = ("_entries",)

    def __init__(self, matchers: Sequence[EndpointMatcher]) -> None:
        self._entries = tuple(
            (m, frozenset(h.lower() for h in m.hosts), tuple(s.lower() for s in m.host_suffixes))
            for m in matchers
        )

    def match(
        self, method: str, scheme: str, host: str, port: int | None, path: str
    ) -> tuple[EndpointMatcher, WireApi] | None:
        """The first matching endpoint and API for a request, else ``None``."""
        if method != "POST":
            return None
        host = host.lower()
        for matcher, hosts, suffixes in self._entries:
            if host not in hosts and not host.endswith(suffixes):  # endswith takes a tuple
                continue
            if scheme not in matcher.schemes or not path.startswith(matcher.path_prefix):
                continue
            if (
                matcher.ports is not None
                and (port or _DEFAULT_PORTS.get(scheme)) not in matcher.ports
            ):
                continue
            if (api := api_for_path(matcher.dialect, path)) is not None:
                return matcher, api
        return None
