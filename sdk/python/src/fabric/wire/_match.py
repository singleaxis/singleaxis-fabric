# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hot-path endpoint matching (spec 042 §2).

String compares only: no regex, no allocation for a non-matching request
beyond the URL component reads ``httpx`` already caches.
"""

from __future__ import annotations

from collections.abc import Sequence

from ._model import EndpointMatcher, WireApi

__all__ = ["OPERATION_NAMES", "EndpointIndex", "api_for_path"]

OPERATION_NAMES: dict[str, str] = {
    "openai.chat_completions": "chat",
    "openai.responses": "chat",
    "openai.completions": "text_completion",
    "openai.embeddings": "embeddings",
    "anthropic.messages": "chat",
}

_DEFAULT_PORTS = {"https": 443, "http": 80}


def api_for_path(dialect: str, path: str) -> WireApi | None:  # noqa: PLR0911
    """Map a request path (no query string) to its wire API, if recognized."""
    if dialect == "openai":
        if path.endswith("/chat/completions"):
            return "openai.chat_completions"
        if path.endswith("/responses"):
            return "openai.responses"
        if path.endswith("/completions"):
            return "openai.completions"
        if path.endswith("/embeddings"):
            return "openai.embeddings"
        return None
    if dialect == "anthropic" and path.endswith("/messages"):
        return "anthropic.messages"
    return None


class EndpointIndex:
    """Precomputed lookup over a set of :class:`EndpointMatcher` values."""

    __slots__ = ("_by_host", "_suffixed")

    def __init__(self, matchers: Sequence[EndpointMatcher]) -> None:
        by_host: dict[str, list[EndpointMatcher]] = {}
        suffixed: list[tuple[str, EndpointMatcher]] = []
        for matcher in matchers:
            for host in matcher.hosts:
                by_host.setdefault(host.lower(), []).append(matcher)
            for suffix in matcher.host_suffixes:
                suffixed.append((suffix.lower(), matcher))
        self._by_host = {host: tuple(found) for host, found in by_host.items()}
        self._suffixed = tuple(suffixed)

    def match(
        self, method: str, scheme: str, host: str, port: int | None, path: str
    ) -> tuple[EndpointMatcher, WireApi] | None:
        """Return the first matcher and API for a request, else ``None``."""
        if method != "POST":
            return None
        host = host.lower()
        candidates = self._by_host.get(host, ())
        for matcher in candidates:
            found = self._check(matcher, scheme, port, path)
            if found is not None:
                return matcher, found
        for suffix, matcher in self._suffixed:
            if host.endswith(suffix):
                found = self._check(matcher, scheme, port, path)
                if found is not None:
                    return matcher, found
        return None

    @staticmethod
    def _check(
        matcher: EndpointMatcher, scheme: str, port: int | None, path: str
    ) -> WireApi | None:
        if scheme not in matcher.schemes:
            return None
        if matcher.ports is not None:
            effective = port if port is not None else _DEFAULT_PORTS.get(scheme)
            if effective not in matcher.ports:
                return None
        if matcher.path_prefix and not path.startswith(matcher.path_prefix):
            return None
        return api_for_path(matcher.dialect, path)
