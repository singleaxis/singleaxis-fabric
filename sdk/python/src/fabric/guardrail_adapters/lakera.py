# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Lakera Guard adapter — a GuardrailChecker backed by Lakera's
hosted prompt-injection / content-moderation API.

Behind the [lakera] extra (httpx). The tenant supplies their own
Lakera API key; Fabric integrates, it does not resell Lakera.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fabric.guardrails import CheckerVerdict

_DEFAULT_ENDPOINT = "https://api.lakera.ai/v2/guard"


@dataclass(slots=True)
class LakeraGuardChecker:
    """GuardrailChecker that calls Lakera Guard.

    On a flagged result Lakera returns categories (prompt_injection,
    jailbreak, moderation, pii, etc.). This adapter maps a flagged
    response to action="block" (the conservative default) with the
    triggering category as the rail. Operators wanting warn-instead-of-
    block for certain categories can subclass and override
    ``_verdict_for``.

    Args:
        api_key: Lakera API key. Required.
        endpoint: Guard API endpoint. Defaults to the v2 guard URL.
        timeout_seconds: per-request timeout.
        block_on: set of Lakera category names that map to block.
            Defaults to the injection/jailbreak categories. Categories
            flagged but not in this set map to "warn".
    """

    api_key: str
    endpoint: str = _DEFAULT_ENDPOINT
    timeout_seconds: float = 3.0
    block_on: frozenset[str] = field(
        default_factory=lambda: frozenset({"prompt_injection", "jailbreak"})
    )
    name: str = "lakera"
    _client: Any = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.api_key:
            raise ValueError("LakeraGuardChecker requires a non-empty api_key")
        try:
            import httpx  # type: ignore[import-not-found, unused-ignore]  # noqa: F401, PLC0415
        except ImportError as exc:  # pragma: no cover — covered by the [lakera] extra
            raise ImportError(
                "LakeraGuardChecker requires httpx; install singleaxis-fabric[lakera]"
            ) from exc

    def _get_client(self) -> Any:
        import httpx  # noqa: PLC0415

        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout_seconds)
        return self._client

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        import httpx  # noqa: PLC0415

        if not value:
            return CheckerVerdict(action="allow", rail=self.name)
        client = self._get_client()
        try:
            resp = client.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"messages": [{"role": "user", "content": value}]},
            )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            # Fail closed: a guardrail that can't reach its backend
            # must not silently allow. The chain converts a raised
            # exception to a block, but we return an explicit block so
            # the reason is precise.
            return CheckerVerdict(
                action="block",
                reason=f"lakera transport error: {exc}",
                rail=self.name,
            )
        return self._verdict_for(payload)

    def _verdict_for(self, payload: dict[str, Any]) -> CheckerVerdict:
        # Lakera v2 returns
        # {"flagged": bool, "results": [{"category": ..., "flagged": bool, ...}]}
        flagged = bool(payload.get("flagged", False))
        if not flagged:
            return CheckerVerdict(action="allow", rail=self.name)
        results = payload.get("results", []) or []
        flagged_categories = [r.get("category", "") for r in results if r.get("flagged")]
        block_hit = next((c for c in flagged_categories if c in self.block_on), None)
        if block_hit is not None:
            return CheckerVerdict(
                action="block",
                reason=f"lakera flagged: {block_hit}",
                rail=f"lakera:{block_hit}",
            )
        # Flagged but not a block category -> warn
        first = flagged_categories[0] if flagged_categories else "unknown"
        return CheckerVerdict(
            action="warn",
            reason=f"lakera flagged (non-blocking): {first}",
            rail=f"lakera:{first}",
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
