# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Adapter that wires NeMo Guardrails' ``LLMRails`` to the sidecar's
:class:`RailsEngine` protocol.

Import is lazy and guarded so the sidecar can be installed and tested
without ``nemoguardrails`` and its transformer / LLM dependency chain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fabric_nemo_sidecar.rails import CheckAction, EngineResult

if TYPE_CHECKING:
    from nemoguardrails import LLMRails  # type: ignore[import-not-found]

_DEFAULT_RAIL = "unknown"


def _coerce_action(raw: object) -> CheckAction:
    """Map a NeMo rails verdict to our fixed action vocabulary.

    NeMo's public surface does not return a tagged action; the Colang
    ``bot refuse`` / ``bot allow`` flows drive the output. Adapters
    may inspect ``rails_info`` (in newer releases) or fall back to
    looking for a block_response string. We accept the most common
    shapes and fail-closed to ``block`` if we can't tell.
    """

    if isinstance(raw, str) and raw in ("allow", "redact", "block", "warn"):
        return raw  # type: ignore[return-value]
    return "block"


class NemoRailsEngine:
    """Wrap an ``LLMRails`` instance as a :class:`RailsEngine`.

    ``LLMRails.generate`` is synchronous and returns a string for a
    single-turn completion. We treat the returned text as the
    ``modified_value``; the action + rail are extracted from the
    rails-info dict that newer NeMo releases attach, with a
    fail-closed fallback.
    """

    __slots__ = ("_rails",)

    def __init__(self, rails: LLMRails) -> None:
        self._rails = rails

    def check(self, phase: str, path: str, value: str) -> EngineResult:
        # NeMo's API is conversation-shaped: pass the user turn as the
        # last message and read back the assistant response.
        messages: list[dict[str, Any]] = [{"role": "user", "content": value}]
        response: Any = self._rails.generate(messages=messages)

        modified = value
        rail = _DEFAULT_RAIL
        action: CheckAction = "allow"
        block_response: str | None = None

        if isinstance(response, dict):
            content = response.get("content")
            if isinstance(content, str):
                modified = content
            info = response.get("rails_info") or {}
            if isinstance(info, dict) and info:
                rail = str(info.get("rail") or _DEFAULT_RAIL)
                if "action" in info:
                    action = _coerce_action(info["action"])
                block_value = info.get("block_response")
                if isinstance(block_value, str):
                    block_response = block_value
        elif isinstance(response, str):
            modified = response

        allowed = action in ("allow", "redact", "warn")
        return EngineResult(
            allowed=allowed,
            action=action,
            rail=rail,
            block_response=block_response,
            modified_value=modified,
        )


def build_default_engine(config_path: str) -> NemoRailsEngine:
    """Construct a :class:`NemoRailsEngine` from a Colang config dir.

    Raises :class:`ImportError` if ``nemoguardrails`` is not installed.
    """

    from nemoguardrails import LLMRails, RailsConfig  # noqa: PLC0415

    config = RailsConfig.from_path(config_path)
    return NemoRailsEngine(LLMRails(config))
