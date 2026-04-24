# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Core rails-check logic.

The sidecar's one job: given a ``(phase, path, value)`` tuple, run it
through a Colang rails runner and return an action. The engine
interface is pluggable — NeMo in production, a passthrough engine in
tests and in setups where the operator has not wired any rails yet.

The wire contract is fixed by ``sdk/python/src/fabric/nemo.py``; if
you are changing these models you are also changing the SDK.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

CheckAction = Literal["allow", "redact", "block", "warn"]


class CheckRequest(BaseModel):
    """Input to ``POST /v1/check``."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)

    phase: Literal["input", "output_stream", "output_final"]
    path: str = Field(min_length=1, max_length=256)
    value: str = Field(min_length=0, max_length=64_000)


class CheckResponse(BaseModel):
    """Output from ``POST /v1/check``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    action: CheckAction
    rail: str
    block_response: str | None = None
    modified_value: str


@dataclass(slots=True)
class EngineResult:
    """Internal result from a ``RailsEngine`` implementation."""

    allowed: bool
    action: CheckAction
    rail: str
    block_response: str | None
    modified_value: str


class RailsEngine(Protocol):
    """Pluggable rails backend.

    The NeMo adapter implements this over ``LLMRails``; the passthrough
    engine is the safe default when no Colang config is loaded.
    """

    def check(self, phase: str, path: str, value: str) -> EngineResult: ...


class PassthroughEngine:
    """Engine that allows everything. Used as a safe default in tests
    and when ``nemoguardrails`` is not installed or no config path is
    configured. ``rail`` is fixed so span events remain queryable."""

    __slots__ = ("_rail",)

    def __init__(self, rail: str = "passthrough") -> None:
        self._rail = rail

    def check(self, phase: str, path: str, value: str) -> EngineResult:
        return EngineResult(
            allowed=True,
            action="allow",
            rail=self._rail,
            block_response=None,
            modified_value=value,
        )


class RailsChecker:
    """Applies a :class:`RailsEngine` and returns a wire-level
    :class:`CheckResponse`. The pydantic boundary lives here so
    engines can stay free of FastAPI / pydantic coupling."""

    __slots__ = ("_engine",)

    def __init__(self, engine: RailsEngine) -> None:
        self._engine = engine

    def check(self, request: CheckRequest) -> CheckResponse:
        result = self._engine.check(request.phase, request.path, request.value)
        return CheckResponse(
            allowed=result.allowed,
            action=result.action,
            rail=result.rail,
            block_response=result.block_response,
            modified_value=result.modified_value,
        )
