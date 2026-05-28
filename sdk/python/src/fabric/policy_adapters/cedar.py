# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AWS Cedar policy adapter.

Evaluates a Cedar policy set against a request via the cedarpy
bindings. Maps Cedar Allow/Deny (+ optional policy annotations) to
the 5-value PolicyDecision vocabulary. Behind the [cedar] extra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fabric.policy import EngineVerdict, PolicyAdapterError


@dataclass(slots=True)
class CedarAdapter:
    """PolicyEngine backed by AWS Cedar via cedarpy.

    Args:
        policies: Cedar policy source (the policy set as a string).
        entities: optional Cedar entities (list of entity dicts).
        engine_name: identifier emitted on events; defaults to "cedar".

    The ``input`` dict passed to ``evaluate`` must contain Cedar
    request fields: ``principal``, ``action``, ``resource``, and
    optional ``context``. The adapter forwards them to cedarpy.

    Decision mapping (spec 019 §Cedar adapter):

    - Allow + no annotations            -> ``allow``
    - Allow + annotation ``redact=true`` -> ``redact``
    - Allow + annotation ``warn=true``   -> ``warn``
    - Deny + annotation ``escalate=true`` -> ``escalate``
    - Deny otherwise                    -> ``deny``

    Requires cedarpy (pip install ``singleaxis-fabric[cedar]``).
    """

    policies: str
    entities: list[dict[str, Any]] = field(default_factory=list)
    engine_name: str = "cedar"
    _cedarpy: Any = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            import cedarpy  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover — covered by extras
            raise ImportError(
                "CedarAdapter requires cedarpy; install with `pip install singleaxis-fabric[cedar]`"
            ) from exc
        self._cedarpy = cedarpy

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        # Cedar request fields come from `input`.
        request = {
            "principal": input.get("principal"),
            "action": input.get("action"),
            "resource": input.get("resource"),
            "context": input.get("context", {}),
        }
        try:
            result = self._cedarpy.is_authorized(request, self.policies, self.entities)
        except Exception as exc:
            raise PolicyAdapterError(f"cedar evaluation failed: {exc}") from exc

        decision_str = str(getattr(result, "decision", "")).lower()
        annotations = self._extract_annotations(result)
        return self._map_verdict(decision_str, annotations, policy_id)

    @staticmethod
    def _extract_annotations(result: Any) -> dict[str, str]:
        # cedarpy attaches policy annotations on the determining
        # policies via diagnostics. Shape varies; best-effort extract
        # a {name: value} dict. Tests inject a simple shape.
        anns = getattr(result, "annotations", None)
        if isinstance(anns, dict):
            return {str(k): str(v) for k, v in anns.items()}
        return {}

    def _map_verdict(
        self, decision_str: str, annotations: dict[str, str], policy_id: str
    ) -> EngineVerdict:
        truthy = {"true", "1", "yes"}
        if decision_str == "allow":
            if annotations.get("redact", "").lower() in truthy:
                return EngineVerdict(decision="redact", reason="cedar allow + redact annotation")
            if annotations.get("warn", "").lower() in truthy:
                return EngineVerdict(decision="warn", reason="cedar allow + warn annotation")
            return EngineVerdict(decision="allow")
        # Deny (anything that is not an explicit allow).
        if annotations.get("escalate", "").lower() in truthy:
            return EngineVerdict(decision="escalate", reason="cedar deny + escalate annotation")
        return EngineVerdict(decision="deny", reason=f"cedar denied policy {policy_id}")

    def close(self) -> None:
        """No persistent client; no-op."""
