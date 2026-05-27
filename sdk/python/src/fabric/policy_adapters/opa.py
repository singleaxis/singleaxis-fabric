# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""OPA (Open Policy Agent) adapter.

Talks to a sidecar OPA daemon over HTTP. Behind the [opa] extra
which pins httpx>=0.27.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, get_args

from fabric.policy import EngineVerdict, PolicyAdapterError, PolicyDecision

_DECISION_VOCAB = frozenset(get_args(PolicyDecision))


@dataclass(slots=True)
class OPAAdapter:
    """OPA adapter via the standard data API.

    Calls ``POST {base_url}/{decision_path_prefix}/{policy_id}`` with
    ``{"input": <input>}``. OPA returns ``{"result": <opa-policy-output>}``.

    The OPA policy is expected to emit:

    - a dict ``{"decision": "<vocab>", "reason": "...", ...}`` — best
    - a bare boolean ``true`` → ``allow``; ``false`` → ``deny`` with
      reason ``"policy returned false"``

    Any other shape raises PolicyAdapterError; the SDK converts to a
    fail-closed deny.

    Requires httpx (pip install ``singleaxis-fabric[opa]``).
    """

    base_url: str = "http://localhost:8181"
    decision_path_prefix: str = "v1/data"
    engine_name: str = "opa"
    _client: Any = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            import httpx  # type: ignore[import-not-found]  # noqa: F401, PLC0415
        except ImportError as exc:  # pragma: no cover — covered by extras
            raise ImportError(
                "OPAAdapter requires httpx; install with `pip install singleaxis-fabric[opa]`"
            ) from exc

    def _get_client(self, timeout_seconds: float) -> Any:
        import httpx  # noqa: PLC0415

        if self._client is None:
            self._client = httpx.Client(base_url=self.base_url, timeout=timeout_seconds)
        return self._client

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        import httpx  # noqa: PLC0415

        client = self._get_client(timeout_seconds)
        path = f"/{self.decision_path_prefix}/{policy_id}"
        try:
            response = client.post(path, json={"input": input}, timeout=timeout_seconds)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise PolicyAdapterError(f"OPA transport failed: {exc}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise PolicyAdapterError(f"OPA response not JSON: {exc}") from exc

        if not isinstance(payload, dict) or "result" not in payload:
            raise PolicyAdapterError(f"OPA response missing 'result': {payload!r}")

        result = payload["result"]
        return self._coerce_result(result)

    @staticmethod
    def _coerce_result(result: object) -> EngineVerdict:
        # Best shape: dict with decision/reason/version/evidence_ref
        if isinstance(result, dict):
            decision_raw = result.get("decision")
            if decision_raw not in _DECISION_VOCAB:
                raise PolicyAdapterError(
                    f"OPA returned unrecognized decision {decision_raw!r}; "
                    f"expected one of {sorted(_DECISION_VOCAB)}"
                )
            reason = result.get("reason")
            if reason is not None and not isinstance(reason, str):
                raise PolicyAdapterError(
                    f"OPA reason must be str or absent, got {type(reason).__name__}"
                )
            return EngineVerdict(
                decision=decision_raw,  # type: ignore[arg-type]
                policy_version=result.get("policy_version"),
                reason=reason,
                evidence_ref=result.get("evidence_ref"),
                bundle_signature=None,
            )
        # Bare boolean: allow / deny
        if isinstance(result, bool):
            if result:
                return EngineVerdict(decision="allow")
            return EngineVerdict(decision="deny", reason="policy returned false")
        raise PolicyAdapterError(
            f"OPA result must be dict or bool, got {type(result).__name__}: {result!r}"
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
