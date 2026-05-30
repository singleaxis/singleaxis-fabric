# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Generic JSON-over-HTTP policy adapter.

For tenant policy services that don't run OPA or Cedar directly.
No extras dependency; uses urllib from stdlib.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import get_args

from fabric.policy import EngineVerdict, PolicyAdapterError, PolicyDecision

_DECISION_VOCAB = frozenset(get_args(PolicyDecision))


@dataclass(slots=True)
class HTTPPolicyAdapter:
    """JSON-over-HTTP adapter for custom policy services.

    Wire shape::

        POST {endpoint}
        Content-Type: application/json
        { "policy_id": "<id>", "input": <input dict> }

    Response shape::

        {
          "decision": "allow|deny|warn|escalate|redact",
          "reason": "<optional>",
          "policy_version": "<optional>",
          "evidence_ref": "<optional>"
        }

    Raises PolicyAdapterError on transport failures, malformed
    responses, or unrecognized decision values.
    """

    endpoint: str
    headers: dict[str, str] = field(default_factory=dict)
    engine_name: str = "custom:http"

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        body = json.dumps({"policy_id": policy_id, "input": input}).encode("utf-8")
        request_headers = {"Content-Type": "application/json", **self.headers}
        req = urllib.request.Request(  # noqa: S310 — operator-supplied endpoint
            self.endpoint, data=body, headers=request_headers, method="POST"
        )
        try:
            # Endpoint is operator-supplied configuration, not attacker-controlled.
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:  # noqa: S310  # nosemgrep
                payload = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise PolicyAdapterError(f"HTTP transport failed: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyAdapterError(f"response not JSON: {exc}") from exc

        if not isinstance(payload, dict):
            raise PolicyAdapterError(f"response not an object: {type(payload).__name__}")
        decision_raw = payload.get("decision")
        if decision_raw not in _DECISION_VOCAB:
            raise PolicyAdapterError(
                f"unrecognized decision {decision_raw!r}; expected one of {sorted(_DECISION_VOCAB)}"
            )

        reason = payload.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise PolicyAdapterError(f"reason must be str or absent, got {type(reason).__name__}")

        return EngineVerdict(
            decision=decision_raw,  # type: ignore[arg-type]
            policy_version=payload.get("policy_version"),
            reason=reason,
            evidence_ref=payload.get("evidence_ref"),
            bundle_signature=None,  # OSS adapter
        )

    def close(self) -> None:
        """No persistent state; no-op."""
