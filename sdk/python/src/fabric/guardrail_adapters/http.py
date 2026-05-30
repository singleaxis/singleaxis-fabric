# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Generic JSON-over-HTTP guardrail adapter.

For custom classifiers / tenant moderation services that don't have
a dedicated Fabric adapter. Zero dependency — stdlib urllib only.

Wire shape (request)::

    POST {endpoint}
    Content-Type: application/json
    { "phase": "input", "path": "input", "value": "<text>" }

Wire shape (response)::

    {
      "action": "allow|redact|warn|block|escalate",
      "modified_value": "<optional rewritten text>",
      "reason": "<optional>",
      "rail": "<optional>"
    }
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import get_args

from fabric.guardrails import CheckerVerdict, GuardrailAction

_ACTION_VOCAB = frozenset(get_args(GuardrailAction))


@dataclass(slots=True)
class HTTPGuardrailChecker:
    """GuardrailChecker over generic JSON/HTTP.

    Args:
        endpoint: URL of the tenant guardrail service.
        headers: optional extra headers (e.g. auth).
        timeout_seconds: per-request timeout.
        name: rail name prefix; defaults to "custom:http".
        fail_open: if True, transport errors map to allow (NOT
            recommended). Default False = fail closed (block).
    """

    endpoint: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 3.0
    name: str = "custom:http"
    fail_open: bool = False

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:  # noqa: PLR0911 — each return is a distinct fail-closed branch
        body = json.dumps({"phase": phase, "path": path, "value": value}).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310 — operator-supplied endpoint
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json", **self.headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # noqa: S310
                payload = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError) as exc:
            if self.fail_open:
                return CheckerVerdict(
                    action="allow",
                    rail=self.name,
                    reason=f"transport error (fail-open): {exc}",
                )
            return CheckerVerdict(
                action="block",
                rail=self.name,
                reason=f"transport error (fail-closed): {exc}",
            )
        except json.JSONDecodeError as exc:
            return CheckerVerdict(
                action="block", rail=self.name, reason=f"non-JSON response: {exc}"
            )

        if not isinstance(payload, dict):
            return CheckerVerdict(action="block", rail=self.name, reason="response not an object")
        action = payload.get("action")
        if action not in _ACTION_VOCAB:
            return CheckerVerdict(
                action="block",
                rail=self.name,
                reason=f"unrecognized action {action!r}; expected one of {sorted(_ACTION_VOCAB)}",
            )
        modified = payload.get("modified_value")
        if modified is not None and not isinstance(modified, str):
            return CheckerVerdict(
                action="block", rail=self.name, reason="modified_value must be str or absent"
            )
        reason = payload.get("reason")
        rail = payload.get("rail") or self.name
        return CheckerVerdict(
            action=action,  # type: ignore[arg-type]
            modified_value=modified,
            reason=reason if isinstance(reason, str) else None,
            rail=rail if isinstance(rail, str) else self.name,
        )

    def close(self) -> None:
        """No persistent state; no-op."""
