# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""NeMo Colang rail client for the SDK.

Spec 005 calls for NeMo Guardrails to run in-process. In practice
``nemoguardrails`` pulls spaCy, transformers, and a handful of model
dependencies that a) bloat the SDK wheel and b) force an LLM
provider dependency into a pure-typing-only install. So the SDK
ships this as a :class:`Protocol` plus a UDS sidecar client — the
same pattern as :mod:`fabric.presidio`. Hosts that want true
in-process execution can implement :class:`NemoClient` over a local
``LLMRails`` instance and pass it straight to :class:`fabric.Fabric`;
the chain does not care which implementation it gets.

Wire contract for the sidecar endpoint ``POST /v1/check``:

Request:

.. code-block:: json

    {"phase": "input", "path": "input", "value": "<text>"}

Response:

.. code-block:: json

    {
      "allowed": true,
      "action": "allow",
      "rail": "jailbreak_defence",
      "block_response": null,
      "modified_value": "<possibly-rewritten text>"
    }

``action`` ∈ ``{allow, redact, block, warn}`` mirrors spec 005's
``GuardrailAction``. ``rail`` is the Colang rail id (e.g.
``off_topic``, ``refusal_policy``, ``jailbreak_defence``) — it is
emitted on the OTel event as ``nemo:<rail>``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from ._uds import UDSHTTPConnection

DEFAULT_TIMEOUT_SECONDS = 1.0
_HTTP_OK = 200

NemoAction = Literal["allow", "redact", "block", "warn"]


@dataclass(frozen=True)
class NemoResult:
    """Per-call verdict returned by the NeMo rail.

    ``allowed`` and ``action`` are redundant by design — the SDK
    treats ``action == "block"`` as the blocking signal, and every
    non-allow action implies a rail fired. Keeping both lets hosts
    reason about "did anything trip?" separately from "must we stop?"
    """

    allowed: bool
    action: NemoAction
    rail: str
    block_response: str | None
    modified_value: str


class NemoError(RuntimeError):
    """Raised on any transport or protocol failure talking to the
    sidecar. Fail-closed: callers should drop the turn, not forward
    the raw value, if NeMo cannot verify it.
    """


@runtime_checkable
class NemoClient(Protocol):
    """Client surface the :class:`GuardrailChain` depends on.

    Runtime-checkable so tests can swap in a fake without inheriting.
    Implementations MUST be safe to call from multiple threads — the
    chain does not serialize calls itself.
    """

    def check(self, phase: str, path: str, value: str) -> NemoResult: ...

    def close(self) -> None: ...


class UDSNemoClient:
    """Default :class:`NemoClient` backed by HTTP over a UDS.

    Opens one connection per request — NeMo's per-call latency
    (10-80 ms p99 on typical inputs per spec 005) dominates, so
    connection pooling is not worth the complexity in Phase 1.
    """

    def __init__(self, socket_path: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        if not socket_path:
            raise ValueError("socket_path must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._socket_path = socket_path
        self._timeout = timeout

    def check(self, phase: str, path: str, value: str) -> NemoResult:
        payload = json.dumps({"phase": phase, "path": path, "value": value}).encode("utf-8")
        conn = UDSHTTPConnection(self._socket_path, timeout=self._timeout)
        try:
            try:
                conn.request(
                    "POST",
                    "/v1/check",
                    body=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Host": "nemo.sock",
                    },
                )
                response = conn.getresponse()
                body = response.read(1 << 20)
            except OSError as err:
                raise NemoError(f"sidecar transport error: {err}") from err
            if response.status != _HTTP_OK:
                raise NemoError(f"nemo sidecar returned {response.status}: {body[:256]!r}")
            try:
                decoded = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as err:
                raise NemoError(f"decode sidecar response: {err}") from err
            try:
                action = decoded["action"]
                if action not in ("allow", "redact", "block", "warn"):
                    raise NemoError(f"invalid action {action!r} from sidecar")
                return NemoResult(
                    allowed=bool(decoded["allowed"]),
                    action=action,
                    rail=str(decoded["rail"]),
                    block_response=decoded.get("block_response"),
                    modified_value=str(decoded["modified_value"]),
                )
            except (KeyError, TypeError) as err:
                raise NemoError(f"sidecar response missing field: {err}") from err
        finally:
            conn.close()

    def close(self) -> None:
        """No-op — see :meth:`UDSPresidioClient.close`."""
