# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Model-looking requests that matched no configured endpoint (integration audit F2).

A request to a model host Fabric does not know (a self-hosted or custom provider) passes
through the tee unrecorded, which is correct: Fabric never captures a host it was not
told about. It must not be silent. A request that looks like a model call (``POST`` to
an OpenAI- or Anthropic-style API path) and matched no endpoint is counted per host, and
the first one for each host logs one diagnostic on the ``fabric.wire`` logger that names
the host and the ``FABRIC_WIRE_ENDPOINTS`` entry that would record it.
``WireHandle.status()`` lists the hosts and ``WireHandle.stats()`` counts the requests.

Only the method, scheme, host, port and path are read, never a query string, header or
body. Nothing here raises, blocks or changes the request (spec 057 B1-B4)."""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

_LOG = logging.getLogger("fabric.wire")
# Path endings of the model APIs the openai and anthropic dialects parse (``_match.py``),
# with the API version where the bare suffix is a common non-model path.
_MODEL_SUFFIXES = (
    "/chat/completions", "/v1/completions", "/v1/responses", "/v1/embeddings", "/v1/messages",
)  # fmt: skip
_MAX_HOSTS = 16  # hosts tracked by name; requests to further hosts are still counted
_DEFAULT_PORTS = {"https": 443, "http": 80}
MSG_UNMATCHED = (
    "fabric.wire: a model-looking request to %s matched no configured endpoint and was not "
    "recorded. Fix: export FABRIC_WIRE_ENDPOINTS='%s' [FW-006]"
)


def looks_like_model_call(method: str, path: str) -> bool:
    return method.upper() == "POST" and path.rstrip("/").endswith(_MODEL_SUFFIXES)


def endpoint_entry(scheme: str, host: str, port: int | None, path: str) -> str:
    """The one ``FABRIC_WIRE_ENDPOINTS`` value (a JSON array) that records this host."""
    entry: dict[str, Any] = {
        "endpoint_id": "my-model",
        "dialect": "anthropic" if path.rstrip("/").endswith("/v1/messages") else "openai",
        "hosts": [host],
        "ports": [port or _DEFAULT_PORTS.get(scheme, 443)],
        "schemes": [scheme],
    }
    return json.dumps([entry], separators=(",", ":"))


class UnmatchedModelHosts:
    """Per-host counts of model-looking requests no endpoint matched (bounded)."""

    __slots__ = ("_hosts", "_lock", "count")

    def __init__(self) -> None:
        self.count = 0
        self._hosts: dict[tuple[str, str, int | None], list[Any]] = {}
        self._lock = threading.Lock()

    def note(self, method: Any, scheme: Any, host: Any, port: Any, path: Any) -> None:
        """Account one request the tee did not record; never raises."""
        try:
            if not looks_like_model_call(str(method), str(path)):
                return
            scheme, host = str(scheme).lower(), str(host).lower()
            port = int(port) if port is not None else None
            key = (scheme, host, port)
            with self._lock:
                self.count += 1
                row = self._hosts.get(key)
                if row is not None:
                    row[0] += 1
                    return
                if len(self._hosts) >= _MAX_HOSTS:
                    return
                fix = endpoint_entry(scheme, host, port, str(path))
                self._hosts[key] = [1, fix]
            _LOG.warning(MSG_UNMATCHED, _named(scheme, host, port), fix)
        except Exception:  # noqa: S110 - a diagnostic never reaches the agent
            pass

    def status(self) -> list[dict[str, Any]]:
        """``[{host, port, count, fix}]``, one per host, in first-seen order."""
        with self._lock:
            return [
                {"host": host, "port": port or _DEFAULT_PORTS.get(scheme, 443), "count": row[0],
                 "fix": f"export FABRIC_WIRE_ENDPOINTS='{row[1]}'"}
                for (scheme, host, port), row in self._hosts.items()
            ]  # fmt: skip

    def reset(self) -> None:
        """After fork: the child is a new source."""
        self._lock = threading.Lock()
        self._hosts = {}
        self.count = 0


def _named(scheme: str, host: str, port: int | None) -> str:
    return f"{scheme}://{host}" + (f":{port}" if port else "")
