# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Thin Langfuse Public API client for the bootstrap Job.

Deliberately not a full Langfuse SDK — we only call the subset needed
to apply the curated bundle: score-configs, prompts, health. Using the
upstream SDK would pull in the entire ingestion pipeline, which this
Job does not need."""

from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

from .config import ScoreConfig

_LOG = logging.getLogger(__name__)


class LangfuseError(RuntimeError):
    """Raised for non-2xx responses from the Langfuse public API."""

    def __init__(self, message: str, *, status_code: int, body: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class LangfuseBootstrapClient:
    """Idempotent creators for score-configs and prompts.

    ``apply_score_config`` and ``apply_prompt`` are both safe to call
    repeatedly: on conflict the existing entity is returned, on novel
    input it's created. Callers do not need to list-then-create."""

    def __init__(
        self,
        *,
        host: str,
        public_key: str,
        secret_key: str,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._host = host.rstrip("/")
        token = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode("ascii")
        self._headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        }
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    def __enter__(self) -> LangfuseBootstrapClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # ---- health -----------------------------------------------------

    def health(self) -> bool:
        """Returns True iff Langfuse's /api/public/health reports OK."""

        resp = self._client.get(f"{self._host}/api/public/health", headers=self._headers)
        return resp.status_code == 200

    # ---- score configs ----------------------------------------------

    def list_score_configs(self) -> list[dict[str, Any]]:
        resp = self._client.get(
            f"{self._host}/api/public/score-configs",
            headers=self._headers,
            params={"limit": 100},
        )
        self._raise_for(resp, "list score-configs")
        data = resp.json()
        return list(data.get("data", []))

    def apply_score_config(self, config: ScoreConfig) -> dict[str, Any]:
        """Create-if-missing. Langfuse score-config names are unique
        per project, so we list-then-decide."""

        existing = {c["name"]: c for c in self.list_score_configs()}
        if config.name in existing:
            _LOG.info("score-config already present: %s", config.name)
            return existing[config.name]

        payload: dict[str, Any] = {
            "name": config.name,
            "dataType": config.data_type.value,
            "description": config.description,
        }
        if config.min_value is not None:
            payload["minValue"] = config.min_value
        if config.max_value is not None:
            payload["maxValue"] = config.max_value
        if config.categories:
            payload["categories"] = [
                {"label": c.label, "value": c.value} for c in config.categories
            ]

        resp = self._client.post(
            f"{self._host}/api/public/score-configs",
            headers=self._headers,
            json=payload,
        )
        self._raise_for(resp, f"create score-config {config.name!r}")
        _LOG.info("score-config created: %s", config.name)
        return dict(resp.json())

    # ---- prompts ----------------------------------------------------

    def apply_prompt(
        self,
        *,
        name: str,
        prompt: str,
        labels: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new prompt version. Langfuse versions prompts by
        name — posting the same content twice is harmless but creates
        a second version, so we probe first."""

        existing = self._fetch_prompt(name)
        if existing and existing.get("prompt") == prompt:
            _LOG.info("prompt already at head version: %s", name)
            return existing

        payload: dict[str, Any] = {
            "name": name,
            "type": "text",
            "prompt": prompt,
            "labels": labels or ["production"],
            "tags": tags or ["fabric"],
        }
        resp = self._client.post(
            f"{self._host}/api/public/v2/prompts",
            headers=self._headers,
            json=payload,
        )
        self._raise_for(resp, f"create prompt {name!r}")
        _LOG.info("prompt created/updated: %s", name)
        return dict(resp.json())

    def _fetch_prompt(self, name: str) -> dict[str, Any] | None:
        resp = self._client.get(
            f"{self._host}/api/public/v2/prompts/{name}",
            headers=self._headers,
        )
        if resp.status_code == 404:
            return None
        self._raise_for(resp, f"fetch prompt {name!r}")
        return dict(resp.json())

    # ---- saved-view URLs --------------------------------------------

    def render_saved_view_url(self, filters: dict[str, str]) -> str:
        """Compose a shareable Langfuse trace-filter URL.

        Langfuse's filter URL takes a JSON-ish query string. We only
        need equality filters for Fabric's saved views, so this is a
        tiny deterministic encoder rather than a full DSL."""

        import urllib.parse

        parts = [f"{k}={v}" for k, v in sorted(filters.items())]
        encoded = urllib.parse.quote(";".join(parts))
        return f"{self._host}/project/traces?filter={encoded}"

    # ---- internal ---------------------------------------------------

    def _raise_for(self, resp: httpx.Response, what: str) -> None:
        if resp.is_success:
            return
        raise LangfuseError(
            f"{what} failed: {resp.status_code}",
            status_code=resp.status_code,
            body=resp.text[:1024],
        )
