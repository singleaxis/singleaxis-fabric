# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from fabric_presidio_sidecar import build_app

from .stub_analyzer import RegexAnalyzer


def test_healthz() -> None:
    app = build_app(tenant_key=b"t")
    with TestClient(app) as c:
        resp = c.get("/healthz")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["version"]


def test_build_app_rejects_missing_tenant_key() -> None:
    with pytest.raises(ValueError, match="tenant_key"):
        build_app()


def test_build_app_rejects_default_sentinel() -> None:
    with pytest.raises(ValueError, match="tenant_key"):
        build_app(tenant_key=b"change-me")


def test_redact_passthrough() -> None:
    app = build_app(tenant_key=b"t")
    with TestClient(app) as c:
        resp = c.post("/v1/redact", json={"path": "p", "value": "alice@example.com"})
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"value": "alice@example.com", "hashed": False, "pii_category": ""}


def test_redact_hashes_with_regex_analyzer() -> None:
    app = build_app(analyzer=RegexAnalyzer(), tenant_key=b"t")
    with TestClient(app) as c:
        resp = c.post("/v1/redact", json={"path": "p", "value": "alice@example.com"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["hashed"] is True
        assert body["pii_category"] == "EMAIL_ADDRESS"
        assert body["value"] != "alice@example.com"


def test_redact_rejects_extra_fields() -> None:
    app = build_app(tenant_key=b"t")
    with TestClient(app) as c:
        resp = c.post("/v1/redact", json={"path": "p", "value": "x", "leak": "y"})
        assert resp.status_code == 422
