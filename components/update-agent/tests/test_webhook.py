# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from fabric_update_agent.config import VerifierConfig
from fabric_update_agent.verifier import Verifier
from fabric_update_agent.webhook import create_app


def _review(obj: dict[str, Any] | None, uid: str = "uid-1") -> dict[str, Any]:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {"uid": uid, "object": obj},
    }


def test_healthz() -> None:
    app = create_app(Verifier(VerifierConfig(fabric_version="0.1.0")))
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_admit_allow(signed_configmap: dict[str, Any], config: VerifierConfig) -> None:
    app = create_app(Verifier(config))
    client = TestClient(app)
    r = client.post("/admit", json=_review(signed_configmap))
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "AdmissionReview"
    assert body["response"]["uid"] == "uid-1"
    assert body["response"]["allowed"] is True


def test_admit_deny(signed_configmap: dict[str, Any], config: VerifierConfig) -> None:
    signed_configmap["data"]["bundle.yaml"] = "tampered"
    app = create_app(Verifier(config))
    client = TestClient(app)
    r = client.post("/admit", json=_review(signed_configmap))
    body = r.json()
    assert body["response"]["allowed"] is False
    assert body["response"]["status"]["code"] == 403
    assert "did not verify" in body["response"]["status"]["message"]


def test_admit_without_object_is_allowed(config: VerifierConfig) -> None:
    # DELETE requests may not have an object in the request — the
    # webhook should never be the reason you can't clean up.
    app = create_app(Verifier(config))
    client = TestClient(app)
    r = client.post("/admit", json=_review(None))
    assert r.json()["response"]["allowed"] is True
