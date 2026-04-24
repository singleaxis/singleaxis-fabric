# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Kubernetes ValidatingAdmissionWebhook HTTP handler.

The API server POSTs an ``AdmissionReview`` to ``/admit``; we reply
with the same object but the ``response`` field populated. Anything
not a plain ``dict`` manifest (e.g. a ``DELETE`` request without
``object``) is allowed so the webhook can never become the reason a
tenant can't clean up their cluster.

The server runs under ``uvicorn`` behind the TLS cert K8s expects at
``/etc/fabric/webhook-tls/{tls.crt,tls.key}``. The chart renders a
self-signed cert bootstrap Job for dev; production should swap in
cert-manager."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI

from .verifier import Verifier

_LOG = logging.getLogger(__name__)


def create_app(verifier: Verifier) -> FastAPI:
    app = FastAPI(title="fabric-update-agent", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/admit")
    def admit(review: dict[str, Any]) -> dict[str, Any]:
        return _admit(review, verifier)

    return app


def _admit(review: dict[str, Any], verifier: Verifier) -> dict[str, Any]:
    request = review.get("request") or {}
    uid = request.get("uid", "")
    manifest = request.get("object")

    response: dict[str, Any]
    if not isinstance(manifest, dict):
        # No object to verify (subresource, DELETE with no body, etc.).
        # Always allow — the webhook is narrow by design.
        response = {"uid": uid, "allowed": True}
    else:
        result = verifier.verify(manifest)
        response = {"uid": uid, "allowed": result.allowed}
        if not result.allowed:
            response["status"] = {
                "code": 403,
                "message": result.reason or "denied by fabric-update-agent",
                "reason": "Forbidden",
            }
            _LOG.info(
                "deny kind=%s name=%s reason=%s",
                manifest.get("kind"),
                _name(manifest),
                result.reason,
            )
        elif result.signer_id:
            _LOG.debug(
                "allow kind=%s name=%s signer=%s",
                manifest.get("kind"),
                _name(manifest),
                result.signer_id,
            )

    return {
        "apiVersion": review.get("apiVersion", "admission.k8s.io/v1"),
        "kind": "AdmissionReview",
        "response": response,
    }


def _name(manifest: dict[str, Any]) -> str:
    meta = manifest.get("metadata")
    if isinstance(meta, dict):
        name = meta.get("name")
        if isinstance(name, str):
            return name
    return "<unnamed>"
