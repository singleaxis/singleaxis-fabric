# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""FastAPI app factory for the Presidio sidecar."""

from __future__ import annotations

from fastapi import FastAPI

from fabric_presidio_sidecar._version import __version__
from fabric_presidio_sidecar.redactor import (
    PassthroughAnalyzer,
    PIIAnalyzer,
    RedactionRequest,
    RedactionResponse,
    Redactor,
)


def build_app(
    analyzer: PIIAnalyzer | None = None,
    tenant_key: bytes | None = None,
) -> FastAPI:
    """Construct the FastAPI app with the given analyzer.

    ``tenant_key`` is required for production deployments; the CLI
    enforces this via the ``--tenant-key-file`` flag. Tests that do not
    care about hashing behaviour may pass an arbitrary non-empty byte
    string (the ``PassthroughAnalyzer`` never invokes the HMAC path).
    Passing ``None`` or the default sentinel is rejected so no caller
    can accidentally ship deterministic, cross-deployment HMACs.
    """

    if tenant_key is None or not tenant_key or tenant_key == b"change-me":
        raise ValueError(
            "tenant_key must be a real, non-sentinel byte string; refusing "
            "to build an app with a default key so HMACs are not reversible "
            "across deployments"
        )
    redactor = Redactor(analyzer or PassthroughAnalyzer(), tenant_key)
    app = FastAPI(
        title="fabric-presidio-sidecar", version=__version__, docs_url=None, redoc_url=None
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/redact", response_model=RedactionResponse)
    def redact(request: RedactionRequest) -> RedactionResponse:
        return redactor.redact(request)

    return app
