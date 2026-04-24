# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""FastAPI app factory for the NeMo sidecar.

``/v1/check`` runs the rails engine under a small dedicated
``ThreadPoolExecutor`` with an internal per-request timeout. This
protects ``/healthz`` — a single slow ``LLMRails.generate()`` used to
pin the shared default threadpool and block liveness probes; now each
/check slot has a bounded wallclock budget.

Timeout is read from ``FABRIC_REQUEST_TIMEOUT_MS`` at app-build time
(default 800). Concurrency of the dedicated pool is
``FABRIC_LIMIT_CONCURRENCY`` (default 16) so it doesn't outstrip the
uvicorn-level cap that ``__main__`` also applies.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from fabric_nemo_sidecar._version import __version__
from fabric_nemo_sidecar.rails import (
    CheckRequest,
    CheckResponse,
    PassthroughEngine,
    RailsChecker,
    RailsEngine,
)


def _timeout_seconds() -> float:
    """Read the per-request timeout from the env. Must be > 0."""

    raw = os.getenv("FABRIC_REQUEST_TIMEOUT_MS", "800")
    try:
        ms = int(raw)
    except ValueError:
        ms = 800
    if ms <= 0:
        ms = 800
    return ms / 1000.0


def _pool_size() -> int:
    raw = os.getenv("FABRIC_LIMIT_CONCURRENCY", "16")
    try:
        n = int(raw)
    except ValueError:
        n = 16
    return max(1, n)


def build_app(engine: RailsEngine | None = None) -> FastAPI:
    """Construct the FastAPI app with the given rails engine."""

    checker = RailsChecker(engine or PassthroughEngine())

    timeout_s = _timeout_seconds()
    executor = ThreadPoolExecutor(
        max_workers=_pool_size(),
        thread_name_prefix="fabric-nemo-check",
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="fabric-nemo-sidecar",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/check", response_model=CheckResponse)
    def check(request: CheckRequest) -> CheckResponse:
        future = executor.submit(checker.check, request)
        try:
            return future.result(timeout=timeout_s)
        except FutureTimeoutError as exc:
            # Fail-closed: a timeout is a policy failure, not a pass.
            # The SDK treats 504 as "rails unavailable → block".
            future.cancel()
            raise HTTPException(
                status_code=504,
                detail=(
                    f"rails check exceeded {int(timeout_s * 1000)}ms internal "
                    "timeout (FABRIC_REQUEST_TIMEOUT_MS)"
                ),
            ) from exc

    return app
