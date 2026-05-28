# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""FastAPI app factory for the Prompt Guard sidecar."""

from __future__ import annotations

from fastapi import FastAPI

from fabric_prompt_guard_sidecar._version import __version__
from fabric_prompt_guard_sidecar.classifier import (
    CheckRequest,
    CheckResponse,
    JailbreakChecker,
    PassthroughClassifier,
    PromptGuardClassifier,
)


def build_app(
    classifier: PromptGuardClassifier | None = None,
    *,
    threshold: float = 0.5,
) -> FastAPI:
    """Construct the FastAPI app with the given classifier.

    ``classifier`` defaults to :class:`PassthroughClassifier` (allows
    everything), which is the safe default for tests. The CLI refuses to
    start with the passthrough classifier in production unless
    ``--allow-passthrough`` is set, so a misconfigured deploy cannot
    silently disable jailbreak defence.

    ``threshold`` is the minimum injection/jailbreak probability that
    maps to ``action="block"``. It must be in ``[0, 1]``; a value
    outside that range is rejected so a typo cannot silently disable or
    over-fire the rail.
    """

    checker = JailbreakChecker(classifier or PassthroughClassifier(), threshold=threshold)
    app = FastAPI(
        title="fabric-prompt-guard-sidecar",
        version=__version__,
        docs_url=None,
        redoc_url=None,
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/check", response_model=CheckResponse)
    def check(request: CheckRequest) -> CheckResponse:
        return checker.check(request)

    return app
