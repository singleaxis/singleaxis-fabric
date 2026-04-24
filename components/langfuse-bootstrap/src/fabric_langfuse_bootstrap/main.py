# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bootstrap orchestration.

Called by the Kubernetes Job and by the docker-compose harness. Reads
the curated bundle for the active Fabric profile, applies it to the
target Langfuse, and prints the saved-view URLs at the end so
operators can drop them straight into a runbook."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from .client import LangfuseBootstrapClient, LangfuseError
from .config import CuratedBundle, load_bundle

_LOG = logging.getLogger("fabric_langfuse_bootstrap")


def bootstrap(
    *,
    host: str,
    public_key: str,
    secret_key: str,
    curated_dir: Path,
    profile: str,
    wait_for_ready_seconds: float = 60.0,
) -> int:
    """Apply the curated bundle for ``profile`` to Langfuse at ``host``.

    Returns a Unix-style exit code — 0 on success, 1 on apply failure.
    """

    bundle = load_bundle(curated_dir, profile)
    _LOG.info(
        "loaded curated bundle: profile=%s scores=%d views=%d prompts=%d",
        profile,
        len(bundle.score_configs),
        len(bundle.saved_views),
        len(bundle.prompts),
    )

    with LangfuseBootstrapClient(
        host=host,
        public_key=public_key,
        secret_key=secret_key,
    ) as client:
        if not _wait_for_ready(client, wait_for_ready_seconds):
            _LOG.error("Langfuse never became healthy at %s", host)
            return 1
        try:
            _apply(client, bundle)
        except LangfuseError as e:
            _LOG.error("bootstrap failed: %s (status=%d)", e, e.status_code)
            return 1
    return 0


def _wait_for_ready(client: LangfuseBootstrapClient, deadline_seconds: float) -> bool:
    # Probe at least once even when the deadline is zero — callers pass
    # ``0.0`` to mean "just check now", not "skip the probe".
    end = time.monotonic() + deadline_seconds
    while True:
        try:
            if client.health():
                return True
        except Exception as e:
            _LOG.debug("health probe error (will retry): %s", e)
        if time.monotonic() >= end:
            return False
        time.sleep(2.0)


def _apply(client: LangfuseBootstrapClient, bundle: CuratedBundle) -> None:
    for score in bundle.score_configs:
        client.apply_score_config(score)
    for prompt in bundle.prompts:
        client.apply_prompt(
            name=prompt.name,
            prompt=prompt.prompt,
            labels=prompt.labels or None,
            tags=prompt.tags or None,
        )
    if bundle.saved_views:
        _LOG.info("saved-view URLs (drop into the profile runbook):")
        for view in bundle.saved_views:
            url = client.render_saved_view_url(view.filters)
            _LOG.info("  %-32s %s", view.name, url)
            sys.stdout.write(f"{view.name}\t{url}\n")
            sys.stdout.flush()
