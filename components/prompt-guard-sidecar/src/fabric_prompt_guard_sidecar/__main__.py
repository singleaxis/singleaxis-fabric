# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Sidecar entry point.

Serves on a Unix domain socket by default, HTTP on TCP for local dev.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

import uvicorn

from fabric_prompt_guard_sidecar.app import build_app

# Re-exported so tests (and any tooling) can monkeypatch the symbol the
# CLI actually calls; the explicit __all__ keeps mypy's
# no-implicit-reexport happy when build_app is accessed via this module.
__all__ = ["build_app", "main"]

logger = logging.getLogger("fabric_prompt_guard_sidecar")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fabric-prompt-guard-sidecar")
    parser.add_argument("--uds", help="Unix domain socket path. Mutually exclusive with --port.")
    parser.add_argument("--port", type=int, help="TCP port (local dev only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--model-id",
        default=None,
        help=(
            "HuggingFace model id for the Llama Prompt Guard classifier. "
            "Defaults to the [model] adapter's built-in default "
            "(meta-llama/Llama-Prompt-Guard-2-86M). Ignored when "
            "--allow-passthrough is used without the [model] extra."
        ),
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help=(
            "Minimum injection/jailbreak probability (0..1) that maps to "
            "action='block'. Lower = more aggressive. Default 0.5."
        ),
    )
    parser.add_argument(
        "--allow-passthrough",
        action="store_true",
        help=(
            "Allow the sidecar to start with the PassthroughClassifier "
            "(flags nothing) when the [model] extra is not installed. "
            "Without this flag the sidecar fails fast so a misconfigured "
            "production deployment cannot silently disable jailbreak "
            "defence."
        ),
    )
    args = parser.parse_args(argv)

    if args.uds and args.port:
        parser.error("--uds and --port are mutually exclusive")
    if not args.uds and not args.port:
        parser.error("one of --uds or --port is required")
    if not 0.0 <= args.threshold <= 1.0:
        parser.error(f"--threshold must be in [0, 1]; got {args.threshold!r}")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    classifier = None
    try:
        from fabric_prompt_guard_sidecar.prompt_guard import (  # noqa: PLC0415
            build_default_classifier,
        )

        classifier = (
            build_default_classifier(args.model_id) if args.model_id else build_default_classifier()
        )
        logger.info("wired real Llama Prompt Guard classifier (transformers + torch)")
    except ImportError as exc:
        if not args.allow_passthrough:
            parser.error(
                f"model extras not installed ({exc}); refusing to start "
                "with PassthroughClassifier (would silently disable "
                "jailbreak defence). Install the [model] extra, or pass "
                "--allow-passthrough for explicit no-op mode (dev / smoke "
                "only)."
            )
        logger.warning(
            "starting with PassthroughClassifier (no jailbreak defence); --allow-passthrough set"
        )

    app = build_app(classifier=classifier, threshold=args.threshold)
    logger.info("jailbreak block threshold: %.3f", args.threshold)

    kwargs: dict[str, object] = {
        "app": app,
        "log_config": None,
    }
    if args.uds:
        if os.path.exists(args.uds):
            os.unlink(args.uds)
        kwargs["uds"] = args.uds
    else:
        kwargs["host"] = args.host
        kwargs["port"] = args.port

    uvicorn.run(**kwargs)  # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    sys.exit(main())
