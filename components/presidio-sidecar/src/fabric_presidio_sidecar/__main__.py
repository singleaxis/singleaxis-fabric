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

from fabric_presidio_sidecar.app import build_app

# Re-exported so tests (and any tooling) can monkeypatch the symbol the
# CLI actually calls; the explicit __all__ keeps mypy's no-implicit-reexport
# happy when build_app is accessed via this module.
__all__ = ["build_app", "main"]

logger = logging.getLogger("fabric_presidio_sidecar")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fabric-presidio-sidecar")
    parser.add_argument("--uds", help="Unix domain socket path. Mutually exclusive with --port.")
    parser.add_argument("--port", type=int, help="TCP port (local dev only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--tenant-key-file",
        required=True,
        help=(
            "Path to the file containing the tenant HMAC key (bytes). "
            "Required: the sidecar refuses to start without a real tenant "
            "key so that HMACs are not reversible across deployments."
        ),
    )
    parser.add_argument(
        "--allow-passthrough",
        action="store_true",
        help=(
            "Allow the sidecar to start with the PassthroughAnalyzer "
            "(redacts nothing) when the [presidio] extra is not "
            "installed. Without this flag the sidecar fails fast so a "
            "misconfigured production deployment cannot silently ship "
            "a no-op redactor."
        ),
    )
    parser.add_argument(
        "--redaction-mode",
        choices=["hmac", "tag"],
        default="hmac",
        help=(
            "Redaction strategy when PII is detected. 'hmac' (default) "
            "returns a tenant-scoped HMAC-SHA256 of the full value. 'tag' "
            "replaces each detected entity in-place with a category-typed "
            "placeholder like <EMAIL_1>. Default stays 'hmac' for backward "
            "compatibility; tag mode is recommended for any agent that "
            "feeds the redacted value back to an LLM (multi-turn)."
        ),
    )
    args = parser.parse_args(argv)

    if args.uds and args.port:
        parser.error("--uds and --port are mutually exclusive")
    if not args.uds and not args.port:
        parser.error("one of --uds or --port is required")

    with open(args.tenant_key_file, "rb") as fh:
        tenant_key = fh.read().strip()
    if not tenant_key or tenant_key == b"change-me":
        parser.error(
            "tenant key file is empty or contains the default sentinel "
            "'change-me'; supply a real key via --tenant-key-file"
        )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    analyzer = None
    try:
        from fabric_presidio_sidecar.presidio_analyzer import (  # noqa: PLC0415
            build_default_analyzer,
        )

        analyzer = build_default_analyzer()
        logger.info("wired real PresidioAnalyzer (presidio-analyzer + spaCy)")
    except ImportError as exc:
        if not args.allow_passthrough:
            parser.error(
                f"presidio extras not installed ({exc}); refusing to start "
                "with PassthroughAnalyzer (would silently redact nothing). "
                "Install the [presidio] extra, or pass --allow-passthrough "
                "for explicit no-op mode (dev / smoke only)."
            )
        logger.warning(
            "starting with PassthroughAnalyzer (no PII redaction); --allow-passthrough set"
        )

    app = build_app(analyzer=analyzer, tenant_key=tenant_key, mode=args.redaction_mode)
    logger.info("redaction mode: %s", args.redaction_mode)

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
