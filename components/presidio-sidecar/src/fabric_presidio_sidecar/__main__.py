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

    analyzer = None
    try:
        from fabric_presidio_sidecar.presidio_analyzer import build_default_analyzer
        analyzer = build_default_analyzer()
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
        logger.info("wired real PresidioAnalyzer (presidio-analyzer + spaCy)")
    except ImportError as exc:
        if not args.allow_passthrough:
            parser.error(
                f"presidio extras not installed ({exc}); refusing to start "
                "with PassthroughAnalyzer (would silently redact nothing). "
                "Install the [presidio] extra, or pass --allow-passthrough "
                "for explicit no-op mode (dev / smoke only)."
            )
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
        logger.warning("starting with PassthroughAnalyzer (no PII redaction); --allow-passthrough set")

    app = build_app(analyzer=analyzer, tenant_key=tenant_key)

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
