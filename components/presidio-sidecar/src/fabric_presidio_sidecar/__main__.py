# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Sidecar entry point.

Serves on a Unix domain socket by default, HTTP on TCP for local dev.
"""

from __future__ import annotations

import argparse
import os
import sys

import uvicorn

from fabric_presidio_sidecar.app import build_app


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

    app = build_app(tenant_key=tenant_key)

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
