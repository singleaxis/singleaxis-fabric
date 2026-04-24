# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Sidecar entry point.

Serves on a Unix domain socket by default, HTTP on TCP for local dev.

Concurrency and timeout knobs (env vars, all optional):

- ``FABRIC_LIMIT_CONCURRENCY`` (default 16) — uvicorn ``limit_concurrency``.
  Caps the number of in-flight requests so ``/check`` cannot starve
  ``/healthz`` by saturating the ~40-thread default pool.
- ``FABRIC_REQUEST_TIMEOUT_MS`` (default 800) — per-request internal
  timeout around ``LLMRails.generate``. Read by ``app.build_app``.
"""

from __future__ import annotations

import argparse
import os
import sys

import uvicorn

from fabric_nemo_sidecar.app import build_app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fabric-nemo-sidecar")
    parser.add_argument("--uds", help="Unix domain socket path. Mutually exclusive with --port.")
    parser.add_argument("--port", type=int, help="TCP port (local dev only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--rails-config",
        help="Directory containing the Colang rails config. If unset, "
        "the sidecar serves a passthrough engine (fail-open) — set "
        "this in production.",
    )
    args = parser.parse_args(argv)

    if args.uds and args.port:
        parser.error("--uds and --port are mutually exclusive")
    if not args.uds and not args.port:
        parser.error("one of --uds or --port is required")

    engine = None
    if args.rails_config:
        from fabric_nemo_sidecar.nemo_adapter import build_default_engine  # noqa: PLC0415

        engine = build_default_engine(args.rails_config)

    app = build_app(engine=engine)

    kwargs: dict[str, object] = {
        "app": app,
        "log_config": None,
        "limit_concurrency": int(os.getenv("FABRIC_LIMIT_CONCURRENCY", "16")),
        "timeout_keep_alive": 5,
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
