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
        help="Directory containing the Colang rails config. Required "
        "for production. Pass --allow-passthrough to opt into the "
        "fail-open passthrough engine for local smoke tests only.",
    )
    parser.add_argument(
        "--allow-passthrough",
        action="store_true",
        help="Permit running without --rails-config. The sidecar will "
        "use the passthrough engine which allows everything — only for "
        "local development. Refused without this flag in 0.1.3+.",
    )
    args = parser.parse_args(argv)

    if args.uds and args.port:
        parser.error("--uds and --port are mutually exclusive")
    if not args.uds and not args.port:
        parser.error("one of --uds or --port is required")

    if not args.rails_config and not args.allow_passthrough:
        parser.error(
            "--rails-config is required. Without it the sidecar would "
            "fall back to a passthrough engine that allows everything, "
            "silently disabling jailbreak/policy defence. Pass "
            "--allow-passthrough explicitly for local smoke tests."
        )

    engine = None
    if args.rails_config:
        from fabric_nemo_sidecar.nemo_adapter import build_default_engine  # noqa: PLC0415

        engine = build_default_engine(args.rails_config)
    else:
        # --allow-passthrough was set; emit a startup-time warning so
        # the operator can see this in pod logs. The rail name on
        # every /check response stamps PASSTHROUGH_FAIL_OPEN so any
        # downstream dashboard surfaces the misconfiguration.
        import logging  # noqa: PLC0415

        logging.getLogger("fabric_nemo_sidecar").warning(
            "NeMo sidecar starting in PASSTHROUGH mode "
            "(--allow-passthrough): jailbreak/policy defence is "
            "disabled. DO NOT use in production."
        )

    # Concurrency env-var: parse robustly. A non-int value should
    # surface a clear error rather than crashing the whole sidecar
    # start with "ValueError: invalid literal for int()".
    raw_conc = os.getenv("FABRIC_LIMIT_CONCURRENCY", "16")
    try:
        limit_concurrency = int(raw_conc)
    except ValueError:
        parser.error(f"FABRIC_LIMIT_CONCURRENCY={raw_conc!r} is not a valid integer")
        return 2  # pragma: no cover (parser.error raises)

    app = build_app(engine=engine)

    kwargs: dict[str, object] = {
        "app": app,
        "log_config": None,
        "limit_concurrency": limit_concurrency,
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
