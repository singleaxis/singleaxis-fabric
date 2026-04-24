# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point. Installed as ``fabric-langfuse-bootstrap``."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import typer

from .main import bootstrap

app = typer.Typer(add_completion=False, help=__doc__)


@app.command()
def run(
    host: str = typer.Option(
        "http://langfuse:3000",
        envvar="LANGFUSE_HOST",
        help="Base URL of the target Langfuse.",
    ),
    public_key: str = typer.Option(
        ...,
        envvar="LANGFUSE_PUBLIC_KEY",
        help="Langfuse project public key (pk-lf-…).",
    ),
    secret_key: str = typer.Option(
        ...,
        envvar="LANGFUSE_SECRET_KEY",
        help="Langfuse project secret key (sk-lf-…).",
    ),
    curated_dir: Path = typer.Option(
        Path("/etc/fabric/curated"),
        envvar="FABRIC_CURATED_DIR",
        help="Directory holding common.yaml + <profile>.yaml.",
    ),
    profile: str = typer.Option(
        "permissive-dev",
        envvar="FABRIC_PROFILE",
        help="Regulatory profile whose overlay to apply.",
    ),
    wait_seconds: float = typer.Option(
        60.0,
        envvar="FABRIC_BOOTSTRAP_WAIT_SECONDS",
        help="How long to wait for Langfuse /health before giving up.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Apply the curated bundle for ``profile`` to Langfuse at ``host``."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    code = bootstrap(
        host=host,
        public_key=public_key,
        secret_key=secret_key,
        curated_dir=curated_dir,
        profile=profile,
        wait_for_ready_seconds=wait_seconds,
    )
    raise typer.Exit(code=code)


def main() -> None:
    # Typer's app() calls sys.exit internally; wrap so unit tests can
    # capture the exit code deterministically.
    try:
        app(standalone_mode=True)
    except SystemExit as e:
        sys.exit(e.code)


if __name__ == "__main__":  # pragma: no cover
    main()
