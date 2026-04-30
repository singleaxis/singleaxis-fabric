# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point.

Two commands:

* ``verify`` — takes a manifest file (or ``-`` for stdin), prints
  allow/deny with the reason. Used as an ArgoCD PreSync hook so an
  apply that would be blocked by the webhook anyway fails loud at
  sync time instead of silently half-applying.

* ``serve`` — boots the FastAPI app under uvicorn with the TLS
  cert at a fixed path. The K8s chart wires this up."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import typer
import uvicorn
import yaml

from .config import load_config
from .verifier import Verifier
from .webhook import create_app

app = typer.Typer(add_completion=False, help=__doc__)


@app.command()
def verify(
    manifest_path: Path = typer.Argument(
        ...,
        help="Path to the manifest YAML. Use '-' for stdin.",
    ),
    config_path: Path = typer.Option(
        Path("/etc/fabric/update-agent/config.yaml"),
        "--config",
        envvar="FABRIC_UPDATE_AGENT_CONFIG",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Verify a single manifest. Exits 0 on allow, 2 on deny."""

    _configure_logging(verbose)
    config = load_config(config_path)
    verifier = Verifier(config)
    manifests = _load_manifests(manifest_path)

    denied = 0
    for m in manifests:
        result = verifier.verify(m)
        name = _name(m)
        kind = m.get("kind", "<unknown>")
        if result.allowed:
            typer.echo(f"allow  kind={kind} name={name} signer={result.signer_id}")
        else:
            denied += 1
            typer.echo(f"deny   kind={kind} name={name} reason={result.reason}")
    if denied:
        raise typer.Exit(code=2)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host"),  # noqa: S104
    port: int = typer.Option(8443, "--port"),
    config_path: Path = typer.Option(
        Path("/etc/fabric/update-agent/config.yaml"),
        "--config",
        envvar="FABRIC_UPDATE_AGENT_CONFIG",
    ),
    tls_cert: Path = typer.Option(
        Path("/etc/fabric/webhook-tls/tls.crt"),
        "--tls-cert",
    ),
    tls_key: Path = typer.Option(
        Path("/etc/fabric/webhook-tls/tls.key"),
        "--tls-key",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run the admission webhook server."""

    _configure_logging(verbose)
    config = load_config(config_path)
    verifier = Verifier(config)
    app_ = create_app(verifier)
    cert_present = tls_cert.exists()
    key_present = tls_key.exists()
    if cert_present != key_present:
        # Refuse to fall back to plaintext on the admission webhook
        # path. Kubernetes API server requires TLS for ValidatingWebhook
        # callbacks; serving plaintext would either fail every admission
        # (if failurePolicy=Fail) or silently bypass admission (if
        # failurePolicy=Ignore) — both are customer-visible outages.
        raise SystemExit(
            f"update-agent: TLS cert+key must both be present or both "
            f"absent. cert={tls_cert} present={cert_present}, "
            f"key={tls_key} present={key_present}."
        )
    # Fully-plaintext mode is for local smoke testing only. Make the
    # operator opt in via an env flag rather than letting it happen
    # by default when both cert and key files are missing.
    if (
        not cert_present
        and not key_present
        and os.environ.get("FABRIC_UPDATE_AGENT_ALLOW_PLAINTEXT", "0") != "1"
    ):
        raise SystemExit(
            "update-agent: no TLS cert/key found; refusing to run "
            "plaintext on an admission webhook. Provide --tls-cert "
            "and --tls-key, or set FABRIC_UPDATE_AGENT_ALLOW_PLAINTEXT=1 "
            "for local smoke tests only."
        )
    uvicorn.run(
        app_,
        host=host,
        port=port,
        ssl_certfile=str(tls_cert) if cert_present else None,
        ssl_keyfile=str(tls_key) if key_present else None,
    )


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _load_manifests(path: Path) -> list[dict[str, object]]:
    text = sys.stdin.read() if str(path) == "-" else path.read_text(encoding="utf-8")
    docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    if not docs:
        raise typer.BadParameter(f"{path}: no YAML documents")
    return docs


def _name(manifest: dict[str, object]) -> str:
    meta = manifest.get("metadata")
    if isinstance(meta, dict):
        name = meta.get("name")
        if isinstance(name, str):
            return name
    return "<unnamed>"


def main() -> None:
    try:
        app(standalone_mode=True)
    except SystemExit as e:
        sys.exit(e.code)


if __name__ == "__main__":  # pragma: no cover
    main()
