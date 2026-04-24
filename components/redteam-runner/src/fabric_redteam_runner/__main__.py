# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point — installed as ``fabric-redteam-runner``.

Used by the Kubernetes CronJob. Also runnable locally against the
integration harness for dev testing:

    fabric-redteam-runner run \\
        --config /etc/fabric/redteam/run.yaml \\
        --otlp-endpoint http://localhost:4318
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import typer
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from .config import load_run_config
from .emitter import OTelEmitter
from .runner import Runner, load_suite

app = typer.Typer(add_completion=False, help=__doc__)


@app.command()
def run(
    config_path: Path = typer.Option(
        Path("/etc/fabric/redteam/run.yaml"),
        "--config",
        envvar="FABRIC_REDTEAM_CONFIG",
        help="Path to the YAML run config.",
    ),
    otlp_endpoint: str = typer.Option(
        "http://otel-collector:4318",
        "--otlp-endpoint",
        envvar="OTEL_EXPORTER_OTLP_ENDPOINT",
        help="Base URL of the Fabric OTel collector (HTTP).",
    ),
    service_name: str = typer.Option(
        "fabric-redteam-runner",
        envvar="OTEL_SERVICE_NAME",
    ),
    fail_on_findings: bool = typer.Option(
        True,
        help="Exit nonzero when at least one probe failed (useful for CronJob retries).",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Execute one run against the configured agent."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_run_config(config_path)
    _install_otel_provider(service_name=service_name, endpoint=otlp_endpoint)

    suites = [load_suite(s.name) for s in config.suites if _suite_known(s.name)]
    result = Runner(suites).run(config)

    emitter = OTelEmitter()
    emitter.emit(result)

    # Ensure the BatchSpanProcessor flushes before the process exits —
    # short-lived CronJobs often terminate faster than the default
    # schedule delay, which loses the final batch.
    provider = trace.get_tracer_provider()
    if hasattr(provider, "force_flush"):
        provider.force_flush(timeout_millis=5000)
    if hasattr(provider, "shutdown"):
        provider.shutdown()

    logging.info(
        "redteam run complete: run_id=%s probes=%d fails=%d",
        result.run_id,
        len(result.probes),
        result.fail_count,
    )
    if fail_on_findings and result.fail_count > 0:
        raise typer.Exit(code=2)


def _suite_known(name: str) -> bool:
    try:
        load_suite(name)
    except ValueError:
        logging.warning("unknown suite in config, skipping: %s", name)
        return False
    return True


def _install_otel_provider(*, service_name: str, endpoint: str) -> None:
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "service.namespace": "fabric",
                "event_class": "redteam_run",
            }
        )
    )
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces"))
    )
    trace.set_tracer_provider(provider)


def main() -> None:
    try:
        app(standalone_mode=True)
    except SystemExit as e:
        sys.exit(e.code)


if __name__ == "__main__":  # pragma: no cover
    main()
