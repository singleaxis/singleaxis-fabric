# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The local-profile Fabric Node of AR-1, run as a host process from a built ``dist/``.

The configuration is the telemetry path of ``deploy/compose/collector-config/
collector.yaml`` (OTLP in, ``memory_limiter`` and ``fabricguard``, OTLP/HTTP out with the
``noredirect`` middleware) on loopback ports, delivering to the AR-1 sink. Local profile:
the agent writes content to its own ``file://`` store, so the Node carries telemetry
only and has no content pipeline. In live auditd mode the logs pipeline also has the
``audit`` receiver (netlink, ``rule_key`` of the AR-1 rules); the eBPF emitter sends its
records to the OTLP/gRPC port like any client. The Node starts through ``fabric-gate``,
which refuses a configuration that breaks the recorder's rules before the collector runs.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
DEFAULT_DIST = REPO / "components" / "otel-collector-fabric" / "dist"
AUDIT_RULE_KEY = "fabric_ar1"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def node_dist(explicit: str | None = None) -> Path | None:
    """The Node ``dist/`` (``fabric-gate`` beside ``otelcol-fabric``): ``explicit``, else
    ``$FABRIC_NODE_DIST``, else the repository build; ``None`` when not built."""
    for candidate in (explicit, os.environ.get("FABRIC_NODE_DIST"), str(DEFAULT_DIST)):
        if (
            candidate
            and (Path(candidate) / "fabric-gate").is_file()
            and (Path(candidate) / "otelcol-fabric").is_file()
        ):
            return Path(candidate)
    return None


def config(sink_url: str, grpc: int, http: int, health: int, *, audit: bool) -> dict[str, Any]:
    receivers: dict[str, Any] = {
        "otlp": {
            "protocols": {
                "grpc": {"endpoint": f"127.0.0.1:{grpc}"},
                "http": {"endpoint": f"127.0.0.1:{http}"},
            }
        },
    }
    logs_in = ["otlp"]
    if audit:
        receivers["audit"] = {
            "source": "netlink",
            "rule_key": AUDIT_RULE_KEY,
            "exec": True,
            "connect": True,
            "file_access": False,
            "manage_rules": False,
            "dedupe_window": "0s",
        }
        logs_in.append("audit")
    guarded = ["memory_limiter", "fabricguard"]
    return {
        "receivers": receivers,
        "extensions": {"health_check": {"endpoint": f"127.0.0.1:{health}"}, "noredirect": {}},
        "processors": {
            "memory_limiter": {"check_interval": "1s", "limit_mib": 512},
            "fabricguard": {
                "event_class_attribute": "event_class",
                "drop_unknown_classes": True,
                "max_field_bytes": 8192,
                "capture_labels": "pseudonymous",
            },
        },
        "exporters": {
            "otlp_http/sink": {
                "endpoint": sink_url,
                "timeout": "5s",
                "middlewares": [{"id": "noredirect"}],
                "tls": {"insecure": True},
                "sending_queue": {"enabled": True, "num_consumers": 2, "queue_size": 1000},
                "retry_on_failure": {
                    "enabled": True,
                    "initial_interval": "1s",
                    "max_interval": "5s",
                    "max_elapsed_time": "0s",
                },
            },
        },
        "service": {
            "extensions": ["health_check", "noredirect"],
            "pipelines": {
                "traces": {
                    "receivers": ["otlp"],
                    "processors": guarded,
                    "exporters": ["otlp_http/sink"],
                },
                "logs": {
                    "receivers": logs_in,
                    "processors": guarded,
                    "exporters": ["otlp_http/sink"],
                },
            },
            "telemetry": {"logs": {"level": "info"}, "metrics": {"level": "none"}},
        },
    }


class Node:
    """One Node process; ``otlp_http`` is the agent's ``OTEL_EXPORTER_OTLP_ENDPOINT``."""

    def __init__(self, dist: Path, directory: Path, sink_url: str, *, audit: bool = False) -> None:
        self.dist = dist
        self.directory = directory
        self.grpc, self.http, self.health = free_port(), free_port(), free_port()
        self.config_path = directory / "node-config.json"
        self.log_path = directory / "node.log"
        self.config_path.write_text(
            json.dumps(config(sink_url, self.grpc, self.http, self.health, audit=audit), indent=2)
        )
        self.process: subprocess.Popen[bytes] | None = None

    @property
    def otlp_http(self) -> str:
        return f"http://127.0.0.1:{self.http}"

    @property
    def otlp_grpc(self) -> str:
        return f"127.0.0.1:{self.grpc}"

    def start(self, timeout_s: float = 60.0) -> Node:
        log = self.log_path.open("ab")
        self.process = subprocess.Popen(  # noqa: S603 - the repository's own Node build
            [str(self.dist / "fabric-gate"), "--config", str(self.config_path)],
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=self.directory,
        )
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"the Node exited ({self.process.returncode}); see node.log")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.health}/", timeout=1):
                    return self
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("the Node did not become healthy; see node.log")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=30)
        self.process = None
