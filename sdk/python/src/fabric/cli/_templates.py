# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The Compose project ``fabric up`` renders for the local profile (spec 058 §5.4): the
Fabric Node with a TLS listener, the local-dir sink, and optionally the host sensor.

The templates are packaged with the CLI as code (the wheel ships code only), so ``up``
needs no repository clone. Every image is a digest reference; every mount is a path;
no secret value is ever written into a rendered file."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import _config, _localsink, _secrets
from ._images import Images

NODE_SERVICE = _secrets.NODE_SERVICE
SINK_SERVICE = "fabric-sink"
SENSOR_SERVICE = "fabric-sensor"
SPOOL_INIT_SERVICE = "fabric-sensor-spool"
COMPOSE_FILE = "docker-compose.yml"
NODE_CONFIG_FILE = "node.yaml"
SINK_FILE = "otlp_sink.py"
PROJECT_LABEL = "ai.singleaxis.fabric.project"
NODE_IMAGE_GID = 65532  # the Node image's nonroot user and group
_TLS_DIR = "/run/fabric-node/tls"
_SINK_HEALTH = (
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
)
_HARDENING: dict[str, Any] = {
    "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
    "restart": "unless-stopped",
    "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
}  # fmt: skip


@dataclass(frozen=True)
class Layout:
    """Where the rendered project and its state live, and what it mounts."""

    compose_dir: Path  # .fabric/compose
    queue_dir: Path  # .fabric/state/node-queue: the Node's durable queue
    data_dir: Path  # the local-dir destination (./fabric-data)
    node_cert: Path
    node_key: Path
    ca_cert: Path
    port: int  # loopback port of the Node's OTLP/HTTP TLS listener
    user: str | None  # "uid:gid" the Node and the sink run as; None: the image's user
    sensor_cgroup: str | None = None  # set: run the sensor, scoped to this cgroup


def node_config() -> dict[str, Any]:
    """The local Node: OTLP over TLS in, the export allowlist, a durable queue, the sink.
    Content is written by the SDK to the file store in the local profile, so there is no
    content pipeline."""
    tls = {"cert_file": f"{_TLS_DIR}/node.crt", "key_file": f"{_TLS_DIR}/node.key",
           "min_version": "1.2"}  # fmt: skip
    return {
        "receivers": {"otlp": {"protocols": {
            "grpc": {"endpoint": "0.0.0.0:4317", "tls": dict(tls)},
            "http": {"endpoint": "0.0.0.0:4318", "tls": dict(tls)},
        }}},
        "extensions": {
            # A 3xx from the destination is a retryable failure, never followed (048 H1).
            "noredirect": {"loss_outbox": {"directory": "/var/lib/fabric-node/queue/loss-outbox"}},
            "file_storage/fabric": {"directory": "/var/lib/fabric-node/queue", "timeout": "1s",
                                    "create_directory": True, "fsync": True},
        },
        "processors": {
            "memory_limiter": {"check_interval": "1s", "limit_mib": 512},
            "fabricguard": {"event_class_attribute": "event_class", "drop_unknown_classes": True,
                            "max_field_bytes": 8192, "capture_labels": "pseudonymous"},
        },
        "exporters": {"otlp_http/local_dir": {
            # The sink is on the project's own Compose network; only the Node reaches it.
            "endpoint": f"http://{SINK_SERVICE}:8080", "timeout": "5s",
            "middlewares": [{"id": "noredirect"}], "tls": {"insecure": True},
            "sending_queue": {"enabled": True, "num_consumers": 2, "queue_size": 1000,
                              "block_on_overflow": True, "storage": "file_storage/fabric"},
            "retry_on_failure": {"enabled": True, "initial_interval": "1s",
                                 "max_interval": "5s", "max_elapsed_time": "0s"},
        }},
        "service": {
            "extensions": ["noredirect", "file_storage/fabric"],
            "pipelines": {signal: {"receivers": ["otlp"],
                                   "processors": ["memory_limiter", "fabricguard"],
                                   "exporters": ["otlp_http/local_dir"]}
                          for signal in ("traces", "logs")},
            "telemetry": {"logs": {"level": "info"}},
        },
    }  # fmt: skip


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def compose(project: str, compose_project: str, images: Images, layout: Layout,
            node_config_text: str, cert_fingerprint: str) -> dict[str, Any]:  # fmt: skip
    """The Compose document. Labels carry the digests of what a container mounts, so a
    changed Node configuration or certificate recreates the Node on the next ``up``."""
    labels = {PROJECT_LABEL: project}
    user = {"user": layout.user} if layout.user else {}
    sink: dict[str, Any] = {
        "image": images.sink, "command": ["python", f"/app/{SINK_FILE}"], **user,
        "environment": {"SINK_DATA_DIR": "/data", "SINK_PORT": "8080",
                        "PYTHONDONTWRITEBYTECODE": "1"},
        "volumes": [f"{layout.compose_dir / SINK_FILE}:/app/{SINK_FILE}:ro",
                    f"{layout.data_dir / 'spans'}:/data/spans",
                    f"{layout.data_dir / 'host-logs'}:/data/host-logs"],
        "healthcheck": {
            "test": ["CMD", "python", "-c", _SINK_HEALTH],
            "interval": "2s", "timeout": "3s", "retries": 30},
        "networks": ["fabric"], "labels": dict(labels), **_HARDENING,
    }  # fmt: skip
    node: dict[str, Any] = {
        "image": images.node, "command": [f"--config=/etc/fabric-node/{NODE_CONFIG_FILE}"],
        **user,
        "volumes": [
            f"{layout.compose_dir / NODE_CONFIG_FILE}:/etc/fabric-node/{NODE_CONFIG_FILE}:ro",
            f"{layout.node_cert}:{_TLS_DIR}/node.crt:ro",
            f"{layout.node_key}:{_TLS_DIR}/node.key:ro",
            f"{layout.queue_dir}:/var/lib/fabric-node/queue"],
        # Loopback only: other machines never reach the local profile's Node.
        "ports": [f"127.0.0.1:{layout.port}:4318"],
        "depends_on": {SINK_SERVICE: {"condition": "service_healthy"}},
        "tmpfs": ["/tmp"],  # noqa: S108 - a container path
        "stop_grace_period": "30s", "networks": ["fabric"],
        "labels": {**labels, "ai.singleaxis.fabric.node-config": _digest(node_config_text),
                   "ai.singleaxis.fabric.node-cert": cert_fingerprint[-16:]},
        **_HARDENING,
    }  # fmt: skip
    document: dict[str, Any] = {
        "name": compose_project,
        "services": {SINK_SERVICE: sink, NODE_SERVICE: node},
        "networks": {"fabric": {"driver": "bridge"}},
    }
    if layout.sensor_cgroup:
        document["volumes"] = {"sensor-spool": {}}
        # The emitter refuses a spool that is not a private directory of its own user.
        document["services"][SPOOL_INIT_SERVICE] = {
            "image": images.sink, "user": "0:0", "network_mode": "none", "restart": "no",
            "command": ["python", "-c", "import os; os.chmod('/spool', 0o700)"],
            "volumes": ["sensor-spool:/spool"], "labels": dict(labels),
            "read_only": True, "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
        }  # fmt: skip
        document["services"][SENSOR_SERVICE] = {
            "image": images.sensor,
            # bpf() and tracefs need root inside the container; every capability is dropped
            # except the four the tracepoint programs need (031). Read-only, passive.
            "user": "0:0", "pid": "host", "cgroup": "host",
            "cap_add": ["BPF", "PERFMON", "SYS_RESOURCE", "DAC_READ_SEARCH"],
            "environment": {
                "EMIT_ENDPOINT": f"{NODE_SERVICE}:4317",
                "EMIT_TLS_CA_FILE": "/etc/fabric-host-emitter/ca.crt",
                "EMIT_CGROUP_PATH": layout.sensor_cgroup,
                "EMIT_SPOOL_DIR": "/var/lib/fabric-host-emitter",
            },
            "volumes": [
                "/sys/kernel/btf:/sys/kernel/btf:ro", "/sys/kernel/tracing:/sys/kernel/tracing:ro",
                "/sys/kernel/debug:/sys/kernel/debug:ro", "/sys/fs/cgroup:/sys/fs/cgroup:ro",
                f"{layout.ca_cert}:/etc/fabric-host-emitter/ca.crt:ro",
                "sensor-spool:/var/lib/fabric-host-emitter"],
            "depends_on": {NODE_SERVICE: {"condition": "service_started"},
                           SPOOL_INIT_SERVICE: {"condition": "service_completed_successfully"}},
            "networks": ["fabric"], "labels": dict(labels), **_HARDENING,
        }  # fmt: skip
    return document


def dump(document: dict[str, Any], header: str) -> str:
    yaml = _config._yaml()
    body: str = yaml.safe_dump(document, sort_keys=False, default_flow_style=False)
    return header + body


def sink_source() -> str:
    """The bundled sink's source, copied into the project and mounted into its container."""
    return Path(_localsink.__file__).read_text(encoding="utf-8")


RENDER_HEADER = (
    "# Rendered by `fabric up` from fabric.yaml and this CLI release's pinned images.\n"
    "# Do not edit: the next `fabric up` rewrites it. It holds paths, never secret values.\n"
)
