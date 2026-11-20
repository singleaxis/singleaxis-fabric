# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The Compose project ``fabric up`` renders for the single-host production shape (spec
058 §5.4, WP8-24): the Fabric Node with static dedicated ingress groups, the trial
destination when it is the preset, the canary tap (§9.3) when the destination cannot be
read back, and the eBPF sensor in production mode.

The Node's configuration is the one the ingress-group Compose files run
(``deploy/compose/collector-config/collector-production-groups.yaml`` and
``collector-production-groups-content.yaml``: the same groups, guards, listeners, queues
and exporters, a test keeps them equal) with one more group, ``canary``: the canary of
``fabric verify`` has its own token, listeners and binding, so the Node binds its records
by the listener they arrive on and an agent's records never reach the tap. The templates
are code (the wheel ships code only). Every mount is a path; no secret value is written
into a rendered file: the one value the Node reads by value, the destination's
Authorization header, reaches Compose from ``fabric up``'s own environment
(``FABRIC_EXPORT_AUTH_HEADER``), as the manual route's env file gives it."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import _secrets, _templates
from ._images import Images

NODE_SERVICE = _secrets.NODE_SERVICE
TRIAL_OTLP_SERVICE = _secrets.TRIAL_OTLP_SERVICE
TRIAL_S3_SERVICE = _secrets.TRIAL_S3_SERVICE
TRIAL_S3_INIT_SERVICE = "fabric-trial-s3-init"
CANARY_TAP_SERVICE = "fabric-canary-tap"
SENSOR_SERVICE = _templates.SENSOR_SERVICE
SENSOR_STATE_INIT_SERVICE = "fabric-sensor-state"
#: The groups of a production Node: the agent, the host sensor and the canary (§7.1).
GROUPS = ("agent", "ebpf", "canary")
#: The variable that carries the destination's Authorization header from `fabric up`'s
#: environment into the Node's (never written into a rendered file).
EXPORT_HEADER_VARIABLE = "FABRIC_EXPORT_AUTH_HEADER"
#: The bounded canary tap (§9.3): at most this many bytes of canary span files are kept,
#: the oldest removed first.
TAP_MAX_BYTES = 16 * 1024 * 1024
#: The trial store's S3 port, published on loopback for the reader (`fabric verify`).
TRIAL_S3_PORT = 8333
TRIAL_BUCKET = "fabric-content"
CONTENT_PREFIX = "fabric/content/"
CANARY_CONTENT_QUEUE_ITEMS = 8
_TLS = "/run/fabric-node/tls"
_SECRETS = "/run/secrets"
_PORTS = {"agent_grpc": 4317, "agent_http": 4318, "content_agent": 4319,
          "canary_http": 4320, "content_canary": 4321, "ebpf_grpc": 4417}  # fmt: skip


@dataclass(frozen=True)
class ProdLayout:
    """What the production project mounts, publishes and binds. Paths are host paths;
    values are identifiers, never secrets."""

    compose_dir: Path
    queue_dir: Path
    content_queue_dirs: dict[str, Path]  # group -> the host directory of its content queue
    data_dir: Path
    tap_dir: Path
    secrets_dir: Path
    port: int  # loopback port of the agent group's OTLP/HTTP listener (4318)
    user: str | None
    tenant: str
    source_ids: dict[str, str]  # group -> the source id its guard binds
    preset: str
    export_endpoint: str
    export_ca: Path | None  # the CA the Node verifies the span destination with
    export_header: bool  # the destination takes an Authorization header
    content: bool  # an S3 content store (trial, s3, s3-compatible) with content on
    content_store: dict[str, str] = field(default_factory=dict)  # FABRIC_CONTENT_S3_*
    s3_ca: Path | None = None
    s3_credentials: Path | None = None
    telemetry_items: int = 10000
    content_items: int = 64
    sensor_cgroup: str | None = None
    sensor_labels: dict[str, str] = field(default_factory=dict)  # source and host label

    @property
    def tap(self) -> bool:
        """The canary tap: for a destination Fabric cannot read spans back from."""
        return self.preset != "trial"

    def host_port(self, name: str) -> int:
        return self.port + {"agent_http": 0, "content_agent": 1, "canary_http": 2,
                            "content_canary": 3}[name]  # fmt: skip


def _receiver_tls() -> dict[str, str]:
    return {"cert_file": f"{_TLS}/node.crt", "key_file": f"{_TLS}/node.key", "min_version": "1.3"}


def _grpc(port: int, group: str) -> dict[str, Any]:
    return {
        "endpoint": f"0.0.0.0:{port}", "auth": {"authenticator": f"bearertokenauth/{group}"},
        "max_recv_msg_size_mib": 8, "max_concurrent_streams": 64,
        "keepalive": {"enforcement_policy": {"min_time": "10s", "permit_without_stream": False}},
        "tls": _receiver_tls(),
    }  # fmt: skip


def _http(port: int, group: str, *, content: bool = False) -> dict[str, Any]:
    return {
        "endpoint": f"0.0.0.0:{port}", "auth": {"authenticator": f"bearertokenauth/{group}"},
        "read_header_timeout": "5s", "read_timeout": "120s" if content else "30s",
        "idle_timeout": "120s",
        "max_request_body_size": 67108864 if content else 8388608,
        "tls": _receiver_tls(),
    }  # fmt: skip


def _guard(group: str, kind: str, source_variable: str) -> dict[str, Any]:
    guard: dict[str, Any] = {
        "event_class_attribute": "event_class", "drop_unknown_classes": True,
        "max_field_bytes": 8192, "capture_labels": "pseudonymous",
        "identity_mode": "pseudonymous", "profile": "production", "source_kind": kind,
    }  # fmt: skip
    if kind == "host.ebpf":
        guard["host_digests"] = "omitted"
    guard["evidence_source_binding"] = {"tenant_id": "${env:FABRIC_TENANT_ID}",
                                        "source_id": "${env:" + source_variable + "}"}  # fmt: skip
    return guard


def _queue(items: int, storage: str | None, consumers: int = 4) -> dict[str, Any]:
    queue: dict[str, Any] = {"enabled": True, "num_consumers": consumers, "queue_size": items,
                             "block_on_overflow": True}  # fmt: skip
    if storage:
        queue["storage"] = storage
    return queue


_RETRY = {"enabled": True, "initial_interval": "5s", "max_interval": "30s",
          "max_elapsed_time": "0s"}  # fmt: skip
SOURCE_VARIABLES = {"agent": "FABRIC_AGENT_SOURCE_ID", "ebpf": "FABRIC_EBPF_SOURCE_ID",
                    "canary": "FABRIC_CANARY_SOURCE_ID"}  # fmt: skip


def node_config(layout: ProdLayout) -> dict[str, Any]:
    """The production Node: the ingress groups of collector-production-groups.yaml (agent,
    ebpf) plus the canary group, the content path of collector-production-groups-content
    .yaml for the agent and the canary when the destination has a content store, the
    customer's span destination, and the canary tap (canary spans only) when that
    destination cannot be read back."""
    extensions: dict[str, Any] = {
        "health_check": {"endpoint": "0.0.0.0:13133"},
        "noredirect": {"loss_outbox": {"directory": "/var/lib/fabric-node/queue/loss-outbox"}},
        "file_storage/fabric": {
            "directory": "/var/lib/fabric-node/queue", "timeout": "1s",
            "create_directory": True, "fsync": True,
            "compaction": {"directory": "/var/lib/fabric-node/queue", "on_start": True,
                           "on_rebound": True}},
    }  # fmt: skip
    for group in GROUPS:
        extensions[f"bearertokenauth/{group}"] = {
            "filename": f"{_SECRETS}/fabric_{group}_token",
            "require_single_token": True,
        }
    receivers: dict[str, Any] = {
        "otlp/agent": {"protocols": {"grpc": _grpc(_PORTS["agent_grpc"], "agent"),
                                     "http": _http(_PORTS["agent_http"], "agent")}},
        "otlp/ebpf": {"protocols": {"grpc": _grpc(_PORTS["ebpf_grpc"], "ebpf")}},
        "otlp/canary": {"protocols": {"http": _http(_PORTS["canary_http"], "canary")}},
    }  # fmt: skip
    processors: dict[str, Any] = {
        "memory_limiter": {"check_interval": "1s", "limit_mib": 1536 if layout.content else 512},
        "fabricguard/agent": _guard("agent", "agent", SOURCE_VARIABLES["agent"]),
        "fabricguard/ebpf": _guard("ebpf", "host.ebpf", SOURCE_VARIABLES["ebpf"]),
        "fabricguard/canary": _guard("canary", "agent", SOURCE_VARIABLES["canary"]),
    }  # fmt: skip
    destination: dict[str, Any] = {
        "endpoint": "${env:FABRIC_EXPORT_ENDPOINT}", "timeout": "10s",
        "middlewares": [{"id": "noredirect"}],
        "tls": {"insecure": False, "insecure_skip_verify": False},
        "sending_queue": _queue(layout.telemetry_items, "file_storage/fabric"),
        "retry_on_failure": dict(_RETRY),
    }  # fmt: skip
    if layout.export_header:
        destination["headers"] = {"Authorization": "${env:" + EXPORT_HEADER_VARIABLE + "}"}
    if layout.export_ca is not None:
        destination["tls"]["ca_file"] = f"{_TLS}/export-ca.crt"
    exporters: dict[str, Any] = {"otlp_http/fabric": destination}
    canary_traces = ["otlp_http/fabric"]
    if layout.tap:
        # §9.3: canary spans, and only those (this exporter is in the canary group's
        # pipeline alone), to a bounded file `fabric verify` reads. Best effort: a small
        # in-memory queue that never holds the canary's delivery to the destination.
        exporters["otlp_http/canary_tap"] = {
            "endpoint": f"https://{CANARY_TAP_SERVICE}:4318", "timeout": "5s",
            "middlewares": [{"id": "noredirect"}],
            "tls": {"insecure": False, "insecure_skip_verify": False,
                    "ca_file": f"{_TLS}/ca.crt"},
            "sending_queue": {"enabled": True, "num_consumers": 1, "queue_size": 100,
                              "block_on_overflow": False},
            "retry_on_failure": {"enabled": True, "initial_interval": "1s",
                                 "max_interval": "5s", "max_elapsed_time": "60s"},
        }  # fmt: skip
        canary_traces.append("otlp_http/canary_tap")
    pipelines: dict[str, Any] = {
        "traces/agent": {"receivers": ["otlp/agent"],
                         "processors": ["memory_limiter", "fabricguard/agent"],
                         "exporters": ["otlp_http/fabric"]},
        "logs/agent": {"receivers": ["otlp/agent"],
                       "processors": ["memory_limiter", "fabricguard/agent"],
                       "exporters": ["otlp_http/fabric"]},
        "traces/ebpf": {"receivers": ["otlp/ebpf"],
                        "processors": ["memory_limiter", "fabricguard/ebpf"],
                        "exporters": ["otlp_http/fabric"]},
        "traces/canary": {"receivers": ["otlp/canary"],
                          "processors": ["memory_limiter", "fabricguard/canary"],
                          "exporters": canary_traces},
        "logs/canary": {"receivers": ["otlp/canary"],
                        "processors": ["memory_limiter", "fabricguard/canary"],
                        "exporters": ["otlp_http/fabric"]},
    }  # fmt: skip
    service_extensions = ["health_check", "noredirect", "file_storage/fabric",
                          *(f"bearertokenauth/{group}" for group in GROUPS)]  # fmt: skip
    if layout.content:
        for group in ("agent", "canary"):
            directory = ("/var/lib/fabric-node/content-queue" if group == "agent"
                         else f"/var/lib/fabric-node/content-queue-{group}")  # fmt: skip
            storage = f"file_storage/fabric_content_{group}"
            envelope = f"fabricenvelope/fabric_content_{group}"
            extensions[storage] = {
                "directory": directory,
                "timeout": "1s",
                "create_directory": True,
                "directory_permissions": "0700",
                "fsync": True,
                "compaction": {"directory": directory, "on_start": True, "on_rebound": True},
            }
            extensions[envelope] = {"storage": storage,
                                    "key_file": f"{_SECRETS}/fabric_content_key"}  # fmt: skip
            service_extensions += [storage, envelope]
            port = _PORTS[f"content_{group}"]
            receivers[f"otlp/content-{group}"] = {
                "protocols": {"http": _http(port, group, content=True)}
            }
            store = {
                "bucket": "${env:FABRIC_CONTENT_S3_BUCKET}",
                "prefix": "${env:FABRIC_CONTENT_S3_PREFIX:-fabric/content/}",
                "region": "${env:FABRIC_CONTENT_S3_REGION:-}",
                "endpoint": "${env:FABRIC_CONTENT_S3_ENDPOINT:-}",
                "use_path_style": "${env:FABRIC_CONTENT_S3_PATH_STYLE:-false}",
                "sse": "${env:FABRIC_CONTENT_S3_SSE:-aws:kms}",
                "kms_key_id": "${env:FABRIC_CONTENT_S3_KMS_KEY_ID:-}",
            }  # fmt: skip
            exporters[f"fabriccontent/{group}"] = {
                "profile": "production",
                "source_binding": {"tenant_id": "${env:FABRIC_TENANT_ID}",
                                   "source_id": "${env:" + SOURCE_VARIABLES[group] + "}"},
                "allowed_tenants": ["${env:FABRIC_TENANT_ID}"],
                "backend": "s3", "s3": store, "timeout": "60s",
                "queue_directory": directory,
                "sending_queue": _queue(layout.content_items if group == "agent"
                                        else CANARY_CONTENT_QUEUE_ITEMS, envelope),
                "retry_on_failure": {**_RETRY, "initial_interval": "1s"},
            }  # fmt: skip
            pipelines[f"logs/content-{group}"] = {
                "receivers": [f"otlp/content-{group}"], "processors": ["memory_limiter"],
                "exporters": [f"fabriccontent/{group}"]}  # fmt: skip
    return {
        "extensions": extensions, "receivers": receivers, "processors": processors,
        "exporters": exporters,
        "service": {
            "extensions": service_extensions, "pipelines": pipelines,
            "telemetry": {"logs": {"level": "info"}, "metrics": {"level": "basic", "readers": [
                {"pull": {"exporter": {"prometheus": {
                    "host": "0.0.0.0", "port": 8888, "without_type_suffix": False,  # noqa: S104
                    "without_units": False, "without_scope_info": False}}}}]}},
        },
    }  # fmt: skip


def node_environment(layout: ProdLayout) -> dict[str, str]:
    """The Node container's environment: identifiers and settings, never a secret value
    (the Authorization header is interpolated by Compose from `up`'s own environment)."""
    env = {
        "FABRIC_TENANT_ID": layout.tenant,
        **{SOURCE_VARIABLES[group]: layout.source_ids[group] for group in GROUPS},
        "FABRIC_EXPORT_ENDPOINT": layout.export_endpoint,
    }  # fmt: skip
    if layout.export_header:
        env[EXPORT_HEADER_VARIABLE] = "${" + EXPORT_HEADER_VARIABLE + ":-}"
    if layout.content:
        env["FABRIC_CONTENT_BACKEND"] = "s3"
        env.update(layout.content_store)
        if layout.s3_ca is not None:
            # The AWS SDK trusts this CA for S3 only; the span export keeps its own trust.
            env["AWS_CA_BUNDLE"] = f"{_TLS}/s3-ca.crt"
        if layout.s3_credentials is not None:
            env["AWS_SHARED_CREDENTIALS_FILE"] = f"{_SECRETS}/fabric_s3_credentials"
            env["AWS_EC2_METADATA_DISABLED"] = "true"
    return env


def _node(layout: ProdLayout, images: Images, labels: dict[str, str], node_text: str,
          fingerprint: str) -> dict[str, Any]:  # fmt: skip
    bind = _templates._bind
    secrets = layout.secrets_dir
    volumes: list[Any] = [
        bind(layout.compose_dir / _templates.NODE_CONFIG_FILE,
             f"/etc/fabric-node/{_templates.NODE_CONFIG_FILE}", read_only=True),
        bind(secrets / _secrets.NODE_CERT, f"{_TLS}/node.crt", read_only=True),
        bind(secrets / _secrets.NODE_KEY, f"{_TLS}/node.key", read_only=True),
        bind(secrets / _secrets.CA_CERT, f"{_TLS}/ca.crt", read_only=True),
        bind(layout.queue_dir, "/var/lib/fabric-node/queue"),
        *(bind(secrets / _secrets.token_file(group), f"{_SECRETS}/fabric_{group}_token",
               read_only=True) for group in GROUPS),
    ]  # fmt: skip
    if layout.export_ca is not None:
        volumes.append(bind(layout.export_ca, f"{_TLS}/export-ca.crt", read_only=True))
    ports = [
        f"127.0.0.1:{layout.host_port('agent_http')}:{_PORTS['agent_http']}",
        f"127.0.0.1:{layout.host_port('canary_http')}:{_PORTS['canary_http']}",
    ]
    if layout.content:
        volumes.append(bind(secrets / _secrets.CONTENT_KEY, f"{_SECRETS}/fabric_content_key",
                            read_only=True))  # fmt: skip
        for group, directory in layout.content_queue_dirs.items():
            target = ("/var/lib/fabric-node/content-queue" if group == "agent"
                      else f"/var/lib/fabric-node/content-queue-{group}")  # fmt: skip
            volumes.append(bind(directory, target))
        if layout.s3_ca is not None:
            volumes.append(bind(layout.s3_ca, f"{_TLS}/s3-ca.crt", read_only=True))
        if layout.s3_credentials is not None:
            volumes.append(bind(layout.s3_credentials, f"{_SECRETS}/fabric_s3_credentials",
                                read_only=True))  # fmt: skip
        ports += [
            f"127.0.0.1:{layout.host_port('content_agent')}:{_PORTS['content_agent']}",
            f"127.0.0.1:{layout.host_port('content_canary')}:{_PORTS['content_canary']}",
        ]
    node: dict[str, Any] = {
        "image": images.node,
        "command": [f"--config=/etc/fabric-node/{_templates.NODE_CONFIG_FILE}"],
        **({"user": layout.user} if layout.user else {}),
        "environment": node_environment(layout),
        "volumes": volumes,
        # Loopback only: the agent and the canary on this host reach it; other machines
        # never do (a LAN bind is the manual route's explicit choice).
        "ports": ports,
        "tmpfs": ["/tmp"],  # noqa: S108 - a container path
        "stop_grace_period": "60s", "mem_limit": "2g" if layout.content else "1g",
        "pids_limit": 256, "networks": ["fabric"],
        "labels": {**labels, "ai.singleaxis.fabric.node-config": _templates._digest(node_text),
                   "ai.singleaxis.fabric.node-cert": fingerprint[-16:]},
        **_templates._HARDENING,
    }  # fmt: skip
    depends: dict[str, Any] = {}
    if layout.preset == "trial":
        depends[TRIAL_OTLP_SERVICE] = {"condition": "service_healthy"}
        if layout.content:
            depends[TRIAL_S3_INIT_SERVICE] = {"condition": "service_completed_successfully"}
    if layout.tap:
        depends[CANARY_TAP_SERVICE] = {"condition": "service_healthy"}
    if depends:
        node["depends_on"] = depends
    return node


def _sink(layout: ProdLayout, images: Images, labels: dict[str, str], *, cert: str,
          data: Path, target: str, token: str | None = None,
          max_bytes: int | None = None) -> dict[str, Any]:  # fmt: skip
    """A TLS OTLP/HTTP receiver writing span files (the trial receiver, the canary tap)."""
    bind = _templates._bind
    secrets = layout.secrets_dir
    env = {"SINK_DATA_DIR": "/data", "SINK_PORT": "4318", "PYTHONDONTWRITEBYTECODE": "1",
           "SINK_TLS_CERT_FILE": "/tls/server.crt", "SINK_TLS_KEY_FILE": "/tls/server.key",
           "SINK_SPANS_ONLY": "1"}  # fmt: skip
    volumes: list[Any] = [
        bind(layout.compose_dir / _templates.SINK_FILE, f"/app/{_templates.SINK_FILE}",
             read_only=True),
        bind(secrets / f"{cert}.crt", "/tls/server.crt", read_only=True),
        bind(secrets / f"{cert}.key", "/tls/server.key", read_only=True),
        bind(data, f"/data/{target}"),
    ]  # fmt: skip
    if token is not None:
        env["SINK_AUTH_TOKEN_FILE"] = "/run/secrets/sink_token"  # noqa: S105 - a path
        volumes.append(bind(secrets / token, "/run/secrets/sink_token", read_only=True))
    if max_bytes is not None:
        env["SINK_MAX_BYTES"] = str(max_bytes)
    # In-container liveness on its own loopback: the handshake and an answer, nothing else.
    health = ("import ssl, urllib.request; urllib.request.urlopen('https://127.0.0.1:4318/"
              "health', timeout=2, context=ssl._create_unverified_context())")  # fmt: skip
    return {
        "image": images.sink, "command": ["python", f"/app/{_templates.SINK_FILE}"],
        **({"user": layout.user} if layout.user else {}),
        "environment": env, "volumes": volumes,
        "healthcheck": {"test": ["CMD", "python", "-c", health], "interval": "2s",
                        "timeout": "3s", "retries": 30},
        "networks": ["fabric"], "labels": dict(labels), **_templates._HARDENING,
    }  # fmt: skip


_TRIAL_S3_SCRIPT = r"""umask 077
ids=/run/secrets/trial_s3
key() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$2" | head -n 1 | tr -d '\r'; }
ident() {
  printf '{"name":"%s","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":%s}' \
    "$1" "$(key aws_access_key_id "${ids}_$2")" "$(key aws_secret_access_key "${ids}_$2")" "$3"
}
WEED_S3_SSE_KEK="$(tr -d ' \r\n' < /run/secrets/trial_s3_kek)"
case "$WEED_S3_SSE_KEK" in
  *[!0-9a-f]*|'') echo "trial store: the KEK file must hold 64 hex characters"; exit 1 ;;
esac
export WEED_S3_SSE_KEK
scope="$BUCKET/$PREFIX*"
{
  printf '{"identities":['
  ident fabric-trial-root root '["Admin","Read","List","Write","Tagging"]'; printf ','
  ident fabric-node-writer node "[\"Read:$scope\",\"Write:$scope\"]"; printf ','
  ident fabric-reader reader "[\"Read:$scope\"]"
  printf ']}\n'
} > /tmp/identities.json
cp /tls/server.crt /tmp/s3.crt
cp /tls/server.key /tmp/s3.key
chown seaweed:seaweed /tmp/identities.json /tmp/s3.crt /tmp/s3.key
exec /entrypoint.sh server -ip=127.0.0.1 -ip.bind=127.0.0.1 -s3 -s3.ip.bind=0.0.0.0 \
  -s3.port=8333 -s3.iam=false -s3.port.iceberg=0 -s3.port.lance=0 \
  -s3.cert.file=/tmp/s3.crt -s3.key.file=/tmp/s3.key -s3.config=/tmp/identities.json \
  -master.telemetry=false -master.volumeSizeLimitMB=64 -volume.max=64
"""

_TRIAL_S3_INIT_SCRIPT = r"""umask 077
root=/run/secrets/trial_s3_root
key() { sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$root" | head -n 1 | tr -d '\r'; }
printf 'user = "%s:%s"\n' "$(key aws_access_key_id)" "$(key aws_secret_access_key)" \
  > /tmp/init.curlrc
s3() {
  curl -sS --cacert /tls/ca.crt -K /tmp/init.curlrc --aws-sigv4 "aws:amz:us-east-1:s3" \
    -o /tmp/init.out -w '%{http_code}' "$@"
}
fail() { echo "trial store: $1 (HTTP $code)"; cat /tmp/init.out; exit 1; }
url="https://fabric-trial-s3:8333/$BUCKET"
tries=0
until code="$(s3 -X PUT "$url")" \
  && { [ "$code" = 200 ] || grep -q BucketAlreadyOwnedByYou /tmp/init.out; }; do
  tries=$((tries + 1)); [ "$tries" -lt 60 ] || fail "bucket not created"; sleep 1
done
rule='<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>'
rule="$rule</ApplyServerSideEncryptionByDefault></Rule>"
xmlns='http://s3.amazonaws.com/doc/2006-03-01/'
body="<ServerSideEncryptionConfiguration xmlns=\"$xmlns\">$rule</ServerSideEncryptionConfiguration>"
code="$(s3 -X PUT "$url?encryption" -H 'Content-Type: application/xml' --data-binary "$body")"
[ "$code" = 200 ] || fail "default encryption not set"
echo "trial store: bucket ready over TLS (default SSE-S3)"
"""


def _compose_literal(script: str) -> str:
    """A shell script as a Compose value: every ``$`` doubled, so Compose passes it to the
    shell instead of interpolating it."""
    return script.replace("$", "$$")


def _trial_store(layout: ProdLayout, images: Images, labels: dict[str, str]
                 ) -> dict[str, Any]:  # fmt: skip
    """§9.2: the S3-compatible test store with TLS (SeaweedFS), its three identities and
    its SSE key from the secrets directory, and the one-shot job that makes the bucket."""
    bind = _templates._bind
    secrets = layout.secrets_dir
    bucket = {"BUCKET": TRIAL_BUCKET, "PREFIX": CONTENT_PREFIX}
    identities = [bind(secrets / _secrets.trial_credentials(identity),
                       f"/run/secrets/trial_s3_{identity}", read_only=True)
                  for identity in _secrets.TRIAL_S3_IDENTITIES]  # fmt: skip
    tls = [bind(secrets / "trial-s3.crt", "/tls/server.crt", read_only=True),
           bind(secrets / "trial-s3.key", "/tls/server.key", read_only=True),
           bind(secrets / _secrets.CA_CERT, "/tls/ca.crt", read_only=True)]  # fmt: skip
    store = {
        "image": images.trial_s3, "entrypoint": ["/bin/sh", "-ec"],
        "command": [_compose_literal(_TRIAL_S3_SCRIPT)],
        "environment": dict(bucket),
        "volumes": [*identities, *tls, "trial-s3-data:/data",
                    bind(secrets / _secrets.TRIAL_S3_KEK, "/run/secrets/trial_s3_kek",
                         read_only=True)],
        # The reader (`fabric verify`) reads content back here, on loopback only.
        "ports": [f"127.0.0.1:{TRIAL_S3_PORT}:8333"],
        "healthcheck": {"test": ["CMD", "curl", "-fsS", "--cacert", "/tls/ca.crt",
                                 "https://localhost:8333/healthz"],
                        "interval": "2s", "timeout": "2s", "retries": 60},
        "restart": "unless-stopped", "networks": ["fabric"], "labels": dict(labels),
    }  # fmt: skip
    init = {
        "image": images.trial_s3, "entrypoint": ["/bin/sh", "-ec"],
        "command": [_compose_literal(_TRIAL_S3_INIT_SCRIPT)], "environment": dict(bucket),
        "depends_on": {TRIAL_S3_SERVICE: {"condition": "service_healthy"}},
        "tmpfs": ["/data"],
        "volumes": [identities[0], tls[2]],
        "restart": "no", "networks": ["fabric"], "labels": dict(labels),
    }  # fmt: skip
    return {TRIAL_S3_SERVICE: store, TRIAL_S3_INIT_SERVICE: init}


def _sensor(layout: ProdLayout, images: Images, labels: dict[str, str]) -> dict[str, Any]:
    """The eBPF emitter in production mode (§5.4 step 4, F14): its own ingress group, its
    own token and client certificate, its source label's pseudonym bound by the Node,
    scoped to the agent cgroup `up` made. Every capability is dropped but the four the
    tracepoint programs need; read-only, passive."""
    bind = _templates._bind
    secrets = layout.secrets_dir
    cert, key = _secrets.client_pair("ebpf")
    sensor = {
        "image": images.sensor, "user": "0:0", "pid": "host", "cgroup": "host",
        "cap_add": ["BPF", "PERFMON", "SYS_RESOURCE", "DAC_READ_SEARCH"],
        "environment": {
            "EMIT_PRODUCTION": "true", "EMIT_TENANT_ID": layout.tenant,
            "EMIT_SOURCE_LABEL": layout.sensor_labels["source"],
            "EMIT_HOST_LABEL": layout.sensor_labels["host"],
            "EMIT_ID_KEY_FILE": "/etc/fabric-host-emitter/id.key",
            "EMIT_STATE_KEY_FILE": "/etc/fabric-host-emitter/state.key",
            "EMIT_STATE_DIR": "/var/lib/fabric-host-emitter/state",
            "EMIT_ENDPOINT": f"{NODE_SERVICE}:{_PORTS['ebpf_grpc']}",
            "EMIT_BEARER_TOKEN_FILE": "/etc/fabric-host-emitter/token",
            "EMIT_TLS_CA_FILE": "/etc/fabric-host-emitter/ca.crt",
            "EMIT_TLS_CERT_FILE": "/etc/fabric-host-emitter/client.crt",
            "EMIT_TLS_KEY_FILE": "/etc/fabric-host-emitter/client.key",
            "EMIT_AGENT_CGROUP_ROOTS": str(layout.sensor_cgroup),
            "EMIT_ALL_HOST": "false", "EMIT_MAX_EVENTS_PER_SEC": "0",
            "EMIT_DEDUPE_WINDOW": "0", "EMIT_DIGESTS": "omitted",
        },
        "volumes": [
            "/sys/kernel/btf:/sys/kernel/btf:ro", "/sys/kernel/tracing:/sys/kernel/tracing:ro",
            "/sys/kernel/debug:/sys/kernel/debug:ro", "/sys/fs/cgroup:/sys/fs/cgroup:ro",
            bind(secrets / _secrets.ID_KEY, "/etc/fabric-host-emitter/id.key", read_only=True),
            bind(secrets / _secrets.SENSOR_STATE_KEY, "/etc/fabric-host-emitter/state.key",
                 read_only=True),
            bind(secrets / _secrets.token_file("ebpf"), "/etc/fabric-host-emitter/token",
                 read_only=True),
            bind(secrets / _secrets.CA_CERT, "/etc/fabric-host-emitter/ca.crt", read_only=True),
            bind(secrets / cert, "/etc/fabric-host-emitter/client.crt", read_only=True),
            bind(secrets / key, "/etc/fabric-host-emitter/client.key", read_only=True),
            "sensor-state:/var/lib/fabric-host-emitter"],
        "depends_on": {NODE_SERVICE: {"condition": "service_started"},
                       SENSOR_STATE_INIT_SERVICE: {"condition": "service_completed_successfully"}},
        "networks": ["fabric"], "labels": dict(labels), **_templates._HARDENING,
    }  # fmt: skip
    init = {
        "image": images.sink, "user": "0:0", "network_mode": "none", "restart": "no",
        "command": ["python", "-c", "import os; os.chmod('/state', 0o700)"],
        "volumes": ["sensor-state:/state"], "labels": dict(labels),
        "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
    }  # fmt: skip
    return {SENSOR_STATE_INIT_SERVICE: init, SENSOR_SERVICE: sensor}


def compose(project: str, compose_project: str, images: Images, layout: ProdLayout,
            node_text: str, cert_fingerprint: str, directory: Path) -> dict[str, Any]:  # fmt: skip
    """The production Compose document."""
    labels = {_templates.PROJECT_LABEL: project, _templates.PROJECT_DIR_LABEL: str(directory)}
    services: dict[str, Any] = {}
    volumes: dict[str, Any] = {}
    if layout.preset == "trial":
        services[TRIAL_OTLP_SERVICE] = _sink(
            layout, images, labels, cert="trial-otlp", data=layout.data_dir / "spans",
            target="spans", token=_secrets.TRIAL_EXPORT_TOKEN)  # fmt: skip
        if layout.content:
            services.update(_trial_store(layout, images, labels))
            volumes["trial-s3-data"] = {}
    if layout.tap:
        services[CANARY_TAP_SERVICE] = _sink(
            layout, images, labels, cert="canary-tap", data=layout.tap_dir, target="spans",
            max_bytes=TAP_MAX_BYTES)  # fmt: skip
    services[NODE_SERVICE] = _node(layout, images, labels, node_text, cert_fingerprint)
    if layout.sensor_cgroup:
        services.update(_sensor(layout, images, labels))
        volumes["sensor-state"] = {}
    document: dict[str, Any] = {"name": compose_project, "services": services,
                                "networks": {"fabric": {"driver": "bridge"}}}  # fmt: skip
    if volumes:
        document["volumes"] = volumes
    return document
