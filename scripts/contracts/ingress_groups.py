# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 053 §6.1, §6.2.6 and spec 056 §7.3.3 (f): ingress-group configuration goldens.

``contracts/capture/v1/fixtures/ingress-groups/`` holds rendered Node configurations as
fabric-gate reads them (after confmap's merge): the valid shapes (one agent group with
content plus an eBPF and an auditd group; an agent group plus one eBPF group per node; the
legacy single binding, unchanged; the auditd sensor collector) and one refused
configuration per gate rule, each with the error text the gate must report. A fixture
token tree (``files/etc/fabric/…``) holds a distinct token per group, two equal ones for
the duplicate-credential case, the content key and the sensor's client token. Tests copy
it to a temporary root with modes 0400 and rewrite the prefix ``/etc/fabric/`` to that root
before running a checker (``rewrite``).

:func:`check` is the executable form of the group rules over one merged configuration; it
returns ``None`` or the first refused rule's error text. fabric-gate (WP4-08a,
``gate/groups.go``) must accept every valid golden and refuse every invalid one with an
error that contains the same text. The legacy single binding is outside :func:`check`: the
existing single-binding rule (``checkDedicatedEvidenceIngress``) keeps checking it, and
``scripts/tests/test_capture_contracts.py`` runs the real gate on it.
"""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

import yaml

from contracts import validate_coverage_contracts as coverage

GOLDENS = Path("contracts/capture/v1/fixtures/ingress-groups")
INDEX_SCHEMA = "fabric.ingress-group-goldens/v1"
PREFIX = "/etc/fabric/"
KEY = "fabric-test-id-key-not-a-secret"
TENANT = "tenant-a"
GROUP_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
SOURCE_KINDS = ("agent", "host.auditd", "host.ebpf")
DEFAULT_GROUPS, MAX_GROUPS = 64, 256
TLS_DIR = "/etc/fabric/receiver-tls"
CONTENT_KEY = "/etc/fabric/content-key/key"
SENSOR_DIR = "/etc/fabric/sensor"

# The error text a refused configuration's gate error must contain, per rule.
ERRORS: dict[str, str] = {
    "name": "an ingress group name matches ^[a-z][a-z0-9-]{0,31}$ and does not start with content (053 §6.1)",
    "mixing": "a configuration has the legacy single binding or only fabricguard/<group> instances, never both (053 §6.1)",
    "r1": "each group has exactly one bearertokenauth/<group>, used only by that group's receivers (053 §6.1 rule 1)",
    "r2": "a group pipeline uses only its own receiver, guard and content exporter; no unbound receiver (053 §6.1 rule 2)",
    "r3": "no processor after fabricguard/<group> but batch (053 §6.1 rule 3)",
    "r4": "fabricguard/<group> and fabriccontent/<group> carry the group's tenant and source; allowed_tenants is exactly that tenant (053 §6.1 rule 4)",
    "r5": "group credentials differ byte for byte (053 §6.1 rule 5)",
    "r6": "a group credential is one watched token file with require_single_token: true (053 §6.1 rule 6)",
    "r7": "no two groups bind one (tenant, source) (053 §6.1 rule 7)",
    "r8": "a group listener uses TLS unless it is loopback (053 §6.1 rule 8)",
    "r9": "each fabriccontent/<group> has its own binding and encrypted queue (053 §6.1 rule 9)",
    "h1": "a host group has only its traces pipeline (053 §6.2.6 rule 1)",
    "h2": "a host group has no content receiver and no fabriccontent exporter (053 §6.2.6 rule 2)",
    "h3": "fabricguard/<group> sets profile production, source_kind and the group's evidence_source_binding (053 §6.2.6 rule 3)",
    "h4": "the audit receiver never runs in a production Node pipeline (053 §6.2.6 rule 4)",
    "h5": "no two group listeners share an address; auditd and eBPF groups have their own (053 §6.1, §6.2.6 rule 5)",
    "s1": "the sensor-collector profile holds exactly the production audit receiver, one traces pipeline from [memory_limiter, batch] and one otlp_http exporter (056 §7.3.3 (f))",
    "s2": "the sensor collector exports with TLS or to loopback, refuses redirects and authenticates with a client bearertokenauth token file (056 §7.3.3 (f))",
}


class Refused(Exception):
    def __init__(self, rule: str) -> None:
        super().__init__(ERRORS[rule])
        self.rule = rule


def _type(component_id: str) -> str:
    return component_id.split("/", 1)[0]


def _name(component_id: str) -> str | None:
    return component_id.split("/", 1)[1] if "/" in component_id else None


def rewrite(value: Any, root: str) -> Any:
    """Every string ``/etc/fabric/…`` with the prefix replaced by ``root`` (the test's
    temporary copy of the fixture token tree)."""
    if isinstance(value, str):
        return (
            root.rstrip("/") + "/" + value[len(PREFIX) :]
            if value.startswith(PREFIX)
            else value
        )
    if isinstance(value, list):
        return [rewrite(v, root) for v in value]
    if isinstance(value, dict):
        return {k: rewrite(v, root) for k, v in value.items()}
    return value


def _loopback(endpoint: str) -> bool:
    host = endpoint.rsplit(":", 1)[0].strip("[]")
    return host in ("127.0.0.1", "localhost", "::1")


def check(cfg: Mapping[str, Any], files: Callable[[str], bytes | None]) -> str | None:
    """The group rules over one merged configuration: ``None`` when it passes, else the
    first refused rule's error text. ``files`` reads a credential file by its configured
    path (``None`` when missing). A configuration without ``fabricguard/<group>`` and
    without a production ``audit`` receiver is the legacy single binding: not checked
    here."""
    try:
        if _sensor_profile(cfg):
            _check_sensor(cfg)
        elif any(
            _type(p) == "fabricguard" and _name(p) for p in cfg.get("processors", {})
        ):
            _check_groups(cfg, files)
    except Refused as exc:
        return ERRORS[exc.rule]
    return None


def _sensor_profile(cfg: Mapping[str, Any]) -> bool:
    return any(
        _type(r) == "audit" and isinstance(v, dict) and v.get("mode") == "production"
        for r, v in cfg.get("receivers", {}).items()
    )


def _check_sensor(cfg: Mapping[str, Any]) -> None:
    receivers, exporters = cfg.get("receivers", {}), cfg.get("exporters", {})
    processors, pipelines = (
        cfg.get("processors", {}),
        cfg["service"].get("pipelines", {}),
    )
    audit = [r for r in receivers if _type(r) == "audit"]
    if len(receivers) != 1 or len(audit) != 1 or len(pipelines) != 1:
        raise Refused("s1")
    ((name, pipeline),) = pipelines.items()
    steps = pipeline.get("processors", [])
    if (
        _type(name) != "traces"
        or pipeline.get("receivers") != audit
        or steps not in ([], ["memory_limiter"], ["batch"], ["memory_limiter", "batch"])
        or set(processors) - {"memory_limiter", "batch"}
        or len(exporters) != 1
        or pipeline.get("exporters") != list(exporters)
        or _type(next(iter(exporters))) != "otlp_http"
    ):
        raise Refused("s1")
    exporter = next(iter(exporters.values()))
    endpoint = str(exporter.get("endpoint", ""))
    tls = exporter.get("tls", {})
    auth = exporter.get("auth", {}).get("authenticator", "")
    ext = cfg.get("extensions", {}).get(auth, {})
    host = endpoint.split("://", 1)[-1].split("/", 1)[0]
    if (
        not (
            endpoint.startswith("https://")
            or (endpoint.startswith("http://") and _loopback(host))
        )
        or tls.get("insecure") is True
        or tls.get("insecure_skip_verify") is True
        or {"id": "noredirect"} not in exporter.get("middlewares", [])
        or _type(auth) != "bearertokenauth"
        or not ext.get("filename")
        or "tokens" in ext
        or auth not in cfg["service"].get("extensions", [])
    ):
        raise Refused("s2")


def _groups(cfg: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {
        str(_name(p)): v
        for p, v in cfg.get("processors", {}).items()
        if _type(p) == "fabricguard" and _name(p)
    }


def _check_groups(cfg: Mapping[str, Any], files: Callable[[str], bytes | None]) -> None:
    processors = cfg.get("processors", {})
    receivers = cfg.get("receivers", {})
    exporters = cfg.get("exporters", {})
    extensions = cfg.get("extensions", {})
    service = cfg.get("service", {})
    pipelines = service.get("pipelines", {})
    if "fabricguard" in processors:
        raise Refused("mixing")
    groups = _groups(cfg)
    for g in groups:
        if not GROUP_NAME.fullmatch(g) or g.startswith("content"):
            raise Refused("name")
    if any(_type(r) == "audit" for r in receivers):
        raise Refused("h4")
    # guards (053 §6.2.6 rule 3; 056 §7.3.3 (e), (f))
    kinds: dict[str, str] = {}
    for g, guard in groups.items():
        binding = guard.get("evidence_source_binding") or {}
        if (
            guard.get("profile") != "production"
            or guard.get("source_kind") not in SOURCE_KINDS
            or not binding.get("tenant_id")
            or not binding.get("source_id")
            or (guard.get("source_kind") == "agent" and "host_digests" in guard)
            or guard.get("host_digests", "omitted") not in ("omitted", "permitted")
        ):
            raise Refused("h3")
        kinds[g] = guard["source_kind"]
    # credentials (053 §6.1 rules 1, 6)
    for g in groups:
        auth = extensions.get(f"bearertokenauth/{g}")
        if (
            not isinstance(auth, dict)
            or not auth.get("filename")
            or "tokens" in auth
            or auth.get("require_single_token") is not True
            or f"bearertokenauth/{g}" not in service.get("extensions", [])
        ):
            raise Refused("r6")
    owner: dict[str, str] = {}
    for rid, receiver in receivers.items():
        name = _name(rid) or ""
        g = name.removeprefix("content-")
        if _type(rid) != "otlp" or g not in groups:
            raise Refused("r2")  # an unbound alternate receiver
        if name.startswith("content-") and kinds[g] != "agent":
            raise Refused("h2")
        owner[rid] = g
        for protocol in (receiver.get("protocols") or {}).values():
            if (protocol.get("auth") or {}).get(
                "authenticator"
            ) != f"bearertokenauth/{g}":
                raise Refused("r1")
    for g in groups:
        if f"otlp/{g}" not in receivers:
            raise Refused("r2")
    # pipelines (053 §6.1 rules 2, 3; §6.2.6 rule 1)
    approved = {e for e in exporters if _type(e) == "otlp_http"}
    for pid, pipeline in pipelines.items():
        signal, _, name = pid.partition("/")
        content = name.startswith("content-")
        g = name.removeprefix("content-")
        if g not in groups:
            raise Refused("r2")
        if kinds[g] != "agent" and (content or signal != "traces"):
            raise Refused("h2" if content else "h1")
        if content:
            if (
                signal != "logs"
                or pipeline.get("receivers") != [f"otlp/content-{g}"]
                or pipeline.get("exporters") != [f"fabriccontent/{g}"]
            ):
                raise Refused("r2")
            if pipeline.get("processors", []) not in ([], ["memory_limiter"]):
                raise Refused("r3")
            continue
        if signal not in ("traces", "logs") or pipeline.get("receivers") != [
            f"otlp/{g}"
        ]:
            raise Refused("r2")
        steps = list(pipeline.get("processors", []))
        if f"fabricguard/{g}" not in steps or any(
            _type(s) == "fabricguard" and s != f"fabricguard/{g}" for s in steps
        ):
            raise Refused("r2")
        after = steps[steps.index(f"fabricguard/{g}") + 1 :]
        if after not in ([], ["batch"]) or steps[
            : steps.index(f"fabricguard/{g}")
        ] not in (
            [],
            ["memory_limiter"],
        ):
            raise Refused("r3")
        if not pipeline.get("exporters") or not set(pipeline["exporters"]) <= approved:
            raise Refused("r2")
    for g, kind in kinds.items():
        if kind != "agent":
            if f"fabriccontent/{g}" in exporters:
                raise Refused("h2")
            if f"traces/{g}" not in pipelines:
                raise Refused("h1")
    # bindings (053 §6.1 rules 4, 7, 9)
    seen: set[tuple[str, str]] = set()
    for g, guard in groups.items():
        binding = guard["evidence_source_binding"]
        pair = (binding["tenant_id"], binding["source_id"])
        if pair in seen:
            raise Refused("r7")
        seen.add(pair)
    queues: set[str] = set()
    for eid, exporter in exporters.items():
        if _type(eid) != "fabriccontent":
            continue
        g = _name(eid) or ""
        guard = groups.get(g)
        if guard is None:
            raise Refused("r2")
        binding = guard["evidence_source_binding"]
        if (
            exporter.get("source_binding") != binding
            or exporter.get("allowed_tenants") != [binding["tenant_id"]]
            or exporter.get("allow_multiple_tenants")
        ):
            raise Refused("r4")
        storage = (exporter.get("sending_queue") or {}).get("storage", "")
        envelope = extensions.get(storage) or {}
        if (
            storage != f"fabricenvelope/fabric_content_{g}"
            or storage in queues
            or not envelope.get("key_file")
            or storage not in service.get("extensions", [])
        ):
            raise Refused("r9")
        queues.add(storage)
    # credential bytes (053 §6.1 rule 5); listeners (rule 8; §6.2.6 rule 5)
    tokens: dict[bytes, str] = {}
    for g in groups:
        data = files(extensions[f"bearertokenauth/{g}"]["filename"])
        if data is None:
            raise Refused("r6")
        if data in tokens:
            raise Refused("r5")
        tokens[data] = g
    listeners: set[str] = set()
    for rid, receiver in receivers.items():
        for protocol in (receiver.get("protocols") or {}).values():
            endpoint = str(protocol.get("endpoint", ""))
            port = endpoint.rsplit(":", 1)[-1]
            if port in listeners:
                raise Refused("h5")
            listeners.add(port)
            tls = protocol.get("tls") or {}
            if not _loopback(endpoint) and (
                not tls.get("cert_file") or not tls.get("key_file")
            ):
                raise Refused("r8")


# ------------------------------------------------------------------ builders
def source_id(label: str) -> str:
    return coverage.pseudonym_v1("s", label, KEY)


AGENT_SOURCE = source_id("build-host-7/travel-agent")
EBPF_SOURCE = source_id("build-host-7/ebpf")
AUDITD_SOURCE = source_id("build-host-7/auditd")
NODES = ("node-a", "node-b", "node-c")


def _tls() -> dict[str, str]:
    return {
        "cert_file": f"{TLS_DIR}/tls.crt",
        "key_file": f"{TLS_DIR}/tls.key",
        "client_ca_file": f"{TLS_DIR}/client-ca.crt",
    }


def _protocol(kind: str, port: int, g: str, content: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "endpoint": f"0.0.0.0:{port}",
        "auth": {"authenticator": f"bearertokenauth/{g}"},
        "tls": _tls(),
    }
    if kind == "grpc":
        out.update(max_recv_msg_size_mib=8, max_concurrent_streams=64,
                   keepalive={"enforcement_policy": {"min_time": "10s",
                                                     "permit_without_stream": False}})  # fmt: skip
    else:
        out.update(read_header_timeout="5s", read_timeout="120s" if content else "30s",
                   idle_timeout="120s",
                   max_request_body_size=67108864 if content else 8388608)  # fmt: skip
    return out


def group(
    name: str, kind: str, source: str, *, grpc: int | None = None, http: int | None = None,
    content: int | None = None, digests: str | None = None,
) -> dict[str, Any]:  # fmt: skip
    return {"name": name, "kind": kind, "source": source, "grpc": grpc, "http": http,
            "content": content, "digests": digests}  # fmt: skip


def node_config(groups: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """A production Node with static ingress groups (056 §7.3.3 (f)), in the shape the
    chart renders for ``receiver.sourceBindings[]`` (WP4-09)."""
    receivers: dict[str, Any] = {}
    processors: dict[str, Any] = {
        "memory_limiter": {"check_interval": "1s", "limit_mib": 512}
    }
    exporters: dict[str, Any] = {
        "otlp_http/fabric": {
            "endpoint": "https://otlp.example.invalid",
            "timeout": "30s",
            "middlewares": [{"id": "noredirect"}],
            "headers": {"Authorization": "${env:FABRIC_EXPORT_AUTH}"},
            "tls": {"insecure": False, "insecure_skip_verify": False},
            "sending_queue": {"enabled": True, "num_consumers": 10, "queue_size": 10000,
                              "block_on_overflow": True, "storage": "file_storage/fabric"},
            "retry_on_failure": {"enabled": True, "initial_interval": "5s",
                                 "max_interval": "30s", "max_elapsed_time": "0s"},
        }
    }  # fmt: skip
    extensions: dict[str, Any] = {
        "health_check": {"endpoint": "0.0.0.0:13133"},
        "noredirect": {"loss_outbox": {"directory": "/var/lib/otelcol-fabric/storage/loss-outbox"}},
        "file_storage/fabric": {"directory": "/var/lib/otelcol-fabric/storage", "timeout": "1s",
                                "create_directory": True, "fsync": True},
    }  # fmt: skip
    active = ["health_check", "noredirect", "file_storage/fabric"]
    pipelines: dict[str, Any] = {}
    for g in groups:
        name, kind = g["name"], g["kind"]
        extensions[f"bearertokenauth/{name}"] = {
            "filename": f"/etc/fabric/ingress/{name}/token",
            "require_single_token": True,
        }
        active.append(f"bearertokenauth/{name}")
        protocols: dict[str, Any] = {}
        if g["grpc"]:
            protocols["grpc"] = _protocol("grpc", g["grpc"], name)
        if g["http"]:
            protocols["http"] = _protocol("http", g["http"], name)
        receivers[f"otlp/{name}"] = {"protocols": protocols}
        guard: dict[str, Any] = {
            "event_class_attribute": "event_class",
            "drop_unknown_classes": True,
            "max_field_bytes": 8192,
            "profile": "production",
            "source_kind": kind,
            "evidence_source_binding": {"tenant_id": TENANT, "source_id": g["source"]},
            "capture_labels": "pseudonymous",
            "identity_mode": "pseudonymous",
        }
        if kind != "agent":
            guard["host_digests"] = g["digests"] or "omitted"
        processors[f"fabricguard/{name}"] = guard
        steps = ["memory_limiter", f"fabricguard/{name}"]
        pipelines[f"traces/{name}"] = {"receivers": [f"otlp/{name}"], "processors": steps,
                                       "exporters": ["otlp_http/fabric"]}  # fmt: skip
        if kind == "agent":
            pipelines[f"logs/{name}"] = {"receivers": [f"otlp/{name}"], "processors": list(steps),
                                         "exporters": ["otlp_http/fabric"]}  # fmt: skip
        if g["content"]:
            receivers[f"otlp/content-{name}"] = {
                "protocols": {
                    "http": _protocol("http", g["content"], name, content=True)
                }
            }
            queue = f"fabric_content_{name}"
            extensions[f"file_storage/{queue}"] = {
                "directory": f"/var/lib/otelcol-fabric/storage/content-queue-{name}",
                "timeout": "1s", "create_directory": True, "directory_permissions": "0700",
                "fsync": True,
            }  # fmt: skip
            extensions[f"fabricenvelope/{queue}"] = {"storage": f"file_storage/{queue}",
                                                     "key_file": CONTENT_KEY}  # fmt: skip
            active += [f"file_storage/{queue}", f"fabricenvelope/{queue}"]
            exporters[f"fabriccontent/{name}"] = {
                "profile": "production",
                "source_binding": {"tenant_id": TENANT, "source_id": g["source"]},
                "allowed_tenants": [TENANT],
                "backend": "s3",
                "s3": {"bucket": "acme-fabric-content", "prefix": f"fabric/{name}/",
                       "region": "eu-west-1", "use_path_style": False, "sse": "aws:kms",
                       "kms_key_id": "alias/fabric-content"},
                "timeout": "60s",
                "queue_directory": f"/var/lib/otelcol-fabric/storage/content-queue-{name}",
                "sending_queue": {"enabled": True, "num_consumers": 4, "queue_size": 64,
                                  "block_on_overflow": True, "storage": f"fabricenvelope/{queue}"},
                "retry_on_failure": {"enabled": True, "initial_interval": "1s",
                                     "max_interval": "30s", "max_elapsed_time": "0s"},
            }  # fmt: skip
            pipelines[f"logs/content-{name}"] = {"receivers": [f"otlp/content-{name}"],
                                                 "processors": ["memory_limiter"],
                                                 "exporters": [f"fabriccontent/{name}"]}  # fmt: skip
    return {
        "receivers": receivers,
        "processors": processors,
        "exporters": exporters,
        "extensions": extensions,
        "service": {"extensions": active, "telemetry": {"logs": {"level": "info"}},
                    "pipelines": pipelines},
    }  # fmt: skip


def legacy_config() -> dict[str, Any]:
    """Today's plain fabricguard render (the chart's production profile, one bound
    workload ingress), unchanged by M2 (053 revision 4 §6.1)."""
    return {
        "receivers": {"otlp": {"protocols": {
            "grpc": {"endpoint": "0.0.0.0:4317", "auth": {"authenticator": "bearertokenauth/workload"},
                     "max_recv_msg_size_mib": 8, "max_concurrent_streams": 64,
                     "keepalive": {"enforcement_policy": {"min_time": "10s", "permit_without_stream": False}},
                     "tls": _tls()},
            "http": {"endpoint": "0.0.0.0:4318", "auth": {"authenticator": "bearertokenauth/workload"},
                     "read_header_timeout": "5s", "read_timeout": "30s", "idle_timeout": "120s",
                     "max_request_body_size": 8388608, "tls": _tls()},
        }}},
        "extensions": {
            "health_check": {"endpoint": "0.0.0.0:13133"},
            "bearertokenauth/workload": {"filename": "/etc/fabric/workload-auth/token",
                                         "require_single_token": True},
            "noredirect": {"loss_outbox": {"directory": "/var/lib/otelcol-fabric/storage/loss-outbox"}},
            "file_storage/fabric": {"directory": "/var/lib/otelcol-fabric/storage", "timeout": "1s",
                                    "create_directory": True, "fsync": True},
        },
        "processors": {
            "memory_limiter": {"check_interval": "1s", "limit_mib": 512},
            "fabricguard": {"event_class_attribute": "event_class", "drop_unknown_classes": True,
                            "max_field_bytes": 8192, "profile": "production",
                            "evidence_source_binding": {"tenant_id": "customer-production",
                                                        "source_id": "s-c5aedfd8a3ee415e277e335bf1517ff4"},
                            "capture_labels": "pseudonymous", "identity_mode": "pseudonymous"},
        },
        "exporters": {"otlp_http/fabric": {
            "endpoint": "https://otlp.example.invalid", "timeout": "30s",
            "middlewares": [{"id": "noredirect"}],
            "headers": {"Authorization": "${env:FABRIC_EXPORT_AUTH}"},
            "tls": {"insecure": False, "insecure_skip_verify": False},
            "sending_queue": {"enabled": True, "num_consumers": 10, "queue_size": 10000,
                              "block_on_overflow": True, "storage": "file_storage/fabric"},
            "retry_on_failure": {"enabled": True, "initial_interval": "5s", "max_interval": "30s",
                                 "max_elapsed_time": "0s"},
        }},
        "service": {
            "extensions": ["health_check", "bearertokenauth/workload", "noredirect", "file_storage/fabric"],
            "telemetry": {"logs": {"level": "info"}},
            "pipelines": {
                "logs": {"receivers": ["otlp"], "processors": ["memory_limiter", "fabricguard"],
                         "exporters": ["otlp_http/fabric"]},
                "traces": {"receivers": ["otlp"], "processors": ["memory_limiter", "fabricguard"],
                           "exporters": ["otlp_http/fabric"]},
            },
        },
    }  # fmt: skip


def sensor_config() -> dict[str, Any]:
    """The customer-deployed auditd sensor collector (053 §6.2.8, 056 §7.3.3 (d), (f)): the
    production audit receiver, one traces pipeline and one otlp_http exporter to its
    group's OTLP/HTTP endpoint with its own client token."""
    return {
        "receivers": {"audit": {
            "source": "logfile",
            "log_path": "/var/log/audit/audit.log",
            "state_directory": "/var/lib/fabric-sensor/auditd/local",
            "rule_key": "fabric",
            "exec": True,
            "connect": True,
            "file_access": False,
            "mode": "production",
            "production": {
                "tenant_id": TENANT,
                "source_label": "build-host-7/auditd",
                "host_label": "build-host-7",
                "id_key_file": f"{SENSOR_DIR}/id_key",
                "state_key_file": f"{SENSOR_DIR}/state_key",
                "state_dir": "/var/lib/fabric-sensor/auditd",
                "digests": "omitted",
                "heartbeat_interval": "10s",
            },
        }},
        "processors": {"memory_limiter": {"check_interval": "1s", "limit_mib": 256},
                       "batch": {"timeout": "1s", "send_batch_size": 512}},
        "exporters": {"otlp_http/node": {
            "endpoint": "https://fabric-node.fabric-system.svc:4428",
            "timeout": "30s",
            "auth": {"authenticator": "bearertokenauth/node"},
            "middlewares": [{"id": "noredirect"}],
            "tls": {"insecure": False, "insecure_skip_verify": False, "ca_file": f"{SENSOR_DIR}/ca.crt"},
            "retry_on_failure": {"enabled": True, "initial_interval": "1s", "max_interval": "30s",
                                 "max_elapsed_time": "0s"},
        }},
        "extensions": {
            "health_check": {"endpoint": "0.0.0.0:13133"},
            "noredirect": {},
            "bearertokenauth/node": {"filename": f"{SENSOR_DIR}/token"},
        },
        "service": {
            "extensions": ["health_check", "noredirect", "bearertokenauth/node"],
            "telemetry": {"logs": {"level": "info"}},
            "pipelines": {"traces": {"receivers": ["audit"], "processors": ["memory_limiter", "batch"],
                                     "exporters": ["otlp_http/node"]}},
        },
    }  # fmt: skip


AGENT_GROUPS = (
    group("agent", "agent", AGENT_SOURCE, grpc=4317, http=4318, content=4319),
    group("ebpf", "host.ebpf", EBPF_SOURCE, grpc=4417),
    group("auditd", "host.auditd", AUDITD_SOURCE, http=4428),
)
THREE_NODES = (
    group("agent", "agent", AGENT_SOURCE, grpc=4317, http=4318, content=4319),
    *(
        group(f"ebpf-{i}", "host.ebpf", source_id(f"{node}/ebpf"), grpc=4417 + i)
        for i, node in enumerate(NODES)
    ),
)


def token_tree() -> dict[str, bytes]:
    """The fixture token tree, keyed by the configured absolute path: one distinct token
    per group of every golden, two equal ones (``dup-a``, ``dup-b``) for the
    duplicate-credential case, the content key and the sensor's files."""
    names = sorted(
        {g["name"] for g in (*AGENT_GROUPS, *THREE_NODES)}
        | {"agent-2", "dup-a", "dup-b"}
    )
    out: dict[str, bytes] = {}
    for name in names:
        token = (
            "fabric-fixture-ingress-token-duplicate-not-a-secret"
            if name.startswith("dup-")
            else f"fabric-fixture-ingress-token-{name}-not-a-secret"
        )
        out[f"/etc/fabric/ingress/{name}/token"] = token.encode()
    out["/etc/fabric/workload-auth/token"] = (
        b"fabric-fixture-workload-token-not-a-secret"
    )
    out[CONTENT_KEY] = (
        b"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="  # base64 of 32 bytes
    )
    out[f"{SENSOR_DIR}/token"] = (
        b"fabric-fixture-sensor-client-token-auditd-not-a-secret"
    )
    out[f"{SENSOR_DIR}/id_key"] = KEY.encode()
    out[f"{SENSOR_DIR}/state_key"] = b"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio="
    return out


def _mutated(
    base: Mapping[str, Any], change: Callable[[dict[str, Any]], None]
) -> dict[str, Any]:
    doc = copy.deepcopy(dict(base))
    change(doc)
    return doc


def goldens() -> dict[str, tuple[dict[str, Any], str | None]]:
    """``valid/*.yaml`` (error ``None``) and ``invalid/*.yaml`` with their rule."""
    base = node_config(AGENT_GROUPS)
    sensor = sensor_config()
    out: dict[str, tuple[dict[str, Any], str | None]] = {
        "valid/agent-ebpf-auditd.yaml": (base, None),
        "valid/agent-ebpf-three-nodes.yaml": (node_config(THREE_NODES), None),
        "valid/legacy-single-binding.yaml": (legacy_config(), None),
        "valid/sensor-auditd.yaml": (sensor, None),
    }

    def bad(name: str, rule: str, change: Callable[[dict[str, Any]], None], doc: Mapping[str, Any] = base) -> None:  # fmt: skip
        out[f"invalid/{name}.yaml"] = (_mutated(doc, change), rule)

    def rename(d: dict[str, Any], old: str, new: str) -> None:
        text = yaml.safe_dump(d, sort_keys=True)
        swapped = yaml.safe_load(re.sub(rf"(?<![a-z.-]){old}(?![a-z0-9-])", new, text))
        d.clear()
        d.update(swapped)
        d["extensions"][f"bearertokenauth/{new}"]["filename"] = (
            f"/etc/fabric/ingress/{old}/token"
        )

    bad(
        "group-name-content-prefix", "name", lambda d: rename(d, "ebpf", "content-ebpf")
    )
    bad("mixing-legacy-and-groups", "mixing",
        lambda d: d["processors"].update(fabricguard=legacy_config()["processors"]["fabricguard"]))  # fmt: skip
    bad("r1-shared-authenticator", "r1",
        lambda d: d["receivers"]["otlp/ebpf"]["protocols"]["grpc"]["auth"].update(authenticator="bearertokenauth/agent"))  # fmt: skip
    bad("r2-cross-wired-receiver", "r2",
        lambda d: d["service"]["pipelines"]["traces/ebpf"].update(receivers=["otlp/agent"]))  # fmt: skip

    def mutating(d: dict[str, Any]) -> None:
        d["processors"]["transform/rename"] = {"trace_statements": []}
        d["service"]["pipelines"]["traces/agent"]["processors"].append(
            "transform/rename"
        )

    bad("r3-mutating-processor-after-guard", "r3", mutating)
    bad("r4-content-binding-differs", "r4",
        lambda d: d["exporters"]["fabriccontent/agent"]["source_binding"].update(source_id=EBPF_SOURCE))  # fmt: skip
    bad("r5-equal-credentials", "r5", lambda d: (
        d["extensions"]["bearertokenauth/ebpf"].update(filename="/etc/fabric/ingress/dup-a/token"),
        d["extensions"]["bearertokenauth/auditd"].update(filename="/etc/fabric/ingress/dup-b/token"),
    ))  # fmt: skip
    bad("r6-inline-token", "r6",
        lambda d: d["extensions"]["bearertokenauth/ebpf"].update(tokens=["inline-token-not-a-secret"]))  # fmt: skip
    bad("r7-one-source-two-groups", "r7",
        lambda d: d["processors"]["fabricguard/auditd"]["evidence_source_binding"].update(source_id=EBPF_SOURCE))  # fmt: skip
    bad("r8-plaintext-group-listener", "r8",
        lambda d: d["receivers"]["otlp/ebpf"]["protocols"]["grpc"].pop("tls"))  # fmt: skip

    def shared_queue(d: dict[str, Any]) -> None:
        two = node_config((*AGENT_GROUPS[:1], group("agent-2", "agent", source_id("build-host-7/billing-agent"),
                                                    grpc=4320, http=4321, content=4322)))  # fmt: skip
        two["exporters"]["fabriccontent/agent-2"]["sending_queue"]["storage"] = (
            "fabricenvelope/fabric_content_agent"
        )
        d.clear()
        d.update(two)

    bad("r9-shared-content-queue", "r9", shared_queue)
    bad("h1-host-logs-pipeline", "h1", lambda d: d["service"]["pipelines"].update({
        "logs/ebpf": {"receivers": ["otlp/ebpf"], "processors": ["memory_limiter", "fabricguard/ebpf"],
                      "exporters": ["otlp_http/fabric"]}}))  # fmt: skip
    bad("h2-host-content-receiver", "h2", lambda d: d["receivers"].update({
        "otlp/content-ebpf": {"protocols": {"http": _protocol("http", 4419, "ebpf", content=True)}}}))  # fmt: skip
    bad(
        "h3-guard-without-source-kind",
        "h3",
        lambda d: d["processors"]["fabricguard/ebpf"].pop("source_kind"),
    )

    def audit_in_node(d: dict[str, Any]) -> None:
        d["receivers"]["audit"] = {
            "source": "netlink",
            "rule_key": "fabric",
            "exec": True,
        }
        d["service"]["pipelines"]["traces/auditd"]["receivers"].append("audit")

    bad("h4-audit-receiver-in-node", "h4", audit_in_node)
    bad("h5-auditd-ebpf-share-a-listener", "h5", lambda d: d["receivers"]["otlp/auditd"]["protocols"].update(
        http=dict(d["receivers"]["otlp/auditd"]["protocols"]["http"], endpoint="0.0.0.0:4417")))  # fmt: skip

    def extra_receiver(d: dict[str, Any]) -> None:
        d["receivers"]["otlp"] = {"protocols": {"grpc": {"endpoint": "127.0.0.1:4317"}}}

    bad("s1-sensor-extra-receiver", "s1", extra_receiver, sensor)
    bad("s2-sensor-without-client-token", "s2",
        lambda d: d["exporters"]["otlp_http/node"].pop("auth"), sensor)  # fmt: skip
    return out


def yaml_text(doc: Mapping[str, Any]) -> str:
    """The documented normalisation: sorted keys, block style, no aliases."""
    return yaml.safe_dump(
        dict(doc), sort_keys=True, default_flow_style=False, width=4096
    )


def _rule_of(error: str) -> str:
    return next(rule for rule, text in ERRORS.items() if text == error)


def index_document(
    texts: Mapping[str, str], tree: Mapping[str, bytes]
) -> dict[str, Any]:
    entries = []
    for rel in sorted(texts):
        doc = yaml.safe_load(texts[rel])
        error = check(doc, tree.get)
        entries.append({
            "path": rel,
            "sha256": hashlib.sha256(texts[rel].encode()).hexdigest(),
            "expectation": "invalid" if rel.startswith("invalid/") else "valid",
            "rule": None if error is None else _rule_of(error),
            "error": error,
        })  # fmt: skip
    return {
        "schema_version": INDEX_SCHEMA,
        "rule": (
            "Spec 053 §6.1, §6.2.6, spec 056 §7.3.3 (f): rendered Node and sensor-collector "
            "configurations as fabric-gate reads them (YAML, sorted keys). Paths follow one "
            "convention: group tokens at /etc/fabric/ingress/<group>/token, receiver TLS at "
            "/etc/fabric/receiver-tls/{tls.crt,tls.key,client-ca.crt} (the chart's existing mount), "
            "the content key at /etc/fabric/content-key/key, the sensor collector's client token "
            "and keys at /etc/fabric/sensor/. files/ holds the token tree at those paths below "
            "'files/'; a test copies it to a temporary root with modes 0400 (directories 0700) and "
            "rewrites the prefix '/etc/fabric/' in every string of the configuration to that root. "
            "Every valid configuration passes the gate; every invalid one is refused with an error "
            "containing its 'error' text. valid/legacy-single-binding.yaml is checked by the "
            "existing single-binding rule, unchanged."
        ),
        "prefix": PREFIX,
        "default_groups": DEFAULT_GROUPS,
        "max_groups": MAX_GROUPS,
        "errors": dict(ERRORS),
        "configs": entries,
        "token_tree": [
            {"path": "files" + path, "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in sorted(tree.items())
        ],
    }


README_HEAD = """# Ingress-group configuration goldens (spec 053 §6.1, §6.2.6; spec 056 M2)

Generated by `scripts/contracts/generate_p0_contracts.py` from
`scripts/contracts/ingress_groups.py`; do not edit. `index.json` pins every file here.

Rendered Node and sensor-collector configurations as fabric-gate reads them, after
confmap's merge, as YAML with sorted keys. fabric-gate (WP4-08a, `gate/groups.go`) accepts
every `valid/` configuration and refuses every `invalid/` one with an error that contains
the text of its row below. The chart (WP4-09) renders the agent-and-host-groups shapes:
`valid/agent-ebpf-auditd.yaml` and `valid/agent-ebpf-three-nodes.yaml` equal its renders
after the same normalisation (sorted keys, resolved names, the prefix rewrite).
`valid/legacy-single-binding.yaml` is today's plain `fabricguard` render, which the
existing single-binding rule keeps checking, unchanged.

## Path convention

| What | Path |
|---|---|
| A group's token | `/etc/fabric/ingress/<group>/token` |
| Receiver TLS (the chart's existing mount) | `/etc/fabric/receiver-tls/{tls.crt,tls.key,client-ca.crt}` |
| The content queue key | `/etc/fabric/content-key/key` |
| The sensor collector's client token, id key, state key, CA | `/etc/fabric/sensor/{token,id_key,state_key,ca.crt}` |

`files/etc/fabric/…` holds the fixture token tree: a distinct token per group of every
golden, two equal tokens (`dup-a`, `dup-b`) for the duplicate-credential case, the content
key and the sensor's files. A test copies the tree to a temporary root with modes 0400
(directories 0700) and rewrites the prefix `/etc/fabric/` in every string of a
configuration to that root before running the gate. The files hold exact bytes, without a
final newline (a trailing newline makes a token fabric-gate refuses); they are test
values, never secrets.

## Configurations

| File | Rule | The gate's error contains |
|---|---|---|
"""


def readme(texts: Mapping[str, str], tree: Mapping[str, bytes]) -> str:
    rows = []
    for entry in index_document(texts, tree)["configs"]:
        rule = entry["rule"] or "(passes)"
        error = f"`{entry['error']}`" if entry["error"] else "(none)"
        rows.append(f"| `{entry['path']}` | {rule} | {error} |")
    return README_HEAD + "\n".join(rows) + "\n"


def generate(w: Any) -> None:
    tree = token_tree()
    texts = {rel: yaml_text(doc) for rel, (doc, _) in goldens().items()}
    for rel, text in texts.items():
        w.text(GOLDENS / rel, text)
    for path, data in tree.items():
        w.text(GOLDENS / ("files" + path), data.decode())
    w.json(GOLDENS / "index.json", index_document(texts, tree))
    w.text(GOLDENS / "README.md", readme(texts, tree))


def validate_index(
    doc: Mapping[str, Any], base: Path, fail: Callable[[str, str, str], NoReturn]
) -> None:
    """The pinned index (``base`` is its directory): every golden and token file hashes as
    listed, every valid configuration passes :func:`check`, every invalid one fails with
    its rule's text."""
    if doc.get("errors") != ERRORS or doc.get("prefix") != PREFIX:
        fail("capture.ingress.index", "$", "errors or prefix differ from the rules")
    tree: dict[str, bytes] = {}
    for entry in doc["token_tree"]:
        data = (base / entry["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            fail("capture.ingress.index", entry["path"], "token file digest")
        tree[entry["path"][len("files") :]] = data
    listed = {e["path"] for e in doc["configs"]}
    on_disk = {p.relative_to(base).as_posix() for p in base.glob("*/*.yaml")}
    if listed != on_disk:
        fail(
            "capture.ingress.index",
            "$.configs",
            f"unlisted configurations {sorted(listed ^ on_disk)}",
        )
    for entry in doc["configs"]:
        text = (base / entry["path"]).read_text(encoding="utf-8")
        if hashlib.sha256(text.encode()).hexdigest() != entry["sha256"]:
            fail("capture.ingress.index", entry["path"], "configuration digest")
        error = check(yaml.safe_load(text), tree.get)
        want = entry["error"] if entry["expectation"] == "invalid" else None
        if error != want or (entry["expectation"] == "invalid") != (want is not None):
            fail(
                "capture.ingress.golden",
                entry["path"],
                f"expected {want!r}, got {error!r}",
            )
    rules = {e["rule"] for e in doc["configs"] if e["expectation"] == "invalid"}
    if rules != set(ERRORS):
        fail(
            "capture.ingress.index",
            "$.configs",
            f"rules without a refused golden {sorted(set(ERRORS) - rules)}",
        )


__all__ = [
    "ERRORS",
    "INDEX_SCHEMA",
    "check",
    "generate",
    "goldens",
    "rewrite",
    "token_tree",
    "validate_index",
]
