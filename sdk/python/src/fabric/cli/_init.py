# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric init`` (spec 058 §5.3), local profile: write ``fabric.yaml``, generate every
secret the profile needs, and compile the environment file.

Idempotent: with a ``fabric.yaml`` it generates only what is missing, never overwrites a
secret, and changes the file only where a flag says so (the diff is printed). ``--force``
rewrites the file and keeps a timestamped backup; it never regenerates a secret (that is
``--rotate``). It is non-interactive, makes no network connection, and never asks for,
prints or logs a secret value."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import difflib
import os
import platform
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..wire._config import parse_endpoints
from . import _config, _kube, _policy, _project, _providers, _secrets, _sizing
from ._report import EXIT_FINDINGS, CliError, Finding, Report

_HEADER = (
    "# SingleAxis Fabric project configuration (fabric.config/v1).\n"
    "# Written by `fabric init`. Edit it, then run `fabric init` again to apply the change.\n"
    "# It holds no secret: generated keys and certificates live in a private directory\n"
    "# outside the project (`fabric init --json` lists their paths and fingerprints).\n"
)
_KEY_ORDER = ("schema", "project", "profile", "shape", "tenant", "agent", "providers",
              "capture", "node", "destination", "sensor", "secrets")  # fmt: skip
#: Variables `--from-env` understands, or that belong to one run and are never imported.
_NOT_IMPORTED_SILENTLY = frozenset({
    "FABRIC_CONFIG", "FABRIC_WIRE_AUTOLOAD", "FABRIC_RUN_ID", "FABRIC_WIRE_STATUS_FILE",
    "FABRIC_NODE_IMAGE", "FABRIC_SENSOR_IMAGE", "FABRIC_SINK_IMAGE", "FABRIC_TRIAL_S3_IMAGE",
})  # fmt: skip
#: The variables `--from-env` writes into fabric.yaml (or stores, with --import-secrets).
_IMPORTED = frozenset({
    "FABRIC_TENANT_ID", "FABRIC_AGENT_ID", "FABRIC_WIRE_EXEC", "FABRIC_WIRE_HTTP_HOSTS",
    "FABRIC_CAPTURE_POLICY", "FABRIC_WIRE_ENDPOINTS", "FABRIC_OTLP_ENDPOINT",
    "FABRIC_OTLP_CERTIFICATE", "FABRIC_WIRE_STORE", "FABRIC_WIRE_ID_KEY",
    "FABRIC_WIRE_ID_KEY_FILE",
})  # fmt: skip
IMPORTED_CA = "imported-ca.crt"
_CA_VARIABLES = ("FABRIC_OTLP_CERTIFICATE", "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
                 "OTEL_EXPORTER_OTLP_CERTIFICATE")  # fmt: skip
#: What `--import-secrets` stores, by the variable a person knows it by (for messages).
_IMPORT_SOURCE = {_secrets.ID_KEY: "FABRIC_WIRE_ID_KEY", IMPORTED_CA: "FABRIC_OTLP_CERTIFICATE"}
#: OTLP variables `--from-env` reads (the SDK reads them when no FABRIC_OTLP_* is set).
_OTEL_UNDERSTOOD = frozenset({
    "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_CERTIFICATE", "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
})  # fmt: skip
_TRUE = ("1", "true", "yes", "on")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """The flags of §5.3. Those this release does not build are accepted and answered with
    ``FC-011``, so the message names the manual route instead of "unknown flag"."""
    parser.add_argument("--profile", choices=("local", "production"))
    parser.add_argument(
        "--production",
        action="store_true",
        help="the production profile (same as --profile production): tokens, client "
        "certificates, an encrypted spool and a capture policy written into the project",
    )
    parser.add_argument("--shape", choices=("laptop", "linux-host", "container", "kubernetes"))
    parser.add_argument("--tenant", metavar="ID")
    parser.add_argument("--agent", metavar="ID")
    parser.add_argument(
        "--provider",
        action="append",
        default=[],
        metavar="[DIALECT=]URL",
        help="a model endpoint outside the built-in table, by its base URL",
    )
    parser.add_argument(
        "--destination",
        metavar="PRESET",
        choices=_config.DESTINATION_PRESETS,
        help="where records go: local-dir (local), trial, s3, s3-compatible or otlp (production)",
    )
    preset = parser.add_argument_group("destination preset inputs (spec 058 §9.1)")
    preset.add_argument("--bucket", metavar="NAME", help="s3, s3-compatible: the bucket")
    preset.add_argument("--region", metavar="NAME", help="s3, s3-compatible: its region")
    preset.add_argument("--sse-kms-key", metavar="KEY", help="s3: the KMS key id or ARN")
    preset.add_argument("--endpoint", metavar="URL",
                        help="s3-compatible: the store's https URL")  # fmt: skip
    preset.add_argument("--ca-file", metavar="PATH",
                        help="s3-compatible: the store's private CA certificate")  # fmt: skip
    preset.add_argument("--credentials-file", metavar="PATH",
                        help="s3-compatible: an AWS credentials file the Node reads")  # fmt: skip
    preset.add_argument("--otlp-endpoint", metavar="URL",
                        help="otlp, s3, s3-compatible: your OTLP/HTTP collector, where spans "
                        "go")  # fmt: skip
    preset.add_argument("--otlp-ca-file", metavar="PATH",
                        help="the collector's private CA certificate")  # fmt: skip
    preset.add_argument("--otlp-headers-file", metavar="PATH",
                        help="a file with the collector's headers (Authorization=...)")  # fmt: skip
    parser.add_argument(
        "--queue-size",
        metavar="SIZE",
        help="the disk the Node's durable queue may use (20GiB, 500MB, or auto: half the "
        "free space)",
    )
    parser.add_argument(
        "--image-digest",
        type=_policy.image_digest_argument,
        metavar="sha256:HEX",
        help="production: the agent image's digest, written into the capture policy",
    )
    parser.add_argument(
        "--exec",
        action="store_true",
        default=None,
        dest="capture_exec",
        help="record the commands the agent runs",
    )
    parser.add_argument(
        "--http-host",
        action="append",
        default=[],
        metavar="HOST",
        help="a non-model HTTP host to record",
    )
    parser.add_argument(
        "--mcp", action="store_true", default=None, help="record MCP transport messages"
    )
    parser.add_argument("--sensor", choices=("auto", "ebpf", "auditd", "off"))
    parser.add_argument(
        "--from-env",
        action="store_true",
        help="import the FABRIC_* and OTEL_* settings of this shell",
    )
    parser.add_argument(
        "--import-secrets",
        action="store_true",
        help="with --from-env: copy the id key and CA into the secrets directory",
    )
    parser.add_argument(
        "--rotate",
        metavar="NAME",
        choices=(*_secrets.ROTATABLE, "all"),
        help="rotate a generated secret: node-cert, ca, id-key, tokens or client-certs "
        "(production), or all (every one but the id key)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="rewrite fabric.yaml from the defaults and flags (keeps a backup, the project "
        "name and where its secrets are)",
    )
    kube = parser.add_argument_group("Kubernetes (spec 058 §10.2): Secrets instead of files")
    kube.add_argument("--kubernetes", action="store_true",
                      help="create the missing Secrets in the current kube context")  # fmt: skip
    kube.add_argument("--namespace", metavar="NS",
                      help="the release namespace (default fabric-system)")  # fmt: skip
    kube.add_argument("--agent-namespace", action="append", metavar="NS[=SOURCE]",
                      help="a namespace whose agents send to the Node (repeatable); SOURCE is "
                      "their source label (default the namespace name)")  # fmt: skip
    kube.add_argument("--render", metavar="DIR",
                      help="write the Secrets as manifests into DIR instead (GitOps)")  # fmt: skip
    kube.add_argument("--release", metavar="NAME", help="the Helm release name (default fabric)")
    kube.add_argument("--injector", action="store_true",
                      help="also the pod injector's serving certificate")  # fmt: skip
    kube.add_argument("--content", action="store_true",
                      help="with --profile production: also the Node's content key")  # fmt: skip
    kube.add_argument("--host-sensor", action="store_true",
                      help="with --profile production: also the Secrets of the chart's host "
                      "sensor DaemonSet (the shared id key, its client certificate and one "
                      "Secret per --host-node)")  # fmt: skip
    kube.add_argument("--host-node", action="append", metavar="NODE",
                      help="a node that runs the host sensor (repeatable), as "
                      "`kubectl get nodes` names it")  # fmt: skip
    kube.add_argument("--cluster-domain", metavar="DOMAIN", help="default cluster.local")
    # Set by the chart's hook Jobs, which know the rendered names.
    kube.add_argument("--in-cluster", action="store_true", help=argparse.SUPPRESS)
    kube.add_argument("--node-service", help=argparse.SUPPRESS)
    kube.add_argument("--injector-service", help=argparse.SUPPRESS)
    kube.add_argument("--secret-name", action="append", metavar="ROLE=NAME", help=argparse.SUPPRESS)
    kube.add_argument("--webhook", metavar="NAME", help=argparse.SUPPRESS)
    # Accepted so the answer is FC-011 with the manual route, not an argparse error.
    parser.add_argument("--from-env-file", metavar="FILE", help=argparse.SUPPRESS)
    parser.add_argument("--from-values", metavar="FILE", help=argparse.SUPPRESS)


_KUBERNETES_ONLY = ("namespace", "agent_namespace", "render", "release", "injector", "content",
                    "cluster_domain", "in_cluster", "node_service", "injector_service",
                    "secret_name", "webhook", "host_sensor", "host_node")  # fmt: skip
#: The destination preset flags (§9.1), each the fabric.yaml key of the same name.
PRESET_FLAGS = ("bucket", "region", "sse_kms_key", "endpoint", "ca_file", "credentials_file",
                "otlp_endpoint", "otlp_ca_file", "otlp_headers_file")  # fmt: skip


def _flag(name: str) -> str:
    return "--" + name.replace("_", "-")


def _production_flag(options: argparse.Namespace) -> None:
    """``--production`` is ``--profile production`` (G3's ``fabric init --production``)."""
    if getattr(options, "production", False):
        if options.profile == "local":
            raise CliError([Finding("FC-004", "--production and --profile local: choose one")])
        options.profile = "production"


def _refuse_unbuilt(options: argparse.Namespace) -> None:
    _production_flag(options)
    for name in _KUBERNETES_ONLY:
        if getattr(options, name, None) and not options.kubernetes:
            raise CliError([Finding("FC-106", "--" + name.replace("_", "-"))])
    if options.kubernetes:
        local_only = [("--from-env", options.from_env), ("--rotate", options.rotate),
                      ("--force", options.force), ("--provider", options.provider),
                      ("--from-env-file", options.from_env_file),
                      ("--from-values", options.from_values),
                      ("--destination", options.destination),
                      ("--queue-size", options.queue_size),
                      ("--image-digest", options.image_digest),
                      *((_flag(key), getattr(options, key)) for key in PRESET_FLAGS)]  # fmt: skip
        for name, given in local_only:
            if given:
                raise CliError([Finding("FC-011", f"{name} with --kubernetes")])
        return
    unbuilt = [
        ("--from-env-file", options.from_env_file), ("--from-values", options.from_values),
        ("--shape kubernetes", options.shape == "kubernetes"),
    ]  # fmt: skip
    for name, given in unbuilt:
        if given:
            raise CliError([Finding("FC-011", name)])
    if options.import_secrets and not options.from_env:
        raise CliError([Finding("FC-006", "--import-secrets needs --from-env")])


def detect_shape(system: str | None = None, in_container: bool | None = None) -> str:
    """The shape `init` writes when none is given: ``container`` inside one, ``linux-host``
    on Linux, ``laptop`` elsewhere (the full probes are `fabric plan`)."""
    system = system or platform.system()
    if in_container is None:
        in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    if system == "Linux":
        return "container" if in_container else "linux-host"
    return "laptop"


# ---------------------------------------------------------------- the document


def _set(document: dict[str, Any], key: str, value: Any) -> None:
    node = document
    *parents, leaf = key.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value


def _ordered(document: Mapping[str, Any]) -> dict[str, Any]:
    known = {key: document[key] for key in _KEY_ORDER if key in document}
    return {**known, **{k: v for k, v in document.items() if k not in known}}


def fresh_document(project: str, shape: str) -> dict[str, Any]:
    """The ``fabric.yaml`` `init` writes (§5.3 defaults, §6.1): the local profile's; the
    production flags change it (:func:`apply_flags`)."""
    return {
        "schema": _config.CONFIG_SCHEMA, "project": project, "profile": "local", "shape": shape,
        "tenant": "default", "agent": project,
        "providers": {"builtin": True, "from_environment": True, "custom": []},
        "capture": {"content": True, "privacy": "profile-default", "exec": False,
                    "http_hosts": [], "mcp": False},
        "node": {"mode": "docker", "endpoint": "auto"},
        "destination": {"preset": "local-dir", "path": "./fabric-data"},
        "sensor": {"kind": "auto"},
        "secrets": {"dir": "auto"},
    }  # fmt: skip


def render_document(document: Mapping[str, Any]) -> str:
    yaml = _config._yaml()
    body: str = yaml.safe_dump(_ordered(document), sort_keys=False, default_flow_style=False,
                               allow_unicode=True)  # fmt: skip
    return _HEADER + body


def _provider_entry(text: str) -> dict[str, Any]:
    matcher = _providers.parse_provider(text)  # FC-008 when not usable
    prefix, _, rest = text.partition("=")
    url = rest if prefix in ("openai", "anthropic") else text
    entry: dict[str, Any] = {"url": url.strip()}
    if matcher.dialect != "openai":
        entry["dialect"] = matcher.dialect
    return entry


def _append_unique(document: dict[str, Any], key: str, items: list[Any]) -> None:
    present, current = _config._lookup(document, key)
    merged = list(current) if present and isinstance(current, list) else []
    for item in items:
        if item not in merged:
            merged.append(item)
    _set(document, key, merged)


LOCAL_DIR = {"preset": "local-dir", "path": "./fabric-data"}
Ask = Callable[[str], str]


def _destination_flags(document: dict[str, Any], options: argparse.Namespace) -> None:
    """``--destination PRESET`` and its inputs (§9.1). A new preset replaces the
    destination; inputs without ``--destination`` change the current one. Keys a preset
    does not take are refused by the schema check that follows, by name."""
    given = {key: getattr(options, key) for key in PRESET_FLAGS if getattr(options, key, None)}
    current = dict(document.get("destination") or {})
    if options.destination:
        destination = current if current.get("preset") == options.destination else {
            "preset": options.destination}  # fmt: skip
        if options.destination in ("local-dir", "trial"):
            destination.setdefault("path", "./fabric-data")
    elif given:
        if not current:
            raise CliError([Finding("FC-004", f"{_flag(next(iter(given)))} needs --destination "
                                              "PRESET")])  # fmt: skip
        destination = current
    else:
        return
    destination.update(given)
    _set(document, "destination", destination)


def _prompt_destination(ask: Ask) -> dict[str, Any]:
    """§5.3: on a TTY, the one choice `init` cannot default, a production destination, and
    the identifiers it needs (never a secret)."""
    choices = ", ".join(_config.PRODUCTION_PRESETS)
    preset = ""
    while preset not in _config.PRODUCTION_PRESETS:
        preset = ask(f"Where should records go? {choices} [trial]: ").strip() or "trial"
    destination: dict[str, Any] = {"preset": preset}
    if preset == "trial":
        destination["path"] = "./fabric-data"
    needed = list(_config.PRESET_REQUIRED.get(preset, ()))
    if preset in ("s3", "s3-compatible"):
        needed.append("otlp_endpoint")
    for key in needed:
        value = ""
        while not value:
            value = ask(f"{_flag(key)[2:].replace('-', ' ')}: ").strip()
        destination[key] = value
    return destination


def _profile_switch(document: dict[str, Any], options: argparse.Namespace,
                    ask: Ask | None, findings: list[Finding]) -> None:  # fmt: skip
    """What the profile implies for the settings this command did not name: production
    writes the capture policy preset (§6.3) and needs a production destination; back to
    local, the local-dir destination and the implicit local policy."""
    present, privacy = _config._lookup(document, "capture.privacy")
    privacy = privacy if present else "profile-default"
    preset = (document.get("destination") or {}).get("preset", "local-dir")
    if options.profile == "production":  # this command asks for production
        if privacy == "profile-default":
            _set(document, "capture.privacy", _policy.PRESET_SETTING)
        if preset == "local-dir" and not options.destination:
            if ask is not None:
                _set(document, "destination", _prompt_destination(ask))
            else:
                _set(document, "destination", {"preset": "trial", "path": "./fabric-data"})
                findings.append(Finding("FC-172", "chosen because no --destination was given"))
    elif options.profile == "local":
        if privacy == _policy.PRESET_SETTING:
            _set(document, "capture.privacy", "profile-default")
        if preset != "local-dir" and not options.destination:
            _set(document, "destination", dict(LOCAL_DIR))


def apply_flags(document: dict[str, Any], options: argparse.Namespace, ask: Ask | None = None,
                findings: list[Finding] | None = None) -> None:  # fmt: skip
    """The settings the flags of this command name, and what a profile change implies;
    nothing else in the file changes."""
    scalars = {"project": options.project, "profile": options.profile, "shape": options.shape,
               "tenant": options.tenant, "agent": options.agent,
               "capture.exec": options.capture_exec, "capture.mcp": options.mcp,
               "sensor.kind": options.sensor,
               "node.queue_size": _queue_size(getattr(options, "queue_size", None))}  # fmt: skip
    for key, value in scalars.items():
        if value is not None:
            _set(document, key, value)
    _destination_flags(document, options)
    _profile_switch(document, options, ask, findings if findings is not None else [])
    if options.provider:
        _append_unique(document, "providers.custom", [_provider_entry(p) for p in options.provider])
    if options.http_host:
        _append_unique(document, "capture.http_hosts", list(options.http_host))


def _queue_size(text: str | None) -> Any:
    """``--queue-size``: ``auto``, or a size kept as the person wrote it."""
    if text is None:
        return None
    value = text.strip()
    if value == "auto":
        return value
    if _config.parse_size(value) is None:
        raise CliError([Finding("FC-004", "--queue-size: must be auto, a number of bytes, or "
                                          "a size such as 20GiB or 500MB")])  # fmt: skip
    return int(value) if value.isdigit() else value


# ---------------------------------------------------------------- --from-env (§11.3)


def _not_imported(name: str, why: str) -> Finding:
    return Finding("FC-018", f"{name}: {why}")


def _matcher_url(matcher: Any) -> str | None:
    if len(matcher.hosts) != 1 or matcher.host_suffixes or len(matcher.schemes) != 1:
        return None
    if matcher.ports is not None and len(matcher.ports) != 1:
        return None
    scheme, host = next(iter(matcher.schemes)), next(iter(matcher.hosts))
    port = f":{next(iter(matcher.ports))}" if matcher.ports else ""
    return f"{scheme}://{host}{port}{matcher.path_prefix}"


def _import_endpoints(text: str, document: dict[str, Any], findings: list[Finding]) -> None:
    try:
        matchers = parse_endpoints(text)
    except ValueError:
        findings.append(_not_imported("FABRIC_WIRE_ENDPOINTS", "is not a valid matcher list"))
        return
    entries = []
    for matcher in matchers:
        url = _matcher_url(matcher)
        if url is None:
            findings.append(
                _not_imported(
                    "FABRIC_WIRE_ENDPOINTS",
                    f"entry {matcher.endpoint_id} names several hosts, "
                    "ports or schemes; fabric.yaml takes one base URL per provider",
                )
            )
            continue
        entry: dict[str, Any] = {"url": url, "name": matcher.endpoint_id}
        if matcher.dialect != "openai":
            entry["dialect"] = matcher.dialect
        entries.append(entry)
    if entries:
        _append_unique(document, "providers.custom", entries)


def _import_node(environ: Mapping[str, str], document: dict[str, Any],
                 findings: list[Finding]) -> None:  # fmt: skip
    for name, suffix in (("FABRIC_OTLP_ENDPOINT", ""),
                         ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "/v1/traces"),
                         ("OTEL_EXPORTER_OTLP_ENDPOINT", "")):  # fmt: skip
        value = (environ.get(name) or "").strip()
        if not value:
            continue
        value = value.removesuffix(suffix).rstrip("/") if suffix else value.rstrip("/")
        try:
            _config._url("https", "http")(name, value)
        except _config._InvalidError:
            findings.append(_not_imported(name, "is not an http(s) URL without credentials"))
            return
        # The shell already points at a Node somebody started: `up` must not start another.
        _set(document, "node.mode", "external")
        _set(document, "node.endpoint", value)
        return


def _import_store(environ: Mapping[str, str], document: dict[str, Any], directory: Path,
                  findings: list[Finding]) -> None:  # fmt: skip
    value = (environ.get("FABRIC_WIRE_STORE") or "").strip()
    if not value:
        return
    parts = urlsplit(value)
    if parts.scheme != "file" or not parts.path:
        findings.append(_not_imported("FABRIC_WIRE_STORE", "only a file:// store is a local-dir "
                                      "destination"))  # fmt: skip
        return
    store = Path(parts.path)
    if store.name != "store":
        findings.append(
            _not_imported(
                "FABRIC_WIRE_STORE",
                "the local-dir destination keeps content in <path>/store; "
                "this store directory has another name",
            )
        )
        return
    data = store.parent
    try:
        relative = data.resolve().relative_to(directory.resolve())
        path = "./" + relative.as_posix() if relative.parts else "."
    except ValueError:
        path = str(data)
    _set(document, "destination", {"preset": "local-dir", "path": path})


def _import_settings(environ: Mapping[str, str], document: dict[str, Any],
                     findings: list[Finding]) -> None:  # fmt: skip
    for name, key in (("FABRIC_TENANT_ID", "tenant"), ("FABRIC_AGENT_ID", "agent")):
        if value := (environ.get(name) or "").strip():
            if _config._ID_RE.fullmatch(value):
                _set(document, key, value)
            else:
                findings.append(_not_imported(name, "is not a valid id"))
    if (environ.get("FABRIC_WIRE_EXEC") or "").strip().lower() in _TRUE:
        _set(document, "capture.exec", True)
    if hosts := _config._env_list(environ.get("FABRIC_WIRE_HTTP_HOSTS") or ""):
        if all(_config._HOST_RE.fullmatch(host) for host in hosts):
            _append_unique(document, "capture.http_hosts", hosts)
        else:
            findings.append(_not_imported("FABRIC_WIRE_HTTP_HOSTS", "has an entry that is not "
                                          "host or host:port"))  # fmt: skip
    if policy := (environ.get("FABRIC_CAPTURE_POLICY") or "").strip():
        _set(document, "capture.privacy", policy)
    if endpoints := environ.get("FABRIC_WIRE_ENDPOINTS"):
        _import_endpoints(endpoints, document, findings)


def _read_for_import(name: str, path: str, findings: list[Finding]) -> bytes | None:
    try:
        return Path(path).read_bytes()
    except OSError:
        findings.append(_not_imported(name, "the file is not readable"))
        return None


def _import_secret_references(environ: Mapping[str, str], document: dict[str, Any],
                              findings: list[Finding], import_secrets: bool
                              ) -> dict[str, bytes]:  # fmt: skip
    """The CA and the id key: referenced by their existing paths, or (``import_secrets``)
    returned for storing as files in the secrets directory."""
    to_store: dict[str, bytes] = {}
    ca_name = next((name for name in _CA_VARIABLES if (environ.get(name) or "").strip()), "")
    ca = (environ.get(ca_name) or "").strip() if ca_name else ""
    _, node_mode = _config._lookup(document, "node.mode")
    if ca and node_mode != "external":
        # No Node endpoint came with it: `fabric up` starts a local Node whose certificate
        # the generated CA signs, so this CA would make agents refuse that Node.
        findings.append(
            _not_imported(
                ca_name,
                "is the CA of a Node this shell does not name (no OTLP endpoint is set); "
                "the local Node gets its own generated CA",
            )
        )
    elif ca and not import_secrets:
        _set(document, "secrets.ca_file", ca)
    elif ca and (data := _read_for_import(ca_name, ca, findings)) is not None:
        to_store[IMPORTED_CA] = data
    key_file = (environ.get("FABRIC_WIRE_ID_KEY_FILE") or "").strip()
    key_value = environ.get("FABRIC_WIRE_ID_KEY") or ""
    if key_file and not import_secrets:
        _set(document, "secrets.id_key_file", key_file)
    elif key_file:
        data = _read_for_import("FABRIC_WIRE_ID_KEY_FILE", key_file, findings)
        if data is not None:
            # Byte for byte: the SDK ignores exactly one trailing newline of a key file,
            # so only an identical copy is certain to give the same key.
            to_store[_secrets.ID_KEY] = data
    elif key_value and import_secrets:
        # The SDK drops one trailing newline of a key file: keep one that is part of the key.
        to_store[_secrets.ID_KEY] = (key_value + ("\n" if key_value.endswith("\n") else "")
                                     ).encode("utf-8", "surrogatepass")  # fmt: skip
    elif key_value:
        findings.append(
            _not_imported(
                "FABRIC_WIRE_ID_KEY",
                "is set by value and stays in your shell; --import-secrets "
                "stores it as a file so pseudonyms stay the same",
            )
        )
    return to_store


def import_environment(
    environ: Mapping[str, str], document: dict[str, Any], directory: Path, *, import_secrets: bool
) -> tuple[list[Finding], dict[str, bytes]]:
    """§11.3: write the settings of an existing manual setup (the ``FABRIC_*`` and
    ``OTEL_*`` environment) into ``document``. Secrets are referenced by their existing
    paths; with ``import_secrets`` the id key and CA are returned for storing as files.
    Whatever cannot be expressed is reported by variable name (never by value)."""
    findings: list[Finding] = []
    _import_settings(environ, document, findings)
    _import_node(environ, document, findings)
    _import_store(environ, document, directory, findings)
    to_store = _import_secret_references(environ, document, findings, import_secrets)
    for name in sorted(environ):
        if name in _IMPORTED or name in _NOT_IMPORTED_SILENTLY or not environ[name].strip():
            continue
        if name.startswith("FABRIC_") or (name.startswith("OTEL_EXPORTER_OTLP_")
                                          and name not in _OTEL_UNDERSTOOD):  # fmt: skip
            findings.append(_not_imported(name, "has no fabric.yaml setting"))
    return findings, to_store


# ---------------------------------------------------------------- the command


#: What `--force` keeps from the file it rewrites: the settings that locate the project's
#: secrets and name its Compose project. Without them the rewrite would move the secrets
#: directory (a new id key, so new pseudonyms; a new CA) and leave the running Node behind
#: under the old Compose project, although --force never regenerates a secret (§5.3).
#: (secrets.ca_file is not kept: it is an external Node's CA, and --force resets the Node
#: to the local one, whose CA is generated.)
_KEPT_ON_FORCE = ("project", "secrets.dir", "secrets.id_key_file")


def _kept_on_force(path: Path, fresh: Mapping[str, Any]) -> dict[str, Any]:
    """The :data:`_KEPT_ON_FORCE` settings of the file ``--force`` rewrites, each kept only
    when it is valid on its own (a file broken elsewhere can still be reset)."""
    yaml = _config._yaml()
    try:
        old = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return {}
    if not isinstance(old, Mapping):
        return {}
    kept: dict[str, Any] = {}
    for key in _KEPT_ON_FORCE:
        present, value = _config._lookup(old, key)
        if not present:
            continue
        candidate = copy.deepcopy(dict(fresh))
        _set(candidate, key, value)
        try:
            _config.validate(candidate)
        except CliError:
            continue
        kept[key] = value
    return kept


def _backup(path: Path, now: dt.datetime | None = None) -> Path:
    stamp = (now or dt.datetime.now(dt.UTC)).strftime("%Y%m%dT%H%M%SZ")
    target = path.with_name(f"{path.name}.bak-{stamp}")
    index = 1
    while target.exists():
        target = path.with_name(f"{path.name}.bak-{stamp}-{index}")
        index += 1
    target.write_bytes(path.read_bytes())
    return target


def _write_text(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _diff(old: str, new: str, name: str) -> list[str]:
    return [
        line.rstrip("\n")
        for line in difflib.unified_diff(
            old.splitlines(keepends=True), new.splitlines(keepends=True), name, name, n=1
        )
    ]


def _rotation_names(name: str, production: bool = False) -> tuple[str, ...]:
    # `all` leaves the id key alone: a new id key changes every pseudonym and is never
    # automatic (§7.3). A new CA comes with a new Node certificate (and, in production,
    # new client certificates).
    if name == "all":
        return ("ca", "tokens", "client-certs") if production else ("ca",)
    return (name,)


_ROTATION_NOTES = {
    "tokens": "tokens: run `fabric up` so the Node restarts with the new tokens (its ingress "
              "takes one token per source, so the old ones stop working then), then restart "
              "agents and the host sensor; the old tokens are kept read-only under retired/",
    "client-certs": "client-certs: restart agents and the host sensor so they present the new "
                    "certificates",
    "node-cert": "node-cert: run `fabric up` so the Node restarts with the new certificate",
    "ca": "ca: run `fabric up`, then restart agents so they load the new CA",
    "id-key": "id-key: restart agents; pseudonyms change from their next start, and the old "
              "key is kept read-only under retired/ for the reader",
}  # fmt: skip


def write_config(options: argparse.Namespace, environ: Mapping[str, str], cwd: Path,
                 ask: Ask | None = None
                 ) -> tuple[_config.Located, dict[str, Any], dict[str, Any], dict[str, bytes],
                            list[Finding], list[str]]:  # fmt: skip
    """Create or update ``fabric.yaml``. Returns where it is, the document, what happened
    (for the report), secrets to store (``--import-secrets``), findings and output lines."""
    located = _config.discover(options.config, environ, cwd)
    path = located.path if located.path is not None else cwd / _config.CONFIG_NAME
    exists = path.is_file()
    directory = path.resolve().parent
    findings: list[Finding] = []
    lines: list[str] = []
    old_text = path.read_text(encoding="utf-8") if exists else ""
    original: dict[str, Any] | None = None
    if exists and not options.force:
        original = _config.load(_config.Located(path, located.source))
        document = copy.deepcopy(original)
    else:
        name = options.project or _config._project_name(directory)
        document = fresh_document(name, options.shape or detect_shape())
        if exists:  # --force
            kept = _kept_on_force(path, document)
            if "project" in kept and not options.project:  # the agent id defaults to it
                document = fresh_document(kept["project"], document["shape"])
            for key, value in kept.items():
                if key != "project" or not options.project:
                    _set(document, key, value)
    to_store: dict[str, bytes] = {}
    if options.from_env:
        imported, to_store = import_environment(environ, document, directory,
                                                import_secrets=options.import_secrets)  # fmt: skip
        findings.extend(imported)
    apply_flags(document, options, ask, findings)
    if IMPORTED_CA in to_store:  # the copied CA is referenced by its new path
        _, setting = _config._lookup(document, "secrets.dir")
        target = _secrets.secrets_dir(
            str(setting or "auto"),
            str(document.get("project") or _config._project_name(directory)),
            directory,
            environ,
        )
        _set(document, "secrets.ca_file", str(target / IMPORTED_CA))
    _config.validate(document)
    # Refuse what this release cannot compile (another profile, an ignored setting, an
    # external CA beside a local Node) before the file changes: a refused `init` changes
    # nothing, rather than writing the flags and then exiting 2 without the diff.
    _project.compile_environment(_project.load(_config.Located(path, "cwd"), {}, environ,
                                               document))  # fmt: skip
    happened: dict[str, Any] = {"path": str(path), "action": "kept"}
    if not exists:
        _write_text(path, render_document(document))
        happened["action"] = "created"
        lines.append(f"wrote {path}")
    elif options.force:
        backup = _backup(path)
        _write_text(path, render_document(document))
        happened.update(action="rewritten", backup=str(backup))
        lines.append(f"rewrote {path} (backup: {backup})")
    elif document != original:
        new_text = render_document(document)
        _write_text(path, new_text)
        happened["action"] = "updated"
        lines.append(f"updated {path}:")
        lines.extend("  " + line for line in _diff(old_text, new_text, path.name))
    return _config.Located(path, located.source if exists else "cwd"), document, happened, \
        to_store, findings, lines  # fmt: skip


def _readable_file(path: Path) -> bool:
    """A regular file this user can open for reading (its content is never read)."""
    return path.is_file() and os.access(path, os.R_OK)


@dataclass
class Prepared:
    """What :func:`prepare` did: the secrets (names, paths, fingerprints; never a value),
    the findings, whether the compiled environment changed and, in production, the
    capture policy, the Node's settings file, the derived source ids and the queue plan."""

    secrets: list[_secrets.SecretInfo]
    findings: list[Finding]
    compiled_changed: bool
    production: dict[str, Any] = field(default_factory=dict)
    queue: _sizing.QueuePlan | None = None


def _private_enough(path: Path) -> bool:
    try:
        return os.name != "posix" or not path.stat().st_mode & 0o077
    except OSError:
        return False


def destination_files(project: _project.Project) -> list[Finding]:
    """``FC-174`` for each file the destination names (§9.1: CA, credentials and headers
    files by path) that is missing or unreadable, and for a credentials or headers file
    other users can read. Contents are never read."""
    findings: list[Finding] = []
    destination = project.destination
    for key in ("ca_file", "credentials_file", "otlp_ca_file", "otlp_headers_file"):
        if not destination.get(key):
            continue
        path = _project._absolute(project.directory, str(destination[key]))
        if not _readable_file(path):
            findings.append(Finding("FC-174", f"destination.{key}: {path} is missing or not "
                                              "a readable file"))  # fmt: skip
        elif key in ("credentials_file", "otlp_headers_file") and not _private_enough(path):
            findings.append(Finding("FC-174", f"destination.{key}: {path} is open to other "
                                              "users; chmod 0600 it"))  # fmt: skip
    return findings


def _production(
    project: _project.Project,
    image_digest: str | None,
    findings: list[Finding],
    rotate: str | None = None,
) -> tuple[list[_secrets.SecretInfo], dict[str, Any]]:
    """§7.1 and §6.3: the production secrets, the capture policy preset (written once,
    then the customer's), and the destination's own files and caveats."""
    preset = project.destination.get("preset")
    rotating_tokens = bool(rotate) and "tokens" in _rotation_names(str(rotate), production=True)
    secrets_now = _secrets.ensure_production(project.secrets_dir, project.source_labels(),
                                             trial=preset == "trial",
                                             rotating_tokens=rotating_tokens)  # fmt: skip
    policy = project.policy_path
    if policy is None:  # compile refuses a production project without one
        raise CliError([Finding("FC-166", "capture.privacy: profile-default")])
    written = False
    if policy == project.directory / _policy.PRESET_FILE:
        written = _policy.write_preset(policy, str(project.resolved["tenant"]),
                                       str(project.resolved["agent"]),
                                       image_digest=image_digest)  # fmt: skip
    if not written and image_digest:
        # The file is the customer's (an existing preset or their own): never rewritten,
        # so the flag's value went nowhere, and the finding says where to put it.
        findings.append(Finding("FC-175", f"--image-digest: {policy}"))
    findings.extend(_policy.check(policy, str(project.resolved["tenant"])))
    findings.extend(destination_files(project))
    if preset == "trial":
        findings.append(Finding("FC-172", "destination.preset: trial"))
    if preset not in _project.CONTENT_PRESETS or not project.resolved["capture.content"]:
        findings.append(Finding("FC-173", f"destination.preset: {preset}"))
    data = {"policy": {"path": str(policy), "action": "generated" if written else "kept"}}
    return secrets_now, data


def prepare(project: _project.Project, *, rotate: str | None = None,
            to_store: Mapping[str, bytes] | None = None,
            image_digest: str | None = None,
            disk_usage: Callable[[Path], Any] | None = None) -> Prepared:  # fmt: skip
    """Everything `init` does after ``fabric.yaml`` exists, shared with `fabric up`: the
    state directory, the secrets (generated when missing), the capture policy preset in
    production, the compiled environment, the Node's settings and the queue advice."""
    _project.compile_environment(project)  # refuse what cannot compile before writing anything
    _project.ensure_state_dir(project)
    findings: list[Finding] = []
    for name, data in (to_store or {}).items():
        stored = _secrets.import_file(project.secrets_dir, name, data,
                                      public=name.endswith(".crt"))  # fmt: skip
        if _secrets._read(stored) != data:
            # Never overwritten (§5.3), and never silently: the shell's secret is not the
            # one this project uses.
            findings.append(
                _not_imported(
                    _IMPORT_SOURCE.get(name, name),
                    f"the secrets directory already holds another {name}, which is kept; "
                    f"move {stored} away and run the import again to use the shell's",
                )
            )
    generate_id_key = project.resolved["secrets.id_key_file"] is None
    secrets_now = _secrets.ensure_local(project.secrets_dir, project.name, id_key=generate_id_key,
                                        tls=project.generates_tls)  # fmt: skip
    production: dict[str, Any] = {}
    if project.production:
        more, production = _production(project, image_digest, findings, rotate)
        secrets_now += more
    if rotate:
        secrets_now = _rotate(project, rotate, generate_id_key, secrets_now, findings)
    for key, name in (("secrets.id_key_file", "id-key"), ("secrets.ca_file", "ca")):
        if not project.resolved[key]:
            continue
        referenced = _project._absolute(project.directory, str(project.resolved[key]))
        secrets_now.append(_secrets.SecretInfo(name, (str(referenced),), "referenced"))
        if not _readable_file(referenced):
            # The compiled environment would name a file the agent cannot read: say so now,
            # not at the agent's first run.
            findings.append(Finding("FC-031", f"{key}: {referenced}"))
    queue = _sizing.plan(project.resolved["node.queue_size"], project.queue_dir,
                         production=project.production,
                         content=project.destination.get("preset") in _project.CONTENT_PRESETS,
                         **({"disk_usage": disk_usage} if disk_usage else {}))  # fmt: skip
    findings.extend(queue.findings)
    _, changed = _project.write_compiled_env(project)
    if project.production:
        node_env, node_changed = _project.write_node_env(project, queue)
        production.update(
            node_env={"path": str(node_env), "changed": node_changed},
            source_labels=project.source_labels(),
            source_ids=_project.derived_source_ids(project),
        )
    return Prepared(secrets_now, findings, changed, production, queue)


def _rotate(project: _project.Project, rotate: str, generate_id_key: bool,
            secrets_now: list[_secrets.SecretInfo], findings: list[Finding]
            ) -> list[_secrets.SecretInfo]:  # fmt: skip
    names = _rotation_names(rotate, project.production)
    if "id-key" in names and not generate_id_key:
        raise CliError([Finding("FC-004", "secrets.id_key_file: the id key is referenced, "
                                "not generated; rotate it where it lives")])  # fmt: skip
    if not project.generates_tls and set(names) & {"ca", "node-cert"}:
        raise CliError([Finding("FC-004", "node.mode: an external Node has its own "
                                "certificate; there is none to rotate here")])  # fmt: skip
    if not project.production and set(names) & _secrets.PRODUCTION_ROTATABLE:
        raise CliError([Finding("FC-004", f"--rotate {rotate}: the local profile has no tokens "
                                          "or client certificates (fabric init --production "
                                          "generates them)")])  # fmt: skip
    local = [name for name in names if name not in _secrets.PRODUCTION_ROTATABLE]
    rotated = {info.name: info for info in
               _secrets.rotate(project.secrets_dir, project.name, local)}  # fmt: skip
    if project.production:
        rotated.update({info.name: info for info in _secrets.rotate_production(
            project.secrets_dir, names, project.source_labels(),
            trial=project.destination.get("preset") == "trial")})  # fmt: skip
    findings.extend(Finding("FC-016", _ROTATION_NOTES[name]) for name in names)
    return [rotated.get(info.name, info) for info in secrets_now]


def _ask_on_tty(options: argparse.Namespace) -> Ask | None:
    """§5.3: prompt only on a TTY (stdin and stderr), never with --json or --quiet."""
    if options.json or options.quiet or not (sys.stdin.isatty() and sys.stderr.isatty()):
        return None

    def ask(prompt: str) -> str:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = sys.stdin.readline()
        if not line:  # end of input (Ctrl-D): stop asking, write nothing
            sys.stderr.write("\n")
            raise CliError([Finding("FC-165", "no answer was given on the terminal")])
        return line

    return ask


def run(options: argparse.Namespace, environ: Mapping[str, str] | None = None,
        cwd: Path | None = None, *, ask: Ask | None = None,
        disk_usage: Callable[[Path], Any] | None = None) -> tuple[Report, list[str]]:  # fmt: skip
    """``fabric init``."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    _refuse_unbuilt(options)
    if options.kubernetes:
        return run_kubernetes(options, environ)
    ask = ask if ask is not None else _ask_on_tty(options)
    located, document, happened, to_store, findings, lines = write_config(options, environ, cwd,
                                                                          ask)  # fmt: skip
    project = _project.load(located, {}, environ, document)
    prepared = prepare(project, rotate=options.rotate, to_store=to_store,
                       image_digest=getattr(options, "image_digest", None),
                       disk_usage=disk_usage)  # fmt: skip
    said = {finding.id for finding in findings}  # FC-172 already said why trial was chosen
    findings.extend(f for f in prepared.findings if not (f.id == "FC-172" and f.id in said))
    secrets_now = prepared.secrets
    ignored = _project.gitignore_entries(project)
    report = Report("init", findings=findings, config=located.to_json())
    report.data = {
        "project": project.name,
        "profile": project.resolved["profile"],
        "shape": project.resolved["shape"],
        "config": happened,
        "secrets_dir": str(project.secrets_dir),
        "secrets": [info.to_json() for info in secrets_now],
        "compiled_env": {
            "path": str(project.compiled_env_path),
            "changed": prepared.compiled_changed,
        },
        "gitignore_added": ignored,
        "destination": project.destination,
    }
    if prepared.queue is not None:
        report.data["queue"] = prepared.queue.to_json()
    if prepared.production:
        report.data["production"] = prepared.production
    if any(finding.severity == "error" for finding in findings):
        report.exit_code = EXIT_FINDINGS  # written, but agents would capture nothing with it
    for info in secrets_now:
        if info.action != "kept":
            expiry = f", expires {info.expires[:10]}" if info.expires else ""
            lines.append(f"{info.action} {info.name} ({info.fingerprint or 'by path'}{expiry})")
    kept = sum(1 for info in secrets_now if info.action == "kept")
    if kept:
        lines.append(f"kept {kept} existing secret(s) unchanged")
    lines.append(f"secrets directory: {project.secrets_dir} (private; values are never printed)")
    lines.append(f"compiled environment: {project.compiled_env_path}"
                 + ("" if prepared.compiled_changed else " (unchanged)"))  # fmt: skip
    if ignored:
        lines.append("added to .gitignore: " + ", ".join(ignored))
    lines.extend(_production_lines(project, prepared))
    if sys.platform == "win32":  # pragma: no cover
        lines.append("note: file modes are not enforced on Windows; keep the secrets directory "
                     "in your own profile")  # fmt: skip
    return report, lines


def _production_lines(project: _project.Project, prepared: Prepared) -> list[str]:
    if not project.production:
        return ["next: fabric up"]
    production, queue = prepared.production, prepared.queue
    policy = production["policy"]
    lines = [
        f"capture policy: {policy['path']} ({policy['action']}; yours to review and edit, "
        "never rewritten)",
        f"destination: {_describe(project.destination)}",
        f"Node settings: {production['node_env']['path']}"
        + ("" if production["node_env"]["changed"] else " (unchanged)"),
    ]
    for source, source_id in production["source_ids"].items():
        lines.append(f"source {source}: {production['source_labels'][source]} -> {source_id}")
    if queue is not None:
        lines.append(f"Node queue: {queue.telemetry_items} batches"
                     + (f" + {queue.content_items} content records" if queue.content_items
                        else "")
                     + f", worst case {_sizing.human(queue.worst_case_bytes)}"
                     + (f" of {_sizing.human(queue.free_bytes)} free" if queue.free_bytes
                        else ""))  # fmt: skip
    lines.append("next: fabric up   then   fabric run -- <your agent command>   then   "
                 "fabric verify --production")  # fmt: skip
    return lines


def _describe(destination: Mapping[str, Any]) -> str:
    preset = str(destination.get("preset"))
    keys = ("bucket", "region", "endpoint", "otlp_endpoint")
    shown = [f"{key} {destination[key]}" for key in keys if destination.get(key)]
    return preset + (" (" + ", ".join(shown) + ")" if shown else "")


def run_kubernetes(
    options: argparse.Namespace, environ: Mapping[str, str]
) -> tuple[Report, list[str]]:
    """``fabric init --kubernetes`` (§10.2): the Secrets the chart references, created where
    they are missing in the current kube context, in this cluster (``--in-cluster``, the
    chart's hook Job) or as manifests (``--render DIR``). No ``fabric.yaml`` is read or
    written: the chart's values are the Kubernetes configuration."""
    plan, store = _kube.from_options(options, environ)
    generator = _kube.Generator(plan, store)
    lines: list[str] = []
    if options.webhook:
        _kube.check_object(options.webhook, "webhook configuration")
        generator.patch_webhook(options.webhook)
        lines.append(f"set the caBundle of mutatingwebhookconfiguration {options.webhook}")
    else:
        generator.run()
    findings = list(generator.findings)
    for outcome in generator.outcomes:
        about = (
            ", ".join(outcome.keys)
            + (f"; {outcome.fingerprint}" if outcome.fingerprint else "")
            + (f"; valid until {outcome.expires[:10]}" if outcome.expires else "")
        )
        lines.append(f"{outcome.action} Secret {outcome.namespace}/{outcome.name} ({about})")
    if isinstance(store, _kube.RenderStore):
        lines.append(f"manifests: {store.where} (private; values are never printed)")
        lines.append(
            f"apply with: kubectl create -f {store.where} --recursive "
            "(create, not apply: apply copies each Secret into an annotation)"
        )
        lines.append(
            "note: these files hold the secret values in clear; encrypt them with your "
            "GitOps tool's own means before they reach a repository"
        )
    if plan.injector and not options.in_cluster:
        findings.append(Finding("FC-107", f"{plan.namespace}/{plan.name('ca')}"))
    report = Report("init", findings=findings)
    report.data = {
        "kubernetes": {
            "namespace": plan.namespace,
            "release": plan.release,
            "where": store.where,
            "production": plan.production,
            "agent_namespaces": [a.name for a in plan.agents],
            "host_sensor": plan.host_sensor,
            "host_nodes": list(plan.host_nodes),
        },
        "secrets": [outcome.to_json() for outcome in generator.outcomes],
    }
    if any(f.severity == "error" for f in findings):
        report.exit_code = EXIT_FINDINGS
    return report, lines
