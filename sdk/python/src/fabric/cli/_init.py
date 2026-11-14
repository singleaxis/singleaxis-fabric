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
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..wire._config import parse_endpoints
from . import _config, _kube, _project, _providers, _secrets
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
    "FABRIC_NODE_IMAGE", "FABRIC_SENSOR_IMAGE", "FABRIC_SINK_IMAGE",
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
    parser.add_argument("--destination", metavar="PRESET", choices=_config.DESTINATION_PRESETS)
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
        help="rotate a generated secret: node-cert, ca, id-key, or all",
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
                    "secret_name", "webhook")  # fmt: skip


def _refuse_unbuilt(options: argparse.Namespace) -> None:
    for name in _KUBERNETES_ONLY:
        if getattr(options, name, None) and not options.kubernetes:
            raise CliError([Finding("FC-106", "--" + name.replace("_", "-"))])
    if options.kubernetes:
        local_only = [("--from-env", options.from_env), ("--rotate", options.rotate),
                      ("--force", options.force), ("--provider", options.provider),
                      ("--from-env-file", options.from_env_file),
                      ("--from-values", options.from_values)]  # fmt: skip
        for name, given in local_only:
            if given:
                raise CliError([Finding("FC-011", f"{name} with --kubernetes")])
        return
    unbuilt = [
        ("--from-env-file", options.from_env_file), ("--from-values", options.from_values),
        ("--profile production", options.profile == "production"),
        (f"--destination {options.destination}",
         options.destination not in (None, "local-dir")),
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
    """The ``fabric.yaml`` `init` writes for the local profile (§5.3 defaults, §6.1)."""
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


def apply_flags(document: dict[str, Any], options: argparse.Namespace) -> None:
    """The settings the flags of this command name; nothing else in the file changes."""
    scalars = {"project": options.project, "profile": options.profile, "shape": options.shape,
               "tenant": options.tenant, "agent": options.agent,
               "capture.exec": options.capture_exec, "capture.mcp": options.mcp,
               "sensor.kind": options.sensor}  # fmt: skip
    for key, value in scalars.items():
        if value is not None:
            _set(document, key, value)
    if options.destination and (document.get("destination") or {}).get("preset") != "local-dir":
        _set(document, "destination", {"preset": "local-dir", "path": "./fabric-data"})
    if options.provider:
        _append_unique(document, "providers.custom", [_provider_entry(p) for p in options.provider])
    if options.http_host:
        _append_unique(document, "capture.http_hosts", list(options.http_host))


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


def _rotation_names(name: str) -> tuple[str, ...]:
    # `all` leaves the id key alone: a new id key changes every pseudonym and is never
    # automatic (§7.3). A new CA comes with a new Node certificate.
    return ("ca",) if name == "all" else (name,)


_ROTATION_NOTES = {
    "node-cert": "node-cert: run `fabric up` so the Node restarts with the new certificate",
    "ca": "ca: run `fabric up`, then restart agents so they load the new CA",
    "id-key": "id-key: restart agents; pseudonyms change from their next start, and the old "
              "key is kept read-only under retired/ for the reader",
}  # fmt: skip


def write_config(options: argparse.Namespace, environ: Mapping[str, str], cwd: Path
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
    apply_flags(document, options)
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


def prepare(project: _project.Project, *, rotate: str | None = None,
            to_store: Mapping[str, bytes] | None = None) -> tuple[list[_secrets.SecretInfo],
                                                                 list[Finding], bool]:  # fmt: skip
    """Everything `init` does after ``fabric.yaml`` exists, shared with `fabric up`: the
    state directory, the secrets (generated when missing), the compiled environment.
    Returns the secrets, findings, and whether the compiled environment changed."""
    _project.compile_environment(project)  # refuse an unbuilt profile before writing anything
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
    if rotate:
        names = _rotation_names(rotate)
        if "id-key" in names and not generate_id_key:
            raise CliError([Finding("FC-004", "secrets.id_key_file: the id key is referenced, "
                                    "not generated; rotate it where it lives")])  # fmt: skip
        if not project.generates_tls and set(names) & {"ca", "node-cert"}:
            raise CliError([Finding("FC-004", "node.mode: an external Node has its own "
                                    "certificate; there is none to rotate here")])  # fmt: skip
        rotated = {info.name: info for info in
                   _secrets.rotate(project.secrets_dir, project.name, names)}  # fmt: skip
        secrets_now = [rotated.get(info.name, info) for info in secrets_now]
        findings.extend(Finding("FC-016", _ROTATION_NOTES[name]) for name in names)
    for key, name in (("secrets.id_key_file", "id-key"), ("secrets.ca_file", "ca")):
        if not project.resolved[key]:
            continue
        referenced = _project._absolute(project.directory, str(project.resolved[key]))
        secrets_now.append(_secrets.SecretInfo(name, (str(referenced),), "referenced"))
        if not _readable_file(referenced):
            # The compiled environment would name a file the agent cannot read: say so now,
            # not at the agent's first run.
            findings.append(Finding("FC-031", f"{key}: {referenced}"))
    _, changed = _project.write_compiled_env(project)
    return secrets_now, findings, changed


def run(options: argparse.Namespace, environ: Mapping[str, str] | None = None,
        cwd: Path | None = None) -> tuple[Report, list[str]]:  # fmt: skip
    """``fabric init``."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    _refuse_unbuilt(options)
    if options.kubernetes:
        return run_kubernetes(options, environ)
    located, document, happened, to_store, findings, lines = write_config(options, environ, cwd)
    project = _project.load(located, {}, environ, document)
    secrets_now, more, compiled_changed = prepare(project, rotate=options.rotate,
                                                  to_store=to_store)  # fmt: skip
    findings.extend(more)
    ignored = _project.gitignore_entries(project)
    report = Report("init", findings=findings, config=located.to_json())
    report.data = {
        "project": project.name,
        "profile": project.resolved["profile"],
        "shape": project.resolved["shape"],
        "config": happened,
        "secrets_dir": str(project.secrets_dir),
        "secrets": [info.to_json() for info in secrets_now],
        "compiled_env": {"path": str(project.compiled_env_path), "changed": compiled_changed},
        "gitignore_added": ignored,
    }
    for info in secrets_now:
        if info.action != "kept":
            expiry = f", expires {info.expires[:10]}" if info.expires else ""
            lines.append(f"{info.action} {info.name} ({info.fingerprint or 'by path'}{expiry})")
    kept = sum(1 for info in secrets_now if info.action == "kept")
    if kept:
        lines.append(f"kept {kept} existing secret(s) unchanged")
    lines.append(f"secrets directory: {project.secrets_dir} (private; values are never printed)")
    lines.append(f"compiled environment: {project.compiled_env_path}"
                 + ("" if compiled_changed else " (unchanged)"))  # fmt: skip
    if ignored:
        lines.append("added to .gitignore: " + ", ".join(ignored))
    lines.append("next: fabric up")
    if sys.platform == "win32":  # pragma: no cover
        lines.append("note: file modes are not enforced on Windows; keep the secrets directory "
                     "in your own profile")  # fmt: skip
    return report, lines


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
        about = ", ".join(outcome.keys) + (
            f"; {outcome.fingerprint}" if outcome.fingerprint else ""
        )
        lines.append(f"{outcome.action} Secret {outcome.namespace}/{outcome.name} ({about})")
    if isinstance(store, _kube.RenderStore):
        lines.append(f"manifests: {store.where} (private; values are never printed)")
        lines.append(
            f"apply with: kubectl create -f {store.where} --recursive "
            "(create, not apply: apply copies each Secret into an annotation)"
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
        },
        "secrets": [outcome.to_json() for outcome in generator.outcomes],
    }
    if any(f.severity == "error" for f in findings):
        report.exit_code = EXIT_FINDINGS
    return report, lines
