# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric.yaml``: discovery, strict validation and precedence (spec 058 §6).

``fabric.yaml`` is a source the CLI compiles; the SDK and the Node never read it (OQ-7).
Validation is strict: an unknown key is refused with the nearest valid key suggested. The
rules here and ``contracts/cli-config/v1/fabric-config-v1.schema.json`` describe the same
document; a repository test runs both over the contract fixtures.

Precedence, for every setting (§6.2): a CLI flag, then a variable already set in the
environment of ``fabric`` (existing ``FABRIC_*`` names, unchanged meaning), then
``fabric.yaml``, then the profile's built-in default. :func:`resolve` reports, by name,
every variable that overrides the file, so an old shell export is never a hidden cause."""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ._report import EXIT_USAGE, CliError, Finding

CONFIG_SCHEMA = "fabric.config/v1"
CONFIG_NAME = "fabric.yaml"
CONFIG_ENV = "FABRIC_CONFIG"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")  # Compose project and Helm release names
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")  # FABRIC_TENANT_ID / AGENT_ID
_ENDPOINT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$")
DESTINATION_PRESETS = ("local-dir", "trial", "s3", "s3-compatible", "otlp")
# §7.2: fabric.yaml holds no secret. A path-valued setting whose value has the shape of a
# credential (the fabricctl reference rules: a PEM block, a bearer or API token, a cloud or
# source-host key, a JWT, a long opaque or hex string) is refused. A value with a / or a
# file extension is a path, so ./token-files/policy.json passes. The JSON schema carries
# the same pattern.
CREDENTIAL_SHAPE = (
    r"^(-----BEGIN |[Bb][Ee][Aa][Rr][Ee][Rr][ :]"
    r"|([Ss][Kk]|[Pp][Kk]|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Tt][Oo][Kk][Ee][Nn]"
    r"|[Ss][Ee][Cc][Rr][Ee][Tt])[_-][A-Za-z0-9_~+-]{8,}$"
    r"|(AKIA|ASIA)[A-Z0-9]{16}$|gh[pousr]_[A-Za-z0-9]{20,}$"
    r"|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
    r"|[A-Za-z0-9_-]{48,}$|[A-Fa-f0-9]{40,}$)"
)
_CREDENTIAL_SHAPE_RE = re.compile(CREDENTIAL_SHAPE)


# ---------------------------------------------------------------- validation rules


class _InvalidError(Exception):
    def __init__(self, finding: Finding) -> None:
        super().__init__(finding.id)
        self.finding = finding


def _bad(path: str, why: str) -> _InvalidError:
    return _InvalidError(Finding("FC-004", f"{path}: {why}"))


Rule = Callable[[str, Any], None]


def _enum(*values: str) -> Rule:
    def check(path: str, value: Any) -> None:
        if value not in values:
            raise _bad(path, "must be one of " + ", ".join(values))

    return check


def _bool(path: str, value: Any) -> None:
    if not isinstance(value, bool):
        raise _bad(path, "must be true or false")


def _pattern(regex: re.Pattern[str], what: str) -> Rule:
    def check(path: str, value: Any) -> None:
        if not isinstance(value, str) or not regex.fullmatch(value):
            raise _bad(path, f"must be {what}")

    return check


def _path_or(*keywords: str) -> Rule:
    def check(path: str, value: Any) -> None:
        if not isinstance(value, str) or not value.strip() or "\0" in value:
            listed = " or ".join(keywords)
            raise _bad(path, f"must be {listed + ' or ' if listed else ''}a file path")
        if _CREDENTIAL_SHAPE_RE.match(value):
            raise _InvalidError(Finding("FC-017", f"{path}: looks like a secret value, not a path"))

    return check


def _nullable(rule: Rule) -> Rule:
    def check(path: str, value: Any) -> None:
        if value is not None:
            rule(path, value)

    return check


def _url(*schemes: str) -> Rule:
    def check(path: str, value: Any) -> None:
        try:
            parts = urlsplit(value) if isinstance(value, str) else None
            _ = parts.port if parts is not None else None
        except ValueError:
            parts = None
        if parts is None or parts.scheme not in schemes or not parts.hostname or (
            "@" in parts.netloc or parts.query or parts.fragment
        ):  # fmt: skip
            raise _bad(path, f"must be a {' or '.join(schemes)} URL with no credentials, query "
                             "or fragment")  # fmt: skip

    return check


def _auto_or(rule: Rule, what: str) -> Rule:
    def check(path: str, value: Any) -> None:
        if value == "auto":
            return
        try:
            rule(path, value)
        except _InvalidError:
            raise _bad(path, f"must be auto or {what}") from None

    return check


def _positive_int(path: str, value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _bad(path, "must be a positive integer")


def _hosts(path: str, value: Any) -> None:
    if not isinstance(value, list) or not all(
        isinstance(h, str) and _HOST_RE.fullmatch(h) for h in value
    ):  # fmt: skip
        raise _bad(path, "must be a list of host names (host or host:port)")


@dataclass(frozen=True)
class _Object:
    fields: Mapping[str, Rule | _Object | _List]
    required: tuple[str, ...] = ()


@dataclass(frozen=True)
class _List:
    item: _Object


_CUSTOM_PROVIDER = _Object({
    "url": _url("https", "http"),
    "dialect": _enum("openai", "anthropic"),
    "name": _pattern(_ENDPOINT_ID_RE, "lowercase letters, digits and ._- (at most 64)"),
}, required=("url",))  # fmt: skip

SCHEMA = _Object({
    "schema": _enum(CONFIG_SCHEMA),
    "project": _pattern(_NAME_RE, "lowercase letters, digits and - (at most 63)"),
    "profile": _enum("local", "production"),
    "shape": _enum("laptop", "linux-host", "container", "kubernetes"),
    "tenant": _pattern(_ID_RE, "letters, digits and ._- (at most 256)"),
    "agent": _pattern(_ID_RE, "letters, digits and ._- (at most 256)"),
    "providers": _Object({
        "builtin": _bool, "from_environment": _bool, "custom": _List(_CUSTOM_PROVIDER),
    }),
    "capture": _Object({
        "content": _bool, "privacy": _path_or("profile-default"), "exec": _bool,
        "http_hosts": _hosts, "mcp": _bool, "security_context": _nullable(_path_or()),
    }),
    "node": _Object({
        "mode": _enum("docker", "helm", "external"),
        "endpoint": _auto_or(_url("https", "http"), "an http(s) URL"),
        "queue_size": _auto_or(_positive_int, "a positive number of bytes"),
    }),
    "destination": _Object({
        "preset": _enum(*DESTINATION_PRESETS), "path": _path_or(),
        "bucket": _pattern(re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"), "an S3 bucket name"),
        "region": _pattern(re.compile(r"^[a-z0-9-]{1,32}$"), "a region name"),
        "sse_kms_key": _pattern(re.compile(r"^[A-Za-z0-9:/_-]{1,2048}$"), "a KMS key id or ARN"),
        "endpoint": _url("https"), "ca_file": _path_or(), "credentials_file": _path_or(),
        "otlp_endpoint": _url("https", "http"), "otlp_ca_file": _path_or(),
        "otlp_headers_file": _path_or(),
    }, required=("preset",)),
    "sensor": _Object({"kind": _enum("auto", "ebpf", "auditd", "off")}),
    # id_key_file / ca_file: an existing setup's own files, referenced by path and never
    # copied (§11.3); unset, `fabric init` generates them in secrets.dir.
    "secrets": _Object({"dir": _path_or("auto"), "id_key_file": _path_or(),
                        "ca_file": _path_or()}),
}, required=("schema",))  # fmt: skip

# The destination keys each preset accepts (spec 058 §9.1), beyond preset itself.
PRESET_KEYS: Mapping[str, frozenset[str]] = {
    "local-dir": frozenset({"path"}),
    "trial": frozenset({"path"}),
    "s3": frozenset({"bucket", "region", "sse_kms_key"}),
    "s3-compatible": frozenset({"endpoint", "bucket", "ca_file", "credentials_file", "region"}),
    "otlp": frozenset({"otlp_endpoint", "otlp_ca_file", "otlp_headers_file"}),
}
PRESET_REQUIRED: Mapping[str, tuple[str, ...]] = {
    "s3": ("bucket", "region"), "s3-compatible": ("endpoint", "bucket"),
    "otlp": ("otlp_endpoint",),
}  # fmt: skip


def _unknown(path: str, key: Any, known: Mapping[str, Any]) -> _InvalidError:
    name = str(key)
    near = difflib.get_close_matches(name, list(known), n=1, cutoff=0.6)
    where = f"{path}.{name}" if path else name
    hint = f"; did you mean {(path + '.') if path else ''}{near[0]}?" if near else ""
    return _InvalidError(Finding("FC-003", f"{where}{hint}"))


def _check(spec: _Object | _List | Rule, path: str, value: Any) -> None:
    if isinstance(spec, _Object):
        if not isinstance(value, Mapping):
            raise _bad(path or "fabric.yaml", "must be a mapping")
        for key in value:
            if key not in spec.fields:
                raise _unknown(path, key, spec.fields)
        for key in spec.required:
            if key not in value:
                raise _bad(f"{path}.{key}" if path else key, "is required")
        for key, item in value.items():
            _check(spec.fields[key], f"{path}.{key}" if path else str(key), item)
    elif isinstance(spec, _List):
        if not isinstance(value, list):
            raise _bad(path, "must be a list")
        for index, item in enumerate(value):
            _check(spec.item, f"{path}[{index}]", item)
    else:
        spec(path, value)


def validate(document: Any) -> None:
    """Raise :class:`CliError` (``FC-003``/``FC-004``/``FC-007``, exit 2) unless ``document``
    is a valid ``fabric.config/v1`` document."""
    if isinstance(document, Mapping) and "schema" in document and (
        document["schema"] != CONFIG_SCHEMA
    ):  # fmt: skip
        raise CliError([Finding("FC-007", f"schema: {str(document['schema'])[:80]}")])
    try:
        _check(SCHEMA, "", document)
        destination = document.get("destination")
        if isinstance(destination, Mapping):
            preset = destination["preset"]
            extra = set(destination) - {"preset"} - PRESET_KEYS[preset]
            if extra:
                raise _bad(
                    f"destination.{sorted(extra)[0]}",
                    f"is not used by the {preset} preset (it takes "
                    f"{', '.join(sorted(PRESET_KEYS[preset])) or 'no other keys'})",
                )
            for key in PRESET_REQUIRED.get(preset, ()):
                if key not in destination:
                    raise _bad(f"destination.{key}", f"is required by the {preset} preset")
        custom = (document.get("providers") or {}).get("custom") or []
        names = [entry.get("name") or _first_label(entry["url"]) for entry in custom]
        if len(set(names)) != len(names):
            raise _bad("providers.custom", "endpoint names must be unique (set name:)")
    except _InvalidError as exc:
        raise CliError([exc.finding]) from None


def _first_label(url: str) -> str:
    host = (urlsplit(url).hostname or "").split(".")[0]
    return host or url


# ---------------------------------------------------------------- discovery and loading


@dataclass(frozen=True)
class Located:
    """Where ``fabric.yaml`` came from: ``flag``, ``env``, ``cwd``, ``parent`` or ``none``."""

    path: Path | None
    source: str

    def to_json(self) -> dict[str, Any]:
        return {"path": str(self.path) if self.path else None, "source": self.source}


def _git_root(start: Path) -> Path | None:
    for directory in (start, *start.parents):
        if (directory / ".git").exists():
            return directory
    return None


def discover(flag: str | None, environ: Mapping[str, str], cwd: Path | None = None,
             home: Path | None = None) -> Located:  # fmt: skip
    """§6.2 discovery: ``--config PATH``, else ``FABRIC_CONFIG``, else ``./fabric.yaml``,
    else the nearest parent directory's, up to the git work-tree root or the home
    directory (only the current directory outside both)."""
    if flag:
        return Located(Path(flag), "flag")
    if value := (environ.get(CONFIG_ENV) or "").strip():
        return Located(Path(value), "env")
    here = (cwd or Path.cwd()).resolve()
    if (here / CONFIG_NAME).is_file():
        return Located(here / CONFIG_NAME, "cwd")
    home = (home or Path.home()).resolve()
    boundary = _git_root(here)
    if boundary is None and (here == home or home in here.parents):
        boundary = home
    if boundary is None:
        return Located(None, "none")
    for directory in here.parents:
        if (directory / CONFIG_NAME).is_file():
            return Located(directory / CONFIG_NAME, "parent")
        if directory == boundary:
            break
    return Located(None, "none")


def _yaml() -> Any:
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        raise CliError([Finding("FC-005", "PyYAML is not installed")], EXIT_USAGE) from None
    return yaml


def load(located: Located) -> dict[str, Any]:
    """Read and validate the located ``fabric.yaml`` (:class:`CliError` with the reason)."""
    if located.path is None:
        raise CliError([Finding("FC-001")])
    yaml = _yaml()
    try:
        text = located.path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CliError([Finding("FC-001", str(located.path))]) from None
    except (OSError, UnicodeDecodeError) as exc:
        raise CliError([Finding("FC-002", f"{located.path}: {type(exc).__name__}")]) from None
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"line {mark.line + 1} column {mark.column + 1}" if mark else "not YAML"
        raise CliError([Finding("FC-002", f"{located.path}: {where}")]) from None
    validate(document)
    return dict(document)


# ---------------------------------------------------------------- precedence


@dataclass(frozen=True)
class Setting:
    """A leaf setting: its ``fabric.yaml`` path, its environment variable (an existing
    ``FABRIC_*`` name, or ``None``) and how a variable's text becomes a value."""

    key: str
    env: str | None = None
    parse: Callable[[str], Any] = str


def _env_bool(text: str) -> bool:
    return text.strip().lower() in ("1", "true", "yes", "on")


def _env_list(text: str) -> list[str]:
    return [item.strip() for item in text.split(",") if item.strip()]


SETTINGS: tuple[Setting, ...] = (
    Setting("project"), Setting("profile"), Setting("shape"),
    Setting("tenant", "FABRIC_TENANT_ID"), Setting("agent", "FABRIC_AGENT_ID"),
    Setting("providers.builtin"), Setting("providers.from_environment"),
    Setting("providers.custom"),
    Setting("capture.content"), Setting("capture.privacy", "FABRIC_CAPTURE_POLICY"),
    Setting("capture.exec", "FABRIC_WIRE_EXEC", _env_bool),
    Setting("capture.http_hosts", "FABRIC_WIRE_HTTP_HOSTS", _env_list),
    Setting("capture.mcp", "FABRIC_WIRE_MCP", _env_bool),
    Setting("capture.security_context"),
    Setting("node.mode"), Setting("node.endpoint", "FABRIC_OTLP_ENDPOINT"),
    Setting("node.queue_size"), Setting("destination"), Setting("sensor.kind"),
    Setting("secrets.dir"), Setting("secrets.id_key_file"), Setting("secrets.ca_file"),
)  # fmt: skip


def defaults(profile: str, project: str) -> dict[str, Any]:
    """The built-in defaults of a profile (§6.1, §6.3); ``shape`` ``None``: detected."""
    return {
        "project": project, "profile": profile, "shape": None, "tenant": "default",
        "agent": project, "providers.builtin": True, "providers.from_environment": True,
        "providers.custom": [], "capture.content": True, "capture.privacy": "profile-default",
        "capture.exec": False, "capture.http_hosts": [], "capture.mcp": False,
        "capture.security_context": None, "node.mode": "docker", "node.endpoint": "auto",
        "node.queue_size": "auto", "sensor.kind": "auto", "secrets.dir": "auto",
        "secrets.id_key_file": None, "secrets.ca_file": None,
        "destination": ({"preset": "local-dir", "path": "./fabric-data"}
                        if profile == "local" else None),
    }  # fmt: skip


def _lookup(document: Mapping[str, Any], key: str) -> tuple[bool, Any]:
    node: Any = document
    for part in key.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return False, None
        node = node[part]
    return True, node


@dataclass
class Resolved:
    """Every setting's value and where it came from: ``flag``, ``env``, ``file``,
    ``default``; ``overrides`` lists ``(variable, key)`` where a variable beat the file."""

    values: dict[str, Any] = field(default_factory=dict)
    sources: dict[str, str] = field(default_factory=dict)
    overrides: list[tuple[str, str]] = field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        return self.values[key]


def resolve(document: Mapping[str, Any] | None, flags: Mapping[str, Any],
            environ: Mapping[str, str], project_dir: Path) -> Resolved:  # fmt: skip
    """Apply §6.2 to every setting. ``flags`` maps a setting key to a flag value (``None``:
    the flag was not given)."""
    document = document or {}
    out = Resolved()
    profile_flag = flags.get("profile")
    present, profile_file = _lookup(document, "profile")
    profile = profile_flag or (profile_file if present else "local")
    present, project_file = _lookup(document, "project")
    project = flags.get("project") or (project_file if present else _project_name(project_dir))
    base = defaults(profile, project)
    for setting in SETTINGS:
        in_file, file_value = _lookup(document, setting.key)
        env_text = (environ.get(setting.env) or "").strip() if setting.env else ""
        if flags.get(setting.key) is not None:
            value, source = flags[setting.key], "flag"
        elif env_text:
            value, source = setting.parse(env_text), "env"
            if in_file and value != file_value and setting.env:
                out.overrides.append((setting.env, setting.key))
        elif in_file:
            value, source = file_value, "file"
        else:
            value, source = base[setting.key], "default"
        out.values[setting.key], out.sources[setting.key] = value, source
    return out


def _project_name(directory: Path) -> str:
    """The directory name as a project name (lowercase, ``-`` for other characters)."""
    name = re.sub(r"[^a-z0-9-]+", "-", directory.name.lower()).strip("-")[:63]
    return name or "fabric"


def override_findings(resolved: Resolved) -> list[Finding]:
    """``FC-009`` per variable that overrides a ``fabric.yaml`` setting, named (§6.2)."""
    return [Finding("FC-009", f"{variable} overrides {key}")
            for variable, key in resolved.overrides]  # fmt: skip


def project_dir(located: Located, cwd: Path | None = None) -> Path:
    """The project directory: the one holding ``fabric.yaml``, else the current one."""
    return located.path.parent if located.path is not None else (cwd or Path.cwd())
