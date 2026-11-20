# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The hardening checks of ``fabric verify --production`` (spec 058 §5.6, §13.4, WP8-25).

Each check has a catalogue id and an outcome (``pass``, ``warn``, ``fail`` or ``skip``);
a check that does not pass is a finding with its fix. The checks that
``deploy/compose/preflight-prod.sh --groups`` also makes carry the same ids there (each
of its lines ends with the id in brackets), and a test runs both on the same project and
compares ids and outcomes (:data:`PREFLIGHT_IDS`), so a CLI user and a manual-route user
are told the same thing about the same files.

Every check is local: files in the secrets directory and the project, the configuration
`fabric up` rendered, its state file, and this host's clock. Nothing is contacted, and no
secret value is printed: a token or key is read only to check its shape."""

from __future__ import annotations

import base64
import contextlib
import ctypes
import ctypes.util
import datetime as dt
import ipaddress
import json
import re
import stat
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import _config, _images, _policy, _project, _secrets, _sizing, _templates
from ._report import CliError, Finding

#: The checks preflight-prod.sh --groups makes with the same id and outcome.
PREFLIGHT_IDS = ("FC-176", "FC-180", "FC-181", "FC-182", "FC-183", "FC-184", "FC-185",
                 "FC-186", "FC-187", "FC-188")  # fmt: skip
_RANK = {"skip": 0, "pass": 1, "warn": 2, "fail": 3}
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SOURCE = re.compile(r"^s-[0-9a-f]{32}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_B64_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
WARN_DAYS = 14


@dataclass(frozen=True)
class Check:
    """One check's outcome. ``detail`` names a file, a group or a setting, never a value."""

    id: str
    outcome: str  # pass | warn | fail | skip
    detail: str = ""

    def to_json(self) -> dict[str, str]:
        out = {"id": self.id, "outcome": self.outcome}
        if self.detail:
            out["detail"] = self.detail
        return out


def outcomes(checks: Iterable[Check]) -> dict[str, str]:
    """The worst outcome per id (``fail`` over ``warn`` over ``pass``)."""
    worst: dict[str, str] = {}
    for check in checks:
        if _RANK[check.outcome] >= _RANK.get(worst.get(check.id, "skip"), 0):
            worst[check.id] = check.outcome
    return worst


def findings(checks: Iterable[Check]) -> list[Finding]:
    """A finding for every check that did not pass, with its detail."""
    return [Finding(c.id, c.detail) for c in checks if c.outcome in ("warn", "fail")]


# ---------------------------------------------------------------- shapes


def url_problem(url: str) -> str | None:  # noqa: PLR0911 - one return per rule
    """Why ``url`` is not an absolute http(s) URL whose authority is host[:port] (the
    rule of preflight-prod.sh's url_check and the chart's validateURL), or ``None``."""
    if not url.lower().startswith(("https://", "http://")):
        return "is not an absolute http(s):// URL"
    if any(c.isspace() or not c.isprintable() or c == "\\" for c in url):
        return "contains whitespace, a control character or a backslash"
    if "@" in url:
        return "contains user info"
    if "?" in url or "#" in url:
        return "contains a query or fragment"
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        return "has a port that is not a number from 1 to 65535"
    if port is not None and not 1 <= port <= 65535:  # noqa: PLR2004
        return "has a port that is not a number from 1 to 65535"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        name = host.rstrip(".")
        if not name or len(name) > 253 or not all(_LABEL.match(p) for p in name.split(".")):  # noqa: PLR2004
            return "has a host that is not a DNS name or an IP address"
    return None


def token_problem(path: Path) -> str | None:  # noqa: PLR0911 - one return per rule
    """Why a group token file breaks the Node's rule (one token, no blank line, no
    trailing newline, closed to other users), or ``None``. Its value is never shown."""
    if path == Path():
        return "is not set"
    try:
        info = path.lstat()
        data = path.read_bytes()
    except FileNotFoundError:
        return "is missing"
    except OSError:
        return "cannot be read"
    if not data:
        return "is empty"
    if any(not line.strip() for line in data.split(b"\n")[:-1]) or b"\n\n" in data:
        return "has a blank line"
    if data.endswith(b"\n"):
        return "ends with a newline"
    if stat.S_IMODE(info.st_mode) & 0o007:
        return "is open to other users"
    return None


def _open_to_others(path: Path) -> str | None:
    try:
        return "is open to other users" if stat.S_IMODE(path.stat().st_mode) & 0o007 else None
    except OSError:
        return "cannot be read"


def key_problem(path: Path) -> str | None:
    """Why a key file does not hold 32 bytes (raw or standard base64), or ``None``."""
    if path == Path():
        return "is not set"
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return "is missing"
    except OSError:
        return "cannot be read"
    text = data[:-1] if data.endswith(b"\n") else data
    if len(data) == 32:  # noqa: PLR2004
        return None
    if _B64_KEY.match(text.decode("ascii", "replace")) and len(base64.b64decode(text)) == 32:  # noqa: PLR2004
        return None
    return "does not hold a 32-byte key (raw or base64)"


# ---------------------------------------------------------------- the checks


def _export(project: _project.Project, env: Mapping[str, str]) -> list[Check]:
    from . import _produp  # noqa: PLC0415 - shares the header reader with `fabric up`

    out = []
    endpoint = env.get("FABRIC_EXPORT_ENDPOINT", "")
    problem = "is not set" if not endpoint else url_problem(endpoint)
    if problem is None and not endpoint.lower().startswith("https://"):
        problem = "is http://; production egress requires https"
    out.append(Check("FC-180", "fail" if problem else "pass",
                     f"the span destination {problem}" if problem else ""))  # fmt: skip
    header, issues = _produp.export_header(project)
    out.append(Check("FC-176", "pass") if header else
               Check("FC-176", "fail", (issues[0].detail or "") if issues else ""))  # fmt: skip
    return out


def _groups(project: _project.Project, env: Mapping[str, str],
            settings: Mapping[str, str]) -> list[Check]:  # fmt: skip
    out: list[Check] = []
    tokens = {"agent": Path(env.get("FABRIC_INGRESS_TOKEN_FILE", "")),
              "ebpf": Path(env.get("FABRIC_EBPF_TOKEN_FILE", "")),
              "canary": Path(settings.get("canary.token_file", ""))}  # fmt: skip
    for group, path in tokens.items():
        problem = token_problem(path)
        out.append(
            Check(
                "FC-181",
                "fail" if problem else "pass",
                f"{group} group token file {path} {problem}" if problem else group,
            )
        )
    seen: dict[bytes, str] = {}
    for group, path in tokens.items():
        with contextlib.suppress(OSError):
            data = path.read_bytes()
            if data in seen:
                out.append(Check("FC-182", "fail", f"the {seen[data]} and {group} groups"))
            seen.setdefault(data, group)
    if not any(c.id == "FC-182" for c in out):
        out.append(Check("FC-182", "pass"))
    sources = {"agent": env.get("FABRIC_AGENT_SOURCE_ID", ""),
               "ebpf": env.get("FABRIC_EBPF_SOURCE_ID", ""),
               "canary": settings.get("canary.source_id", "")}  # fmt: skip
    owners: dict[str, str] = {}
    shared = []
    for group, source in sources.items():
        ok = bool(_SOURCE.match(source))
        out.append(Check("FC-183", "pass" if ok else "fail",
                         group if ok else f"the {group} group's source id"))  # fmt: skip
        if source and source in owners:
            shared.append(Check("FC-184", "fail", f"the {owners[source]} and {group} groups"))
        owners.setdefault(source, group)
    out.extend(shared or [Check("FC-184", "pass")])
    tenant = env.get("FABRIC_TENANT_ID", "")
    out.append(Check("FC-185", "pass" if _TENANT.match(tenant) else "fail",
                     "" if _TENANT.match(tenant) else "tenant"))  # fmt: skip
    return out


def _receivers(rendered: Mapping[str, Any]) -> Check:
    plain = []
    for receiver_id, receiver in (rendered.get("receivers") or {}).items():
        for protocol, settings in ((receiver or {}).get("protocols") or {}).items():
            tls = (settings or {}).get("tls") or {}
            if not (tls.get("cert_file") and tls.get("key_file")):
                plain.append(f"{receiver_id}.{protocol}")
    return Check("FC-186", "fail", ", ".join(plain)) if plain else Check("FC-186", "pass")


def _content(project: _project.Project, env: Mapping[str, str]) -> list[Check]:
    if env.get("FABRIC_CONTENT_BACKEND") != "s3":
        return [Check("FC-187", "skip"), Check("FC-188", "skip")]
    key = Path(env.get("FABRIC_CONTENT_KEY_FILE", ""))
    problem = key_problem(key) or _open_to_others(key)
    out = [Check("FC-187", "fail" if problem else "pass",
                 f"content key file {key} {problem}" if problem else "")]  # fmt: skip
    store: list[str] = []
    if not _BUCKET.match(env.get("FABRIC_CONTENT_S3_BUCKET", "")):
        store.append("the bucket is not a bucket name")
    if not env.get("FABRIC_CONTENT_S3_REGION"):
        store.append("the region is not set")
    endpoint = env.get("FABRIC_CONTENT_S3_ENDPOINT", "")
    if endpoint:
        problem = url_problem(endpoint)
        if problem:
            store.append(f"the endpoint {problem}")
        elif urlsplit(endpoint).path not in ("", "/"):
            store.append("the endpoint has a path")
        elif not endpoint.lower().startswith("https://"):
            store.append("the endpoint is plaintext http")
    sse = env.get("FABRIC_CONTENT_S3_SSE", "aws:kms")
    if sse not in ("aws:kms", "AES256"):
        store.append("server-side encryption is not aws:kms or AES256")
    if env.get("FABRIC_CONTENT_S3_KMS_KEY_ID") and sse != "aws:kms":
        store.append("a KMS key needs aws:kms")
    out.append(Check("FC-188", "fail", "; ".join(store)) if store else Check("FC-188", "pass"))
    return out


def _certificates(project: _project.Project, now: dt.datetime) -> list[Check]:
    directory = project.secrets_dir
    names = [(_secrets.CA_CERT, "ca"), (_secrets.NODE_CERT, "node-cert")]
    names += [(_secrets.client_pair(source)[0], f"{source}-client-cert")
              for source in _secrets.SOURCES]  # fmt: skip
    names += [(f"{stem}.crt", label) for stem, _, label in _secrets.SERVICE_CERTS]
    out = []
    for name, label in names:
        path = directory / name
        if not path.is_file():
            continue
        try:
            _, expires = _secrets.certificate_info(path)
        except CliError:
            out.append(Check("FC-191", "fail", f"{label}: {path} is not a certificate"))
            continue
        if expires <= now:
            out.append(Check("FC-191", "fail", f"{label} expired {expires:%Y-%m-%d}"))
        elif expires - now <= dt.timedelta(days=WARN_DAYS):
            out.append(Check("FC-190", "warn", f"{label} expires {expires:%Y-%m-%d}"))
    return out or [Check("FC-191", "pass")]


def clock_synchronized() -> bool | None:
    """Whether the kernel says the clock is synchronized (``adjtimex`` read-only, Linux),
    ``None`` where it cannot tell."""
    if not sys.platform.startswith("linux"):
        return None
    name = ctypes.util.find_library("c")
    try:
        libc = ctypes.CDLL(name or "libc.so.6", use_errno=True)
        buffer = ctypes.create_string_buffer(512)  # struct timex, modes 0: read only
        state = int(libc.adjtimex(buffer))
    except (OSError, AttributeError):
        return None
    if state < 0:
        return None
    return state != 5  # noqa: PLR2004 - TIME_ERROR: the clock is not synchronized


def run(project: _project.Project, environ: Mapping[str, str], *,
        now: dt.datetime | None = None,
        clock: Callable[[], bool | None] | None = None,
        disk_usage: Callable[[Path], Any] | None = None
        ) -> tuple[list[Check], list[Finding]]:  # fmt: skip
    """Every production check, and the findings the CLI already has ids for (the capture
    policy, the destination's caveats and files, the queue advice, secret file modes)."""
    now = now or dt.datetime.now(dt.UTC)
    extra: list[Finding] = []
    state = _read_json(project.state_dir / "state" / "up.json")
    checks: list[Check] = []
    if state.get("profile") != "production":
        checks.append(Check("FC-195", "fail", str(project.compose_project)))
    queue = _sizing.plan(project.resolved["node.queue_size"], project.queue_dir,
                         production=True,
                         content=project.destination.get("preset") in _project.CONTENT_PRESETS,
                         **({"disk_usage": disk_usage} if disk_usage else {}))  # fmt: skip
    extra.extend(queue.findings)
    env, settings = node_settings(project, queue)
    checks += _export(project, env)
    checks += _groups(project, env, settings)
    rendered = _read_yaml(project.state_dir / "compose" / _templates.NODE_CONFIG_FILE)
    checks.append(_receivers(rendered) if rendered else Check("FC-186", "skip"))
    checks += _content(project, env)
    spool = project.secrets_dir / _secrets.SPOOL_KEY
    problem = key_problem(spool)
    checks.append(Check("FC-189", "fail" if problem else "pass",
                        f"{spool} {problem}" if problem else ""))  # fmt: skip
    checks += _certificates(project, now)
    pinned = _images.resolve(environ).node
    if state.get("node_image") and state.get("node_image") != _images.NODE:
        checks.append(
            Check(
                "FC-192",
                "warn",
                f"running {state['node_image']}"
                + (" (FABRIC_NODE_IMAGE)" if pinned != _images.NODE else ""),
            )
        )
    else:
        checks.append(Check("FC-192", "pass"))
    sensor_on = state.get("sensor_mode") == "production"
    checks.append(
        Check(
            "FC-193",
            "pass" if sensor_on else "warn",
            "" if sensor_on else f"sensor: {state.get('sensor') or 'off'}",
        )
    )
    synced = (clock or clock_synchronized)()
    checks.append(Check("FC-194", "skip" if synced is None else ("pass" if synced else "warn")))
    # The capture policy (present, not the local default, one the SDK accepts) and the
    # destination: the ids `fabric init` reports, checked again on the files as they are.
    if project.policy_path is None:
        extra.append(Finding("FC-166", "capture.privacy: profile-default"))
    else:
        extra.extend(_policy.check(project.policy_path, str(project.resolved["tenant"])))
    from . import _init  # noqa: PLC0415

    extra.extend(_init.destination_files(project))
    preset = project.destination.get("preset")
    if preset == "trial":
        extra.append(Finding("FC-172", "destination.preset: trial"))
    if preset not in _project.CONTENT_PRESETS or not project.resolved["capture.content"]:
        extra.append(Finding("FC-173", f"destination.preset: {preset}"))
    extra.extend(_secret_modes(project))
    return checks, extra


def node_settings(project: _project.Project, queue: Any = None
                  ) -> tuple[dict[str, str], dict[str, str]]:  # fmt: skip
    """The Node's settings as ``.fabric/node.env`` holds them: the file `fabric up` renders
    the Node from and preflight-prod.sh reads (``FABRIC_ENV_FILE``), so both check the same
    values. Compiled afresh when the file is missing."""
    try:
        text = project.node_env_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return _project.node_environment(project, queue)
    env: dict[str, str] = {}
    settings: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith(_project.SETTING_PREFIX):
            key, _, value = line[len(_project.SETTING_PREFIX) :].partition("=")
            settings[key] = value
        elif line and not line.startswith("#") and "=" in line:
            name, _, value = line.partition("=")
            env[name] = value
    return env, settings


def _secret_modes(project: _project.Project) -> list[Finding]:
    """``FC-013`` for a production secret file that is a symlink, another user's, or open
    to others (the generator's own file rules)."""
    out: list[Finding] = []
    directory = project.secrets_dir
    names = [_secrets.ID_KEY, _secrets.SPOOL_KEY, _secrets.CONTENT_KEY, _secrets.SENSOR_STATE_KEY,
             _secrets.NODE_KEY, _secrets.CA_KEY,
             *(_secrets.token_file(source) for source in _secrets.SOURCES),
             *(_secrets.headers_file(source) for source in _secrets.HEADER_SOURCES),
             *(_secrets.client_pair(source)[1] for source in _secrets.SOURCES)]  # fmt: skip
    for name in names:
        try:
            _secrets.check_secret_file(directory / name)
        except CliError as exc:
            out.extend(exc.findings)
    return out


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_yaml(path: Path) -> dict[str, Any]:
    yaml = _config._yaml()
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return {}
    return value if isinstance(value, dict) else {}
