# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hook configuration (spec 053 §4 "Activation and configuration errors"; spec 056
§7.3.3 (i)).

Two ways in, with different error rules:
- :func:`config_from_args` (``fabric.hooks.install(...)``) is configuration: a malformed
  argument raises ``ValueError`` with fixed text, as ``fabric.wire.install()`` does.
- :func:`config_from_env` (``FABRIC_WIRE_EXEC=1`` and friends) never raises: a malformed
  value disables every hook and is reported as ``invalid_configuration``.

Absent means disabled. This build registers three channels: ``exec.subprocess``
(``FABRIC_WIRE_EXEC``), ``http.nonmodel`` (``FABRIC_WIRE_HTTP_HOSTS``, a JSON array of
hosts) and ``remote.sandbox`` (``FABRIC_WIRE_REMOTE_SANDBOX``, comma-separated providers;
only ``e2b``). ``FABRIC_WIRE_SANDBOX_HOSTS`` (a JSON array of hosts) declares the sandbox
providers a deployment uses, for the manifest only (056 §4.4.1). The other spec 053
switches name channels this build does not have; a set one is reported by ``status()``
(``not_in_build``) and changes nothing.

**Hosts** (053 §5.4) are normalised here, once: ``host`` or ``host:port``, ``https`` unless
``http://`` is given (``https://`` may be given). The host is lower-cased and IDNA-encoded
the way httpx encodes a request's host (the ``idna`` package, IDNA 2008), one trailing dot
is dropped, an IPv4 literal stays dotted decimal and an IPv6 literal (in brackets) takes
its RFC 5952 form. The port defaults to the scheme's (443 or 80). A path, query,
fragment, user information, wildcard, zone, empty label or second scheme is refused. A
host is matched exactly, never as a substring or a suffix.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import NamedTuple

__all__ = [
    "EXEC_ENV", "HOOK_ENV_NAMES", "HOST_LABEL_ENV", "HTTP_HOSTS_ENV", "MAX_HOSTS",
    "NOT_IN_BUILD_ENV", "REMOTE_SANDBOX_ENV", "SANDBOX_HOSTS_ENV", "SANDBOX_PROVIDERS",
    "HooksConfig", "HostRule", "canonical_host", "config_from_args", "config_from_env",
    "ipv6_text", "parse_host",
]  # fmt: skip

EXEC_ENV = "FABRIC_WIRE_EXEC"
HOST_LABEL_ENV = "FABRIC_HOST_LABEL"
HTTP_HOSTS_ENV = "FABRIC_WIRE_HTTP_HOSTS"
REMOTE_SANDBOX_ENV = "FABRIC_WIRE_REMOTE_SANDBOX"
SANDBOX_HOSTS_ENV = "FABRIC_WIRE_SANDBOX_HOSTS"
# Spec 053 §4 switches of channels this build does not register.
NOT_IN_BUILD_ENV: tuple[str, ...] = (
    "FABRIC_WIRE_EXEC_AUDIT", "FABRIC_WIRE_FILE_AUDIT", "FABRIC_WIRE_DB_DRIVERS",
    "FABRIC_WIRE_MCP",
)  # fmt: skip
HOOK_ENV_NAMES: tuple[str, ...] = (
    EXEC_ENV, HTTP_HOSTS_ENV, REMOTE_SANDBOX_ENV, SANDBOX_HOSTS_ENV, *NOT_IN_BUILD_ENV,
)  # fmt: skip

# Remote sandbox providers this build knows (056 §4.4.1, OD-3).
SANDBOX_PROVIDERS: tuple[str, ...] = ("e2b",)
# fabric.http.observation/v1 ``rule_index`` is 0..255: at most 256 host rules.
MAX_HOSTS = 256

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("", "0", "false", "no", "off")
# A host label is operator configuration (053 C41), mapped to ``hst-`` before it is
# emitted; it is bounded and printable so a mistake cannot carry payload-sized text.
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_MAX_HOST_TEXT = 300  # "https://" + a 253-character name + ":65535", with room to spare
_MAX_NAME = 253  # the DNS name bound
_NAME_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_MAX_PORT = 65535
_DEFAULT_PORTS = {"https": 443, "http": 80}
_SCHEMES = (("http://", "http"), ("https://", "https"))
_REFUSED = frozenset("/?#@*\\%")


class HostRule(NamedTuple):
    """One normalised allowlist entry: the request's scheme, canonical host and port."""

    scheme: str
    host: str
    port: int

    @property
    def text(self) -> str:
        """The canonical spelling (``host``, ``host:port`` or ``http://host[:port]``)."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        port = "" if self.port == _DEFAULT_PORTS[self.scheme] else f":{self.port}"
        return f"{'http://' if self.scheme == 'http' else ''}{host}{port}"


def ipv6_text(packed: bytes) -> str:
    """RFC 5952 §4 text of 16 address bytes: lower-case hex, no leading zeros, the longest
    run of two or more zero groups compressed (the first on a tie). Python's own
    ``str(IPv6Address)`` is not used: 3.13 changed it for IPv4-mapped addresses."""
    groups = [int.from_bytes(packed[i : i + 2], "big") for i in range(0, 16, 2)]
    best_start, best_len, start = -1, 0, -1
    for index, group in enumerate([*groups, 1]):
        if group == 0 and start < 0:
            start = index
        elif group != 0 and start >= 0:
            if index - start > best_len and index - start >= 2:  # noqa: PLR2004 - a run
                best_start, best_len = start, index - start
            start = -1
    text = [format(g, "x") for g in groups]
    if best_start < 0:
        return ":".join(text)
    return f"{':'.join(text[:best_start])}::{':'.join(text[best_start + best_len :])}"


def _idna(host: str) -> str:
    """``host`` (already lower-cased) as the ASCII name httpx sends; ``ValueError`` when it
    is not a valid IDNA name."""
    if host.isascii():
        return host
    try:
        import idna  # noqa: PLC0415 - httpx's own encoder, only for a non-ASCII host
    except ImportError:  # pragma: no cover - httpx depends on idna
        return host.encode("idna").decode("ascii")
    try:
        return str(idna.encode(host).decode("ascii"))
    except Exception as exc:
        raise ValueError("a host is not a valid IDNA name") from exc


def canonical_host(host: str) -> str:
    """A host (``[v6]`` in brackets, else a name or IPv4 literal) in canonical form;
    ``ValueError`` (fixed text) when it is none of them."""
    if host.startswith("["):
        if not host.endswith("]"):
            raise ValueError("an IPv6 host must be in brackets")
        try:
            address = ipaddress.IPv6Address(host[1:-1])
        except ValueError as exc:
            raise ValueError("an IPv6 host is not an address") from exc
        return ipv6_text(address.packed)
    name = _idna(host.lower())
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > _MAX_NAME:
        raise ValueError("a host name must be 1-253 characters")
    labels = name.split(".")
    if all(label.isdigit() for label in labels):
        try:
            return str(ipaddress.IPv4Address(name))
        except ValueError as exc:
            raise ValueError("a numeric host is not an IPv4 address") from exc
    if not all(_NAME_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("a host name has an invalid label")
    return name


def _split_scheme(value: str) -> tuple[str, str]:
    lowered = value.lower()
    for prefix, scheme in _SCHEMES:
        if lowered.startswith(prefix):
            return scheme, value[len(prefix) :]
    return "https", value


def parse_host(value: object) -> HostRule:
    """One allowlist entry as a :class:`HostRule`; ``ValueError`` (fixed text, never the
    value) when it is not ``[http://|https://]host[:port]``."""
    if type(value) is not str or not value or len(value) > _MAX_HOST_TEXT:
        raise ValueError("a host must be a non-empty string of at most 300 characters")
    scheme, rest = _split_scheme(value)
    if any(c.isspace() or c in _REFUSED for c in rest):
        raise ValueError("a host must be host or host:port, with no path, query or wildcard")
    port_text: str | None = None
    if rest.startswith("["):
        close = rest.find("]")
        if close < 0:
            raise ValueError("an IPv6 host must be in brackets")
        host, tail = rest[: close + 1], rest[close + 1 :]
        if tail:
            if not tail.startswith(":"):
                raise ValueError("a host must be host or host:port")
            port_text = tail[1:]
    else:
        host, colon, found = rest.partition(":")
        port_text = found if colon else None
    port = _DEFAULT_PORTS[scheme]
    if port_text is not None:
        if not _PORT_RE.fullmatch(port_text) or not 1 <= int(port_text) <= _MAX_PORT:
            raise ValueError("a port must be 1-65535")
        port = int(port_text)
    return HostRule(scheme, canonical_host(host), port)


def _hosts(value: object, what: str) -> tuple[HostRule, ...]:
    """A list or tuple of host strings, normalised, at most :data:`MAX_HOSTS`, no two
    equal after normalisation (that would be contradictory)."""
    if type(value) is not tuple and type(value) is not list:
        raise ValueError(f"{what} must be a list or tuple of host strings")
    if len(value) > MAX_HOSTS:
        raise ValueError(f"{what} holds more than 256 hosts")
    rules = tuple(parse_host(item) for item in value)
    if len(set(rules)) != len(rules):
        raise ValueError(f"{what} names one host twice")
    return rules


def _providers(value: object) -> tuple[str, ...]:
    if type(value) is not tuple and type(value) is not list:
        raise ValueError("remote_sandbox must be a list or tuple of provider names")
    providers = tuple(value)
    if not all(type(p) is str and p in SANDBOX_PROVIDERS for p in providers):
        raise ValueError("remote_sandbox names a provider this build does not have (only e2b)")
    if len(set(providers)) != len(providers):
        raise ValueError("remote_sandbox names one provider twice")
    return providers


@dataclass(frozen=True, slots=True)
class HooksConfig:
    """What the operator asked for: one value per registered channel, the host label whose
    ``hst-`` pseudonym is ``fabric.execution.host_id`` on exec records, and the declared
    sandbox provider hosts (manifest only)."""

    exec: bool = False
    host_label: str | None = None
    http_hosts: tuple[HostRule, ...] = ()
    remote_sandbox: tuple[str, ...] = ()
    sandbox_hosts: tuple[HostRule, ...] = ()

    def requested(self, point: str) -> bool:
        """Whether the channel at capture point ``point`` was asked for."""
        if point == "exec.subprocess":
            return self.exec
        if point == "http.nonmodel":
            return bool(self.http_hosts)
        if point == "remote.sandbox":
            return bool(self.remote_sandbox)
        return False

    @property
    def any_requested(self) -> bool:
        return self.exec or bool(self.http_hosts) or bool(self.remote_sandbox)

    @property
    def sandbox_undeclared(self) -> bool:
        """Sandbox hosts are declared but no provider is enabled: the manifest says
        ``remote.sandbox`` ``disabled(remote_sandbox)`` (056 §4.4.1)."""
        return bool(self.sandbox_hosts) and not self.remote_sandbox


def _label(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not _LABEL_RE.fullmatch(value):
        raise ValueError(
            "host_label must be 1-128 characters of letters, digits and ._:/- "
            "starting with a letter or digit"
        )
    return value


def config_from_args(
    *, exec: object = False, host_label: object = None, http_hosts: object = (),
    remote_sandbox: object = (), sandbox_hosts: object = (),
) -> HooksConfig:  # fmt: skip
    """The configuration of an explicit ``fabric.hooks.install(...)``: ``exec`` must be a
    ``bool`` (not a truthy string or int), ``host_label`` ``None`` or a bounded label,
    ``http_hosts`` and ``sandbox_hosts`` lists or tuples of host strings (a bare string is
    refused: it is not a list of hosts), ``remote_sandbox`` a list or tuple of provider
    names (only ``"e2b"``). Malformed or contradictory arguments raise ``ValueError``
    (fixed text, never the value)."""
    if type(exec) is not bool:
        raise ValueError("exec must be True or False")
    return HooksConfig(
        exec=exec, host_label=_label(host_label), http_hosts=_hosts(http_hosts, "http_hosts"),
        remote_sandbox=_providers(remote_sandbox),
        sandbox_hosts=_hosts(sandbox_hosts, "sandbox_hosts"),
    )  # fmt: skip


def _flag(environ: Mapping[str, str], name: str) -> bool:
    value = (environ.get(name) or "").strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{name} must be 1 or 0")


def _json_hosts(environ: Mapping[str, str], name: str) -> tuple[HostRule, ...]:
    """A JSON array of host strings (absent or empty: none)."""
    text = (environ.get(name) or "").strip()
    if not text:
        return ()
    if len(text) > MAX_HOSTS * (_MAX_HOST_TEXT + 4):
        raise ValueError(f"{name} is too long")
    value = json.loads(text)
    if type(value) is not list:
        raise ValueError(f"{name} must be a JSON array of strings")
    return _hosts(value, name)


def _env_providers(environ: Mapping[str, str]) -> tuple[str, ...]:
    text = (environ.get(REMOTE_SANDBOX_ENV) or "").strip()
    if not text:
        return ()
    return _providers([part.strip() for part in text.split(",")])


def config_from_env(
    environ: Mapping[str, str],
) -> tuple[HooksConfig | None, tuple[str, ...]]:
    """``(config, not_in_build)`` from the environment; never raises. ``config`` is
    ``None`` when any value is malformed (every hook stays disabled); ``not_in_build``
    lists the set switches of channels this build does not have."""
    not_in_build = tuple(name for name in NOT_IN_BUILD_ENV if (environ.get(name) or "").strip())
    try:
        label = (environ.get(HOST_LABEL_ENV) or "").strip() or None
        config = HooksConfig(
            exec=_flag(environ, EXEC_ENV), host_label=_label(label),
            http_hosts=_json_hosts(environ, HTTP_HOSTS_ENV),
            remote_sandbox=_env_providers(environ),
            sandbox_hosts=_json_hosts(environ, SANDBOX_HOSTS_ENV),
        )  # fmt: skip
        return config, not_in_build
    except Exception:
        return None, not_in_build
