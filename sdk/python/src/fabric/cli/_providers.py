# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Model endpoints for the CLI (spec 058 §8): the built-in table, a custom provider in one
line, and endpoints derived from the provider clients' base-URL variables.

Everything compiles to the SDK's existing endpoint matcher (``FABRIC_WIRE_ENDPOINTS``):
the CLI adds no matching rule of its own. Key variables (``OPENAI_API_KEY`` and the like)
are read by name only, to tell which providers are in use; their values are never read."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..wire._config import DEFAULT_ENDPOINTS, ENDPOINT_TABLE_VERSION, validate_endpoint
from ..wire._model import EndpointMatcher
from ._report import CliError, Finding

# The standard base-URL variables of the provider clients (§8.3): client-library
# conventions of the providers, not agent frameworks (I6). Variable -> dialect.
BASE_URL_VARIABLES: Mapping[str, str] = {
    "OPENAI_BASE_URL": "openai", "OPENAI_API_BASE": "openai",
    "ANTHROPIC_BASE_URL": "anthropic", "AZURE_OPENAI_ENDPOINT": "openai",
}  # fmt: skip
# Key variables, read by NAME only: which providers an environment uses.
KEY_VARIABLES: Mapping[str, str] = {
    "OPENAI_API_KEY": "openai", "ANTHROPIC_API_KEY": "anthropic",
    "AZURE_OPENAI_API_KEY": "azure-openai",
}  # fmt: skip
_DEFAULT_PORTS = {"https": 443, "http": 80}
_LABEL_RE = re.compile(r"[^a-z0-9-]+")
_SUFFIX_PATHS = ("/chat/completions", "/completions", "/responses", "/embeddings", "/messages")


@dataclass(frozen=True)
class Derived:
    """An endpoint ``fabric`` adds, and why: ``custom`` (fabric.yaml or ``--provider``) or
    the base-URL variable it came from."""

    matcher: EndpointMatcher
    origin: str


def _host_is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _endpoint_name(host: str, port: int, scheme: str) -> str:
    """The default endpoint name: the host's first DNS label (§8.2); ``local-<port>`` for a
    loopback host, ``ip-<address>`` for another address."""
    if _host_is_loopback(host):
        return f"local-{port}"
    try:
        ipaddress.ip_address(host)
        return "ip-" + _LABEL_RE.sub("-", host.lower()).strip("-")[:60]
    except ValueError:
        pass
    label = _LABEL_RE.sub("-", host.split(".", maxsplit=1)[0].lower()).strip("-")[:64]
    return label or f"custom-{scheme}"


def parse_provider(text: str, *, dialect: str | None = None, name: str | None = None
                   ) -> EndpointMatcher:  # fmt: skip
    """Compile one custom provider (§8.2): ``URL`` or ``anthropic=URL`` / ``openai=URL``, the
    base URL the client uses. :class:`CliError` (``FC-008``) when it is not usable."""
    raw = text.strip()
    match = re.match(r"^(openai|anthropic)=(.+)$", raw)
    if match:
        dialect, raw = match.group(1), match.group(2).strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise CliError([Finding("FC-008", "not a URL")]) from None
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        raise CliError([Finding("FC-008", "needs an http:// or https:// URL")])
    if "@" in parts.netloc or parts.query or parts.fragment:
        raise CliError([Finding("FC-008", "remove credentials, query and fragment")])
    path = parts.path.rstrip("/")
    for suffix in _SUFFIX_PATHS:  # a pasted full call URL: keep its base
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    port = port or _DEFAULT_PORTS[scheme]
    dialect = dialect or "openai"
    matcher = EndpointMatcher(
        endpoint_id=name or _endpoint_name(host, port, scheme), dialect=dialect,  # type: ignore[arg-type]
        hosts=frozenset({host}), ports=frozenset({port}), path_prefix=path,
        provider_name="anthropic" if dialect == "anthropic" else "openai",
        schemes=frozenset({scheme}),
    )  # fmt: skip
    try:
        validate_endpoint(matcher)
    except ValueError:
        raise CliError([Finding("FC-008", "the endpoint name or host is not usable")]) from None
    return matcher


def covered(matcher_set: Iterable[EndpointMatcher], scheme: str, host: str, port: int,
            path: str) -> bool:  # fmt: skip
    """Whether a request to this base URL is already recorded by ``matcher_set``."""
    for m in matcher_set:
        host_ok = host in m.hosts or any(host.endswith(s) for s in m.host_suffixes)
        if (host_ok and scheme in m.schemes and (m.ports is None or port in m.ports)
                and path.startswith(m.path_prefix)):  # fmt: skip
            return True
    return False


def from_environment(environ: Mapping[str, str], known: Sequence[EndpointMatcher]
                     ) -> list[Derived]:  # fmt: skip
    """§8.3: a matcher for each base-URL variable whose host ``known`` does not cover."""
    derived: list[Derived] = []
    for variable, dialect in BASE_URL_VARIABLES.items():
        value = (environ.get(variable) or "").strip()
        if not value:
            continue
        try:
            matcher = parse_provider(value, dialect=dialect)
        except CliError:
            continue  # not a URL Fabric can match: plan reports it (E3)
        host = next(iter(matcher.hosts))
        port = next(iter(matcher.ports or {443}))
        scheme = next(iter(matcher.schemes))
        everything = [*known, *(d.matcher for d in derived)]
        if not covered(everything, scheme, host, port, matcher.path_prefix or "/"):
            derived.append(Derived(matcher, variable))
    return derived


def providers_in_use(environ: Mapping[str, str]) -> list[str]:
    """Providers whose key variable is set, by variable name only (the value is never read)."""
    return sorted({provider for name, provider in KEY_VARIABLES.items() if name in environ})


def matcher_json(matcher: EndpointMatcher) -> dict[str, Any]:
    """One ``FABRIC_WIRE_ENDPOINTS`` entry (the SDK's matcher fields)."""
    entry: dict[str, Any] = {"endpoint_id": matcher.endpoint_id, "dialect": matcher.dialect}
    if matcher.hosts:
        entry["hosts"] = sorted(matcher.hosts)
    if matcher.host_suffixes:
        entry["host_suffixes"] = sorted(matcher.host_suffixes)
    if matcher.ports:
        entry["ports"] = sorted(matcher.ports)
    entry["schemes"] = sorted(matcher.schemes)
    if matcher.path_prefix:
        entry["path_prefix"] = matcher.path_prefix
    if matcher.provider_name != "openai":
        entry["provider_name"] = matcher.provider_name
    return entry


def endpoints_value(matchers: Sequence[EndpointMatcher]) -> str:
    """The ``FABRIC_WIRE_ENDPOINTS`` value for ``matchers`` (compact JSON, stable order)."""
    return json.dumps([matcher_json(m) for m in matchers], separators=(",", ":"))


def builtin(*, enabled: bool = True) -> tuple[EndpointMatcher, ...]:
    """The built-in rows in force (``providers.builtin: false``: none)."""
    return DEFAULT_ENDPOINTS if enabled else ()


def table_version() -> int:
    return ENDPOINT_TABLE_VERSION


def custom_from_config(entries: Sequence[Mapping[str, Any]]) -> list[Derived]:
    """``providers.custom`` entries of a validated ``fabric.yaml``."""
    return [Derived(parse_provider(str(e["url"]), dialect=e.get("dialect"), name=e.get("name")),
                    "custom") for e in entries]  # fmt: skip
