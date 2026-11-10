# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Configuration diagnostics that name the reason and the fix (``python -m fabric.wire
status``, ``FABRIC_WIRE_DIAGNOSTICS=stderr``), never a secret.

A configuration error is described by its message only when Fabric itself raised it (the
innermost frame of its traceback is in a ``fabric`` module): Fabric's configuration
messages name variables and rules, never a value. A message from any other library may
echo what it was given, so it is described by its class name only. Either way the text is
scrubbed before it leaves: a URL keeps only its scheme, host and port (no user info, path,
query or fragment), a long run of key-like characters is replaced, and the text is one
line of bounded length. These messages go to Fabric's own diagnostics channels, never to
the monitored process's output (spec 057 B1-B4)."""

from __future__ import annotations

import contextlib
import re
from urllib.parse import urlsplit

_MAX_REASON = 300
_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,15}://[^\s'\"<>]+")
# A run of base64/hex-like characters long enough to be a key or token. It must hold a
# digit and a letter, so variable names and package names stay readable.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
_REDACTED = "<redacted>"

# (substring of a Fabric configuration message, its catalogue id, the one-line fix). The
# ids are contracts/diagnostics/v1/messages-v1.json's (spec 058 §13.1); the first match wins.
_FIXES: tuple[tuple[str, str, str], ...] = (
    ("requires verified HTTPS or loopback HTTP", "FW-012",
     "plaintext HTTP to a non-loopback host is refused: use https:// with a CA the process "
     "trusts (FABRIC_OTLP_CERTIFICATE or OTEL_EXPORTER_OTLP_CERTIFICATE), or a loopback "
     "address (127.0.0.1, localhost, [::1]), for example by publishing the Fabric Node's "
     "port on this host"),
    ("requires verified TLS or loopback plaintext", "FW-012",
     "plaintext OTLP to a non-loopback host is refused: use https:// with a CA the process "
     "trusts (OTEL_EXPORTER_OTLP_CERTIFICATE), or a loopback address (127.0.0.1, localhost, "
     "[::1])"),
    ("must not carry credentials, a query or a fragment", "FW-010",
     "remove user:password@, ?query and #fragment from the URL; send credentials as "
     "OTEL_EXPORTER_OTLP_HEADERS (or in FABRIC_OTLP_HEADERS_FILE)"),
    ("needs opentelemetry-exporter-otlp-proto", "FW-011",
     'install the exporter: pip install "singleaxis-fabric[otlp]"'),
    ("Fabric capture needs an OTLP traces endpoint", "FW-013",
     "set OTEL_EXPORTER_OTLP_ENDPOINT (or FABRIC_OTLP_ENDPOINT) to the Fabric Node "
     "(http://127.0.0.1:4318 for a local Node)"),
    ("needs FABRIC_OTLP_ENDPOINT", "FW-017",
     "set FABRIC_OTLP_ENDPOINT to the Fabric Node's base URL, or remove the other "
     "FABRIC_OTLP_* variables"),
    ("FABRIC_WIRE_BUILTIN_ENDPOINTS", "FW-020",
     "set FABRIC_WIRE_BUILTIN_ENDPOINTS to table (the default) or legacy (the three rows of "
     "releases before 0.13)"),
    ("FABRIC_WIRE_ENDPOINTS", "FW-014",
     'FABRIC_WIRE_ENDPOINTS is a JSON array such as [{"endpoint_id":"my-model",'
     '"dialect":"openai","hosts":["models.example.com"]}] (see docs/quickstart.md)'),
    ("invalid endpoint matcher", "FW-015",
     "each FABRIC_WIRE_ENDPOINTS entry needs an endpoint_id and provider_name of lowercase "
     "letters, digits and ._-, dialect openai or anthropic, hosts or host_suffixes, schemes "
     "http/https and ports 1-65535"),
    ("cannot carry wire spans", "FW-016",
     "set OTEL_EXPORTER_OTLP_ENDPOINT (or FABRIC_OTLP_ENDPOINT): capture then delivers "
     "through its own private tracer provider"),
    ("_FILE, not both", "FW-018",
     "set either the variable or its _FILE variant, not both"),
    ("is not readable", "FW-019",
     "check the path and the permissions of the file the reason names"),
    ("_FILE must hold", "FW-019",
     "check the contents of the file the reason names"),
    ("must hold k=v pairs", "FW-019",
     "the headers file holds k=v pairs separated by commas or newlines"),
    ("must be k=v pairs", "FW-024",
     "headers are k=v pairs separated by commas"),
    ("client key and client certificate", "FW-024",
     "set the client key and the client certificate together, or neither"),
)  # fmt: skip
#: The catalogue id of a configuration error no specific rule describes.
GENERIC_REASON_ID = "FW-001"


def _raised_by_fabric(exc: BaseException) -> bool:
    """Whether the innermost frame that raised ``exc`` is Fabric code."""
    tb = exc.__traceback__
    if tb is None:
        return False
    while tb.tb_next is not None:
        tb = tb.tb_next
    module = str(tb.tb_frame.f_globals.get("__name__", ""))
    return module == "fabric" or module.startswith("fabric.")


def _scrub_url(match: re.Match[str]) -> str:
    try:
        parts = urlsplit(match.group(0))
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return _REDACTED
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}{port}" if host else _REDACTED


def _scrub_token(match: re.Match[str]) -> str:
    text = match.group(0)
    if any(c.isdigit() for c in text) and any(c.isalpha() for c in text):
        return _REDACTED
    return text


def scrub(text: str) -> str:
    """``text`` as one bounded line with URLs reduced to scheme, host and port and
    key-like runs replaced."""
    line = " ".join(str(text).split())
    line = _URL_RE.sub(_scrub_url, line)
    line = _TOKEN_RE.sub(_scrub_token, line)
    if len(line) > _MAX_REASON:
        line = line[: _MAX_REASON - 3] + "..."
    return line


def reason(exc: BaseException) -> str:
    """What went wrong, safe to print: a Fabric configuration message (scrubbed), else the
    exception's class name."""
    if isinstance(exc, (ValueError, TypeError)) and _raised_by_fabric(exc):
        with contextlib.suppress(Exception):
            text = scrub(str(exc))
            if text:
                return text
    return type(exc).__name__


def fix(text: str) -> str | None:
    """The one-line fix for a reason Fabric knows, else ``None``."""
    return next((hint for needle, _, hint in _FIXES if needle in text), None)


def reason_id(text: str) -> str:
    """The catalogue id of a reason (spec 058 §13.2), ``FW-001`` when no rule matches."""
    return next((rid for needle, rid, _ in _FIXES if needle in text), GENERIC_REASON_ID)


def describe(exc: BaseException) -> tuple[str, str | None]:
    """``(reason, fix)`` of a configuration error."""
    why = reason(exc)
    return why, fix(why)


def not_installed_message(error: str, why: str, hint: str | None) -> str:
    """The ``capture not installed`` diagnostic: the class name, then the reason and fix
    when they say more than the class name, then the catalogue id."""
    text = f"fabric.wire: capture not installed ({error})"
    if why != error:
        text += f": {why}"
    if hint:
        text += f". Fix: {hint}"
    return f"{text} [{reason_id(why)}]"
