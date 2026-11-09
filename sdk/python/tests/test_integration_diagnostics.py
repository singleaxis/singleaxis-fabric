# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Diagnostics that name the reason and the fix (integration friction audit, 2026-11-09).

- F3: capture not installed (plaintext OTLP to a non-loopback host, the common container
  layout) said only ``ValueError``. ``python -m fabric.wire status`` and
  ``FABRIC_WIRE_DIAGNOSTICS=stderr`` now give the reason and the fix, scrubbed: no URL
  credential, query string or key-like value is ever printed.
- F2: with no OTLP endpoint the private provider drops every span, and ``status`` said
  ``warnings: []``; a model call to a host no endpoint matches was recorded nowhere,
  silently. ``status`` now warns ``spans have no destination``, and at run time each such
  host is counted, named in ``WireHandle.status()`` with its one-line fix, and logged once
  on the diagnostics channel (never on the agent's own output).
- Silent failure 6: content capture enabled while the policy masks roles the autoload has
  no transformation for (``redact``): those roles are withheld, and ``status`` now says so.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric.wire import WireConfig
from fabric.wire.__main__ import autoload_path
from fabric.wire._config import parse_endpoints
from fabric.wire._diagnose import describe, reason, scrub

from .test_wire_helpers import chat_response

SRC = Path(wire.__file__).resolve().parents[2]
SECRETS = ("hunter2-secret", "t0ps3cr3tvalue", "alice")


def _env(extra: dict[str, str], *, autoload: bool = True) -> dict[str, str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    base["PYTHONPATH"] = os.pathsep.join([autoload_path(), str(SRC)]) if autoload else str(SRC)
    if autoload:
        base["FABRIC_WIRE_AUTOLOAD"] = "1"
    base.update(extra)
    return base


def _run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        [sys.executable, *args], env=env, capture_output=True, timeout=60, check=False
    )


def _status(extra: dict[str, str]) -> tuple[int, dict[str, Any], str]:
    result = _run(["-m", "fabric.wire", "status"], _env(extra))
    assert result.stderr == b"", result.stderr
    text = result.stdout.decode()
    (line,) = text.splitlines()
    return result.returncode, json.loads(line), text


def _node_env(tmp_path: Path, endpoint: str) -> dict[str, str]:
    """The quickstart's local-store environment with the Node at ``endpoint``."""
    return {
        "FABRIC_TENANT_ID": "demo", "FABRIC_WIRE_STORE": f"file://{tmp_path}/store",
        "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
    }  # fmt: skip


# -- F3: the reason and the fix -----------------------------------------------------------


def test_status_names_the_plaintext_rule_and_its_fix(tmp_path: Path) -> None:
    code, status, _ = _status(_node_env(tmp_path, "http://fabric-node:4318"))
    assert code == 1
    wire_status = status["wire"]
    assert wire_status["capture"] == "not_installed" and wire_status["error"] == "ValueError"
    assert wire_status["reason"] == (
        "OTEL_EXPORTER_OTLP_ENDPOINT requires verified HTTPS or loopback HTTP"
    )  # the variable the user set
    assert "use https:// with a CA" in wire_status["fix"] and "loopback" in wire_status["fix"]
    (warning,) = [w for w in status["warnings"] if "capture not installed" in w]
    assert warning.startswith("fabric.wire: capture not installed (ValueError): ")
    assert "Fix: plaintext HTTP to a non-loopback host is refused" in warning


def test_status_never_prints_url_credentials_or_query(tmp_path: Path) -> None:
    endpoint = "http://alice:hunter2-secret@fabric-node:4318/v1/traces?token=t0ps3cr3tvalue"
    code, status, text = _status(_node_env(tmp_path, endpoint))
    assert code == 1
    assert "must not carry credentials, a query or a fragment" in status["wire"]["reason"]
    assert "OTEL_EXPORTER_OTLP_HEADERS" in status["wire"]["fix"]
    for secret in SECRETS:
        assert secret not in text


def test_diagnostics_on_stderr_give_the_reason_once(tmp_path: Path) -> None:
    env = _env({**_node_env(tmp_path, "http://fabric-node:4318"),
                "FABRIC_WIRE_DIAGNOSTICS": "stderr"})  # fmt: skip
    result = _run(["-c", "print(1)"], env)
    assert result.returncode == 0 and result.stdout == b"1\n"  # the agent is unaffected
    lines = [line for line in result.stderr.decode().splitlines() if "not installed" in line]
    assert len(lines) == 1
    assert "requires verified HTTPS or loopback HTTP" in lines[0] and "Fix:" in lines[0]


def test_diagnostics_stay_off_the_agent_output_by_default(tmp_path: Path) -> None:
    on = _run(["-c", "print(1)"], _env(_node_env(tmp_path, "http://fabric-node:4318")))
    off = _run(["-c", "print(1)"], _env({}, autoload=False))
    assert (on.stdout, on.stderr) == (off.stdout, off.stderr)


def test_scrub_reduces_urls_and_key_like_values() -> None:
    text = scrub(
        "bad http://u:p4ss@host.example:8443/a/b?k=v#f and key AbC123dEf456GhI789jKl012mNo"
    )
    assert text == "bad http://host.example:8443 and key <redacted>"
    # names of variables and packages stay readable
    assert (
        scrub("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT needs opentelemetry-exporter-otlp-proto-http")
        == "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT needs opentelemetry-exporter-otlp-proto-http"
    )
    assert len(scrub("x" * 1000)) <= 300


def test_a_message_from_outside_fabric_is_its_class_name_only() -> None:
    try:
        json.loads('{"token": "t0ps3cr3tvalue"')
    except ValueError as exc:
        assert reason(exc) == "JSONDecodeError"
        assert describe(exc) == ("JSONDecodeError", None)


def test_invalid_endpoints_json_is_described_without_its_text() -> None:
    with pytest.raises(ValueError) as caught:
        parse_endpoints('[{"endpoint_id": "t0ps3cr3tvalue",')
    why, hint = describe(caught.value)
    assert why.startswith("FABRIC_WIRE_ENDPOINTS is not valid JSON (line 1 column")
    assert "t0ps3cr3tvalue" not in why and hint is not None and "endpoint_id" in hint


# -- F2: spans with no destination --------------------------------------------------------


def test_status_warns_when_spans_have_no_destination() -> None:
    code, status, _ = _status({})  # the README's two variables only
    assert code == 1
    assert status["wire"]["capture"] == "enabled"
    assert status["wire"]["span_destination"] == "none"
    (warning,) = [w for w in status["warnings"] if "no destination" in w]
    assert "captured spans are dropped" in warning and "OTEL_EXPORTER_OTLP_ENDPOINT=" in warning


def test_status_with_a_loopback_node_has_a_destination(tmp_path: Path) -> None:
    code, status, _ = _status(_node_env(tmp_path, "http://127.0.0.1:4318"))
    assert status["wire"]["span_destination"] == "otlp"
    assert not any("no destination" in w for w in status["warnings"])
    assert code == 0


def test_status_with_the_global_tracer_defers_to_the_application() -> None:
    code, status, _ = _status({"FABRIC_WIRE_TRACER": "global"})
    assert code == 0 and status["wire"]["span_destination"] == "application"


README = SRC.parents[2] / "README.md"


def _readme_own_app_env(tmp_path: Path) -> dict[str, str]:
    """The ``export`` lines of the README's "record your own application" block, with
    ``$PWD`` as ``tmp_path`` (``PYTHONPATH`` and the autoload come from ``_env``)."""
    text = README.read_text("utf-8")
    block = text.split("To record your own application", 1)[1].split("```bash", 1)[1]
    block = block.split("```", 1)[0]
    env: dict[str, str] = {}
    for line in block.splitlines():
        words = shlex.split(line.replace("$PWD", str(tmp_path)), comments=True)
        if words[:1] == ["export"] and "=" in words[1]:
            name, value = words[1].split("=", 1)
            if name not in ("PYTHONPATH", "FABRIC_WIRE_AUTOLOAD"):
                env[name] = value
    return env


def test_the_readme_own_application_route_has_a_destination_and_an_endpoint(
    tmp_path: Path,
) -> None:
    """Audit F2: the README's route used to be two variables, which recorded nothing."""
    env = _readme_own_app_env(tmp_path)
    assert {"OTEL_EXPORTER_OTLP_ENDPOINT", "FABRIC_WIRE_ENDPOINTS"} <= set(env)
    code, status, _ = _status(env)
    assert (code, status["warnings"]) == (0, [])
    assert status["wire"]["span_destination"] == "otlp"
    (matcher,) = parse_endpoints(env["FABRIC_WIRE_ENDPOINTS"])
    assert matcher.hosts == frozenset({"models.example.com"})


def test_install_from_env_logs_the_missing_destination(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="fabric")
    handle = wire.install_from_env({})
    try:
        assert handle is not None
        assert any("spans have no destination" in r.getMessage() for r in caplog.records)
    finally:
        wire.uninstall()


# -- F2: model-looking traffic no endpoint matched ----------------------------------------


@pytest.fixture(autouse=True)
def _isolated_loss_emitter(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)


@pytest.fixture
def fake_network(monkeypatch: pytest.MonkeyPatch) -> list[httpx.Request]:
    sent: list[httpx.Request] = []

    def handle_request(self: Any, request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=chat_response({"role": "assistant", "content": "ok"}))

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle_request)
    return sent


def _provider() -> TracerProvider:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(InMemorySpanExporter()))
    return provider


CUSTOM = "https://models.example.com/v1/chat/completions"


def test_unmatched_model_host_is_counted_named_and_logged_once(
    fake_network: list[httpx.Request], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="fabric.wire")
    handle = wire.install(WireConfig(tracer_provider=_provider()))
    body = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    with httpx.Client() as client:
        first = client.post(f"{CUSTOM}?api-key=t0ps3cr3tvalue", json=body)
        client.post(CUSTOM, json=body)
        client.get("https://models.example.com/v1/models")  # not a model call
        client.post("https://other.example.com/upload", json=body)  # not a model path
    assert first.json()["choices"][0]["message"]["content"] == "ok"  # the agent's result
    assert len(fake_network) == 4  # every request was sent, unchanged
    assert handle.stats().unmatched_model_calls == 2
    assert handle.stats().matched == 0
    (row,) = handle.status()["unmatched_model_hosts"]
    assert (row["host"], row["port"], row["count"]) == ("models.example.com", 443, 2)
    assert row["fix"].startswith("export FABRIC_WIRE_ENDPOINTS='")
    messages = [r.getMessage() for r in caplog.records if "model-looking" in r.getMessage()]
    assert len(messages) == 1
    assert messages[0] == (
        "fabric.wire: a model-looking request to https://models.example.com matched no "
        "configured endpoint and was not recorded. Fix: export FABRIC_WIRE_ENDPOINTS='"
        '[{"endpoint_id":"my-model","dialect":"openai","hosts":["models.example.com"],'
        '"ports":[443],"schemes":["https"]}]\''
    )
    assert all("t0ps3cr3tvalue" not in m for m in messages)
    assert "t0ps3cr3tvalue" not in json.dumps(handle.status())


def test_the_named_fix_records_the_host(fake_network: list[httpx.Request]) -> None:
    handle = wire.install(WireConfig(tracer_provider=_provider()))
    with httpx.Client() as client:
        client.post(CUSTOM, json={"model": "m", "messages": []})
    fix = handle.status()["unmatched_model_hosts"][0]["fix"]
    wire.uninstall()
    value = fix.split("=", 1)[1].strip("'")
    endpoints = parse_endpoints(value)
    handle = wire.install(WireConfig(tracer_provider=_provider(), extra_endpoints=endpoints))
    with httpx.Client() as client:
        client.post(CUSTOM, json={"model": "m", "messages": []})
    assert handle.flush(5.0)
    assert handle.stats().matched == 1 and handle.stats().unmatched_model_calls == 0
    assert "unmatched_model_hosts" not in handle.status()


# -- silent failure 6: redact withholds commands under autoload ---------------------------


def _policy(tmp_path: Path, modes: dict[str, str]) -> Path:
    document = {
        "schema_version": "fabric.deployment-policy/v1", "policy_id": "policy",
        "policy_version": 1, "tenant_id": "demo", "workload_id": "agent",
        "privacy": modes,
        "storage": {"backend": "local", "region": "laptop", "key_id": "local"},
        "retention": {"days": 1}, "required_integrations": [],
        "deployment": {"profile": "local", "image_digest": "local", "tls_required": False,
                       "encrypted_store_required": False},
    }  # fmt: skip
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document))
    return path


def test_status_says_when_the_policy_withholds_commands(tmp_path: Path) -> None:
    policy = _policy(tmp_path, {"terminal.argv": "redact", "terminal.stdout": "redact",
                                "llm.request": "retain_original"})  # fmt: skip
    env = {**_node_env(tmp_path, "http://127.0.0.1:4318"), "FABRIC_CAPTURE_POLICY": str(policy)}
    code, status, _ = _status(env)
    assert code == 1
    assert status["wire"]["content_capture"] == "enabled"
    assert status["wire"]["content_withheld_roles"] == ["terminal.argv", "terminal.stdout"]
    (warning,) = [w for w in status["warnings"] if "withheld" in w]
    assert "terminal.argv, terminal.stdout (redact)" in warning and "Fix:" in warning


def test_status_is_quiet_when_the_policy_masks_nothing(tmp_path: Path) -> None:
    policy = _policy(tmp_path, {"terminal.argv": "retain_original"})
    env = {**_node_env(tmp_path, "http://127.0.0.1:4318"), "FABRIC_CAPTURE_POLICY": str(policy)}
    code, status, _ = _status(env)
    assert "content_withheld_roles" not in status["wire"]
    assert code == 0, status["warnings"]
