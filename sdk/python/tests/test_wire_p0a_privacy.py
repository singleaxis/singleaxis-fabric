# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 049 P0-A on the wire input: the production profile gate (C0A-3), the privacy
canaries (C0A-2), the stored-object digests (§2.4 rule 8), typed extraction through the
Node path (§7.4) and the 63 MiB request bound."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

import fabric
from fabric import wire
from fabric._loss import LossEmitter
from fabric.content_store import LocalFilesystemContentStore
from fabric.deployment_policy import DeploymentPolicy
from fabric.reconstruct import reconstruct
from fabric.wire import RedactionService, Transformation, WireConfig
from fabric.wire._content import encode_content_request
from fabric.wire._keys import envelope_key_id, key_from_env

from .test_wire_helpers import (
    OPENAI_CHAT,
    PRODUCTION_ID_KEY,
    PRODUCTION_SPOOL_KEY,
    make_rig,
    open_record,
    production_env,
    production_policy,
    validate_capture,
)
from .test_wire_spool import FakeNode, install_node, records, wait_for

SECRET = "canary-ssn-078-05-1120"  # noqa: S105 - a planted canary, not a secret
REQUEST = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": SECRET}]})
ANSWER = {"index": 0, "message": {"role": "assistant", "content": SECRET}}
REPLY = {"id": "chatcmpl-1", "model": "gpt-4o", "choices": [ANSWER]}
REQUEST_SHA = hashlib.sha256(REQUEST.encode()).hexdigest()
REPLY_SHA = hashlib.sha256(json.dumps(REPLY).encode()).hexdigest()
TOKEN_KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    for name in ("FABRIC_WIRE_ID_KEY", "FABRIC_CAPTURE_POLICY", "FABRIC_WIRE_SPOOL_KEY",
                 "FABRIC_TOKENIZATION_KEY"):  # fmt: skip
        monkeypatch.delenv(name, raising=False)
    yield
    wire.uninstall()
    emitter.close(1.0)


@pytest.fixture
def node() -> Iterator[FakeNode]:
    created = FakeNode()
    yield created
    created.close()


def _reply(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=json.dumps(REPLY).encode(),
                          headers={"content-type": "application/json"})  # fmt: skip


def _call(handle: wire.WireHandle) -> None:
    transport = wire.WireTransport(httpx.MockTransport(_reply), handle=handle)
    with wire.run("private-run-name"), httpx.Client(transport=transport) as client:
        client.post(OPENAI_CHAT, content=REQUEST.encode(),
                    headers={"content-type": "application/json"})  # fmt: skip


@pytest.fixture(autouse=True)
def _service(redaction: RedactionService) -> None:
    """The customer redaction service (``FABRIC_REDACTION_ENDPOINT``) of these tests."""


def _policy(mode: str, *, profile: str = "production") -> DeploymentPolicy:
    privacy = {"model.exchange.request": mode, "model.exchange.response": mode}
    return DeploymentPolicy(production_policy(privacy=privacy, profile=profile))


def _protection(mode: str, transform: str = "redact_secret") -> dict[str, Any]:
    roles = ("model.exchange.request", "model.exchange.response")
    return {
        "capture_policy": _policy(mode), "tokenization_key": TOKEN_KEY,
        "transformations": {r: Transformation(transform, "1") for r in roles},
        "redaction": RedactionService.from_env(os.environ),
    }  # fmt: skip


# --- C0A-3: the production profile gate ------------------------------------------------


GATE = [
    # (name, node, store, policy, id key, spool key, expected state, reason)
    ("local default", False, True, None, False, False, "enabled", None),
    ("metadata only", False, False, None, False, False, "metadata_only", "no_store"),
    ("node without policy", True, False, None, True, True, "disabled", "missing_capture_policy"),
    ("node without id key", True, False, "production", False, True, "disabled",
     "missing_id_key"),
    ("node without spool key", True, False, "production", True, False, "disabled",
     "missing_spool_key"),
    ("node complete", True, False, "production", True, True, "enabled", None),
    ("file store marked production, no key", False, True, "production", False, False,
     "disabled", "missing_id_key"),
    ("file store marked production", False, True, "production", True, False, "enabled", None),
    ("file store, local policy", False, True, "local", False, False, "enabled", None),
]  # fmt: skip


@pytest.mark.parametrize(
    ("name", "node_mode", "store", "profile", "id_key", "spool_key", "state", "reason"), GATE,
    ids=[case[0] for case in GATE],
)  # fmt: skip
def test_profile_gate_matrix(
    node: FakeNode, tmp_path: Path, caplog: pytest.LogCaptureFixture, name: str,
    node_mode: bool, store: bool, profile: str | None, id_key: bool, spool_key: bool,
    state: str, reason: str | None,
) -> None:  # fmt: skip
    caplog.set_level(logging.WARNING, logger="fabric.wire")
    settings: dict[str, Any] = {
        "capture_policy": _policy("retain_original", profile=profile) if profile else None,
        "id_key": PRODUCTION_ID_KEY if id_key else None,
        "spool_key": PRODUCTION_SPOOL_KEY if spool_key else None,
    }
    if node_mode:
        handle = install_node(node, tmp_path / "spool", **settings)
    else:
        local = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
        handle = wire.install(WireConfig(
            store=local if store else None, tenant_id="tenant-a", patch_httpx=False,
            tracer_provider=_provider(node), **settings,
        ))  # fmt: skip
    status = handle.status()
    assert (status["content_capture"], status["store_reason"]) == (state, reason)
    assert status["profile"] == ("production" if node_mode or profile == "production"
                                 else "local")  # fmt: skip
    expected_policy = "fabric.local-default" if profile is None else "test-capture"
    if state == "enabled":
        assert status["capture_policy"]["policy_id"] == expected_policy
    _call(handle)
    _call(handle)
    assert handle.flush(10.0)
    spans = node.named("fabric.model_call") if node_mode else _spans(node)
    assert len(spans) == 2
    for span in spans:
        assert span.get("fabric.wire.store_reason") == reason  # on every exchange span
        assert SECRET not in json.dumps(span)
        if state != "enabled":
            assert "fabric.wire.request_sha256" not in span and "fabric.content.request_ref" \
                not in span  # fmt: skip
    if state != "enabled":
        assert node.content == []
    if state == "disabled":
        warnings = [r.getMessage() for r in caplog.records if "content capture disabled" in
                    r.getMessage()]  # fmt: skip
        assert reason is not None  # a disabled gate always names its reason
        assert len(warnings) == 2 and all(reason in w for w in warnings)  # install + 1st exchange
    assert SECRET not in caplog.text and str(tmp_path) not in caplog.text


def test_the_disabled_state_is_logged_at_every_install(
    node: FakeNode, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="fabric.wire")
    for _ in range(2):
        install_node(node, tmp_path / "spool", capture_policy=None)
        wire.uninstall()
    installs = [r for r in caplog.records if "metadata capture continues" in r.getMessage()]
    assert len(installs) == 2


def test_production_without_a_key_sends_nothing_derived_from_caller_ids(
    node: FakeNode, tmp_path: Path
) -> None:
    """049 §2.9 rule 5: the source id is random per process and the run id is the
    generated source fallback; neither the configured label nor the run name leaves."""
    handle = install_node(node, tmp_path / "spool", id_key=None, source_id="host-label-xyz")
    _call(handle)
    assert handle.flush(10.0)
    (span,) = node.named("fabric.model_call")
    assert re.fullmatch(r"s-[0-9a-f]{32}", span["fabric.source_id"])
    assert span["fabric.source_id"] != wire._source_id(WireConfig(source_id="host-label-xyz"))
    assert span["fabric.run.id"].startswith("source:")
    text = json.dumps(node.spans)
    assert "private-run-name" not in text and "host-label-xyz" not in text


def _provider(node: FakeNode) -> Any:
    from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: PLC0415
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: PLC0415
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    node.exporter = exporter  # type: ignore[attr-defined]
    return provider


def _spans(node: FakeNode) -> list[dict[str, Any]]:
    exporter = node.exporter  # type: ignore[attr-defined]
    return [dict(s.attributes or {}) for s in exporter.get_finished_spans()
            if s.name == "fabric.model_call"]  # fmt: skip


MALFORMED = [
    ("FABRIC_CAPTURE_POLICY", "missing"),
    ("FABRIC_CAPTURE_POLICY", "not-json"),
    ("FABRIC_CAPTURE_POLICY", "invalid"),
    ("FABRIC_WIRE_ID_KEY", "short-secret"),
    ("FABRIC_WIRE_SPOOL_KEY", "not base64!"),
    ("FABRIC_WIRE_SPOOL_KEY", base64.b64encode(b"x" * 16).decode()),
    ("FABRIC_TOKENIZATION_KEY", base64.b64encode(b"x" * 8).decode()),
]


@pytest.mark.parametrize(("name", "value"), MALFORMED)
def test_malformed_configuration_still_raises_at_install(
    node: FakeNode, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture, name: str, value: str,
) -> None:  # fmt: skip
    """049 §7.3: missing protection never raises; a malformed setting does, at install()
    (fixed text, never the value or a path); autoload catches it and logs the class."""
    (tmp_path / "not-json").write_text("{not json")
    (tmp_path / "invalid").write_text(json.dumps({"schema_version": "x"}))
    if name == "FABRIC_CAPTURE_POLICY":
        value = str(tmp_path / value)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name) as raised:
        install_node(node, tmp_path / "spool", capture_policy=None, id_key=None, spool_key=None)
    assert value not in str(raised.value) and str(tmp_path) not in str(raised.value)
    caplog.set_level(logging.WARNING, logger="fabric.wire")
    store = (tmp_path / "store").as_uri()
    assert wire.install_from_env({"FABRIC_TENANT_ID": "tenant-a", "FABRIC_WIRE_STORE": store}) \
        is None  # fmt: skip
    assert "ValueError" in caplog.text and value not in caplog.text


def test_a_policy_for_another_tenant_is_malformed() -> None:
    with pytest.raises(ValueError, match="another tenant"):
        WireConfig(tenant_id="tenant-b", capture_policy=_policy("retain_original"))


def test_keys_from_files_and_their_errors(tmp_path: Path) -> None:
    raw, text = tmp_path / "raw.key", tmp_path / "b64.key"
    raw.write_bytes(PRODUCTION_SPOOL_KEY)
    text.write_text(base64.b64encode(PRODUCTION_SPOOL_KEY).decode() + "\n")
    for path in (raw, text):
        env = {"FABRIC_WIRE_SPOOL_KEY_FILE": str(path)}
        assert key_from_env(env, "FABRIC_WIRE_SPOOL_KEY", exact=32) == PRODUCTION_SPOOL_KEY
    with pytest.raises(ValueError, match="not both"):
        key_from_env({"K": "a", "K_FILE": "b"}, "K")
    with pytest.raises(ValueError, match="not readable") as raised:
        key_from_env({"K_FILE": str(tmp_path / "absent")}, "K")
    assert str(tmp_path) not in str(raised.value)
    (tmp_path / "short").write_bytes(b"x" * 5)
    with pytest.raises(ValueError, match="32-byte"):
        key_from_env({"K_FILE": str(tmp_path / "short")}, "K", exact=32)
    assert key_from_env({}, "K") is None


def test_production_policy_and_keys_come_from_the_environment(
    node: FakeNode, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in production_env(tmp_path).items():
        monkeypatch.setenv(name, value)
    handle = install_node(node, tmp_path / "spool", capture_policy=None, id_key=None,
                          spool_key=None)  # fmt: skip
    status = handle.status()
    assert status["content_capture"] == "enabled" and status["spool_encrypted"] is True
    assert status["pseudonym_mode"] == "keyed" and re.fullmatch(r"kid-[0-9a-f]{8}",
                                                                status["key_id"])  # fmt: skip
    assert status["spool_key_id"] == envelope_key_id(PRODUCTION_SPOOL_KEY)
    assert PRODUCTION_ID_KEY.decode() not in json.dumps(status)


# --- C0A-2: privacy canaries ---------------------------------------------------------------


PROTECTING = [
    "redact",
    "masked_only",
    "tokenize",
    "metadata_only",
    "omit",
    "failure",
    "masked_copy_failure",
]


def _settings(mode: str) -> dict[str, Any]:
    """``failure``: an injected redact failure; ``masked_copy_failure``: the review copy of
    ``original_plus_masked`` fails, which withholds the original too (049 §7.7 rule 4)."""
    if mode == "failure":
        return _protection("redact", "raises")
    if mode == "masked_copy_failure":
        return _protection("original_plus_masked", "raises")
    return _protection(mode)


def _scan(text: str, where: str) -> None:
    assert SECRET not in text, where
    assert REQUEST_SHA not in text and REPLY_SHA not in text, where  # no original digest


@pytest.mark.parametrize("mode", PROTECTING)
def test_canaries_direct_store(tmp_path: Path, caplog: pytest.LogCaptureFixture, mode: str) -> None:
    """Telemetry, the store, logs and the report hold no original bytes and no digest of
    the original under every protecting mode (an injected transformation failure too)."""
    caplog.set_level(logging.DEBUG)
    settings = _settings(mode)
    rig = make_rig(tmp_path, tenant_id="tenant-a", **settings)
    try:
        with rig.client(_reply) as client:
            response = client.post(OPENAI_CHAT, content=REQUEST.encode(),
                                   headers={"content-type": "application/json"})  # fmt: skip
        assert response.json() == REPLY  # the application is unaffected
        rig.flush()
        (span,) = rig.spans()
        attrs = dict(span.attributes or {})
        _scan(json.dumps(attrs), "telemetry")
        failed, policy = "protection_failed", "privacy_policy"
        expected = {"failure": failed, "masked_copy_failure": failed, "metadata_only": policy,
                    "omit": policy}.get(mode)  # fmt: skip
        assert attrs.get("fabric.wire.store_reason") == expected
        stored = [p for p in (tmp_path / "store").rglob("*") if p.is_file()]
        for path in stored:
            _scan(path.read_bytes().decode("utf-8", "replace"), f"store {path.name}")
        for key in ("fabric.wire.request_sha256", "fabric.wire.response_sha256"):
            if key in attrs:  # the stored, protected object's digest
                ref = attrs["fabric.content.request_ref" if "request" in key
                            else "fabric.content.result_ref"]  # fmt: skip
                assert hashlib.sha256(rig.read_ref(str(ref))).hexdigest() == attrs[key]
        validate_capture(rig)
        rows = tmp_path / "spans.jsonl"
        rows.write_text(json.dumps({
            "kind": "span", "name": span.name, "trace_id": f"{span.context.trace_id:032x}",
            "span_id": f"{span.context.span_id:016x}", "start_ns": span.start_time,
            "end_ns": span.end_time, "attributes": attrs,
            "resource": dict(span.resource.attributes),
        }) + "\n")  # fmt: skip
        report = reconstruct([rows], store=rig.store)
        _scan(json.dumps(report), "report")
        _scan(caplog.text, "logs")
    finally:
        rig.close()


@pytest.mark.parametrize("mode", PROTECTING)
def test_canaries_node_spool(node: FakeNode, tmp_path: Path, mode: str) -> None:
    """The spool (sealed and opened), the content records and the spans the Node receives
    hold no original bytes and no digest of the original."""
    node.mode = "down"
    spool = tmp_path / "spool"
    settings = _settings(mode)
    handle = install_node(node, spool, **settings)
    _call(handle)
    assert handle._tee.flush(5.0)
    assert wait_for(lambda: bool(records(spool)))
    for path in records(spool):
        sealed = path.read_bytes()
        assert sealed.startswith(b"FWSPENC1")
        _scan(sealed.decode("latin-1"), "sealed spool")
        _scan(open_record(path).decode("latin-1"), "opened spool")
    node.mode = "ok"
    assert handle.flush(20.0)
    for attrs, data in node.content:
        _scan(json.dumps(attrs) + data.decode("latin-1"), "content record")
        assert "source_authenticated" not in attrs
    _scan(json.dumps(node.spans), "telemetry")
    if mode in ("omit",):
        assert node.content == []
    if mode in ("metadata_only", "failure", "masked_copy_failure"):
        assert node.content and all(data == b"" for _, data in node.content)
        assert {a["status"] for a, _ in node.content} == {"not_captured"}
    if mode == "masked_copy_failure":  # both objects withheld: no digest, no length
        assert {a["status_reason"] for a, _ in node.content} == {"protection_failed"}
        assert not any("source_byte_length" in a or "source_sha256" in a
                       for a, _ in node.content)  # fmt: skip


def test_retain_original_digests_are_the_stored_objects(node: FakeNode, tmp_path: Path) -> None:
    handle = install_node(node, tmp_path / "spool")
    _call(handle)
    assert handle.flush(20.0)
    (span,) = node.named("fabric.model_call")
    by_id = {attrs["object_id"]: data for attrs, data in node.content}
    for ref, digest in (("fabric.content.request_ref", "fabric.wire.request_sha256"),
                        ("fabric.content.result_ref", "fabric.wire.response_sha256")):  # fmt: skip
        assert hashlib.sha256(by_id[span[ref]]).hexdigest() == span[digest]
    assert "fabric.wire.store_reason" not in span


# --- §7.4: typed extraction through the Node path, and the 63 MiB bound ---------------


def test_a_large_request_is_split_and_its_text_survives(node: FakeNode, tmp_path: Path) -> None:
    image = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(3000)).decode()
    body = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": [
        {"type": "text", "text": "keep this text"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64," + image}},
    ]}]}).encode()  # fmt: skip
    handle = install_node(node, tmp_path / "spool", part_min_bytes=1024)  # max_body 4096
    transport = wire.WireTransport(httpx.MockTransport(_reply), handle=handle)
    with httpx.Client(transport=transport) as client:
        client.post(OPENAI_CHAT, content=body, headers={"content-type": "application/json"})
    assert handle.flush(20.0)
    (span,) = node.named("fabric.model_call")
    assert span["fabric.wire.truncated"] is False and span["fabric.wire.store_status"] == "stored"
    by_id = {attrs["object_id"]: (attrs, data) for attrs, data in node.content}
    skeleton_attrs, skeleton = by_id[span["fabric.content.request_ref"]]
    assert skeleton_attrs["representation"] == "split" and b"keep this text" in skeleton
    assert hashlib.sha256(skeleton).hexdigest() == span["fabric.wire.request_sha256"]
    ((part_attrs, part),) = [v for v in by_id.values() if v[0]["role"] == "model.exchange.part"]
    assert part_attrs["media_type"] == "image/png" and part == image.encode()
    (link,) = part_attrs["links"]
    start, end = link["byte_range"]
    assert body[start:end] == part and skeleton == body[:start] + body[end:]
    assert skeleton_attrs["source_sha256"] == "sha256:" + hashlib.sha256(body).hexdigest()


def test_a_63_mib_skeleton_and_descriptor_fit_the_node_request_cap() -> None:
    """049 §7.4/P0-A exit: the largest object node mode stores, with a maximal descriptor,
    encodes below the Node's 64 MiB request cap."""
    body = b"x" * (63 * 1024 * 1024)
    long_id = "a" * 128
    descriptor: dict[str, Any] = {
        "schema_version": "fabric.content-object/v2", "object_id": "0" * 36,
        "tenant_id": "t" * 256, "role": "model.exchange.request",
        "media_type": "application/" + "x" * 100, "content_encoding": "identity",
        "representation": "split", "transformations": ["extract_parts", "redact"],
        "provenance": "protocol", "boundary": "provider_bound", "status": "stored",
        "stored_byte_length": len(body), "stored_sha256": "sha256:" + "0" * 64,
        "source_byte_length": 1 << 26, "source_sha256": "sha256:" + "1" * 64,
        "source_id": long_id, "source_epoch": (1 << 63) - 1, "source_sequence": (1 << 63) - 1,
        "run_id": long_id, "operation_id": long_id, "captured_at": "2026-10-19T09:00:00+00:00",
        "privacy_mode": "original_plus_masked", "policy_id": long_id,
        "policy_version": 2147483647, "policy_digest": "sha256:" + "2" * 64,
        "protection_status": "retained", "workload_id": long_id,
        "transformation_id": long_id, "transformation_version": long_id,
    }  # fmt: skip
    encoded = encode_content_request(descriptor, body, service_name="svc-" + "f" * 32)
    assert len(encoded) < 64 * 1024 * 1024
    assert WireConfig(content_endpoint="https://node:4319/v1/logs", tenant_id="t",
                      spool_dir="/s", max_body_bytes=63 * 1024 * 1024,
                      spool_max_bytes=1 << 30).max_body_bytes == 63 * 1024 * 1024  # fmt: skip
    with pytest.raises(ValueError, match="max_body_bytes"):
        WireConfig(content_endpoint="https://node:4319/v1/logs", tenant_id="t", spool_dir="/s",
                   max_body_bytes=63 * 1024 * 1024 + 1, spool_max_bytes=1 << 30)  # fmt: skip


def test_defaults_follow_049() -> None:
    config = WireConfig()
    assert (config.max_body_bytes, config.max_retain_bytes, config.part_min_bytes) == (
        32 << 20, 64 << 20, 64 << 10)  # fmt: skip
    with pytest.raises(ValueError, match="max_retain_bytes"):
        WireConfig(max_body_bytes=1 << 20, max_retain_bytes=1 << 19)
    assert "spool_key" not in repr(WireConfig(spool_key=b"x" * 32)) or "xxxx" not in repr(
        WireConfig(spool_key=b"x" * 32))  # fmt: skip


def test_a_hung_service_never_stalls_the_capture_worker(
    tmp_path: Path, redaction: RedactionService
) -> None:
    """Sol P0-A #6 / round 2 #2, through the pipeline: a redaction service that never
    answers is abandoned at the timeout; every exchange is withheld
    (``protection_failed``), the worker keeps up and the application is never affected."""
    import time  # noqa: PLC0415

    transform = Transformation("hang", "1")  # both roles
    roles = ("model.exchange.request", "model.exchange.response")
    settings: dict[str, Any] = {
        "capture_policy": _policy("redact"), "transformations": dict.fromkeys(roles, transform),
        "redaction": RedactionService(redaction.endpoint, timeout_s=0.05),
    }  # fmt: skip
    rig = make_rig(tmp_path, tenant_id="tenant-a", **settings)
    try:
        with rig.client(_reply) as client:
            for _ in range(4):
                started = time.monotonic()
                response = client.post(OPENAI_CHAT, content=REQUEST.encode(),
                                       headers={"content-type": "application/json"})  # fmt: skip
                assert response.json() == REPLY and time.monotonic() - started < 1.0
        assert rig.tee.flush(30.0)  # the worker is not stuck behind the hung service
        spans = rig.spans()
        assert len(spans) == 4
        for span in spans:
            attrs = dict(span.attributes or {})
            assert attrs.get("fabric.wire.store_reason") == "protection_failed"
            _scan(json.dumps(attrs), "telemetry")
        stats = rig.handle.stats()
        assert (stats.redaction_timeouts, stats.redaction_saturated) == (8, 0)
        assert not [p for p in (tmp_path / "store").rglob("*") if p.is_file()
                    and SECRET.encode() in p.read_bytes()]  # fmt: skip
    finally:
        rig.close()
