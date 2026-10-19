# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 049 P0-A exit gate, with real processes, on the built Node image.

    application (_p0a_gate_agent.py: fabric.wire.install() in node mode, a capture
    policy, the id key, a sealed spool; customer transformations where the mode
    needs them) -> production Fabric Node (fabric-gate, collector-production.yaml +
    the content path, source binding, sealed content queue)
        -> customer store: the Node's sealed directory (file backend) and the
           S3-compatible evaluation store (SeaweedFS, SSE, GetObject-only reader)
    -> python -m fabric.reconstruct (the object resolver: by id, digest, descriptor,
       binding, source stamp; split sides reassembled) on trusted readback

It proves, against the running stacks (the stacks of
``test_wire_capture_node_e2e.py`` and ``test_wire_capture_s3_eval_e2e.py``):

- C0A-1, per role family (``model.exchange.request``/``response``, the extracted
  ``model.exchange.part`` objects of a split side, the review copy of
  ``original_plus_masked``), on both stores: stored by the Node, stamped
  ``source_authenticated``, resolved and verified by reconstruct, the split side
  reassembled to its original digest by a reader that cannot list;
- ``masked_only`` never persists the original (store, spool, Node queue and
  telemetry, sink, logs, reports: C0A-2 canaries);
- a failed transformation withholds: ``store_reason=protection_failed``, a
  descriptor-only ``not_captured(protection_failed)``, no byte and no exception
  text anywhere, the application unaffected;
- C0A-3 through the Node: production without a policy, the id key or the spool key
  records no content and every exchange span says why (``store_reason``);
- the Node drops a forged unknown role, another tenant's record, a foreign source
  and an agent-supplied ``source_authenticated`` without storing or logging their
  bytes; a corrupt stored object is a gap in the report, never its content;
- a 63 MiB skeleton plus its descriptor fits the Node's 64 MiB request cap and
  reassembles.

Opt-in by environment like the stacks it reuses: skips without Docker Compose (and,
for the S3 stack, without boto3). ``FABRIC_NODE_IMAGE`` reuses a prebuilt Node image.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import test_wire_capture_node_e2e as node_e2e
import test_wire_capture_s3_eval_e2e as s3_e2e
from _wire_capture_common import (
    build_image,
    capture_protection,
    compose_available,
    spool_header,
    spool_records,
    volume_grep,
    wait_until,
)

GATE_AGENT = Path(__file__).with_name("_p0a_gate_agent.py")
CANARY = f"P0AGATE{uuid.uuid4().hex[:12]}"
FAIL_TEXT = f"transformation failed on {CANARY}"
MIB = 1024 * 1024
SPLIT_LIMITS = {"FABRIC_WIRE_MAX_BODY_BYTES": "8192", "FABRIC_WIRE_PART_MIN_BYTES": "1024"}
PART_ROLE = "model.exchange.part"

pytestmark = pytest.mark.skipif(
    not compose_available(), reason="docker compose unavailable — env-dependent gate"
)


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _without_autoload(env: dict[str, str]) -> dict[str, str]:
    """The gate application installs capture itself (its transformations are code)."""
    return {k: v for k, v in env.items() if k not in ("PYTHONPATH", "FABRIC_WIRE_AUTOLOAD")}


def _run(env: dict[str, str], model_url: str, root: Path, *args: str) -> dict[str, Any]:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(GATE_AGENT), "--model-url", model_url, *args],
        env={**env, "E2E_GATE_CANARY": CANARY}, cwd=root, capture_output=True, text=True,
        timeout=900, check=False,
    )  # fmt: skip
    # The application is never affected: it exits normally with its model answer.
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    info: dict[str, Any] = json.loads(result.stdout.strip().splitlines()[-1])
    assert info["status_code"] == 200, info
    assert FAIL_TEXT not in result.stdout + result.stderr
    assert CANARY not in result.stderr, "the canary reached the application's logs"
    return info


def _exchange(spans: list[dict[str, Any]]) -> dict[str, Any]:
    (span,) = {s["attributes"]["fabric.wire.exchange_id"]: s for s in spans
               if s["name"] == "fabric.model_call"}.values()  # fmt: skip
    for record in spans:  # 049 §7.9: the bound Node stamped every record it admitted
        assert record["attributes"].get("fabric.source.authenticated") is True, record["name"]
    return span


def _by_op(descriptors: list[dict[str, Any]], exchange_id: str) -> list[dict[str, Any]]:
    return [d for d in descriptors if d["operation_id"] == exchange_id]


def _assert_run(report: dict[str, Any], span: dict[str, Any]) -> dict[str, Any]:
    by_run = {run["run_id"]: run for run in report["runs"]}
    run = by_run[span["attributes"]["fabric.run.id"]]
    assert run["verdict"] == "complete_for_declared_scope", run["gaps"]
    # A single call's emitted tool call is never consumed: an info gap, nothing else.
    assert all(g["effect"] == "info" for g in run["gaps"]), run["gaps"]
    assert report["inputs"]["telemetry_origin"] == "trusted_readback"
    (exchange,) = run["exchanges"]
    assert exchange["objects"]["request"]["verification"] == "verified"
    assert exchange["objects"]["response"]["verification"] == "verified"
    assert CANARY not in json.dumps(report)
    return exchange


def _assert_split(descriptors: list[dict[str, Any]], span: dict[str, Any]) -> None:
    """The request side is a stamped skeleton plus parts named from it (§7.4, §7.5)."""
    from fabric._roles import part_object_id

    own = _by_op(descriptors, span["attributes"]["fabric.wire.exchange_id"])
    (skeleton,) = [d for d in own if d["representation"] == "split"]
    assert skeleton["object_id"] == span["attributes"]["fabric.content.request_ref"]
    parts = sorted((d for d in own if d["role"] == PART_ROLE),
                   key=lambda d: d["links"][0]["byte_range"][0])  # fmt: skip
    assert len(parts) == 2
    assert [d["object_id"] for d in parts] == [
        part_object_id(skeleton["object_id"], i) for i in range(2)]  # fmt: skip
    for descriptor in [skeleton, *parts]:
        assert descriptor["source_authenticated"] is True
        assert descriptor["privacy_mode"] == "retain_original"


# --------------------------------------------------------------------------- file Node


class FileGate:
    """The file-backend production Node of ``test_wire_capture_node_e2e``."""

    def __init__(self, stack: node_e2e.Stack) -> None:
        self.stack = stack

    def env(self, service: str, *, mode: str = "retain_original", token: str | None = None,
            extra: dict[str, str] | None = None, drop: tuple[str, ...] = ()) -> dict[str, str]:  # fmt: skip
        stack = self.stack
        spool = stack.root / "spool" / service
        env = _without_autoload(stack.agent_env(service, spool, token or node_e2e.INGRESS_TOKEN))
        env |= capture_protection(stack.root, node_e2e.TENANT, node_e2e.SPOOL_KEY, mode)
        env |= extra or {}
        return {k: v for k, v in env.items() if k not in drop}

    def run(self, service: str, *args: str, **env: Any) -> dict[str, Any]:
        return _run(self.env(service, **env), self.stack.model.url, self.stack.root, *args)

    def spans(self, service: str) -> list[dict[str, Any]]:
        return self.stack.wait_for_run(service, calls=1)

    def descriptors(self, span: dict[str, Any] | None = None) -> tuple[Path, list[Any]]:
        """An opened snapshot of the Node's store, once ``span``'s objects are written."""
        refs = {span["attributes"][k] for k in ("fabric.content.request_ref",
                                                "fabric.content.result_ref")
                if span is not None and k in span["attributes"]}  # fmt: skip
        store = self.stack.wait_content(refs, timeout_s=300) if refs else (
            self.stack.content_snapshot())  # fmt: skip
        return store, list(node_e2e._store_descriptors(store).values())

    def body(self, store: Path, object_id: str) -> bytes:
        return (store / node_e2e.TENANT / "evidence" / object_id).read_bytes()

    def dropped(self) -> dict[str, int]:
        """fabriccontent's permanent drops, by reason, from the Node's log (its only field
        is the reason: no tenant, id, path or byte)."""
        out: dict[str, int] = {}
        for line in self.stack.node_logs().splitlines():
            if "fabriccontent: dropped content record" in line:
                found = re.search(r'"reason"\W+([a-z_]+)', line)
                reason = found.group(1) if found else "unknown"
                out[reason] = out.get(reason, 0) + 1
        return out

    def leak_scan(self, markers: list[str]) -> None:
        """C0A-2: telemetry (sink, delivered bytes), Node logs, Node volumes, reports."""
        stack = self.stack
        sink, raw, logs = (
            stack.records.read_text("utf-8"),
            stack.sink.raw_bytes(),
            stack.node_logs(),
        )
        reports = "\n".join(stack.reports)
        assert sink and raw and logs, "a leak scan would be vacuous"
        for marker in markers:
            assert marker not in sink and marker.encode() not in raw, marker
            assert marker not in logs and marker not in reports, marker
            for volume in ("fabric-queue", "fabric-content-queue", "fabric-content"):
                assert volume_grep(f"{stack.project}_{volume}", marker) == "", (volume, marker)


@pytest.fixture(scope="module")
def node(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FileGate]:
    stack = node_e2e.Stack(tmp_path_factory.mktemp("p0a-gate-file"))
    # 049 §4.3 rule 4: the Node's role cap is the deployment's max_body_bytes (default
    # 32 MiB); the 63 MiB case runs the node-mode ceiling on both sides.
    text = stack.content_config.read_text("utf-8")
    assert text.count("\n  fabriccontent:\n") == 1
    stack.content_config.write_text(
        text.replace(
            "\n  fabriccontent:\n", f"\n  fabriccontent:\n    max_body_bytes: {63 * MIB}\n"
        ),
        "utf-8",
    )
    try:
        if not os.environ.get("FABRIC_NODE_IMAGE"):
            build_image(stack.image)
        stack.sink.start()
        stack.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "90")
        stack.wait_health()
        yield FileGate(stack)
    finally:
        stack.compose("down", "-v", "--remove-orphans", check=False)
        stack.sink.stop()
        stack.model.close()


def test_role_families_reach_the_store_and_resolve(node: FileGate) -> None:
    """C0A-1 (file): request, response and parts of a split side, stamped and verified;
    the request reassembles to its original digest."""
    node.run("gate-split", "--body", "split", extra=SPLIT_LIMITS)
    span = _exchange(node.spans("gate-split"))
    assert span["attributes"]["fabric.wire.store_status"] == "stored"
    store, descriptors = node.descriptors(span)
    _assert_split(descriptors, span)
    code, report = node.stack.reconstruct(store)
    exchange = _assert_run(report, span)
    assert exchange["parse_status"] == "ok"  # parsed from the reassembled original
    assert code in (0, 1)


def test_masked_only_never_persists_the_original(node: FileGate) -> None:
    node.run("gate-masked", "--body", "split", "--transform", "mask", mode="masked_only",
             extra=SPLIT_LIMITS)  # fmt: skip
    span = _exchange(node.spans("gate-masked"))
    attrs = span["attributes"]
    store, descriptors = node.descriptors(span)
    own = _by_op(descriptors, attrs["fabric.wire.exchange_id"])
    assert own and all(d["privacy_mode"] == "masked_only" for d in own)
    for descriptor in own:
        assert "source_sha256" not in descriptor and "source_byte_length" not in descriptor
        assert descriptor["protection_status"] == "redacted"
        data = node.body(store, descriptor["object_id"])
        assert CANARY.encode() not in data
    request = node.body(store, attrs["fabric.content.request_ref"])
    assert b"[masked]" in request
    # 049 §2.4 rule 8: the span digest is the stored (masked) object's.
    assert "sha256:" + attrs["fabric.wire.request_sha256"] == _sha(request)
    _assert_run(node.stack.reconstruct(store)[1], span)
    assert spool_records(node.stack.root / "spool" / "gate-masked") == []
    node.leak_scan([CANARY])


def test_original_plus_masked_links_a_review_copy(node: FileGate) -> None:
    node.run("gate-review", "--transform", "mask", mode="original_plus_masked")
    span = _exchange(node.spans("gate-review"))
    attrs = span["attributes"]
    store, descriptors = node.descriptors(span)
    own = _by_op(descriptors, attrs["fabric.wire.exchange_id"])
    original = next(d for d in own if d["object_id"] == attrs["fabric.content.request_ref"])
    assert CANARY.encode() in node.body(store, original["object_id"])
    assert original["protection_status"] == "retained"
    reviews = [d for d in own if d.get("links", [{}])[0].get("relation") == "derived_from"]
    review = next(d for d in reviews if d["links"][0]["object_id"] == original["object_id"])
    assert review["protection_status"] == "redacted" and review["source_authenticated"] is True
    assert "source_sha256" not in review and "source_byte_length" not in review
    assert CANARY.encode() not in node.body(store, review["object_id"])
    # The span names the originals; a review copy never satisfies them.
    _assert_run(node.stack.reconstruct(store)[1], span)


def test_a_failed_transformation_withholds(node: FileGate) -> None:
    node.run("gate-fail", "--transform", "fail", mode="masked_only")
    span = _exchange(node.spans("gate-fail"))
    attrs = span["attributes"]
    assert attrs["fabric.wire.store_reason"] == "protection_failed"
    assert "fabric.content.request_ref" not in attrs
    assert "fabric.wire.request_sha256" not in attrs
    own: list[dict[str, Any]] = []

    def withheld() -> bool:  # the Node writes descriptor-only records asynchronously
        own[:] = _by_op(node.descriptors()[1], attrs["fabric.wire.exchange_id"])
        return len(own) >= 2  # noqa: PLR2004 - request and response

    wait_until(withheld, 90, lambda: f"descriptor-only records: {own}")
    for descriptor in own:
        assert descriptor["status"] == "not_captured"
        assert descriptor["status_reason"] == "protection_failed"
        assert descriptor["protection_status"] == "withheld"
        assert "stored_sha256" not in descriptor and "source_sha256" not in descriptor
    node.leak_scan([CANARY, FAIL_TEXT])


@pytest.mark.parametrize(
    ("drop", "reason"),
    [
        ("FABRIC_CAPTURE_POLICY", "missing_capture_policy"),
        ("FABRIC_WIRE_ID_KEY", "missing_id_key"),
        ("FABRIC_WIRE_SPOOL_KEY", "missing_spool_key"),
    ],
)
def test_production_without_protection_records_no_content(
    node: FileGate, drop: str, reason: str
) -> None:
    """C0A-3 through the Node: content disabled, metadata continues, and every exchange
    span says why. Without the id key the agent's unkeyed source pseudonym is not the
    Node's bound source, so its spans are checked in its (sealed) spool, kept by a
    rejected token."""
    service = f"gate-off-{reason}"
    token = node_e2e.WRONG_TOKEN if drop == "FABRIC_WIRE_ID_KEY" else None
    info = node.run(service, drop=(drop,), token=token)
    assert info["status"]["content_capture"] == "disabled"
    assert info["status"]["store_reason"] == reason
    if token is not None:
        spool = node.stack.root / "spool" / service
        headers = [spool_header(p, node_e2e.SPOOL_KEY) for p in spool_records(spool)]
        spans = [h["span"] for h in headers if h["record_kind"] == "exchange"]
    else:
        spans = [s for s in node.spans(service) if s["name"] == "fabric.model_call"]
    assert spans, "no exchange span to check"
    for span in spans:
        assert span["attributes"]["fabric.wire.store_reason"] == reason
        assert span["attributes"]["fabric.wire.store_status"] == "disabled"
        assert "fabric.content.request_ref" not in span["attributes"]
    exchange_ids = {s["attributes"]["fabric.wire.exchange_id"] for s in spans}
    _, descriptors = node.descriptors()
    assert not exchange_ids & {d["operation_id"] for d in descriptors}


def _forged(template: dict[str, Any], **changes: Any) -> tuple[dict[str, Any], bytes]:
    body = f"{CANARY} forged body".encode()
    descriptor = {k: v for k, v in template.items()
                  if k not in ("encoding", "ref", "source_authenticated")}  # fmt: skip
    descriptor.update(object_id=str(uuid.uuid4()), stored_byte_length=len(body),
                      stored_sha256=_sha(body), source_byte_length=len(body),
                      source_sha256=_sha(body), representation="exact", transformations=[],
                      status="stored", role="model.exchange.request")  # fmt: skip
    descriptor.pop("links", None)
    descriptor.update(changes)
    return descriptor, body


def test_the_node_drops_forged_records_and_leaks_nothing(node: FileGate) -> None:
    """Unknown role, another tenant, a foreign source and an agent-supplied stamp are
    dropped by fabriccontent (counted by reason), never stored, never logged."""
    from fabric.wire._content import encode_content_request

    node.run("gate-template")
    template_span = _exchange(node.spans("gate-template"))
    _, descriptors = node.descriptors(template_span)
    template = next(d for d in descriptors
                    if d["object_id"] == template_span["attributes"]["fabric.content.request_ref"])  # fmt: skip
    before = node.dropped()
    cases = [
        _forged(template, role="model.exchange.secret"),
        _forged(template, tenant_id="another-tenant"),
        _forged(template, source_id="s-" + "0" * 32),
        _forged(template, source_authenticated="true"),
    ]
    stack = node.stack
    context = ssl.create_default_context(cafile=str(stack.tls / "ca.crt"))
    for descriptor, body in cases:
        request = urllib.request.Request(
            f"https://127.0.0.1:{stack.ports['otlp_content']}/v1/logs",
            data=encode_content_request(descriptor, body, service_name="svc-" + "f" * 32),
            method="POST", headers={"Content-Type": "application/x-protobuf",
                                    "Authorization": f"Bearer {node_e2e.INGRESS_TOKEN}"},
        )  # fmt: skip
        try:
            with urllib.request.urlopen(request, timeout=30, context=context) as response:
                assert response.status == 200  # accepted into the queue, judged after
        except urllib.error.HTTPError as exc:
            assert 400 <= exc.code < 500, exc.code
    forged = {descriptor["object_id"] for descriptor, _ in cases}

    def judged() -> bool:
        return sum(node.dropped().values()) - sum(before.values()) >= len(cases)

    wait_until(judged, 60, lambda: f"dropped: {before} -> {node.dropped()}")
    _, after = node.descriptors()
    assert not forged & {d["object_id"] for d in after}
    node.leak_scan([CANARY])


def test_a_corrupt_object_is_a_gap_never_content(node: FileGate) -> None:
    node.run("gate-corrupt")
    span = _exchange(node.spans("gate-corrupt"))
    store, _ = node.descriptors(span)
    sealed = node.stack.sealed[store]
    corrupt = node.stack.root / f"corrupt-{uuid.uuid4().hex[:8]}"
    shutil.copytree(sealed, corrupt)
    target = (
        corrupt / node_e2e.TENANT / "evidence" / span["attributes"]["fabric.content.request_ref"]
    )
    data = bytearray(target.read_bytes())
    data[-1] ^= 0xFF  # breaks the envelope's tag: never opened, never returned
    target.write_bytes(bytes(data))
    node.stack.sealed[corrupt] = corrupt
    code, report = node.stack.reconstruct(corrupt)
    run = {r["run_id"]: r for r in report["runs"]}[span["attributes"]["fabric.run.id"]]
    assert run["verdict"] == "partial" and code == 1
    assert {(g["gap_type"], g.get("object_role")) for g in run["gaps"]} == {
        ("digest_mismatch", "request")} or {g["gap_type"] for g in run["gaps"]} == {
        "missing_object"}, run["gaps"]  # fmt: skip
    assert CANARY not in json.dumps(report)


def test_a_63_mib_skeleton_fits_the_node_request_cap(node: FileGate) -> None:
    """049 §7.4: max_body_bytes 63 MiB in node mode; the skeleton of a 63+ MiB request is
    one content request below the Node's 64 MiB cap, stored and reassembled."""
    limits = {"FABRIC_WIRE_MAX_BODY_BYTES": str(63 * MIB)}
    node.run("gate-63mib", "--body", "big", "--size", str(63 * MIB - 64 * 1024), extra=limits)
    span = node.stack.wait_for_run("gate-63mib", calls=1, timeout_s=300)
    span = _exchange(span)
    assert span["attributes"]["fabric.wire.store_status"] == "stored"
    store, descriptors = node.descriptors(span)
    skeleton = next(d for d in descriptors
                    if d["object_id"] == span["attributes"]["fabric.content.request_ref"])  # fmt: skip
    assert skeleton["representation"] == "split"
    assert 62 * MIB < skeleton["stored_byte_length"] <= 63 * MIB
    assert skeleton["source_byte_length"] > 63 * MIB
    exchange = _assert_run(node.stack.reconstruct(store)[1], span)
    assert exchange["parse_status"] == "ok"


# --------------------------------------------------------------------------- S3 Node


class S3Gate:
    """The S3-backend production Node of ``test_wire_capture_s3_eval_e2e``."""

    def __init__(self, stack: s3_e2e.Stack) -> None:
        self.stack = stack

    def run(self, service: str, *args: str, mode: str = "retain_original",
            extra: dict[str, str] | None = None) -> dict[str, Any]:  # fmt: skip
        stack = self.stack
        env = _without_autoload(stack.agent_env(service, stack.root / "spool" / service,
                                                s3_e2e.INGRESS_TOKEN))  # fmt: skip
        env |= capture_protection(stack.root, s3_e2e.TENANT, stack.spool_key, mode)
        return _run(env | (extra or {}), stack.model.url, stack.root, *args)

    def descriptors(self, span: dict[str, Any], count: int) -> tuple[dict[str, Any], list[Any]]:
        """Every object of the exchange, once the Node wrote ``count`` of them."""
        exchange_id = span["attributes"]["fabric.wire.exchange_id"]
        found: list[dict[str, Any]] = []

        def written() -> bool:
            objects = self.stack.store_objects()
            found[:] = [objects]
            metas = [json.loads(s3_e2e._decode(objects, k)) for k in objects if "/meta/" in k]
            return len(_by_op(metas, exchange_id)) >= count

        wait_until(written, 90, lambda: "the Node did not write the objects")
        objects = found[0]
        metas = [json.loads(s3_e2e._decode(objects, k)) for k in objects if "/meta/" in k]
        return objects, metas


@pytest.fixture(scope="module")
def s3(tmp_path_factory: pytest.TempPathFactory) -> Iterator[S3Gate]:
    if importlib_missing("boto3"):
        pytest.skip("boto3 unavailable for the S3 reader")
    stack = s3_e2e.Stack(tmp_path_factory.mktemp("p0a-gate-s3"))
    try:
        if not os.environ.get("FABRIC_NODE_IMAGE"):
            build_image(stack.image)
        stack.sink.start()
        up = stack.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180",
                           check=False)  # fmt: skip
        assert up.returncode == 0, f"{up.stdout}\n{up.stderr}\n{stack.node_logs()[-4000:]}"
        stack.wait_health()
        yield S3Gate(stack)
    finally:
        stack.compose("down", "-v", "--remove-orphans", check=False)
        stack.sink.stop()
        stack.model.close()


def importlib_missing(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is None


def test_s3_role_families_resolve_with_a_get_only_reader(s3: S3Gate) -> None:
    """C0A-1 (S3): the split request's parts are found from the skeleton's id by a reader
    that may GetObject but not list, and reassemble to the original digest."""
    s3.run("gate-s3-split", "--body", "split", extra=SPLIT_LIMITS)
    span = _exchange(s3.stack.wait_spans("gate-s3-split", exchanges=1))
    objects, metas = s3.descriptors(span, count=4)  # skeleton, two parts, response
    _assert_split(metas, span)
    own = {d["object_id"] for d in _by_op(metas, span["attributes"]["fabric.wire.exchange_id"])}
    for key, entry in objects.items():
        if key.rsplit("/", 1)[-1].removesuffix(".json") in own:
            assert entry["sse"] == "AES256", key  # SSE on every body and descriptor
    _code, report = s3.stack.reconstruct(span["attributes"]["fabric.run.id"])
    exchange = _assert_run(report, span)
    assert exchange["parse_status"] == "ok"


def test_s3_masked_only_never_persists_the_original(s3: S3Gate) -> None:
    s3.run("gate-s3-masked", "--transform", "mask", mode="masked_only")
    span = _exchange(s3.stack.wait_spans("gate-s3-masked", exchanges=1))
    objects, metas = s3.descriptors(span, count=2)
    own = _by_op(metas, span["attributes"]["fabric.wire.exchange_id"])
    for descriptor in own:
        assert descriptor["privacy_mode"] == "masked_only"
        assert "source_sha256" not in descriptor and descriptor["source_authenticated"] is True
    ids = {d["object_id"] for d in own}
    for key in objects:  # this exchange's bodies and descriptors
        if key.rsplit("/", 1)[-1].removesuffix(".json") in ids:
            assert CANARY.encode() not in s3_e2e._decode(objects, key), key
    _assert_run(s3.stack.reconstruct(span["attributes"]["fabric.run.id"])[1], span)
    sink = s3.stack.sink.records.read_text("utf-8")
    assert CANARY not in sink and CANARY not in s3.stack.node_logs()
    assert base64.b64encode(CANARY.encode()).decode() not in sink
