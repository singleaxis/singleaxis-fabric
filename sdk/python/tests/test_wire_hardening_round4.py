# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Round-4 hardening (Sol re-check of 03484d5), each test failing on the code it guards:

- sol2 #3: a writer's record quarantined, or removed, by another process is a failure for
  that writer; only a drainer's receipt makes a disappearance a delivery.
- sol2 new: flush/close never exceed their deadline, also while another pump holds the
  pump lock during stalled disk I/O (the admission check runs inside the bounded helper).
- sol2 #4: an ``abandoned`` exchange, and an ``error`` one with an HTTP status, received a
  response: without response evidence it is ``partial``.
- sol2 #5: a capture record with a valid identity but malformed payload keeps its claims
  and blocks completeness of every run and scope it names; a malformed identity refuses
  the input with fixed text.
- J1: source id and ``service.name`` leave capture pseudonymous by default
  (``FABRIC_WIRE_LABELS=clear`` opts out); the report shows tenant, source and run ids only
  in pseudonymous form, projecting legacy clear values through the same function.
- J2: numeric identifiers after an allowlisted prefix are hashed, in capture and report.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric._sequence import run_pseudonym, source_label
from fabric.content_store import LocalFilesystemContentStore
from fabric.reconstruct import ReconstructInputError, reconstruct
from fabric.reconstruct.__main__ import main
from fabric.wire import WireConfig
from fabric.wire._sender import Sender
from fabric.wire._spool import Spool, marker_doc

from .test_reconstruct_verifier import (
    TENANT,
    Capture,
    only_run,
    react_turns,
    real_gaps,
    run_by_id,
)
from .test_wire_helpers import OPENAI_CHAT, ChunkStream, chat_response, make_rig
from .test_wire_spool import SPOOL_MIN, FakeNode, headers_of, install_node, model_client

KEY = "fabric-test-id-key-not-a-secret"
LABEL = "patient-Jane-Doe-12345"  # an operator label that identifies a person
TURN = react_turns()[0]


def hex32(value: str, key: str | None = None) -> str:
    data = value.encode()
    digest = hmac.new(key.encode(), data, hashlib.sha256) if key else hashlib.sha256(data)
    return digest.hexdigest()[:32]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    for name in ("FABRIC_WIRE_ID_KEY", "FABRIC_WIRE_LABELS", "FABRIC_SOURCE_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("OTEL_SERVICE_NAME", raising=False)
    yield
    wire.uninstall()
    emitter.close(1.0)


@pytest.fixture
def node() -> Iterator[FakeNode]:
    created = FakeNode()
    yield created
    created.close()


class _Ok(SpanExporter):
    def export(self, spans: Any) -> SpanExportResult:
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _sender(root: Path, max_bytes: int = SPOOL_MIN) -> tuple[Spool, LossEmitter, Sender]:
    spool = Spool(str(root), max_bytes)
    loss = LossEmitter()
    sender = Sender(spool, _Ok(), loss, content=None, service_name="svc-test")
    loss.attach(sender.wake)
    return spool, loss, sender


def _in_child(work: Any) -> None:
    """Run ``work`` in a forked process (another drainer on the same spool)."""
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child
        code = 1
        try:
            work()
            code = 0
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0


def _drain_elsewhere(root: Path) -> None:
    def work() -> None:
        spool = Spool(str(root), SPOOL_MIN)
        assert spool.try_lock()
        Sender(spool, _Ok(), LossEmitter(), content=None, service_name="svc-other")._drain()
        spool.release()

    _in_child(work)


# ------------------------------------------------- sol2 #3: outcomes across drainer processes


def test_a_record_quarantined_by_another_drainer_fails_its_writers_flush_and_close(
    tmp_path: Path,
) -> None:
    root = tmp_path / "spool"
    spool, _, sender = _sender(root)
    name = spool.write(marker_doc(("writer", 1, 0, None, None, "final")), reserve=True)
    assert name is not None
    data = bytearray((root / name).read_bytes())
    data[-1] ^= 0xFF
    (root / name).write_bytes(bytes(data))
    _drain_elsewhere(root)  # a forked drainer quarantines the writer's record
    assert not (root / name).exists() and (root / (name + ".corrupt")).exists()
    assert not sender.flush(2.0)  # sol2 #3 probe: was True
    closed = sender.close(2.0)
    assert not closed


def test_a_record_delivered_by_another_drainer_is_acknowledged(tmp_path: Path) -> None:
    root = tmp_path / "spool"
    spool, _, sender = _sender(root)
    name = spool.write(marker_doc(("writer", 1, 0, None, None, "final")), reserve=True)
    assert name is not None
    _drain_elsewhere(root)  # delivered by the other process, which leaves a receipt
    assert not (root / name).exists() and (root / (name + ".ack")).exists()
    assert sender.flush(2.0)
    assert not (root / (name + ".ack")).exists()  # the receipt was consumed
    closed = sender.close(2.0)
    assert closed


def test_a_record_that_disappears_without_a_receipt_is_not_a_delivery(tmp_path: Path) -> None:
    root = tmp_path / "spool"
    spool, _, sender = _sender(root)
    name = spool.write(marker_doc(("writer", 1, 0, None, None, "final")), reserve=True)
    assert name is not None
    (root / name).unlink()  # removed by an operator or a drainer that left no receipt
    assert not sender.flush(2.0)
    assert sender.flush(2.0)  # nothing failed since
    closed = sender.close(2.0)
    assert not closed  # close answers for the whole lifetime


# ------------------------------------- sol2 new: the deadline holds while a pump stalls on disk


@pytest.mark.parametrize("operation", ["flush", "close"])
def test_flush_and_close_keep_their_deadline_while_another_pump_stalls_on_disk(
    tmp_path: Path, operation: str
) -> None:
    """Sol's interleaving: right after the bounded pump, another pump takes the lock and
    stalls in a disk write. The caller must still return at its deadline."""
    spool, loss, sender = _sender(tmp_path / "spool")
    loss.attach(lambda: None)  # no sender thread: the test drives the pumps
    entered, release = threading.Event(), threading.Event()
    write, take = spool.write, loss.take

    def stalled_write(*args: Any, **kwargs: Any) -> Any:
        entered.set()
        release.wait(10)
        return write(*args, **kwargs)

    def take_then_race(*args: Any, **kwargs: Any) -> Any:
        taken = take(*args, **kwargs)
        if not entered.is_set() and threading.current_thread().name == "fabric-wire-flush":
            loss.record("agent", 1, "queue_full", 0)  # pending work for the other pump
            threading.Thread(target=sender.pump, daemon=True).start()  # waits for the lock
            time.sleep(0.05)  # it is queued on the lock before this pump releases it
        return taken

    spool.write = stalled_write  # type: ignore[method-assign]
    loss.take = take_then_race  # type: ignore[method-assign]
    try:
        started = time.monotonic()
        result = getattr(sender, operation)(0.3)
        elapsed = time.monotonic() - started
        assert entered.wait(2)  # the other pump did stall inside the disk write
        assert result is False
        assert elapsed < 1.0, f"{operation}(0.3) blocked for {elapsed:.2f}s"
    finally:
        release.set()


# ------------------------------------------------------- sol2 #4: response evidence


def _real_capture_rows(tmp_path: Path, state: str) -> tuple[list[dict[str, Any]], Any]:
    """An actual tee capture ending ``error`` (stream failed after the 200) or
    ``abandoned`` (stream garbage-collected unclosed), as sink rows."""
    import gc  # noqa: PLC0415

    rig = make_rig(tmp_path)
    reply = json.dumps(chat_response({"role": "assistant", "content": "ok"})).encode()
    stream = ChunkStream([reply, b"next"], fail_after=1 if state == "error" else None)
    headers = {"content-type": "application/json"}
    with rig.client(lambda r: httpx.Response(200, headers=headers, stream=stream)) as client:
        request = client.build_request("POST", OPENAI_CHAT, json={"model": "gpt-4o"})
        response = client.send(request, stream=True)
        if state == "error":
            with pytest.raises(httpx.ReadError):
                list(response.iter_raw())
        del response
        gc.collect()
    closed = rig.handle.close(5)
    assert closed
    rows = []
    for span in rig.exporter.get_finished_spans():
        context = span.context
        assert context is not None
        rows.append({
            "kind": "span", "name": span.name, "trace_id": f"{context.trace_id:032x}",
            "span_id": f"{context.span_id:016x}", "start_ns": span.start_time,
            "end_ns": span.end_time, "attributes": dict(span.attributes or {}),
        })  # fmt: skip
    return rows, rig.store


@pytest.mark.parametrize("state", ["error", "abandoned"])
def test_a_received_response_without_evidence_is_partial(tmp_path: Path, state: str) -> None:
    rows, store = _real_capture_rows(tmp_path, state)
    model = next(r for r in rows if r["name"] == "fabric.model_call")["attributes"]
    assert model["fabric.wire.response_state"] == state
    assert model["http.response.status_code"] == 200
    path = tmp_path / "intact.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    intact = only_run(reconstruct([path], store=store))
    assert ("missing_object", "response_not_recorded") not in real_gaps(intact)
    for key in ("fabric.wire.response_sha256", "fabric.content.result_ref"):
        del model[key]  # the record now proves only the request
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    run = only_run(reconstruct([path], store=store))
    assert run["verdict"] == "partial"  # was complete_for_declared_scope
    assert ("missing_object", "response_not_recorded") in real_gaps(run)


def test_an_error_with_a_status_needs_response_evidence(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    capture.exchange(TURN[0], None, state="error", http_status=502)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert ("missing_object", "response_not_recorded") in real_gaps(run)


# --------------------------------------------- sol2 #5: malformed payload, malformed identity

R, Q = run_pseudonym("run-travel-42"), run_pseudonym("run-travel-43")


def _two_runs(capture: Capture) -> tuple[Any, Any, str, str]:
    r_scope = capture.run_start(R)
    r_call = capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    q_scope = capture.run_start(Q)
    q_call = capture.exchange(*TURN, run_id=Q)
    capture.run_end(Q)
    return r_call, q_call, r_scope, q_scope


@pytest.mark.parametrize(
    "damage",
    [
        {"fabric.wire.response_sha256": "bad"},  # Sol's probe
        {"fabric.wire.api": "unknown.api"},
        {"fabric.wire.truncated": "no"},
        {"http.response.status_code": 42},
        {"fabric.content.request_ref": 7},
    ],
)
def test_a_malformed_duplicate_keeps_its_claims_and_invalidates_both_runs(
    tmp_path: Path, damage: dict[str, Any]
) -> None:
    capture = Capture(tmp_path)
    r_call, q_call, r_scope, q_scope = _two_runs(capture)
    bad = copy.deepcopy(r_call.span)
    bad["attributes"].update({
        "fabric.run.id": Q, "fabric.run.scope_id": q_scope,
        "fabric.source.sequence": q_call.source_sequence, **damage,
    })  # fmt: skip
    capture.rows.append(bad)
    document = capture.reconstruct()
    for run_id in (R, Q):
        assert run_by_id(document, run_id)["verdict"] == "partial"  # both were complete
    assert {s["scope_id"]: s["verdict"] for s in document["scopes"]} == {
        r_scope: "partial",
        q_scope: "partial",
    }
    q_gaps = run_by_id(document, Q)["gaps"]
    assert (r_call.exchange_id, "malformed_record") in {
        (g.get("exchange_id"), g.get("reason")) for g in q_gaps
    }
    assert ("digest_mismatch", "conflicting_claim") in real_gaps(run_by_id(document, Q))


def test_a_malformed_record_alone_is_partial_not_ignored(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    scope = capture.run_start(R)
    call = capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    call.span["attributes"]["fabric.wire.request_sha256"] = "sha256:not-hex"
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "partial"
    assert ("digest_mismatch", "malformed_record") in real_gaps(run)
    assert [(s["scope_id"], s["verdict"]) for s in document["scopes"]] == [(scope, "partial")]
    assert run["exchanges"] == []  # its payload is never reported as if it were valid
    assert ("sequence_gap", None) not in real_gaps(run)  # its sequence is claimed


@pytest.mark.parametrize(
    "damage",
    [{"fabric.heartbeat.last_sequence": "x"}, {"fabric.run.id": "bad id"}],
)
def test_a_malformed_marker_of_a_closed_scope_keeps_it_from_completing(
    tmp_path: Path, damage: dict[str, Any]
) -> None:
    capture = Capture(tmp_path)
    scope = capture.run_start(R)
    capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    bad = copy.deepcopy(capture.rows[-1])  # a damaged copy of the scope's run_end
    bad["span_id"] = "f" * 16
    bad["attributes"].update(damage)
    capture.rows.append(bad)
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "unverified"  # was complete_for_observed_scopes
    assert ("tail_unverified", "malformed_record") in real_gaps(run)
    assert [(s["scope_id"], s["state"]) for s in run["scopes"]] == [(scope, "conflict")]


@pytest.mark.parametrize(
    "damage",
    [
        {"fabric.source.sequence": "x"},
        {"fabric.source.epoch": -1},
        {"fabric.run.id": "has space"},
        {"fabric.run.scope_id": "NOT-A-UUID"},
        {"fabric.source_id": ""},
        {"fabric.wire.exchange_id": 17},
    ],
)
def test_a_malformed_identity_refuses_the_input_with_fixed_text(
    tmp_path: Path, damage: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    capture = Capture(tmp_path)
    capture.run_start(R)
    call = capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    call.span["attributes"].update(damage)
    with pytest.raises(ReconstructInputError, match=r"^span file 1 span \d+: an exchange span"):
        capture.reconstruct()
    code = main(["--spans", str(capture.write())])
    assert code == 2
    err = capsys.readouterr().err
    assert "malformed identity" in err
    assert str(capture.root) not in err and "has space" not in err and "NOT-A-UUID" not in err


# --------------------------------------------------------- J1: pseudonymous labels in capture


def _sink_rows(spans: Sequence[ReadableSpan]) -> list[dict[str, Any]]:
    rows = []
    for span in spans:
        context = span.context
        assert context is not None
        rows.append({
            "kind": "span", "name": span.name, "trace_id": f"{context.trace_id:032x}",
            "span_id": f"{context.span_id:016x}", "start_ns": span.start_time,
            "end_ns": span.end_time, "attributes": dict(span.attributes or {}),
            "resource": dict(span.resource.attributes),
        })  # fmt: skip
    return rows


class _Sink(SpanExporter):
    def __init__(self) -> None:
        self.spans: list[ReadableSpan] = []

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _capture_with_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, key: str | None, labels: str | None
) -> tuple[list[dict[str, Any]], LocalFilesystemContentStore]:
    """Sol's data-exposure probe: an actual capture whose source, service, tenant and run
    labels identify a person, and whose provider returns a numeric-suffix model name."""
    monkeypatch.setenv("OTEL_SERVICE_NAME", LABEL)
    if key:
        monkeypatch.setenv("FABRIC_WIRE_ID_KEY", key)
    if labels:
        monkeypatch.setenv("FABRIC_WIRE_LABELS", labels)
    sink = _Sink()
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=LABEL)
    handle = wire.install(store=store, source_id=LABEL, span_exporter=sink, patch_httpx=False,
                          spool_dir=str(tmp_path / "spool"))  # fmt: skip
    reply = {"model": "gpt-4o-123-45-6789", "choices": [
        {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}  # fmt: skip
    transport = wire.WireTransport(httpx.MockTransport(lambda r: httpx.Response(200, json=reply)))
    with wire.run("private-run-Jane-Doe"), httpx.Client(transport=transport) as client:
        client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": []})
    closed = handle.close(5.0)
    assert closed
    return _sink_rows(sink.spans), store


@pytest.mark.parametrize("key", [None, KEY])
def test_capture_telemetry_carries_no_operator_label_in_clear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str | None
) -> None:
    rows, store = _capture_with_labels(tmp_path, monkeypatch, key=key, labels=None)
    assert LABEL not in json.dumps(rows) and "gpt-4o-123-45-6789" not in json.dumps(rows)
    source, service = "s-" + hex32(LABEL, key), "svc-" + hex32(LABEL, key)
    names = {row["name"] for row in rows}
    assert {"fabric.model_call", "fabric.capture_heartbeat"} <= names
    for row in rows:  # spans, markers and heartbeats alike
        assert row["attributes"]["fabric.source_id"] == source
        assert row["resource"] == {"service.name": service}
    model = next(r for r in rows if r["name"] == "fabric.model_call")["attributes"]
    expected_model = "m-" + hashlib.sha256(b"gpt-4o-123-45-6789").hexdigest()[:16]
    assert model["gen_ai.response.model"] == expected_model  # J2
    descriptors = list((tmp_path / "store").rglob("*.json"))
    assert descriptors and all(
        json.loads(p.read_text())["source_id"] == source for p in descriptors
    )
    # The report: tenant, source and run only in pseudonymous form.
    path = tmp_path / "spans.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    document = reconstruct([path], store=store, id_key=key.encode() if key else None)
    text = json.dumps(document)
    assert LABEL not in text and "private-run-Jane-Doe" not in text
    assert "gpt-4o-123-45-6789" not in text
    assert document["inputs"]["store"]["tenant_id"] == "t-" + hex32(LABEL, key)
    assert document["sources"][0]["source_id"] == source
    assert only_run(document)["run_id"] == "r-" + hex32("private-run-Jane-Doe", key)
    assert only_run(document)["verdict"] == "complete_for_observed_scopes"


def test_clear_labels_are_an_explicit_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows, _ = _capture_with_labels(tmp_path, monkeypatch, key=KEY, labels="clear")
    for row in rows:
        assert row["attributes"]["fabric.source_id"] == LABEL
        assert row["resource"] == {"service.name": LABEL}
    run_ids = {r["attributes"].get("fabric.run.id") for r in rows} - {None}
    assert run_ids == {"r-" + hex32("private-run-Jane-Doe", KEY)}  # run ids: always H3


def test_spool_records_and_content_records_carry_the_pseudonyms(
    node: FakeNode, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OTEL_SERVICE_NAME", LABEL)
    node.mode = "down"
    spool = tmp_path / "spool"
    handle = install_node(node, spool, source_id=LABEL)  # node mode: keyed (049 §7.3)
    with wire.run("run-h"), model_client() as client:
        client.post(OPENAI_CHAT, json={"messages": []})
    assert not handle.flush(0.5)  # the Node is down: everything stays spooled
    headers = headers_of(spool)
    assert headers and LABEL not in json.dumps(headers)
    assert {h["source"]["source_id"] for h in headers} == {"s-" + hex32(LABEL, KEY)}
    exchange = next(h for h in headers if h["record_kind"] == "exchange")
    assert exchange["service_name"] == "svc-" + hex32(LABEL, KEY)
    assert {b["descriptor"]["source_id"] for b in exchange["bodies"]} == {"s-" + hex32(LABEL, KEY)}
    node.mode = "ok"
    assert handle.flush(10.0)
    assert node.content and all(a["source_id"] == "s-" + hex32(LABEL, KEY) for a, _ in node.content)
    spans = node.spans
    assert spans and all(resource == {"service.name": "svc-" + hex32(LABEL, KEY)}
                         for _, _, resource in spans)  # fmt: skip


def test_an_unknown_labels_mode_installs_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_LABELS", "patient-Jane-Doe")
    caplog.set_level("WARNING", logger="fabric.wire")
    assert wire.install_from_env() is None
    assert "patient" not in caplog.text
    with pytest.raises(ValueError, match="labels"):
        WireConfig(labels="verbatim")  # type: ignore[arg-type]


# ---------------------------------------------------------- J1: the report projects labels


def test_the_report_projects_legacy_clear_labels_through_the_capture_function(
    tmp_path: Path,
) -> None:
    """Old records with clear source and run ids, and a newer record of the same source in
    pseudonymous form: the report names neither clear value and still sees one source."""
    old = Capture(tmp_path, source_id=LABEL)
    old.exchange(*TURN, run_id="clear-run-Jane-Doe")  # 0
    new = Capture(tmp_path, source_id=source_label(LABEL, KEY.encode()), id_prefix="b")
    new.sequence = 1
    new.exchange(*TURN, run_id=run_pseudonym("clear-run-Jane-Doe", KEY.encode()))  # 1
    new.heartbeat()
    old.rows.extend(new.rows)
    document = old.reconstruct(id_key=KEY.encode())
    text = json.dumps(document)
    assert LABEL not in text and "clear-run-Jane-Doe" not in text and TENANT not in text
    (source,) = document["sources"]
    assert source["source_id"] == "s-" + hex32(LABEL, KEY) and source["missing_sequences"] == []
    run = only_run(document)
    assert run["run_id"] == "r-" + hex32("clear-run-Jane-Doe", KEY)
    selected = old.reconstruct(id_key=KEY.encode(), run_ids=["clear-run-Jane-Doe"])
    assert [r["run_id"] for r in selected["runs"]] == [run["run_id"]]


def test_a_source_fallback_run_id_keeps_its_form_with_the_source_projected(
    tmp_path: Path,
) -> None:
    capture = Capture(tmp_path, source_id=LABEL)
    capture.exchange(*TURN, run_id=f"source:{LABEL}:7")
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["run_id"] == f"source:s-{hex32(LABEL)}:7"


def test_cli_report_and_stderr_name_no_clear_label(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", KEY)
    capture = Capture(tmp_path, source_id=LABEL)
    capture.exchange(*TURN, run_id="clear-run-Jane-Doe")
    capture.heartbeat()
    out = tmp_path / "report.json"
    argv = ["--spans", str(capture.write()), "--store-root", str(tmp_path / "store"),
            "--tenant", TENANT, "--out", str(out), "--run", "clear-run-Jane-Doe"]  # fmt: skip
    assert main(argv) == 0
    err = capsys.readouterr().err
    report = out.read_text()
    for clear in (LABEL, "clear-run-Jane-Doe", TENANT, KEY):
        assert clear not in report and clear not in err
    assert "r-" + hex32("clear-run-Jane-Doe", KEY) in err
