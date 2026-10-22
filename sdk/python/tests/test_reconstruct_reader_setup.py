# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reader-side setup of ``python -m fabric.reconstruct`` (new-user findings, PR #185).

* A missing boto3 is a setup error (exit 2, fixed text naming the real
  ``singleaxis-fabric[s3]`` extra), never ``missing_object`` gaps; a genuine
  per-object read error stays a gap.
* The ``[s3]`` extra exists, holds boto3, and keeps boto3 out of the base and
  ``[otlp]`` installs.
* ``--spans`` reads the Compose sink's raw OTLP protobuf requests (``*.otlp``)
  and directories of them.
* ``--wait-for-objects`` re-reads absent objects up to a bounded deadline.
"""

from __future__ import annotations

import base64
import json
import sys
import time
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from google.protobuf.json_format import ParseDict  # type: ignore[import-untyped, unused-ignore]
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from fabric.content_store.s3 import S3ContentStore
from fabric.reconstruct import ReconstructInputError, reconstruct
from fabric.reconstruct.__main__ import main
from tests.test_reconstruct_inputs import to_otlp
from tests.test_reconstruct_s3_options import (
    BUCKET,
    ENDPOINT,
    PREFIX,
    _ClientError,
    _FakeS3,
    _node_capture,
    fake_s3,  # noqa: F401 - pytest fixture
)
from tests.test_reconstruct_verifier import (
    GENERATED_AT,
    TENANT,
    Capture,
    only_run,
    react_run,
    validate,
)

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
HINT = 'pip install "singleaxis-fabric[s3]"'


def _s3_argv(spans: Path, out: Path | None = None) -> list[str]:
    argv = ["--spans", str(spans), "--store-uri", f"s3://{BUCKET}/{PREFIX}", "--tenant", TENANT]
    argv += ["--s3-endpoint-url", ENDPOINT, "--s3-path-style"]
    return [*argv, "--out", str(out)] if out is not None else argv


# --------------------------------------------------------------------------
# B1: a missing boto3 is a setup error, not lost content
# --------------------------------------------------------------------------


def test_missing_boto3_exits_two_with_the_extra_hint_and_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    monkeypatch.setitem(sys.modules, "boto3", None)  # import boto3 -> ImportError
    out = tmp_path / "report.json"
    exit_code = main(_s3_argv(capture.write(), out))
    assert exit_code == 2
    captured = capsys.readouterr()
    assert HINT in captured.err
    assert "missing_object" not in captured.err + captured.out
    assert "partial" not in captured.err
    assert not out.exists()
    assert BUCKET not in captured.err and ENDPOINT not in captured.err


def test_boto3_lost_mid_run_is_a_setup_error_not_a_gap(
    fake_s3: tuple[_FakeS3, list[dict[str, Any]]],  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client, _ = fake_s3
    capture = _node_capture(tmp_path)

    def broken(**_: Any) -> None:
        raise ImportError("botocore.vendored is gone")

    monkeypatch.setattr(client, "get_object", broken)
    out = tmp_path / "report.json"
    exit_code = main(_s3_argv(capture.write(), out))
    assert exit_code == 2
    err = capsys.readouterr().err
    assert HINT in err
    assert "vendored" not in err
    assert not out.exists()


def test_a_genuine_per_object_read_error_is_still_a_gap(
    fake_s3: tuple[_FakeS3, list[dict[str, Any]]],  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = fake_s3
    capture = _node_capture(tmp_path)
    victim = next(key for _, key in client.objects if "/meta/" not in key)
    real_get = client.get_object

    def denied(*, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        if Key == victim:
            raise _ClientError("AccessDenied")
        return real_get(Bucket=Bucket, Key=Key)

    monkeypatch.setattr(client, "get_object", denied)
    out = tmp_path / "report.json"
    exit_code = main(_s3_argv(capture.write(), out))
    assert exit_code == 1
    run = only_run(json.loads(out.read_text()))
    assert run["verdict"] == "partial"
    assert [(g["gap_type"], g["reason"]) for g in run["gaps"] if g["effect"] == "partial"] == [
        ("missing_object", "read_error")
    ]


def test_s3_store_import_hint_names_the_real_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    store = S3ContentStore(bucket=BUCKET, prefix=PREFIX, tenant_id=TENANT)
    with pytest.raises(ImportError, match=r'pip install "singleaxis-fabric\[s3\]"'):
        store.ensure_client()


# --------------------------------------------------------------------------
# B2: the [s3] extra
# --------------------------------------------------------------------------


def test_s3_extra_holds_boto3_and_only_there() -> None:
    project = tomllib.loads(PYPROJECT.read_text("utf-8"))["project"]
    extras: Mapping[str, list[str]] = project["optional-dependencies"]
    assert [dep for dep in extras["s3"] if dep.startswith("boto3")] == ["boto3>=1.34"]

    def names(deps: list[str]) -> set[str]:
        return {dep.split(">", 1)[0].split("=", 1)[0].split("[", 1)[0] for dep in deps}

    for cloud_sdk in ("boto3", "botocore", "aiobotocore"):
        assert cloud_sdk not in names(project["dependencies"])
        assert cloud_sdk not in names(extras["otlp"])


# --------------------------------------------------------------------------
# D2: raw OTLP protobuf span requests (*.otlp) and directories of them
# --------------------------------------------------------------------------


def _hex_ids_to_base64(otlp_json: dict[str, Any]) -> dict[str, Any]:
    """OTLP/JSON carries ids as hex; protobuf's JSON mapping wants base64 bytes."""
    for resource in otlp_json["resourceSpans"]:
        for scope in resource["scopeSpans"]:
            for span in scope["spans"]:
                for key in ("traceId", "spanId", "parentSpanId"):
                    if span.get(key):
                        span[key] = base64.b64encode(bytes.fromhex(span[key])).decode()
    return otlp_json


def _proto_bytes(rows: list[dict[str, Any]]) -> bytes:
    request = ExportTraceServiceRequest()
    ParseDict(_hex_ids_to_base64(to_otlp(rows)), request)
    return bytes(request.SerializeToString())


def test_otlp_protobuf_file_reconstructs_like_the_sink_rows(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    expected = capture.reconstruct()
    proto = tmp_path / "traces-0001.otlp"
    proto.write_bytes(_proto_bytes(capture.rows))
    document = reconstruct([proto], store=capture.store, generated_at=GENERATED_AT)
    validate(document)
    assert document["inputs"]["span_files"][0]["format"] == "otlp_proto"
    assert document["runs"] == expected["runs"]
    assert only_run(document)["verdict"] == "complete_for_declared_scope"


def test_a_directory_of_sink_requests_is_read_in_name_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    spans = tmp_path / "fabric-spans"
    spans.mkdir()
    # One request per span, as the sink stores them; a non-*.otlp file is ignored.
    for index, row in enumerate(capture.rows):
        (spans / f"traces-{index:04d}.otlp").write_bytes(_proto_bytes([row]))
    (spans / "notes.txt").write_text("not a span file")
    out = tmp_path / "report.json"
    argv = ["--spans", str(spans), "--store-root", str(tmp_path / "store"), "--tenant", TENANT]
    assert main([*argv, "--out", str(out)]) == 0, capsys.readouterr().err
    document = json.loads(out.read_text())
    validate(document)
    assert len(document["inputs"]["span_files"]) == len(capture.rows)
    assert {entry["format"] for entry in document["inputs"]["span_files"]} == {"otlp_proto"}
    assert only_run(document)["verdict"] == "complete_for_declared_scope"


def test_an_empty_span_directory_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "secret-dir"
    empty.mkdir()
    assert main(["--spans", str(empty)]) == 2
    err = capsys.readouterr().err
    assert "no *.otlp files" in err
    assert "secret-dir" not in err


def test_a_corrupt_otlp_file_is_a_usage_error_without_echo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "secret-name.otlp"
    bad.write_bytes(b"\xff\xff\xff\xff not protobuf SECRET")
    assert main(["--spans", str(bad)]) == 2
    err = capsys.readouterr().err
    assert "not an OTLP protobuf trace export" in err
    assert "SECRET" not in err and "secret-name" not in err


def test_reading_otlp_without_opentelemetry_proto_names_the_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proto = tmp_path / "traces-1.otlp"
    proto.write_bytes(b"")
    monkeypatch.setitem(
        sys.modules, "opentelemetry.proto.collector.trace.v1.trace_service_pb2", None
    )
    with pytest.raises(ReconstructInputError, match=r"singleaxis-fabric\[otlp\]"):
        reconstruct([proto])


# --------------------------------------------------------------------------
# D4: --wait-for-objects
# --------------------------------------------------------------------------


class _LateStore:
    """Delegates to a real store; each object (and descriptor) is absent for its
    first ``misses`` reads, as if the Node were still writing it."""

    def __init__(self, store: Any, misses: int) -> None:
        self._store = store
        self.tenant_id = store.tenant_id
        self.misses = misses
        self.reads: dict[str, int] = {}

    def evidence_ref_for(self, object_id: str) -> str:
        return str(self._store.evidence_ref_for(object_id))

    def _late(self, uri: str) -> None:
        self.reads[uri] = self.reads.get(uri, 0) + 1
        if self.reads[uri] <= self.misses:
            raise FileNotFoundError("still in flight")

    def read(self, uri: str) -> bytes:
        self._late(uri)
        return bytes(self._store.read(uri))

    def read_descriptor(self, uri: str) -> Mapping[str, Any]:
        return dict(self._store.read_descriptor(uri))


def test_without_wait_an_in_flight_object_is_reported_absent(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    late = _LateStore(capture.store, misses=1)
    document = reconstruct([capture.write()], store=late, generated_at=GENERATED_AT)
    run = only_run(document)
    assert run["verdict"] == "partial"
    assert {g["reason"] for g in run["gaps"] if g["gap_type"] == "missing_object"} == {"absent"}
    assert set(late.reads.values()) == {1}


def test_wait_for_objects_rereads_until_the_object_arrives(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    late = _LateStore(capture.store, misses=2)
    document = reconstruct(
        [capture.write()], store=late, generated_at=GENERATED_AT, wait_for_objects_s=30
    )
    validate(document)
    assert only_run(document)["verdict"] == "complete_for_declared_scope"
    assert set(late.reads.values()) == {3}


def test_wait_for_objects_is_bounded(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    late = _LateStore(capture.store, misses=10**6)
    started = time.monotonic()
    document = reconstruct(
        [capture.write()], store=late, generated_at=GENERATED_AT, wait_for_objects_s=0.5
    )
    elapsed = time.monotonic() - started
    assert 0.5 <= elapsed < 5  # one deadline for the whole run, not per object
    run = only_run(document)
    assert run["verdict"] == "partial"
    assert {g["reason"] for g in run["gaps"] if g["gap_type"] == "missing_object"} == {"absent"}


def test_wait_for_objects_does_not_retry_a_digest_mismatch(tmp_path: Path) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    store = capture.store
    assert store is not None
    tampered = next(
        p for p in (tmp_path / "store").rglob("*") if p.is_file() and "meta" not in p.parts
    )
    tampered.write_bytes(tampered.read_bytes() + b"x")
    started = time.monotonic()
    document = reconstruct(
        [capture.write()], store=store, generated_at=GENERATED_AT, wait_for_objects_s=30
    )
    assert time.monotonic() - started < 5
    assert "digest_mismatch" in {g["gap_type"] for g in only_run(document)["gaps"]}


@pytest.mark.parametrize("value", ["-1", "nan", "inf", "3601", "soon"])
def test_wait_for_objects_rejects_bad_values(
    tmp_path: Path, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    argv = ["--spans", str(capture.write()), "--store-root", str(tmp_path / "store")]
    code: object
    try:
        code = main([*argv, "--tenant", TENANT, "--wait-for-objects", value])
    except SystemExit as exc:  # argparse rejects a non-number itself
        code = exc.code
    assert code == 2
    assert value not in capsys.readouterr().err.replace("3600", "")


def test_wait_for_objects_needs_a_store(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    exit_code = main(["--spans", str(capture.write()), "--wait-for-objects", "5"])
    assert exit_code == 2
    assert "--wait-for-objects needs" in capsys.readouterr().err
