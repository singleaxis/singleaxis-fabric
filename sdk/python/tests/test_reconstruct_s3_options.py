# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct reads Node-written content from S3-compatible stores (spec 043 §10, F10).

``boto3`` / ``botocore`` are replaced by an in-memory fake that records how
the client is built and serves objects from a dict, so these tests need no
network and no AWS SDK. The MinIO end-to-end (real Node, real bucket) lives
in ``scripts/tests/test_wire_capture_minio_e2e.py``.
"""

from __future__ import annotations

import io
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from fabric.content_store.s3 import S3ContentStore
from fabric.reconstruct.__main__ import main
from fabric.reconstruct._objects import StoreReader
from tests.test_reconstruct_verifier import (
    CAPTURE_ROOT,
    TENANT,
    Capture,
    only_run,
    react_run,
    validate,
)

BUCKET = "fabric-evidence"
PREFIX = "node/content/"
ENDPOINT = "http://minio:9000"


class _ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _FakeS3:
    """Just enough of an S3 client: conditional puts and gets."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.gets: list[str] = []

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **extra: Any) -> None:  # noqa: N803
        if extra.get("IfNoneMatch") == "*" and (Bucket, Key) in self.objects:
            raise _ClientError("PreconditionFailed")
        self.objects[(Bucket, Key)] = bytes(Body)

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        self.gets.append(Key)
        if (Bucket, Key) not in self.objects:
            raise _ClientError("NoSuchKey")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}


class _Config:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


@pytest.fixture
def fake_s3(monkeypatch: pytest.MonkeyPatch) -> tuple[_FakeS3, list[dict[str, Any]]]:
    client = _FakeS3()
    calls: list[dict[str, Any]] = []

    def make_client(service: str, **kwargs: Any) -> _FakeS3:
        assert service == "s3"
        calls.append(kwargs)
        return client

    boto3 = types.ModuleType("boto3")
    boto3.client = make_client  # type: ignore[attr-defined]
    botocore = types.ModuleType("botocore")
    config = types.ModuleType("botocore.config")
    config.Config = _Config  # type: ignore[attr-defined]
    botocore.config = config  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", config)
    return client, calls


# --------------------------------------------------------------------------
# S3ContentStore.addressing_style
# --------------------------------------------------------------------------


@pytest.mark.parametrize("style", ["path", "virtual", "auto"])
def test_addressing_style_reaches_the_client_config(
    fake_s3: tuple[_FakeS3, list[dict[str, Any]]], style: str
) -> None:
    _, calls = fake_s3
    store = S3ContentStore(
        bucket=BUCKET,
        prefix=PREFIX,
        tenant_id=TENANT,
        endpoint_url=ENDPOINT,
        region_name="eu-west-1",
        addressing_style=style,
    )
    store._get_client()
    (kwargs,) = calls
    assert kwargs["endpoint_url"] == ENDPOINT
    assert kwargs["region_name"] == "eu-west-1"
    assert kwargs["config"].kwargs == {"s3": {"addressing_style": style}}


def test_without_addressing_style_no_config_is_passed(
    fake_s3: tuple[_FakeS3, list[dict[str, Any]]],
) -> None:
    _, calls = fake_s3
    S3ContentStore(bucket=BUCKET, tenant_id=TENANT)._get_client()
    assert calls == [{"region_name": None, "endpoint_url": None}]


@pytest.mark.parametrize("style", ["PATH", "", "dns", "bucket"])
def test_unknown_addressing_style_is_rejected(style: str) -> None:
    with pytest.raises(ValueError, match="addressing_style"):
        S3ContentStore(bucket=BUCKET, tenant_id=TENANT, addressing_style=style)


# --------------------------------------------------------------------------
# The Node's store layout
# --------------------------------------------------------------------------


def test_reader_resolves_the_node_layout_of_the_golden_descriptor(
    fake_s3: tuple[_FakeS3, list[dict[str, Any]]],
) -> None:
    """The keys the Node's fabriccontent exporter writes are the keys reconstruct reads."""
    client, _ = fake_s3
    golden = json.loads(
        (CAPTURE_ROOT / "fixtures" / "golden" / "content-descriptor-s3.json").read_text()
    )
    attributes = golden["content_log_record"]["attributes"]
    backend = golden["backend"]
    store = S3ContentStore(
        bucket=backend["bucket"],
        prefix=backend["prefix"],
        tenant_id=attributes["tenant_id"],
        addressing_style="path",
    )
    ref = store.evidence_ref_for(attributes["object_id"])
    assert ref == golden["ref"]
    client.objects[(backend["bucket"], golden["descriptor_key"])] = golden[
        "descriptor_json"
    ].encode("utf-8")
    descriptor = store.read_descriptor(ref)
    assert client.gets == [golden["descriptor_key"]]
    expected = {k: v for k, v in attributes.items() if k != "event_class"}
    assert descriptor == {**expected, "encoding": "binary", "ref": golden["ref"]}
    with pytest.raises(_ClientError):
        store.read(ref)
    assert client.gets[-1] == golden["object_key"]


def _node_capture(tmp_path: Path) -> Capture:
    """A capture whose bodies sit in the fake bucket exactly as the Node writes them."""
    capture = Capture(tmp_path)
    capture.store = S3ContentStore(  # type: ignore[assignment]
        bucket=BUCKET, prefix=PREFIX, tenant_id=TENANT, endpoint_url=ENDPOINT
    )
    react_run(capture)
    return capture


def test_reconstruct_reads_node_content_through_an_s3_compatible_endpoint(
    fake_s3: tuple[_FakeS3, list[dict[str, Any]]],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client, calls = fake_s3
    capture = _node_capture(tmp_path)
    # Node layout: <prefix><tenant>/evidence/<id> and .../evidence/meta/<id>.json,
    # descriptor = sorted-key JSON + "\n" (spec 043 §4).
    keys = sorted(key for _, key in client.objects)
    assert keys and all(key.startswith(f"{PREFIX}{TENANT}/evidence/") for key in keys)
    for (_, key), data in client.objects.items():
        if "/meta/" in key:
            document = json.loads(data)
            assert data.decode() == json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n"
    calls.clear()
    out = tmp_path / "report.json"
    argv = [
        "--spans",
        str(capture.write()),
        "--store-uri",
        f"s3://{BUCKET}/{PREFIX}",
        "--tenant",
        TENANT,
        "--s3-endpoint-url",
        ENDPOINT,
        "--s3-region",
        "us-east-1",
        "--s3-path-style",
        "--out",
        str(out),
    ]
    assert main(argv) == 0, capsys.readouterr().err
    document = json.loads(out.read_text())
    validate(document)
    assert document["inputs"]["store"] == {"kind": "s3", "tenant_id": TENANT}
    run = only_run(document)
    assert run["verdict"] == "complete_for_declared_scope"
    assert {obj["verification"] for e in run["exchanges"] for obj in e["objects"].values()} == {
        "verified"
    }
    (kwargs,) = calls
    assert kwargs["endpoint_url"] == ENDPOINT
    assert kwargs["region_name"] == "us-east-1"
    assert kwargs["config"].kwargs == {"s3": {"addressing_style": "path"}}
    text = out.read_text()
    assert ENDPOINT not in text
    assert BUCKET not in text


def test_reconstruct_detects_a_deleted_node_object(
    fake_s3: tuple[_FakeS3, list[dict[str, Any]]], tmp_path: Path
) -> None:
    client, _ = fake_s3
    capture = _node_capture(tmp_path)
    victim = next(key for _, key in client.objects if "/meta/" not in key)
    del client.objects[(BUCKET, victim)]
    out = tmp_path / "report.json"
    argv = ["--spans", str(capture.write()), "--store-uri", f"s3://{BUCKET}/{PREFIX}"]
    argv += ["--tenant", TENANT, "--s3-endpoint-url", ENDPOINT, "--s3-path-style"]
    assert main([*argv, "--out", str(out)]) == 1
    run = only_run(json.loads(out.read_text()))
    assert run["verdict"] == "partial"
    assert [(g["gap_type"], g["reason"]) for g in run["gaps"] if g["effect"] == "partial"] == [
        ("missing_object", "absent")
    ]


def test_store_reader_reports_the_s3_kind(fake_s3: tuple[_FakeS3, list[dict[str, Any]]]) -> None:
    store = S3ContentStore(bucket=BUCKET, prefix=PREFIX, tenant_id=TENANT, addressing_style="path")
    assert StoreReader(store, TENANT).kind == "s3"


# --------------------------------------------------------------------------
# CLI usage errors
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        ["--s3-endpoint-url", ENDPOINT],
        ["--s3-region", "eu-west-1"],
        ["--s3-path-style"],
        ["--store-root", "STORE", "--tenant", TENANT, "--s3-path-style"],
    ],
)
def test_s3_options_need_store_uri(
    tmp_path: Path, extra: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    extra = [str(tmp_path / "store") if item == "STORE" else item for item in extra]
    assert main(["--spans", str(capture.write()), *extra]) == 2
    assert "--store-uri" in capsys.readouterr().err


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://AKIASECRET:sk-SECRET@minio:9000",
        "http://minio:9000/?X-Amz-Credential=SECRET",
        "http://minio:9000/#SECRET",
        "ftp://minio-SECRET:9000",
        "minio-SECRET:9000",
        "http://:9000/SECRET",
        "http://minio:SECRET/",
    ],
)
def test_bad_endpoint_urls_exit_two_without_echo(
    fake_s3: tuple[_FakeS3, list[dict[str, Any]]],
    tmp_path: Path,
    endpoint: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    capture = Capture(tmp_path)
    react_run(capture)
    argv = ["--spans", str(capture.write()), "--store-uri", f"s3://{BUCKET}/{PREFIX}"]
    argv += ["--tenant", TENANT, "--s3-endpoint-url", endpoint]
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert "SECRET" not in captured.err + captured.out
    assert fake_s3[1] == []  # no client was ever built
