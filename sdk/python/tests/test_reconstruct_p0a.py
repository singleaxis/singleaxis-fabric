# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The verifier's side of spec 049 P0-A: protected descriptors, the request digest rule
(§2.4 rule 8) and keyed ``p-`` provider ids (§2.9 rule 4)."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct import reconstruct
from fabric.reconstruct._inputs import pseudonym
from fabric.reconstruct._objects import descriptor_contract_ok
from fabric.reconstruct._stitch import extract_stitch_keys

from .test_wire_helpers import OPENAI_CHAT, make_rig, production_policy

KEY = b"fabric-test-id-key-not-a-secret"
VECTORS = json.loads(
    (Path(__file__).resolve().parents[3]
     / "contracts/coverage/v1/fixtures/vectors/pseudonym-v2.json").read_text()
)  # fmt: skip
STORED = "sha256:" + "a" * 64
BASE: dict[str, Any] = {
    "schema_version": "fabric.content-object/v2", "object_id": "o-1", "tenant_id": "t",
    "role": "model.exchange.request", "media_type": "application/json",
    "content_encoding": "identity", "provenance": "protocol", "boundary": "provider_bound",
    "source_id": "s-1", "source_epoch": 1, "source_sequence": 0, "run_id": "r-1",
    "operation_id": "x-1", "captured_at": "2026-10-19T09:00:00Z", "encoding": "binary",
    "ref": "file:///s/o-1", "stored_byte_length": 10, "stored_sha256": STORED,
}  # fmt: skip
POLICY = {"policy_id": "p", "policy_version": 1, "policy_digest": "sha256:" + "b" * 64}


def _d(**fields: Any) -> dict[str, Any]:
    return {k: v for k, v in {**BASE, **fields}.items() if v is not None}


@pytest.mark.parametrize(("descriptor", "ok"), [
    (_d(representation="exact", transformations=[], status="stored", source_byte_length=10,
        source_sha256=STORED), True),
    (_d(representation="exact", transformations=[], status="stored", source_byte_length=10,
        source_sha256=STORED, privacy_mode="retain_original", protection_status="retained",
        **POLICY), True),
    (_d(representation="split", transformations=["extract_parts"], status="stored",
        source_byte_length=99, source_sha256="sha256:" + "c" * 64,
        privacy_mode="retain_original", protection_status="retained", **POLICY), True),
    (_d(representation="redacted", transformations=["redact"], status="redacted",
        privacy_mode="redact", protection_status="redacted", transformation_id="t",
        transformation_version="1", **POLICY), True),
    (_d(representation="redacted", transformations=["extract_parts", "redact"],
        status="redacted", privacy_mode="masked_only", protection_status="redacted",
        **POLICY), True),
    (_d(representation="tokenized", transformations=["tokenize"], status="redacted",
        privacy_mode="tokenize", protection_status="tokenized", **POLICY), True),
    # a redacted object never carries the original's digest or length
    (_d(representation="redacted", transformations=["redact"], status="redacted",
        source_sha256=STORED, privacy_mode="redact", protection_status="redacted",
        **POLICY), False),
    # half a policy block, or a mode that disagrees with the representation
    (_d(representation="exact", transformations=[], status="stored", source_byte_length=10,
        source_sha256=STORED, privacy_mode="retain_original"), False),
    (_d(representation="redacted", transformations=["redact"], status="redacted",
        privacy_mode="retain_original", protection_status="retained", **POLICY), False),
    # a review copy is never the object a span names
    (_d(representation="redacted", transformations=["redact"], status="redacted",
        privacy_mode="original_plus_masked", protection_status="redacted",
        links=[{"relation": "derived_from", "object_id": "o-0"}], **POLICY), False),
    (_d(representation="split", transformations=["extract_parts"], status="stored",
        source_byte_length=5, source_sha256=STORED), False),
    (_d(representation="exact", transformations=[], status="stored",
        transformation_id="t", transformation_version="1", source_byte_length=10,
        source_sha256=STORED), False),
])  # fmt: skip
def test_descriptor_contract_admits_protected_objects(descriptor: dict[str, Any], ok: bool) -> None:
    assert descriptor_contract_ok(descriptor) is ok


def test_provider_ids_are_keyed_with_the_key_and_legacy_without() -> None:
    case = next(c for c in VECTORS["cases"] if c["name"] == "p- (provider)")
    legacy = next(c for c in VECTORS["cases"] if c["function"] == "legacy_provider")
    assert pseudonym(case["value"], case["key"].encode()) == case["pseudonym"]
    assert pseudonym(legacy["value"]) == legacy["pseudonym"]
    reply = json.dumps({"id": case["value"], "model": "m", "choices": []}).encode()
    keys = [
        extract_stitch_keys("openai.chat_completions", b'{"messages":[]}', "application/json",
                            None, False, reply, "application/json", None, False, id_key=key)
        for key in (case["key"].encode(), None)
    ]  # fmt: skip
    assert [k.response_id for k in keys] == [case["pseudonym"], legacy["pseudonym"]]


def test_redacted_capture_verifies_and_the_report_uses_keyed_ids(tmp_path: Path) -> None:
    """A redacted exchange verifies against the stored (redacted) objects' digests, and
    a keyed verifier reports the provider id in its keyed form."""
    from fabric.deployment_policy import DeploymentPolicy  # noqa: PLC0415
    from fabric.wire import Transformation  # noqa: PLC0415

    privacy = {"model.exchange.request": "redact", "model.exchange.response": "redact"}
    redact = Transformation("acme", "1", lambda data: data.replace(b"Lisbon", b"[city]"))
    rig = make_rig(
        tmp_path, tenant_id="tenant-a",
        capture_policy=DeploymentPolicy(production_policy(privacy=privacy, profile="local")),
        transformations=dict.fromkeys(privacy, redact),
    )  # fmt: skip
    reply = {"id": "chatcmpl-9AbCdEfGhIjKlMn", "model": "gpt-4o", "choices": []}
    try:
        with rig.client(lambda r: __import__("httpx").Response(200, json=reply)) as client:
            client.post(OPENAI_CHAT, json={"messages": [{"role": "user", "content": "Lisbon"}]})
        rig.flush()
        (span,) = rig.spans()
        attrs = dict(span.attributes or {})
        stored = rig.read_ref(attrs["fabric.content.request_ref"])
        assert b"Lisbon" not in stored
        assert hashlib.sha256(stored).hexdigest() == attrs["fabric.wire.request_sha256"]
        rows = tmp_path / "spans.jsonl"
        rows.write_text(json.dumps({
            "kind": "span", "name": span.name, "trace_id": f"{span.context.trace_id:032x}",
            "span_id": f"{span.context.span_id:016x}", "start_ns": span.start_time,
            "end_ns": span.end_time, "attributes": attrs,
            "resource": dict(span.resource.attributes),
        }) + "\n")  # fmt: skip
        report = reconstruct([rows], store=rig.store, id_key=KEY)
        (run,) = report["runs"]
        (exchange,) = run["exchanges"]
        objects = exchange["objects"]
        assert objects["request"]["verification"] == "verified"
        assert objects["response"]["verification"] == "verified"
        assert exchange["response_id"] == pseudonym("chatcmpl-9AbCdEfGhIjKlMn", KEY)
        assert "Lisbon" not in json.dumps(report)
    finally:
        rig.close()


# --- the Node directory envelope (049 §7.8) and the receiver-owned stamp (§7.9) ---------

NODE_KEY_B64 = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo="
NODE_VECTORS = [  # contracts/content/v2/fixtures/node-envelope-v1.json (contract owner)
    ("tenant-a/evidence/0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01",
     "eyJtb2RlbCI6ImdwdC00byIsIm1lc3NhZ2VzIjpbeyJyb2xlIjoidXNlciIsImNvbnRlbnQiOiJoaSJ9XX0=",
     "RkFCUklDLU5PREUtQ09OVEVOVC0xCgABAgMEBQYHCAkKCzaDQApaptLuNBaqns4KYWeoZ/UWOJ8Ac5tJyYo+e7w4"
     "TVMYBv9pcFuWPN5F3gwcymCDNbAjdxvipPcu1l6HrGySg5AoFjv95QyId3HvOA=="),
    ("tenant-a/evidence/meta/0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01.json",
     "eyJvYmplY3RfaWQiOiAiMGI4ZTFjNTItMWYwYS00ZDdlLThmM2ItNWM5YTJlN2QxYTAxIiwgInRlbmFudF9pZCI6"
     "ICJ0ZW5hbnQtYSJ9Cg==",
     "RkFCUklDLU5PREUtQ09OVEVOVC0xCgwNDg8QERITFBUWFyFKW/OKehFYnwqgQmAO6clEfC/WqiLot1XKMuwCnnwG"
     "ypJr99yb2Ru4ohChtn+XwdJUMld8eSmAil7vvteX26f7gsTn/L5kiVESDzge0pDioDhU82O9r51NAPMsGUj6"),
]  # fmt: skip
NODE_FIXTURE = (Path(__file__).resolve().parents[3]
                / "contracts/content/v2/fixtures/node-envelope-v1.json")  # fmt: skip


def _node_cases() -> list[tuple[str, bytes, bytes | None]]:
    import base64  # noqa: PLC0415

    if NODE_FIXTURE.exists():
        cases = json.loads(NODE_FIXTURE.read_text())["cases"]
        return [(c["path"], base64.b64decode(c["envelope_base64"]),
                 base64.b64decode(c["plaintext_base64"]) if c["valid"] else None)
                for c in cases]  # fmt: skip
    return [(path, base64.b64decode(env), base64.b64decode(plain))
            for path, plain, env in NODE_VECTORS]  # fmt: skip


@pytest.mark.parametrize("case", _node_cases(), ids=lambda c: c[0][-12:])
def test_node_envelope_vectors_open_or_fail_closed(
    tmp_path: Path, case: tuple[str, bytes, bytes | None]
) -> None:
    import base64  # noqa: PLC0415

    from fabric.content_store.base import CorruptedObjectError  # noqa: PLC0415
    from fabric.content_store.local import (  # noqa: PLC0415
        LocalFilesystemContentStore,
        open_node_envelope,
    )

    relative, sealed, plain = case
    key = base64.b64decode(NODE_KEY_B64)
    if plain is None:
        with pytest.raises(CorruptedObjectError):
            open_node_envelope(sealed, relative, key)
        return
    assert open_node_envelope(sealed, relative, key) == plain
    with pytest.raises(CorruptedObjectError):  # without the key: refused, never returned
        open_node_envelope(sealed, relative, None)
    with pytest.raises(CorruptedObjectError):  # with the key, plaintext is refused
        open_node_envelope(plain, relative, key)
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(sealed)
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a",
                                        envelope_key=key)  # fmt: skip
    if "/meta/" in relative:
        object_path = tmp_path / relative.replace("meta/", "").removesuffix(".json")
        assert store.read_descriptor(object_path.as_uri()) == json.loads(plain)
    else:
        assert store.read(path.as_uri()) == plain
    assert repr(key) not in repr(store)


def test_source_authenticated_is_admitted_only_as_true() -> None:
    good = _d(representation="exact", transformations=[], status="stored",
              source_byte_length=10, source_sha256=STORED)  # fmt: skip
    assert descriptor_contract_ok({**good, "source_authenticated": True})
    assert not descriptor_contract_ok({**good, "source_authenticated": False})
    assert not descriptor_contract_ok({**good, "source_authenticated": "true"})


def test_cli_content_key_file_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from fabric.reconstruct.__main__ import main  # noqa: PLC0415

    spans = tmp_path / "s.jsonl"
    spans.write_text("")
    (tmp_path / "bad.key").write_bytes(b"short-secret")
    code = main(["--spans", str(spans), "--store-root", str(tmp_path), "--tenant", "t",
                 "--content-key-file", str(tmp_path / "bad.key")])  # fmt: skip
    assert code != 0
    err = capsys.readouterr().err
    assert "content-key-file" in err and "short-secret" not in err


# --- source authentication on trusted readback (049 §7.9, decision 20) and split
# reassembly (§7.5) ----------------------------------------------------------------

STAMP = "fabric.source.authenticated"


def _rows(rig: Any, path: Path, *, stamp: Any = None, skip: str | None = None) -> Path:
    """Every span the rig exported, as sink JSONL rows; ``stamp`` (when not ``None``) is
    written as the Node's source stamp on every row except those named ``skip``."""
    rows = []
    for span in rig.exporter.get_finished_spans():
        attrs = dict(span.attributes or {})
        if stamp is not None and span.name != skip:
            attrs[STAMP] = stamp
        rows.append(json.dumps({
            "kind": "span", "name": span.name, "trace_id": f"{span.context.trace_id:032x}",
            "span_id": f"{span.context.span_id:016x}", "start_ns": span.start_time,
            "end_ns": span.end_time, "attributes": attrs,
            "resource": dict(span.resource.attributes),
        }))  # fmt: skip
    path.write_text("\n".join(rows) + "\n")
    return path


def _stamp_descriptors(store: Any) -> None:
    """What the Node's fabriccontent exporter persists at a bound ingress."""
    meta = Path(store.root) / store.tenant_id / "evidence" / "meta"
    for path in meta.glob("*.json"):
        path.write_text(json.dumps({**json.loads(path.read_text()), "source_authenticated": True}))


def _captured(tmp_path: Path, **config: Any) -> Any:
    rig = make_rig(tmp_path, tenant_id="tenant-a", **config)
    reply = {"id": "chatcmpl-1", "model": "gpt-4o", "choices": []}
    with rig.client(lambda r: __import__("httpx").Response(200, json=reply)) as client:
        client.post(
            OPENAI_CHAT, json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}
        )
    rig.flush()
    assert rig.loss.flush(5.0)
    return rig


def _auth_gaps(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [g for run in report["runs"] for g in run["gaps"]
            if g["gap_type"] == "source_unauthenticated"]  # fmt: skip


def _valid(report: dict[str, Any]) -> None:
    from .test_wire_helpers import capture_schemas, load_validator  # noqa: PLC0415

    load_validator().validate_document(report, capture_schemas())


def test_local_profile_ignores_the_stamp_and_records_the_origin(tmp_path: Path) -> None:
    rig = _captured(tmp_path)
    try:
        report = reconstruct([_rows(rig, tmp_path / "s.jsonl")], store=rig.store)
        assert report["inputs"]["telemetry_origin"] == "imported"
        assert report["inputs"]["profile"] == "local"
        assert _auth_gaps(report) == []
        _valid(report)
        trusted = reconstruct([tmp_path / "s.jsonl"], store=rig.store, trusted_source=True)
        assert trusted["inputs"]["telemetry_origin"] == "trusted_readback"
        assert trusted["runs"][0]["verdict"] == report["runs"][0]["verdict"]
    finally:
        rig.close()


def test_production_imported_spans_are_unverified_whatever_they_carry(tmp_path: Path) -> None:
    rig = _captured(tmp_path)
    try:
        _stamp_descriptors(rig.store)
        spans = _rows(rig, tmp_path / "s.jsonl", stamp=True)
        for profile in ("production", None):  # None: the stamp says a bound Node (production)
            report = reconstruct([spans], store=rig.store, profile=profile)
            assert report["inputs"]["profile"] == "production"
            (gap,) = _auth_gaps(report)
            assert gap["effect"] == "unverified" and gap["reason"] == "imported_telemetry"
            assert report["runs"][0]["verdict"] == "unverified"
            _valid(report)
    finally:
        rig.close()


def test_production_trusted_readback_counts_only_stamped_records(tmp_path: Path) -> None:
    rig = _captured(tmp_path)
    try:
        stamped = _rows(rig, tmp_path / "stamped.jsonl", stamp=True)
        # The telemetry is stamped and trusted, the stored objects are not.
        report = reconstruct([stamped], store=rig.store, profile="production",
                             trusted_source=True)  # fmt: skip
        assert {(g.get("object_role"), g["reason"]) for g in _auth_gaps(report)} == {
            ("request", "unstamped_object"), ("response", "unstamped_object")}  # fmt: skip
        assert report["runs"][0]["verdict"] == "unverified"
        _valid(report)
        _stamp_descriptors(rig.store)
        clean = reconstruct([stamped], store=rig.store, profile="production",
                            trusted_source=True)  # fmt: skip
        local = reconstruct([stamped], store=rig.store, profile="local", trusted_source=True)
        assert _auth_gaps(clean) == []
        assert clean["runs"][0]["verdict"] == local["runs"][0]["verdict"]
        _valid(clean)
        # One unstamped marker, or a forged (non-boolean) stamp, is no authentication.
        for rows in (
            _rows(rig, tmp_path / "marker.jsonl", stamp=True, skip="fabric.capture_heartbeat"),
            _rows(rig, tmp_path / "forged.jsonl", stamp="true"),
        ):
            report = reconstruct([rows], store=rig.store, profile="production",
                                 trusted_source=True)  # fmt: skip
            assert {g["reason"] for g in _auth_gaps(report)} == {"unstamped_record"}
            assert report["runs"][0]["verdict"] == "unverified"
    finally:
        rig.close()


def test_cli_trusted_source_and_profile(tmp_path: Path) -> None:
    from fabric.reconstruct.__main__ import main  # noqa: PLC0415

    rig = _captured(tmp_path)
    try:
        _stamp_descriptors(rig.store)
        spans = _rows(rig, tmp_path / "s.jsonl", stamp=True)
        out = tmp_path / "report.json"
        base = ["--spans", str(spans), "--store-root", str(rig.store.root), "--tenant",
                "tenant-a", "--out", str(out)]  # fmt: skip
        main([*base, "--profile", "production"])
        assert {g["reason"] for g in _auth_gaps(json.loads(out.read_text()))} == {
            "imported_telemetry"}  # fmt: skip
        main([*base, "--profile", "production", "--trusted-source"])
        report = json.loads(out.read_text())
        assert report["inputs"]["telemetry_origin"] == "trusted_readback"
        assert _auth_gaps(report) == []
    finally:
        rig.close()


def _split_capture(tmp_path: Path) -> tuple[Any, Path, dict[str, Any], list[dict[str, Any]]]:
    """One chat request with two inline images, split under retain_original."""
    import base64  # noqa: PLC0415

    image = "data:image/png;base64," + base64.b64encode(bytes(range(256)) * 8).decode()
    content = [{"type": "text", "text": "keep this text"}] + [
        {"type": "image_url", "image_url": {"url": image}} for _ in range(2)]  # fmt: skip
    rig = make_rig(tmp_path, tenant_id="tenant-a", max_body_bytes=4096, part_min_bytes=1024)
    reply = {"id": "chatcmpl-1", "model": "gpt-4o", "choices": []}
    with rig.client(lambda r: __import__("httpx").Response(200, json=reply)) as client:
        client.post(
            OPENAI_CHAT,
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": content}]},
        )
    rig.flush()
    descriptors = rig.descriptors()
    (skeleton,) = [d for d in descriptors if d["representation"] == "split"]
    parts = [d for d in descriptors if d["role"] == "model.exchange.part"]
    assert len(parts) == 2 and all("byte_range" in d["links"][0] for d in parts)
    return rig, _rows(rig, tmp_path / "s.jsonl"), skeleton, parts


def _request_gaps(report: dict[str, Any]) -> set[tuple[str, str]]:
    return {(g["gap_type"], g.get("reason", "")) for g in report["runs"][0]["gaps"]
            if g.get("object_role") == "request"}  # fmt: skip


def test_a_split_request_reassembles_to_its_original_digest(tmp_path: Path) -> None:
    rig, spans, skeleton, _ = _split_capture(tmp_path)
    try:
        report = reconstruct([spans], store=rig.store)
        assert _request_gaps(report) == set()
        (exchange,) = report["runs"][0]["exchanges"]
        assert exchange["objects"]["request"]["verification"] == "verified"
        assert exchange["parse_status"] == "ok"  # parsed from the reassembled original
        assert skeleton["source_byte_length"] > skeleton["stored_byte_length"]
        _valid(report)
    finally:
        rig.close()


def test_split_part_ids_derive_from_the_skeleton(tmp_path: Path) -> None:
    """Spec 049 §7.5: a GetObject-only reader finds every part from the skeleton's id."""
    from fabric._roles import part_object_id  # noqa: PLC0415

    rig, _, skeleton, parts = _split_capture(tmp_path)
    try:
        ordered = sorted(parts, key=lambda d: d["links"][0]["byte_range"][0])
        expected = [part_object_id(skeleton["object_id"], i) for i in range(len(parts))]
        assert [d["object_id"] for d in ordered] == expected
        uuid4 = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
        assert all(re.fullmatch(uuid4, d["object_id"]) for d in ordered)
    finally:
        rig.close()


@pytest.mark.parametrize("fault", ["missing", "corrupt", "shifted", "foreign", "relinked"])
def test_a_split_request_that_does_not_reassemble_is_a_gap(tmp_path: Path, fault: str) -> None:
    rig, spans, _, parts = _split_capture(tmp_path)
    try:
        root = Path(rig.store.root) / "tenant-a" / "evidence"
        part = parts[0]
        meta = root / "meta" / f"{part['object_id']}.json"
        if fault == "missing":
            (root / part["object_id"]).unlink()
            meta.unlink()
        elif fault == "corrupt":
            (root / part["object_id"]).write_bytes(b"A" * part["stored_byte_length"])
        elif fault == "shifted":
            start, end = part["links"][0]["byte_range"]
            part["links"][0]["byte_range"] = [start + 1, end + 1]
            meta.write_text(json.dumps(part))
        elif fault == "foreign":  # a part bound to another exchange
            meta.write_text(json.dumps({**part, "operation_id": "another-exchange"}))
        elif fault == "relinked":  # a part that names another skeleton
            link = {**part["links"][0], "object_id": part["object_id"]}
            meta.write_text(json.dumps({**part, "links": [link]}))
        report = reconstruct([spans], store=rig.store)
        expected = {
            "missing": ("missing_object", "part_missing"),
            "corrupt": ("digest_mismatch", "part_digest"),
            "shifted": ("digest_mismatch", "split_reassembly"),
            "foreign": ("digest_mismatch", "part_binding_mismatch"),
            "relinked": ("digest_mismatch", "part_binding_mismatch"),
        }[fault]
        assert _request_gaps(report) == {expected}
        assert report["runs"][0]["verdict"] == "partial"
        _valid(report)
    finally:
        rig.close()
