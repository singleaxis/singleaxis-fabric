# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The PROTECT stage and typed extraction (spec 049 §7.4, §7.5, §7.7): unit and property
tests of :class:`fabric.wire._protect.Protector`, on bytes alone (no transport)."""

from __future__ import annotations

import base64
import hashlib
import json
import random
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from fabric._roles import ROLES
from fabric.deployment_policy import DeploymentPolicy
from fabric.redaction import RedactionService, Transformation
from fabric.wire._policy import LOCAL_DEFAULT, CapturePolicy
from fabric.wire._protect import (
    Protector,
    SideResult,
    find_parts,
    skeleton_of,
    sniff_media_type,
)

from . import transforms
from .redaction_server import RedactionServer
from .test_wire_helpers import content_validator, production_policy

REPO = Path(__file__).resolve().parents[3]
SPLIT_VECTOR = REPO / "contracts/content/v2/valid/split-reassembly-retain-original.json"
REQUEST = "model.exchange.request"
PART = "model.exchange.part"
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 3)  # 1036 bytes
WAV = base64.b64encode(b"RIFF\x00\x00\x00\x00WAVEfmt " + bytes(1024))  # 1388 bytes
SECRET = b"canary-ssn-078-05-1120"
KEY = b"t" * 32
CONTENT = content_validator()
BASE = {
    "schema_version": "fabric.content-object/v2", "tenant_id": "tenant-a",
    "media_type": "application/json", "content_encoding": "identity", "provenance": "protocol",
    "boundary": "provider_bound", "source_id": "s-" + "a" * 32, "source_epoch": 1,
    "source_sequence": 0, "captured_at": "2026-10-19T09:00:00+00:00",
    "run_id": "r-" + "b" * 32, "operation_id": "0f4c2a7e-9b1d-4e3f-8a6c-5d2e1b0a9f8e",
}  # fmt: skip


def _policy(**modes: str) -> CapturePolicy:
    privacy = {k.replace("_", "."): v for k, v in modes.items()}
    return CapturePolicy.from_deployment(
        DeploymentPolicy(production_policy(privacy=privacy, profile="local"))
    )


REDACT = Transformation("acme-redactor", "3")
_ENDPOINT: list[str] = []


@pytest.fixture(autouse=True)
def _service(redaction_server: RedactionServer) -> None:
    """The customer redaction service of these tests (contracts/redaction/v1)."""
    redaction_server.behaviours |= {"acme-redactor": transforms.redact_secret,
                                    "acme-part-mask": transforms.masked_part}  # fmt: skip
    _ENDPOINT[:] = [redaction_server.endpoint]


def _protector(
    policy: CapturePolicy, *, max_body: int = 1 << 20, timeout_s: float = 5.0,
    max_in_flight: int = 2, **kwargs: Any,
) -> Protector:  # fmt: skip
    if kwargs.get("transformations"):
        kwargs["redaction"] = RedactionService(_ENDPOINT[0], timeout_s=timeout_s,
                                               max_in_flight=max_in_flight)  # fmt: skip
    return Protector(policy, max_body_bytes=max_body, part_min_bytes=64, **kwargs)


def _side(
    protector: Protector, data: bytes, *, role: str = REQUEST, chunks: list[bytes] | None = None,
    cut: str | None = None, partial: bool = False, prefix: int | None = None,
) -> SideResult:  # fmt: skip
    return protector.side(
        BASE, role, chunks or [data], observed=len(data), cut_reason=cut, partial=partial,
        prefix=prefix,
    )  # fmt: skip


def _valid(result: SideResult) -> None:
    for obj in result.objects:
        descriptor = dict(obj.descriptor)
        if obj.stored:
            descriptor |= {"encoding": "binary", "ref": f"file:///s/{descriptor['object_id']}"}
            assert descriptor["stored_sha256"] == "sha256:" + hashlib.sha256(obj.data).hexdigest()
            assert descriptor["stored_byte_length"] == len(obj.data)
        else:
            assert obj.data == b"" and "stored_byte_length" not in descriptor
            assert descriptor["protection_status"] == "withheld"
            assert descriptor["status"] == "not_captured" and descriptor["status_reason"]
        errors = list(CONTENT.iter_errors(descriptor))
        assert not errors, (errors[0].message, descriptor)
        row = ROLES[descriptor["role"]]
        assert row.admits_media(descriptor["media_type"])


def _canary_free(result: SideResult, original: bytes) -> None:
    """No original bytes and no digest of the original anywhere in what is stored."""
    digest = hashlib.sha256(original).hexdigest()
    text = json.dumps([o.descriptor for o in result.objects])
    assert digest not in text
    for obj in result.objects:
        assert SECRET not in obj.data


def _big_request(parts: list[bytes]) -> bytes:
    content: list[Any] = [{"type": "text", "text": "describe " + SECRET.decode()}]
    for part in parts:
        url = "data:image/png;base64," + part.decode()
        content.append({"type": "image_url", "image_url": {"url": url}})
    return json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": content}]},
                      separators=(",", ":")).encode()  # fmt: skip


# --- modes on a whole side ----------------------------------------------------------


def test_retain_original_is_exact_with_the_original_digest() -> None:
    data = b'{"q":"' + SECRET + b'"}'
    result = _side(_protector(LOCAL_DEFAULT), data)
    (obj,) = result.objects
    assert result.primary is obj and obj.data == data and result.reason is None
    d = obj.descriptor
    assert (d["representation"], d["status"], d["transformations"]) == ("exact", "stored", [])
    assert d["source_sha256"] == d["stored_sha256"] == "sha256:" + hashlib.sha256(data).hexdigest()
    assert (d["privacy_mode"], d["protection_status"]) == ("retain_original", "retained")
    assert d["policy_id"] == "fabric.local-default" and d["policy_version"] == 1
    _valid(result)


@pytest.mark.parametrize("mode", ["redact", "masked_only"])
def test_redact_and_masked_only_store_only_the_transformed_copy(mode: str) -> None:
    data = b'{"q":"' + SECRET + b'"}'
    result = _side(_protector(_policy(model_exchange_request=mode),
                              transformations={REQUEST: REDACT}), data)  # fmt: skip
    (obj,) = result.objects
    d = obj.descriptor
    assert obj.data == b'{"q":"[redacted]"}'
    assert (d["representation"], d["status"], d["transformations"]) == (
        "redacted", "redacted", ["redact"])  # fmt: skip
    assert (d["privacy_mode"], d["protection_status"]) == (mode, "redacted")
    assert (d["transformation_id"], d["transformation_version"]) == ("acme-redactor", "3")
    assert "source_sha256" not in d and "source_byte_length" not in d
    _valid(result)
    _canary_free(result, data)


def test_tokenize_is_a_keyed_whole_object_token() -> None:
    data = b'{"q":"' + SECRET + b'"}'
    protector = _protector(_policy(model_exchange_request="tokenize"), tokenization_key=KEY)
    first, second = _side(protector, data), _side(protector, data)
    token = first.objects[0].data
    assert token.startswith(b"fabric.token.v1:") and token == second.objects[0].data
    other = _protector(_policy(model_exchange_request="tokenize"), tokenization_key=b"u" * 32)
    assert _side(other, data).objects[0].data != token  # tenant-scoped by the key
    d = first.objects[0].descriptor
    assert (d["representation"], d["status"], d["protection_status"]) == (
        "tokenized", "redacted", "tokenized")  # fmt: skip
    _valid(first)
    _canary_free(first, data)


def test_metadata_only_keeps_a_length_and_nothing_else() -> None:
    data = b'{"q":"' + SECRET + b'"}'
    result = _side(_protector(_policy(model_exchange_request="metadata_only")), data)
    (obj,) = result.objects
    assert result.primary is None and result.reason == "privacy_policy"
    assert obj.descriptor["source_byte_length"] == len(data)
    assert "source_sha256" not in obj.descriptor
    _valid(result)
    _canary_free(result, data)


def test_omit_and_an_unnamed_role_store_nothing() -> None:
    data = b'{"q":"' + SECRET + b'"}'
    for policy in (
        _policy(model_exchange_request="omit"),
        _policy(model_exchange_response="redact"),
    ):
        result = _side(_protector(policy), data)
        assert result.objects == [] and result.reason == "privacy_policy"


def test_original_plus_masked_links_a_review_copy() -> None:
    data = b'{"q":"' + SECRET + b'"}'
    result = _side(_protector(_policy(model_exchange_request="original_plus_masked"),
                              transformations={REQUEST: REDACT}), data)  # fmt: skip
    original, review = result.objects
    assert result.primary is original and original.data == data
    assert original.descriptor["protection_status"] == "retained"
    assert review.data == b'{"q":"[redacted]"}'
    assert review.descriptor["links"] == [{"relation": "derived_from",
                                           "object_id": original.object_id}]  # fmt: skip
    assert review.descriptor["privacy_mode"] == "original_plus_masked"
    _valid(result)


# --- failure withholds (§7.7 rule 4) --------------------------------------------------


# An error status, a redirect, an oversized answer, no answer, an unknown transformation.
FAILING = [Transformation(name, "1") for name in ("raises", "redirects", "huge", "hang",
                                                   "unknown-transformation")]  # fmt: skip


@pytest.mark.parametrize("transform", [None, *FAILING])
def test_a_failed_transformation_withholds_never_raw(transform: Transformation | None) -> None:
    data = b'{"q":"' + SECRET + b'"}'
    mapping = {REQUEST: transform} if transform is not None else {}
    result = _side(_protector(_policy(model_exchange_request="redact"), max_body=4096,
                              timeout_s=0.2, transformations=mapping), data)  # fmt: skip
    (obj,) = result.objects
    assert result.primary is None and result.reason == "protection_failed"
    assert obj.descriptor["status_reason"] == "protection_failed"
    assert "source_byte_length" not in obj.descriptor
    _valid(result)
    _canary_free(result, data)


@pytest.mark.parametrize("transform", [None, *FAILING])
def test_a_failed_review_copy_withholds_the_original_too(transform: Transformation | None) -> None:
    """Sol P0-A #1: ``original_plus_masked`` admits nothing until both objects exist; a
    failed masked copy withholds the original as well, with no digest and no length."""
    data = b'{"q":"' + SECRET + b'"}'
    mapping = {REQUEST: transform} if transform is not None else {}
    result = _side(_protector(_policy(model_exchange_request="original_plus_masked"),
                              max_body=4096, timeout_s=0.2, transformations=mapping),
                   data)  # fmt: skip
    original, review = result.objects
    assert result.primary is None and result.reason == "protection_failed"
    for obj in (original, review):
        d = obj.descriptor
        assert obj.data == b"" and (d["status"], d["status_reason"]) == (
            "not_captured", "protection_failed")  # fmt: skip
        assert d["protection_status"] == "withheld"
        assert "source_byte_length" not in d and "source_sha256" not in d
    assert review.descriptor["links"] == [{"relation": "derived_from",
                                           "object_id": original.object_id}]  # fmt: skip
    _valid(result)
    _canary_free(result, data)


def test_a_service_that_never_answers_is_abandoned_at_its_timeout() -> None:
    """049 §7.7 rule 4: the timeout bounds every call. A service that never answers is
    abandoned at the timeout (the side is withheld, the worker continues)."""
    protector = _protector(_policy(model_exchange_request="redact"), timeout_s=0.05,
                           transformations={REQUEST: Transformation("hang", "1")})  # fmt: skip
    data = b'{"q":"' + SECRET + b'"}'
    try:
        started = time.monotonic()
        results = [_side(protector, data) for _ in range(3)]
        assert time.monotonic() - started < 3 * (0.05 + 0.5)
        for result in results:
            assert result.primary is None and result.reason == "protection_failed"
            _canary_free(result, data)
        assert protector.stats()["redaction_timeouts"] == 3
    finally:
        assert protector.close()


def test_the_in_flight_bound_is_shared_across_threads() -> None:
    """Sol P0-A round 2 #5: concurrent sides share one bound of in-flight service calls;
    beyond two a side is withheld at once (counted), never queued."""
    protector = _protector(_policy(model_exchange_request="redact"), timeout_s=1.0,
                           transformations={REQUEST: Transformation("hang", "1")})  # fmt: skip
    data, barrier = b'{"q":"' + SECRET + b'"}', threading.Barrier(6)
    results: list[SideResult] = []

    def side() -> None:
        barrier.wait()
        results.append(_side(protector, data))

    threads = [threading.Thread(target=side) for _ in range(6)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30.0)
        assert all(r.reason == "protection_failed" for r in results) and len(results) == 6
        stats = protector.stats()
        assert (stats["redaction_timeouts"], stats["redaction_saturated"]) == (2, 4)
    finally:
        assert protector.close()


def test_tokenize_without_a_key_withholds() -> None:
    result = _side(_protector(_policy(model_exchange_request="tokenize")), b"{}")
    assert result.reason == "protection_failed" and result.primary is None


def test_a_cut_side_is_never_transformed() -> None:
    data = b'{"q":"' + SECRET + b'"}' * 10
    result = _side(_protector(_policy(model_exchange_request="redact"), max_body=16,
                              transformations={REQUEST: REDACT}), data, cut="body_cap",
                   prefix=0)  # fmt: skip
    (obj,) = result.objects
    assert obj.descriptor["status_reason"] == "body_cap" and result.reason == "body_cap"
    _valid(result)


def test_transformation_settings_are_validated() -> None:
    with pytest.raises(ValueError, match="opaque"):
        Transformation("bad id", "1")
    docs = "redaction service.*docs/wire-capture-deployment.md#redaction-service"
    with pytest.raises(ValueError, match=docs):  # a module reference: removed
        Transformation("x", "1", "tests.transforms:redact_secret")
    with pytest.raises(ValueError, match=docs):  # a callable: never run by Fabric
        Transformation(lambda data: data, "1")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="timeout_s"):  # RedactionService.timeout_s now
        Transformation("x", "1", timeout_s=1.0)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match=docs):
        _protector(_policy(model_exchange_request="redact"),
                   transformations={REQUEST: "tests.transforms:redact_secret"})  # fmt: skip
    with pytest.raises(TypeError, match="transform_env_allowlist"):  # deleted setting
        Protector(_policy(model_exchange_request="redact"), max_body_bytes=64,
                  transform_env_allowlist=("HOME",))  # type: ignore[call-arg]  # fmt: skip
    with pytest.raises(ValueError, match="FABRIC_REDACTION_ENDPOINT"):
        Protector(_policy(model_exchange_request="redact"), max_body_bytes=64,
                  transformations={REQUEST: REDACT})  # fmt: skip


# --- truncation keeps today's prefix ----------------------------------------------------


def test_a_side_above_max_body_that_cannot_split_is_truncated_to_the_whole_chunk_prefix() -> None:
    chunks = [b"a" * 40, b"b" * 40, b"c" * 40]
    data = b"".join(chunks)
    result = _side(_protector(LOCAL_DEFAULT, max_body=64), data, chunks=chunks, prefix=40)
    (obj,) = result.objects
    assert obj.data == b"a" * 40 and result.truncated and result.reason == "body_cap"
    d = obj.descriptor
    assert (d["representation"], d["transformations"], d["source_byte_length"]) == (
        "truncated", ["truncate"], 120)  # fmt: skip
    assert "source_sha256" not in d
    _valid(result)


# --- typed extraction ------------------------------------------------------------------


def test_find_parts_reproduces_the_contract_split_vector() -> None:
    vector = json.loads(SPLIT_VECTOR.read_text())
    objects = vector["objects"]
    skeleton = base64.b64decode(objects[0]["base64"])
    parts = sorted((o["descriptor"]["links"][0]["byte_range"], base64.b64decode(o["base64"]),
                    o["descriptor"]["media_type"]) for o in objects[1:])  # fmt: skip
    original, pos, consumed = b"", 0, 0
    for (start, end), part, _ in parts:
        take = start - consumed
        original += skeleton[pos : pos + take] + part
        pos, consumed = pos + take, end
    original += skeleton[pos:]
    assert "sha256:" + hashlib.sha256(original).hexdigest() == vector["original"]["sha256"]
    found = find_parts(original, 50)
    assert found is not None
    assert [(p.start, p.end, p.media_type) for p in found] == [
        (start, end, media) for (start, end), _, media in parts
    ]
    assert skeleton_of(original, found) == skeleton


def test_split_side_retains_parts_with_half_open_ranges() -> None:
    data = _big_request([PNG, WAV])
    protector = _protector(LOCAL_DEFAULT, max_body=1500)
    result = _side(protector, data)
    skeleton, *parts = result.objects
    assert result.primary is skeleton and len(parts) == 2
    d = skeleton.descriptor
    assert (d["representation"], d["transformations"]) == ("split", ["extract_parts"])
    assert d["source_sha256"] == "sha256:" + hashlib.sha256(data).hexdigest()
    assert d["source_byte_length"] == len(data)
    assert [p.descriptor["media_type"] for p in parts] == ["image/png", "audio/wav"]
    for part in parts:
        (link,) = part.descriptor["links"]
        start, end = link["byte_range"]
        assert link["object_id"] == skeleton.object_id and data[start:end] == part.data
        assert part.descriptor["content_encoding"] == "base64"
    assert _reassemble(skeleton.data, parts) == data
    assert SECRET in skeleton.data  # the text survives the large parts
    _valid(result)


def _reassemble(skeleton: bytes, parts: list[Any]) -> bytes:
    out, pos, consumed = b"", 0, 0
    for part in sorted(parts, key=lambda p: p.descriptor["links"][0]["byte_range"]):
        start, end = part.descriptor["links"][0]["byte_range"]
        take = start - consumed
        out += skeleton[pos : pos + take] + part.data
        pos, consumed = pos + take, end
    return out + skeleton[pos:]


def test_a_part_above_max_body_is_descriptor_only_part_cap() -> None:
    huge = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(4096))
    data = _big_request([huge])
    result = _side(_protector(LOCAL_DEFAULT, max_body=2048), data)
    skeleton, part = result.objects
    assert part.descriptor["status_reason"] == "part_cap" and part.data == b""
    start, end = part.descriptor["links"][0]["byte_range"]
    assert end - start == part.descriptor["source_byte_length"] == len(huge)
    assert result.primary is skeleton and result.reason == "part_cap"
    _valid(result)


def test_redacted_split_withholds_binary_parts_and_drops_ranges() -> None:
    data = _big_request([PNG])
    policy = _policy(model_exchange_request="redact", model_exchange_part="redact")
    result = _side(_protector(policy, max_body=1100, transformations={REQUEST: REDACT}), data)
    skeleton, part = result.objects
    assert skeleton.descriptor["transformations"] == ["extract_parts", "redact"]
    assert "source_sha256" not in skeleton.descriptor
    assert part.descriptor["status_reason"] == "privacy_policy"
    assert part.descriptor["links"] == [{"relation": "part_of", "object_id": skeleton.object_id}]
    _valid(result)
    _canary_free(result, data)


def _node_rules(result: SideResult) -> None:
    """The Node's closed descriptor rules (mirrored by the capture validator)."""
    from .test_wire_helpers import load_validator  # noqa: PLC0415

    capture = load_validator()
    for obj in result.objects:
        capture._check_descriptor(dict(obj.descriptor), "part")


def test_original_plus_masked_parts_get_a_masked_review_copy() -> None:
    """Sol P0-A round 2 #1: an extracted part under ``original_plus_masked`` follows the
    whole-side rule: the original part (exact, with its range) plus a masked review copy
    of it, linked ``part_of`` the skeleton and ``derived_from`` the original part."""
    data = _big_request([PNG])
    policy = _policy(model_exchange_request="retain_original",
                     model_exchange_part="original_plus_masked")  # fmt: skip
    mask = Transformation("acme-part-mask", "2")
    result = _side(_protector(policy, max_body=1100, transformations={PART: mask}), data)
    skeleton, part, review = result.objects
    assert result.primary is skeleton and result.reason is None
    (link,) = part.descriptor["links"]
    start, end = link["byte_range"]
    assert part.data == data[start:end] == PNG
    assert (part.descriptor["status"], part.descriptor["protection_status"]) == (
        "stored", "retained")  # fmt: skip
    d = review.descriptor
    assert review.data == b"[masked-part]"
    assert (d["status"], d["protection_status"], d["privacy_mode"]) == (
        "redacted", "redacted", "original_plus_masked")  # fmt: skip
    assert (d["transformation_id"], d["transformation_version"]) == ("acme-part-mask", "2")
    assert d["links"] == [{"relation": "part_of", "object_id": skeleton.object_id},
                          {"relation": "derived_from", "object_id": part.object_id}]  # fmt: skip
    assert "source_sha256" not in d and "source_byte_length" not in d
    _valid(result)
    _node_rules(result)


@pytest.mark.parametrize("transform", [None, *FAILING])
def test_a_failed_part_review_copy_withholds_the_part_too(
    transform: Transformation | None,
) -> None:
    """Sol P0-A round 2 #1: the reproduction (``request=retain_original``,
    ``part=original_plus_masked``, no transformation) stored the unchanged PNG part with
    its digest and range. A part whose masked copy cannot be produced is withheld with
    its copy: ``not_captured(protection_failed)``, no digest, length or range."""
    data = _big_request([PNG])
    policy = _policy(model_exchange_request="retain_original",
                     model_exchange_part="original_plus_masked")  # fmt: skip
    mapping = {PART: transform} if transform is not None else {}
    result = _side(_protector(policy, max_body=1100, timeout_s=0.2, transformations=mapping),
                   data)  # fmt: skip
    skeleton, part, review = result.objects
    assert result.primary is skeleton and result.reason == "protection_failed"
    for obj in (part, review):
        d = obj.descriptor
        assert obj.data == b"" and (d["status"], d["status_reason"]) == (
            "not_captured", "protection_failed")  # fmt: skip
        assert d["protection_status"] == "withheld"
        assert "source_byte_length" not in d and "source_sha256" not in d
    assert part.descriptor["links"] == [{"relation": "part_of", "object_id": skeleton.object_id}]
    assert review.descriptor["links"][-1] == {"relation": "derived_from",
                                              "object_id": part.object_id}  # fmt: skip
    assert PNG not in skeleton.data
    text = json.dumps([o.descriptor for o in result.objects])
    assert hashlib.sha256(PNG).hexdigest() not in text
    _valid(result)
    _node_rules(result)


def test_tokenized_split_tokenizes_each_object() -> None:
    data = _big_request([PNG])
    policy = _policy(model_exchange_request="tokenize", model_exchange_part="tokenize")
    result = _side(_protector(policy, max_body=1100, tokenization_key=KEY), data)
    skeleton, part = result.objects
    assert skeleton.descriptor["transformations"] == ["extract_parts", "tokenize"]
    assert part.descriptor["transformations"] == ["tokenize"]
    assert "byte_range" not in part.descriptor["links"][0]
    _valid(result)
    _canary_free(result, data)


def test_an_unnamed_part_role_is_omitted_while_the_skeleton_follows_its_role() -> None:
    data = _big_request([PNG])
    result = _side(_protector(_policy(model_exchange_request="retain_original"),
                              max_body=1100), data)  # fmt: skip
    (skeleton,) = result.objects
    assert skeleton.descriptor["representation"] == "split" and result.reason is None


def test_non_json_partial_or_encoded_sides_are_not_split() -> None:
    data = _big_request([PNG])
    protector = _protector(LOCAL_DEFAULT, max_body=1100)
    for base in ({**BASE, "media_type": "text/event-stream"},
                 {**BASE, "content_encoding": "gzip"}):  # fmt: skip
        result = protector.side(base, REQUEST, [data], observed=len(data), cut_reason=None,
                                partial=False, prefix=1000)  # fmt: skip
        assert result.objects[0].descriptor["representation"] == "truncated"
    partial = _side(protector, data, role="model.exchange.response", partial=True, prefix=1000)
    assert partial.objects[0].descriptor["representation"] == "truncated"


def test_find_parts_ignores_other_keys_escapes_and_non_json() -> None:
    blob = PNG.decode()
    assert find_parts(b"not json", 8) is None
    assert find_parts(b'{"a":"unterminated', 8) is None
    assert find_parts(json.dumps({"embedding": blob}).encode(), 64) == []
    assert find_parts(json.dumps({"data": "has spaces " * 20}).encode(), 64) == []
    escaped = json.dumps({"text": 'say \\"' + blob + '\\"', "data": blob}).encode()
    (part,) = find_parts(escaped, 64) or []
    assert escaped[part.start : part.end] == PNG
    assert sniff_media_type(base64.b64encode(b"%PDF-1.7 xxxxxxxx")) == "application/pdf"
    assert sniff_media_type(b"AAAA", "image/svg+xml") == "image/svg+xml"
    assert sniff_media_type(b"AAAA", "text/html") == "application/octet-stream"
    assert sniff_media_type(b"!!", None) == "application/octet-stream"


@pytest.mark.parametrize("seed", range(40))
def test_property_retained_splits_reassemble_and_protected_splits_never_leak(seed: int) -> None:
    """Random requests with random inline parts: retain_original always reassembles to
    the original; every protecting mode stores no original bytes and no original digest."""
    rng = random.Random(seed)  # noqa: S311 - reproducible test data
    parts = [base64.b64encode(rng.randbytes(rng.randint(48, 900)))
             for _ in range(rng.randint(1, 5))]  # fmt: skip
    data = _big_request(parts)
    max_body = rng.randint(len(data) - sum(map(len, parts)) + 8, len(data) - 1)
    kept = _side(_protector(LOCAL_DEFAULT, max_body=max_body), data)
    stored = [o for o in kept.objects[1:] if o.stored]
    if len(stored) == len(kept.objects) - 1:
        assert _reassemble(kept.objects[0].data, stored) == data
    _valid(kept)
    mode = rng.choice(["redact", "masked_only", "tokenize", "metadata_only"])
    policy = _policy(model_exchange_request=mode, model_exchange_part=mode)
    protected = _side(_protector(policy, max_body=max_body, tokenization_key=KEY,
                                 transformations={REQUEST: REDACT}), data)  # fmt: skip
    _valid(protected)
    _canary_free(protected, data)
    for obj in protected.objects:
        assert not any(part in obj.data for part in parts)
        assert all("byte_range" not in link for link in obj.descriptor.get("links", []))


def test_the_node_contract_admits_these_descriptors() -> None:
    """The capture/v1 spool descriptor $defs admit every object the PROTECT stage builds."""
    schema = json.loads((REPO / "contracts/capture/v1/schema/spool-record-v1.schema.json")
                        .read_text())  # fmt: skip
    descriptor = Draft202012Validator({**schema["$defs"]["descriptor"],
                                       "$defs": schema["$defs"]})  # fmt: skip
    data = _big_request([PNG])
    for policy in (LOCAL_DEFAULT, _policy(model_exchange_request="redact",
                                          model_exchange_part="metadata_only")):  # fmt: skip
        result = _side(_protector(policy, max_body=1100, transformations={REQUEST: REDACT}),
                       data)  # fmt: skip
        for obj in result.objects:
            errors = list(descriptor.iter_errors(obj.descriptor))
            assert not errors, errors[0].message


@pytest.mark.parametrize("mode", ["redact", "masked_only"])
def test_a_privacy_withheld_binary_part_passes_the_node_rules(mode: str) -> None:
    """Sol P0-A #7: a binary part no part transformation applies to is withheld as
    ``not_captured(privacy_policy)`` under ``redact``/``masked_only`` (§7.5). The Node's
    descriptor rules (mirrored by the capture validator) and the content-v2 evidence
    validator accept it, so the withholding record survives delivery; on any other role
    that combination is still refused."""
    import importlib.util  # noqa: PLC0415
    import sys  # noqa: PLC0415

    from .test_wire_helpers import load_validator  # noqa: PLC0415

    path = REPO / "scripts/contracts/validate_evidence_contracts.py"
    spec = importlib.util.spec_from_file_location("_evidence_validator", path)
    assert spec is not None and spec.loader is not None
    evidence = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_evidence_validator", evidence)
    spec.loader.exec_module(evidence)
    capture = load_validator()
    policy = _policy(model_exchange_request=mode, model_exchange_part=mode)
    result = _side(_protector(policy, max_body=1100, transformations={REQUEST: REDACT}),
                   _big_request([PNG]))  # fmt: skip
    (part,) = [o for o in result.objects if o.descriptor["role"] == "model.exchange.part"]
    d = dict(part.descriptor)
    assert (d["status"], d["status_reason"], d["privacy_mode"]) == (
        "not_captured", "privacy_policy", mode)  # fmt: skip
    capture._check_descriptor(d, "part")  # the Node's closed rules, mirrored
    evidence._validate_content_protection(d)
    other = {**d, "role": REQUEST, "media_type": "application/json",
             "content_encoding": "identity"}  # fmt: skip
    other.pop("links")
    with pytest.raises(capture.CaptureContractError):
        capture._check_descriptor(other, "request")
    with pytest.raises(evidence.EvidenceContractError):
        evidence._validate_content_protection(other)
