# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Privacy policy parity, failure safety and real byte-recorder routing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from fabric.byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder, BytePrivacyPolicy
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.deployment_policy import ContentProtector, DeploymentPolicy

ROOT = Path(__file__).resolve().parents[3]
SECRET = b"sensitive-value"
GOLDEN_DIGEST = "sha256:777dda0c14d100c2c6728b2e3858f53c55cd62fdf3c1c3ced5decee0a5f36ea6"
GOLDEN_TOKEN = b"fabric.token.v1:a603512146debdb7ec03d124e146fbd4ae088f64c32642b950877829a632a31d"


def policy_data() -> dict[str, Any]:
    return json.loads((ROOT / "examples/enterprise/policy.local.json").read_text())  # type: ignore[no-any-return]


def policy_for(mode: str) -> DeploymentPolicy:
    data = policy_data()
    data["privacy"] = {"terminal.stdout": mode}
    return DeploymentPolicy.from_dict(data)


def test_policy_golden_digest_schema_and_snapshot() -> None:
    data = policy_data()
    policy = DeploymentPolicy.from_dict(data)
    assert policy.digest == GOLDEN_DIGEST
    schema = json.loads(
        (
            ROOT / "contracts/deployment-policy/v1/schema/deployment-policy-v1.schema.json"
        ).read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(policy.to_dict())
    assert policy.schema_version == "fabric.deployment-policy/v1"
    assert policy.policy_id == "local-example"
    assert policy.policy_version == 1
    assert policy.tenant_id == "example-tenant"
    assert policy.workload_id == "example-agent"
    assert policy.storage["key_id"] == "local-example-key"
    assert policy.retention["days"] == 7
    assert policy.deployment["profile"] == "local"
    assert policy.required_integrations == ("fabric.call_recorder",)
    data["privacy"]["tool.call.arguments"] = "retain_original"
    copied = policy.to_dict()
    copied["storage"]["key_id"] = "other"
    assert policy.digest == GOLDEN_DIGEST
    assert policy.privacy["tool.call.arguments"] == "omit"
    with pytest.raises(TypeError):
        policy.privacy["tool.call.arguments"] = "retain_original"  # type: ignore[index]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "future"),
        ("policy_id", "secret/path"),
        ("policy_version", True),
        ("policy_version", 0),
        ("policy_version", 2**31),
        ("privacy", {}),
        ("privacy", {"terminal.stdout": "original"}),
        ("privacy", {"invalid role": "omit"}),
        ("required_integrations", ["http", "http"]),
        ("required_integrations", "http"),
        ("storage", {"backend": "cloud", "region": "local", "key_id": "key"}),
        ("storage", {"backend": "local", "region": "local", "key_id": "key", "secret": "secret"}),
        ("storage", {"backend": "local", "region": "local", "key_id": "key", "root": "\n"}),
        ("retention", {"days": 0}),
        ("retention", {"days": 36501}),
    ],
)
def test_reject_invalid_policy(field: str, value: Any) -> None:
    data = policy_data()
    data[field] = value
    with pytest.raises(ValueError):
        DeploymentPolicy(data)


def test_no_unknown_fields_and_production_requires_security_declarations() -> None:
    data = policy_data()
    data["secret"] = "never-print-me"  # noqa: S105 - rejection fixture
    with pytest.raises(ValueError, match="unknown") as exc:
        DeploymentPolicy(data)
    assert "never-print-me" not in str(exc.value)
    data = policy_data()
    data["deployment"]["profile"] = "production"
    with pytest.raises(ValueError, match="production"):
        DeploymentPolicy(data)
    data["deployment"].update(
        image_digest="sha256:" + "a" * 64, tls_required=True, encrypted_store_required=True
    )
    assert DeploymentPolicy(data).deployment["profile"] == "production"
    data["deployment"]["tls_required"] = 1
    with pytest.raises(ValueError, match="booleans"):
        DeploymentPolicy(data)


def test_integrations_are_normalized() -> None:
    data = policy_data()
    data["required_integrations"] = ["z", "a"]
    policy = DeploymentPolicy(data)
    assert policy.required_integrations == ("a", "z")
    data["required_integrations"].reverse()
    assert policy.digest == DeploymentPolicy(data).digest


@pytest.mark.parametrize("mode", ["omit", "metadata_only"])
def test_withheld_content_does_not_expose_digest_or_bytes(mode: str) -> None:
    protector = ContentProtector(policy_for(mode))
    result = protector.protect("terminal.stdout", SECRET)
    assert result.status == "withheld"
    assert result.original_digest is None
    assert result.protected_bytes is None
    assert ("source_byte_length" in result.metadata) == (mode == "metadata_only")
    assert "sensitive-value" not in json.dumps(result.to_dict())
    assert hashlib.sha256(SECRET).hexdigest() not in json.dumps(result.to_dict())
    unknown = protector.protect("tool.call.result", SECRET)
    assert unknown.mode == "omit"
    assert "source_byte_length" not in unknown.metadata


def test_original_and_redacted_outputs_remain_separate() -> None:
    original = ContentProtector(policy_for("retain_original")).protect("terminal.stdout", SECRET)
    assert original.status == "retained"
    assert original.protected_bytes == SECRET
    assert original.original_digest == "sha256:" + hashlib.sha256(SECRET).hexdigest()
    assert "sensitive-value" not in repr(original)
    redacted = ContentProtector(
        policy_for("redact"), redactors={"terminal.stdout": lambda _: b"[redacted]"}
    ).protect("terminal.stdout", SECRET)
    assert redacted.status == "redacted"
    assert redacted.original_digest is None
    assert redacted.protected_bytes == b"[redacted]"
    assert "source_byte_length" not in redacted.metadata


def test_transforms_require_explicit_implementation_and_key() -> None:
    with pytest.raises(ValueError, match="redactor"):
        ContentProtector(policy_for("redact"))
    with pytest.raises(ValueError, match="caller-supplied key"):
        ContentProtector(policy_for("tokenize"))
    with pytest.raises(ValueError, match="32 bytes"):
        ContentProtector(policy_for("tokenize"), tokenization_key=b"weak")
    with pytest.raises(ValueError, match="explicitly"):
        ContentProtector(policy_for("omit"), redactors={"terminal.stdout": lambda d: d})


def test_token_is_keyed_scoped_irreversible_and_matches_typescript() -> None:
    policy = policy_for("tokenize")
    result = ContentProtector(policy, tokenization_key=b"k" * 32).protect("terminal.stdout", SECRET)
    assert result.status == "tokenized"
    assert result.protected_bytes == GOLDEN_TOKEN
    assert result.original_digest is None
    assert "source_byte_length" not in result.metadata
    for field, value in [
        ("tenant_id", "other-tenant"),
        ("workload_id", "other-workload"),
        ("policy_version", 2),
    ]:
        data = policy.to_dict()
        data[field] = value
        other = ContentProtector(DeploymentPolicy(data), tokenization_key=b"k" * 32)
        assert other.protect("terminal.stdout", SECRET).protected_bytes != GOLDEN_TOKEN
    assert (
        ContentProtector(policy, tokenization_key=b"j" * 32)
        .protect("terminal.stdout", SECRET)
        .protected_bytes
        != GOLDEN_TOKEN
    )


def test_transform_failures_are_safe_explicit_and_bounded() -> None:
    def fail(_: bytes) -> bytes:
        raise RuntimeError("sensitive-value")

    protector = ContentProtector(policy_for("redact"), redactors={"terminal.stdout": fail})
    result = protector.protect("terminal.stdout", SECRET)
    assert result.status == "lost"
    assert result.metadata["reason"] == "protection_failed"
    assert "sensitive-value" not in repr(result)
    assert result.protected_bytes is None
    bad = ContentProtector(policy_for("redact"), redactors={"terminal.stdout": lambda _: "bad"})  # type: ignore[dict-item,return-value]
    assert bad.protect("terminal.stdout", SECRET).status == "unsupported"
    oversized = ContentProtector(
        policy_for("redact"), redactors={"terminal.stdout": lambda _: b"abc"}, payload_max_bytes=2
    )
    assert (
        oversized.protect("terminal.stdout", b"x").metadata["reason"]
        == "protected_payload_too_large"
    )
    assert oversized.protect("terminal.stdout", SECRET).metadata["reason"] == "payload_too_large"
    assert oversized.protect("terminal.stdout", "bad").status == "unsupported"  # type: ignore[arg-type]


@pytest.mark.parametrize("mode", ["retain_original", "omit", "metadata_only", "redact", "tokenize"])
def test_real_recorder_routes_only_protected_bytes(
    tmp_path: Path, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = policy_for(mode)
    store = LocalFilesystemContentStore(str(tmp_path / "original"), tenant_id=policy.tenant_id)
    review = LocalFilesystemContentStore(str(tmp_path / "derivative"), tenant_id=policy.tenant_id)
    protector = ContentProtector(
        policy,
        redactors={"terminal.stdout": lambda _: b"[redacted]"} if mode == "redact" else None,
        tokenization_key=b"k" * 32,
    )
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            review_store=review,
            roles=frozenset({"terminal.stdout"}),
            deployment_policy=policy,
            content_protector=protector,
        )
    )
    queued: list[bytes] = []
    admit = recorder._queue.put_nowait

    def inspect_admission(item: tuple[str, bytes, str | None]) -> None:
        queued.append(item[1])
        admit(item)

    monkeypatch.setattr(recorder._queue, "put_nowait", inspect_admission)
    try:
        initial = recorder.capture(
            SECRET,
            role="terminal.stdout",
            boundary="terminal",
            source_id="sdk",
            source_epoch=0,
            source_sequence=1,
        )
        assert recorder.flush()
        settled = recorder.get(initial["object_id"])
        assert settled is not None
        schema = json.loads(
            (ROOT / "contracts/content/v2/schema/content-object-v2.schema.json").read_text()
        )
        jsonschema.Draft202012Validator(schema).validate(settled)
        assert settled["policy_digest"] == policy.digest
        if mode == "retain_original":
            assert queued == [SECRET]
            assert settled["status"] == "stored"
            assert store.read(settled["ref"]) == SECRET
        elif mode in {"redact", "tokenize"}:
            assert queued == [b"[redacted]" if mode == "redact" else GOLDEN_TOKEN]
            assert settled["status"] == "redacted"
            assert settled["representation"] == ("redacted" if mode == "redact" else "tokenized")
            assert "source_sha256" not in settled
            assert "source_byte_length" not in settled
            assert review.read(settled["ref"]) == (
                b"[redacted]" if mode == "redact" else GOLDEN_TOKEN
            )
        else:
            assert queued == []
            assert settled["status"] == "not_captured"
            assert "ref" not in settled
        if mode != "retain_original":
            for path in tmp_path.rglob("*"):
                if path.is_file():
                    assert SECRET not in path.read_bytes()
                    assert hashlib.sha256(SECRET).hexdigest().encode() not in path.read_bytes()
    finally:
        _assert_result_275 = recorder.close()
        assert _assert_result_275


def test_recorder_rejects_ambiguous_policy_tenant_and_plane(tmp_path: Path) -> None:
    policy = policy_for("redact")
    store = LocalFilesystemContentStore(str(tmp_path), tenant_id=policy.tenant_id)
    protector = ContentProtector(policy, redactors={"terminal.stdout": lambda _: b"safe"})
    with pytest.raises(ValueError, match="same-tenant"):
        ByteEvidenceConfig(
            store=store, roles=frozenset({"terminal.stdout"}), content_protector=protector
        )
    with pytest.raises(ValueError, match="namespaces"):
        ByteEvidenceConfig(
            store=store,
            review_store=store,
            roles=frozenset({"terminal.stdout"}),
            content_protector=protector,
        )
    with pytest.raises(ValueError, match="cannot be combined"):
        ByteEvidenceConfig(
            store=store,
            roles=frozenset({"terminal.stdout"}),
            deployment_policy=policy,
            role_policies={"terminal.stdout": BytePrivacyPolicy()},
        )
    bad = LocalFilesystemContentStore(str(tmp_path / "wrong"), tenant_id="wrong")
    with pytest.raises(ValueError, match="tenant"):
        ByteEvidenceConfig(
            store=bad, roles=frozenset({"terminal.stdout"}), deployment_policy=policy
        )


@pytest.mark.parametrize("reverse", [False, True])
def test_deployment_policy_rejects_overlapping_resolver_planes(
    tmp_path: Path, reverse: bool
) -> None:
    policy = policy_for("redact")
    store = LocalFilesystemContentStore(str(tmp_path / "original"), tenant_id=policy.tenant_id)
    review = LocalFilesystemContentStore(
        str(tmp_path / "original" / policy.tenant_id / "nested"), tenant_id=policy.tenant_id
    )
    if reverse:
        store, review = review, store
    protector = ContentProtector(policy, redactors={"terminal.stdout": lambda _: b"safe"})
    assert store.evidence_ref_for("object") != review.evidence_ref_for("object")
    with pytest.raises(ValueError, match="overlap"):
        ByteEvidenceConfig(
            store=store,
            review_store=review,
            roles=frozenset({"terminal.stdout"}),
            content_protector=protector,
        )
    assert not any(tmp_path.iterdir())


def test_token_output_respects_configured_bound() -> None:
    protector = ContentProtector(
        policy_for("tokenize"), tokenization_key=b"k" * 32, payload_max_bytes=2
    )
    result = protector.protect("terminal.stdout", b"x")
    assert result.status == "lost"
    assert result.metadata["reason"] == "protected_payload_too_large"
    assert result.protected_bytes is None


def test_transform_failure_in_recorder_never_stores_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_: bytes) -> bytes:
        raise RuntimeError("sensitive-value")

    policy = policy_for("redact")
    store = LocalFilesystemContentStore(str(tmp_path / "original"), tenant_id=policy.tenant_id)
    review = LocalFilesystemContentStore(str(tmp_path / "derivative"), tenant_id=policy.tenant_id)
    protector = ContentProtector(policy, redactors={"terminal.stdout": fail})
    recorder = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store,
            review_store=review,
            roles=frozenset({"terminal.stdout"}),
            content_protector=protector,
        )
    )
    monkeypatch.setattr(
        recorder._queue, "put_nowait", lambda _: pytest.fail("failed content entered queue")
    )
    try:
        item = recorder.capture(
            SECRET,
            role="terminal.stdout",
            boundary="terminal",
            source_id="sdk",
            source_epoch=0,
            source_sequence=1,
        )
        assert item["status"] == "failed"
        assert item["protection_status"] == "lost"
        assert item["status_reason"] == "protection_failed"
        assert "source_sha256" not in item
        assert "source_byte_length" not in item
        assert "sensitive-value" not in json.dumps(item)
        assert not any(p.is_file() for p in tmp_path.rglob("*"))
    finally:
        _assert_result_378 = recorder.close()
        assert _assert_result_378


def test_masked_only_stores_only_the_masked_copy_and_original_plus_masked_withholds() -> None:
    """049 §7.5/§7.7: masked_only is a customer-masked copy with no original digest;
    original_plus_masked needs two objects, which the explicit line's protector does not
    make, so it withholds (fails closed) rather than storing the original alone."""
    masked = ContentProtector(
        policy_for("masked_only"), redactors={"terminal.stdout": lambda _: b"[masked]"}
    ).protect("terminal.stdout", SECRET)
    assert (masked.status, masked.mode, masked.protected_bytes) == (
        "redacted", "masked_only", b"[masked]")  # fmt: skip
    assert masked.original_digest is None and "source_byte_length" not in masked.metadata
    with pytest.raises(ValueError, match="redactor"):
        ContentProtector(policy_for("masked_only"))
    both = ContentProtector(policy_for("original_plus_masked")).protect("terminal.stdout", SECRET)
    assert both.status == "unsupported" and both.protected_bytes is None
    assert both.original_digest is None


# --- spec 049 §7.3/§7.7: the production gate on the explicit (records) input ------------


def _production(mode: str = "retain_original") -> DeploymentPolicy:
    from .test_wire_helpers import production_policy  # noqa: PLC0415

    return DeploymentPolicy(production_policy("tenant-a", {"terminal.stdout": mode}))


def _capture(recorder: ByteEvidenceRecorder) -> dict[str, Any]:
    return recorder.capture(
        SECRET, role="terminal.stdout", boundary="terminal", source_id="sdk",
        source_epoch=0, source_sequence=1,
    )  # fmt: skip


class _ProductionStore(LocalFilesystemContentStore):
    """A store whose own policy is marked production (as a governed store's is)."""

    policy = _production()


@pytest.mark.parametrize(
    ("policy", "store_marked", "id_key", "reason"),
    [
        ("production", False, None, "missing_id_key"),
        (None, True, None, "missing_capture_policy"),
        (None, True, b"i" * 16, "missing_capture_policy"),
        ("production", False, b"i" * 16, None),
        ("local", False, None, None),
    ],
)  # fmt: skip
def test_the_explicit_input_has_the_production_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    policy: str | None, store_marked: bool, id_key: bytes | None, reason: str | None,
) -> None:  # fmt: skip
    """Sol P0-A #4: production content capture on the explicit input needs a capture
    policy and the id key, as on the wire (049 §7.3, §7.7 "both inputs"); otherwise
    content is disabled with the reason recorded, and nothing is stored or digested."""
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    deployment = {"production": _production(), "local": None}.get(policy or "")
    if policy == "local":
        data = policy_data()
        data["tenant_id"], data["privacy"] = "tenant-a", {"terminal.stdout": "retain_original"}
        deployment = DeploymentPolicy.from_dict(data)
    kind = _ProductionStore if store_marked else LocalFilesystemContentStore
    store = kind(str(tmp_path / "store"), tenant_id="tenant-a")
    recorder = ByteEvidenceRecorder(ByteEvidenceConfig(
        store=store, roles=frozenset({"terminal.stdout"}), deployment_policy=deployment,
        id_key=id_key,
    ))  # fmt: skip
    try:
        initial = _capture(recorder)
        assert recorder.flush()
        settled = recorder.get(initial["object_id"])
        assert settled is not None
        status = recorder.status()
        expected_profile = "production" if policy == "production" or store_marked else "local"
        assert status["profile"] == expected_profile
        if reason is None:
            assert status["content_capture"] == "enabled"
            assert settled["status"] == "stored" and store.read(settled["ref"]) == SECRET
            return
        assert (status["content_capture"], status["content_capture_reason"]) == (
            "disabled", reason)  # fmt: skip
        for descriptor in (initial, settled):
            assert (descriptor["status"], descriptor["status_reason"]) == ("not_captured", reason)
            assert "ref" not in descriptor and "source_sha256" not in descriptor
            assert "source_byte_length" not in descriptor
        digest = hashlib.sha256(SECRET).hexdigest().encode()
        for path in tmp_path.rglob("*"):
            if path.is_file():
                assert SECRET not in path.read_bytes() and digest not in path.read_bytes()
        assert any(reason in r.getMessage() for r in caplog.records)  # never silent
    finally:
        assert recorder.close()


def test_the_explicit_gate_reads_the_id_key_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", "fabric-test-id-key-not-a-secret")
    store = LocalFilesystemContentStore(str(tmp_path / "store"), tenant_id="tenant-a")
    config = ByteEvidenceConfig(
        store=store, roles=frozenset({"terminal.stdout"}), deployment_policy=_production()
    )
    recorder = ByteEvidenceRecorder(config)
    try:
        assert recorder.status()["content_capture"] == "enabled"
        assert recorder.get(_capture(recorder)["object_id"]) is not None
    finally:
        assert recorder.close()
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", "short")
    with pytest.raises(ValueError, match="FABRIC_WIRE_ID_KEY"):  # malformed: still raises
        ByteEvidenceRecorder(config)
