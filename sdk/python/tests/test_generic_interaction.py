# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Generic interaction capture (spec 023).

Everything here is GENERIC — surface-agnostic. The universal
``record_interaction`` primitive captures ANY interaction kind; the
:class:`fabric.Baseline`, taxonomy tags, and :func:`fabric.verify_signature`
are cross-cutting capabilities that apply to any hashed thing / any
artifact / any event; and the coverage loop self-reports what is being
captured generically. Raw payload/metadata never land on the span.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    Baseline,
    BaselineCheck,
    Fabric,
    FabricConfig,
    SignatureCheck,
    Taxonomy,
    bundled_taxonomy_names,
    load_bundled_taxonomies,
    signing,
    validate_tag,
    verify_signature,
)
from fabric.decision import reset_coverage_registry
from fabric.integrations.mcp import record_mcp_inventory

DECISION_SPAN = "fabric.decision"


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _decision_span(exporter: InMemorySpanExporter) -> Any:
    return next(s for s in exporter.get_finished_spans() if s.name == DECISION_SPAN)


def _event(span: Any, name: str) -> dict[str, Any]:
    event = next(e for e in span.events if e.name == name)
    return dict(event.attributes or {})


def _events(span: Any, name: str) -> list[dict[str, Any]]:
    return [dict(e.attributes or {}) for e in span.events if e.name == name]


def _span_tree_blob(exporter: InMemorySpanExporter) -> str:
    parts: list[str] = []
    for span in exporter.get_finished_spans():
        parts.append(repr(dict(span.attributes or {})))
        parts.append(repr([dict(e.attributes or {}) for e in span.events]))
    return "".join(parts)


def _hmac_sig(artifact_hash: str, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"), artifact_hash.encode("utf-8"), hashlib.sha256
    ).hexdigest()


# --------------------------------------------------------------------------- #
# 1. Universal record_interaction
# --------------------------------------------------------------------------- #


def test_record_interaction_event_shape(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction(
            "http.request",
            "https://api.example.com/v1",
            direction="outbound",
            payload_hash="a" * 64,
        )
    span = _decision_span(span_exporter)
    assert dict(span.attributes or {})["fabric.interaction_count"] == 1
    assert dict(span.attributes or {})["fabric.interaction_kinds"] == ("http.request",)
    attrs = _event(span, "fabric.interaction")
    assert attrs["fabric.interaction.kind"] == "http.request"
    assert attrs["fabric.interaction.target"] == "https://api.example.com/v1"
    assert attrs["fabric.interaction.direction"] == "outbound"
    assert attrs["fabric.interaction.payload_hash"] == "a" * 64
    assert attrs["fabric.interaction.target_redacted"] is False


def test_record_interaction_arbitrary_kind_is_captured(span_exporter: InMemorySpanExporter) -> None:
    """A never-before-seen kind is capturable today — the completeness guarantee."""
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("quantum.teleport", "qubit://node-7")
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.interaction.kind"] == "quantum.teleport"


def test_record_interaction_optionals_omitted(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("db.query", "orders")
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert "fabric.interaction.direction" not in attrs
    assert "fabric.interaction.payload_hash" not in attrs
    assert "fabric.interaction.metadata_hash" not in attrs
    assert "fabric.tags" not in attrs
    assert "fabric.baseline.name" not in attrs
    assert "fabric.signature.verified" not in attrs


def test_record_interaction_rolling_count_and_kinds(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("http.request", "u1")
        d.record_interaction("db.query", "t1")
        d.record_interaction("http.request", "u2")
    span = _decision_span(span_exporter)
    attrs = dict(span.attributes or {})
    assert attrs["fabric.interaction_count"] == 3
    # distinct kinds, sorted.
    assert attrs["fabric.interaction_kinds"] == ("db.query", "http.request")
    assert len(_events(span, "fabric.interaction")) == 3


@pytest.mark.parametrize("direction", ["inbound", "outbound", "internal"])
def test_record_interaction_accepts_all_directions(
    direction: str, span_exporter: InMemorySpanExporter
) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("k", "t", direction=direction)
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.interaction.direction"] == direction


def test_record_interaction_rejects_bad_direction(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="unknown interaction direction"),
    ):
        d.record_interaction("k", "t", direction="sideways")


def test_record_interaction_metadata_is_hashed_not_raw(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    metadata = {"api_key": "SECRET_VALUE_XYZ", "method": "GET"}
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("http.request", "u", metadata=metadata)
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    expected = _sha256(json.dumps(metadata, sort_keys=True, default=str))
    assert attrs["fabric.interaction.metadata_hash"] == expected
    assert "SECRET_VALUE_XYZ" not in _span_tree_blob(span_exporter)


def test_record_interaction_redacted_target(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    sensitive = "/patients/jane/record.pdf"
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("file.read", sensitive, redact_target=True)
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.interaction.target_redacted"] is True
    assert attrs["fabric.interaction.target_hash"] == _sha256(sensitive)
    assert "fabric.interaction.target" not in attrs
    assert sensitive not in _span_tree_blob(span_exporter)


def test_record_interaction_no_raw_data_leak(span_exporter: InMemorySpanExporter) -> None:
    """Plant secrets in payload, metadata, and target; assert none reach the span tree."""
    reset_coverage_registry()
    client = _client()
    raw_payload = "RAW_PAYLOAD_SSN_123-45-6789"
    raw_target = "https://internal.example.com/SECRET_TARGET_PATH"
    metadata = {"authorization": "Bearer LEAKED_TOKEN_999", "n": 3}
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction(
            "http.request",
            raw_target,
            direction="outbound",
            payload_hash=_sha256(raw_payload),
            metadata=metadata,
            redact_target=True,
        )
    blob = _span_tree_blob(span_exporter)
    for secret in ("RAW_PAYLOAD_SSN_123-45-6789", "SECRET_TARGET_PATH", "LEAKED_TOKEN_999"):
        assert secret not in blob, f"raw data leaked onto span: {secret!r}"
    # the hashes ARE present (they are the contract).
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.interaction.payload_hash"] == _sha256(raw_payload)
    assert attrs["fabric.interaction.target_hash"] == _sha256(raw_target)


# --------------------------------------------------------------------------- #
# 2. Generic baseline
# --------------------------------------------------------------------------- #


def test_baseline_check_match_deviation_unknown() -> None:
    bl = Baseline.load({"tool-set": "h1", "skills": "h2"})
    assert bl.check("tool-set", "h1") == "match"
    assert bl.check("tool-set", "DIFFERENT") == "deviation"
    assert bl.check("never-approved", "h1") == "unknown"


def test_baseline_load_from_dict_and_file(tmp_path: Path) -> None:
    from_dict = Baseline.load({"a": "h"})
    assert from_dict.check("a", "h") == "match"

    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"endpoint": "approved-hash"}), encoding="utf-8")
    from_file = Baseline.load(path)
    assert from_file.check("endpoint", "approved-hash") == "match"
    assert from_file.names == ("endpoint",)


def test_baseline_load_rejects_non_object_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON object"):
        Baseline.load(path)


def test_baseline_is_generic_across_surfaces(span_exporter: InMemorySpanExporter) -> None:
    """The SAME baseline primitive stamps onto a skill, a file, and an interaction."""
    reset_coverage_registry()
    bl = Baseline.load({"refund-skill": "e" * 64, "/etc/hosts": "f" * 64, "db.query": "g" * 64})
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_skill(
            "refund-skill",
            "1.0",
            baseline=BaselineCheck(bl, "refund-skill", "e" * 64),
        )
        d.record_file_access(
            "/etc/hosts",
            "read",
            baseline=BaselineCheck(bl, "/etc/hosts", "CHANGED"),
        )
        d.record_interaction(
            "db.query",
            "orders",
            baseline=BaselineCheck(bl, "db.query", "g" * 64),
        )
    span = _decision_span(span_exporter)
    assert _event(span, "fabric.skill")["fabric.baseline.status"] == "match"
    assert _event(span, "fabric.file")["fabric.baseline.status"] == "deviation"
    assert _event(span, "fabric.interaction")["fabric.baseline.status"] == "match"


def test_baseline_check_stamps_name_and_status(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    bl = Baseline.load({"srv": "h"})
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("mcp.list", "srv", baseline=BaselineCheck(bl, "srv", "h"))
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.baseline.name"] == "srv"
    assert attrs["fabric.baseline.status"] == "match"


def test_baseline_unknown_status_on_emitted_event(span_exporter: InMemorySpanExporter) -> None:
    """A name absent from the baseline stamps status 'unknown' on the event."""
    reset_coverage_registry()
    bl = Baseline.load({"approved": "a" * 64})
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction(
            "db.query",
            "orders",
            baseline=BaselineCheck(bl, "never-approved", "z" * 64),
        )
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.baseline.name"] == "never-approved"
    assert attrs["fabric.baseline.status"] == "unknown"


def test_record_interaction_rejects_bad_baseline_type(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        pytest.raises(TypeError, match="BaselineCheck"),
    ):
        d.record_interaction("k", "t", baseline="not-a-baseline-check")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 3. Generic taxonomy tagging (open vocabulary)
# --------------------------------------------------------------------------- #


def test_tags_captured_on_interaction(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("llm.call", "anthropic", tags=["atlas:AML.T0051", "owasp-llm:LLM01"])
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.tags"] == ("atlas:AML.T0051", "owasp-llm:LLM01")


def test_arbitrary_tags_always_allowed(span_exporter: InMemorySpanExporter) -> None:
    """Open vocabulary: a tag from no known framework is captured unchanged."""
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("x", "y", tags=["myco:risk-high", "totally-made-up", "ns:code"])
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.tags"] == ("myco:risk-high", "totally-made-up", "ns:code")


def test_empty_tags_dropped(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("x", "y", tags=["", "keep"])
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.tags"] == ("keep",)


def test_tags_reject_non_string(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        pytest.raises(TypeError, match="tags must be strings"),
    ):
        d.record_interaction("x", "y", tags=["ok", 123])  # type: ignore[list-item]


def test_bundled_taxonomies_present() -> None:
    names = bundled_taxonomy_names()
    assert "mitre-atlas" in names
    assert "owasp-llm" in names


def test_taxonomy_validate_and_lookup() -> None:
    atlas = Taxonomy.load("mitre-atlas")
    assert atlas.namespace == "atlas"
    assert atlas.validate("atlas:AML.T0051") is True
    entry = atlas.lookup("atlas:AML.T0051")
    assert entry is not None
    assert entry.name == "LLM Prompt Injection"
    # wrong namespace / unknown code do not validate (but are still legal tags).
    assert atlas.validate("owasp-llm:LLM01") is False
    assert atlas.validate("atlas:NOPE") is False
    assert atlas.lookup("atlas:NOPE") is None


def test_taxonomy_validate_rejects_malformed_tag() -> None:
    atlas = Taxonomy.load("mitre-atlas")
    assert atlas.validate("no-colon") is False
    assert atlas.lookup("no-colon") is None


def test_validate_tag_against_any_loaded_taxonomy() -> None:
    taxes = load_bundled_taxonomies()
    loaded = list(taxes.values())
    assert validate_tag("atlas:AML.T0054", loaded) is True
    assert validate_tag("owasp-llm:LLM06", loaded) is True
    # arbitrary tag: not in any known framework — but still a legal tag.
    assert validate_tag("myco:whatever", loaded) is False


def test_taxonomy_drop_in_json_zero_code(tmp_path: Path) -> None:
    """Adding a framework is dropping a JSON file — no code change."""
    doc = {
        "namespace": "nist-ai-rmf",
        "title": "NIST AI RMF",
        "entries": {"GOVERN-1.1": {"name": "Legal and regulatory requirements"}},
    }
    path = tmp_path / "nist.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    tax = Taxonomy.load(path)
    assert tax.validate("nist-ai-rmf:GOVERN-1.1") is True
    assert tax.lookup("nist-ai-rmf:GOVERN-1.1").name == "Legal and regulatory requirements"  # type: ignore[union-attr]


def test_taxonomy_unknown_bundled_name_raises() -> None:
    with pytest.raises(FileNotFoundError, match="no bundled taxonomy"):
        Taxonomy.load("does-not-exist")


# --------------------------------------------------------------------------- #
# 4. Generic signature verification
# --------------------------------------------------------------------------- #

_SECRET = "shared-secret-key"  # noqa: S105 — a test HMAC secret, not a credential


def test_verify_signature_hmac_verified() -> None:
    ah = "a" * 64
    result = verify_signature(
        ah, _hmac_sig(ah, _SECRET), _SECRET, scheme="hmac-sha256", key_id="k1"
    )
    assert result.verified is True
    assert result.scheme == "hmac-sha256"
    assert result.key_id == "k1"


def test_verify_signature_hmac_failed() -> None:
    ah = "a" * 64
    result = verify_signature(ah, "deadbeef", _SECRET, scheme="hmac-sha256")
    assert result.verified is False


def test_verify_signature_unknown_scheme_raises() -> None:
    with pytest.raises(ValueError, match="unknown signature scheme"):
        verify_signature("a" * 64, "sig", "key", scheme="rsa-pss")


def test_verify_signature_ed25519_verified_and_failed() -> None:
    crypto = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        Encoding,
        PublicFormat,
    )

    assert crypto  # keep the import referenced
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_hex = pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    artifact = "f" * 64
    sig_hex = priv.sign(artifact.encode("utf-8")).hex()

    ok = verify_signature(artifact, sig_hex, pub_hex, scheme="ed25519", key_id="ed-1")
    assert ok.verified is True
    assert ok.scheme == "ed25519"
    assert ok.key_id == "ed-1"

    # tamper the artifact -> verification fails (no raise).
    bad = verify_signature("e" * 64, sig_hex, pub_hex, scheme="ed25519")
    assert bad.verified is False


def test_ed25519_degrades_cleanly_without_cryptography(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Best-effort ed25519: with no `cryptography`, verification degrades to False."""
    signing._ED25519_FALLBACK_WARNED.clear()
    # Setting the submodule to None makes `from cryptography... import` raise
    # ImportError, simulating the optional dependency being absent.
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    result = verify_signature("a" * 64, "00" * 64, "00" * 32, scheme="ed25519")
    assert result.verified is False
    assert result.scheme == "ed25519"


def test_signature_check_stamps_results(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    ah = "b" * 64
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction(
            "policy.bundle",
            "bundle://v1",
            signature=SignatureCheck(
                artifact_hash=ah,
                signature=_hmac_sig(ah, _SECRET),
                public_key=_SECRET,
                scheme="hmac-sha256",
                key_id="key-7",
            ),
        )
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.signature.verified"] is True
    assert attrs["fabric.signature.scheme"] == "hmac-sha256"
    assert attrs["fabric.signature.key_id"] == "key-7"


def test_signature_failed_is_stamped_false(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction(
            "policy.bundle",
            "bundle://v1",
            signature=SignatureCheck(
                artifact_hash="b" * 64,
                signature="badc0ffee",
                public_key=_SECRET,
                scheme="hmac-sha256",
            ),
        )
    attrs = _event(_decision_span(span_exporter), "fabric.interaction")
    assert attrs["fabric.signature.verified"] is False
    assert "fabric.signature.key_id" not in attrs


def test_signature_secret_never_on_span(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    ah = "b" * 64
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction(
            "policy.bundle",
            "bundle://v1",
            signature=SignatureCheck(
                artifact_hash=ah,
                signature=_hmac_sig(ah, _SECRET),
                public_key=_SECRET,
                scheme="hmac-sha256",
            ),
        )
    assert _SECRET not in _span_tree_blob(span_exporter)


def test_record_interaction_rejects_bad_signature_type(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        pytest.raises(TypeError, match="SignatureCheck"),
    ):
        d.record_interaction("k", "t", signature="nope")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 5. Coverage loop
# --------------------------------------------------------------------------- #


def test_coverage_fires_once_per_kind(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("http.request", "u1")
        d.record_interaction("http.request", "u2")
        d.record_interaction("http.request", "u3")
    coverage = _events(_decision_span(span_exporter), "fabric.coverage")
    assert len(coverage) == 1
    assert coverage[0]["fabric.coverage.kind"] == "http.request"
    assert coverage[0]["fabric.coverage.suggestion"] == "generic"
    assert coverage[0]["fabric.coverage.reason"] == "new_kind"


def test_coverage_fires_for_each_new_kind(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction("http.request", "u")
        d.record_interaction("db.query", "t")
    coverage = _events(_decision_span(span_exporter), "fabric.coverage")
    kinds = sorted(c["fabric.coverage.kind"] for c in coverage)
    assert kinds == ["db.query", "http.request"]


def test_coverage_is_process_wide_one_shot(span_exporter: InMemorySpanExporter) -> None:
    """A kind already seen in the process does not re-emit on a later decision."""
    reset_coverage_registry()
    client = _client()
    with client.decision(session_id="s1", request_id="r1") as d:
        d.record_interaction("ws.message", "topic")
    span_exporter.clear()
    with client.decision(session_id="s2", request_id="r2") as d:
        d.record_interaction("ws.message", "topic")
    assert _events(_decision_span(span_exporter), "fabric.coverage") == []


def test_coverage_unclassified_deviation_signal(span_exporter: InMemorySpanExporter) -> None:
    reset_coverage_registry()
    bl = Baseline.load({"shell.exec": "a" * 64})
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction(
            "shell.exec", "/bin/sh", baseline=BaselineCheck(bl, "shell.exec", "DEVIATED")
        )
    reasons = {
        c["fabric.coverage.reason"]
        for c in _events(_decision_span(span_exporter), "fabric.coverage")
    }
    assert reasons == {"new_kind", "unclassified_deviation"}


def test_coverage_deviation_with_tags_is_classified(span_exporter: InMemorySpanExporter) -> None:
    """A deviation WITH tags is classified — no unclassified-deviation signal."""
    reset_coverage_registry()
    bl = Baseline.load({"shell.exec": "a" * 64})
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_interaction(
            "shell.exec",
            "/bin/sh",
            tags=["atlas:AML.T0011"],
            baseline=BaselineCheck(bl, "shell.exec", "DEVIATED"),
        )
    reasons = {
        c["fabric.coverage.reason"]
        for c in _events(_decision_span(span_exporter), "fabric.coverage")
    }
    assert reasons == {"new_kind"}


# --------------------------------------------------------------------------- #
# 6. Cross-cutting kwargs on the spec-022 surfaces + tool_call (additive)
# --------------------------------------------------------------------------- #


def test_cross_cutting_on_skill(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_skill("sk", "1.0", tags=["owasp-llm:LLM03"])
    attrs = _event(_decision_span(span_exporter), "fabric.skill")
    assert attrs["fabric.tags"] == ("owasp-llm:LLM03",)


def test_cross_cutting_on_hook(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_hook("h", "pre_tool", tags=["myco:audited"])
    attrs = _event(_decision_span(span_exporter), "fabric.hook")
    assert attrs["fabric.tags"] == ("myco:audited",)


def test_cross_cutting_on_file_access(span_exporter: InMemorySpanExporter) -> None:
    ah = "d" * 64
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_file_access(
            "/f",
            "read",
            signature=SignatureCheck(
                artifact_hash=ah,
                signature=_hmac_sig(ah, _SECRET),
                public_key=_SECRET,
                scheme="hmac-sha256",
            ),
        )
    attrs = _event(_decision_span(span_exporter), "fabric.file")
    assert attrs["fabric.signature.verified"] is True


def test_cross_cutting_on_delegation(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        d.delegate("sub", protocol="a2a", tags=["atlas:AML.T0048"]),
    ):
        pass
    attrs = _event(_decision_span(span_exporter), "fabric.delegation")
    assert attrs["fabric.tags"] == ("atlas:AML.T0048",)


def test_cross_cutting_on_tool_call(span_exporter: InMemorySpanExporter) -> None:
    bl = Baseline.load({"vector_search": "h" * 64})
    client = _client()
    with (
        client.decision(session_id="s", request_id="r") as d,
        d.tool_call(
            "vector_search",
            tags=["owasp-llm:LLM02"],
            baseline=BaselineCheck(bl, "vector_search", "h" * 64),
        ),
    ):
        pass
    tool_span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.tool_call")
    attrs = dict(tool_span.attributes or {})
    assert attrs["fabric.tags"] == ("owasp-llm:LLM02",)
    assert attrs["fabric.baseline.status"] == "match"


def test_cross_cutting_on_mcp_inventory(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        record_mcp_inventory(
            d,
            server="m",
            transport="stdio",
            tools=[{"name": "t", "description": "d", "inputSchema": {}}],
            tags=["atlas:AML.T0024"],
        )
    attrs = _event(_decision_span(span_exporter), "fabric.mcp.inventory")
    assert attrs["fabric.tags"] == ("atlas:AML.T0024",)


def test_cross_cutting_absent_is_byte_identical(span_exporter: InMemorySpanExporter) -> None:
    """Surfaces called WITHOUT the new kwargs emit no cross-cutting keys."""
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        d.record_skill("sk", "1.0")
        d.record_hook("h", "pre_tool")
        d.record_file_access("/f", "read")
    span = _decision_span(span_exporter)
    for event_name in ("fabric.skill", "fabric.hook", "fabric.file"):
        attrs = _event(span, event_name)
        assert not any(
            k.startswith(("fabric.tags", "fabric.baseline", "fabric.signature")) for k in attrs
        )
