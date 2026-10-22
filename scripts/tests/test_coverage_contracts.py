# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the draft four-layer coverage contracts (spec 049)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_coverage_contracts import (  # noqa: E402
    FAMILY,
    FREE_TEXT,
    MANIFEST_RECORD_SCHEMA,
    PSEUDONYM_V1_VECTORS,
    REGISTRY,
    SPEC,
    PSEUDONYM_V2_TYPES,
    CoverageContractError,
    check_value,
    field_set_keys,
    load_registries,
    manifest_digest,
    parse_resume_token,
    pseudonym_v1,
    pseudonym_v2,
    validate_coverage_contracts,
)
from release import package_contracts as packaging  # noqa: E402


def _copy_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / FAMILY, root / FAMILY)
    (root / SPEC).parent.mkdir(parents=True)
    shutil.copy(REPO_ROOT / SPEC, root / SPEC)
    for extra in (
        Path("contracts/content/v2/schema/content-object-v2.schema.json"),
        MANIFEST_RECORD_SCHEMA,
        PSEUDONYM_V1_VECTORS,
    ):
        (root / extra).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / extra, root / extra)
    return root


def _edit_registry(root: Path, name: str, change: Callable[[Any], None]) -> None:
    path = root / FAMILY / REGISTRY[name]
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    manifest_path = root / FAMILY / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for record in manifest["artifacts"]:
        if record["path"] == REGISTRY[name]:
            record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _assert_code(root: Path, code: str) -> None:
    with pytest.raises(CoverageContractError) as caught:
        validate_coverage_contracts(root)
    assert caught.value.code == code


def test_repository_coverage_contracts_and_spec_blocks_validate() -> None:
    checked = validate_coverage_contracts(REPO_ROOT)
    assert "coverage/registry/field-registry-v1.json" in checked
    assert "spec/fields:N" in checked
    assert "spec/roles" in checked


def test_spec_table_drift_is_detected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    spec = root / SPEC
    text = spec.read_text(encoding="utf-8")
    assert "| N09 |" in text
    spec.write_text(text.replace("| N09 |", "| N09x |", 1), encoding="utf-8")
    _assert_code(root, "coverage.spec.drift")


def test_write_regenerates_drifted_blocks(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    spec = root / SPEC
    original = spec.read_text(encoding="utf-8")
    spec.write_text(original.replace("| N09 |", "| N09x |", 1), encoding="utf-8")
    validate_coverage_contracts(root, write=True)
    assert spec.read_text(encoding="utf-8") == original


def test_unknown_capture_point_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def change(document: Any) -> None:
        document["fields"][0]["observed_by"] = ["no.such.point"]

    _edit_registry(root, "fields", change)
    _assert_code(root, "coverage.fields.observed_by")


def test_supplies_must_match_fields(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def change(document: Any) -> None:
        document["capture_points"][0]["supplies"] = []

    _edit_registry(root, "points", change)
    _assert_code(root, "coverage.points.supplies")


def test_every_role_needs_media_types(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def change(document: Any) -> None:
        document["roles"][0]["media_types"] = []

    _edit_registry(root, "roles", change)
    _assert_code(root, "coverage.roles.incomplete")


def test_unpinned_registry_change_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    path = root / FAMILY / REGISTRY["keys"]
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    _assert_code(root, "coverage.manifest.digest")


def test_manifest_property_without_telemetry_key_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def change(document: Any) -> None:
        for key in document["keys"]:
            if key.get("manifest_property") == "limits/part_min_bytes":
                del key["manifest_property"]

    _edit_registry(root, "keys", change)
    _assert_code(root, "coverage.keys.manifest")


def test_step_level_open_verdict_is_rejected_by_the_projection_schema() -> None:
    from jsonschema import Draft202012Validator

    schema = json.loads(
        (REPO_ROOT / FAMILY / "schema/step-projection-v1.schema.json").read_text()
    )
    verdict = {"verdict": "open"}
    layers = {
        k: verdict for k in ("context", "structure", "content", "decisions_effects")
    }
    validator = Draft202012Validator(schema)
    step_layers = {"$ref": "#/$defs/step_layer_verdicts"}
    run_layers = {"$ref": "#/$defs/run_layer_verdicts"}
    sub_step = {"$defs": schema["$defs"], **step_layers}
    sub_run = {"$defs": schema["$defs"], **run_layers}
    assert list(Draft202012Validator(sub_step).iter_errors(layers))
    assert not list(Draft202012Validator(sub_run).iter_errors(layers))
    assert validator is not None


# ---------------------------------------------------------------- spec 049 P0 conformance
def _rewrite(root: Path, relative: str, change: Callable[[Any], None]) -> None:
    """Edit a pinned coverage artifact and re-pin it, so only semantics can fail."""
    path = root / FAMILY / relative
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    manifest_path = root / FAMILY / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for record in manifest["artifacts"]:
        if record["path"] == relative:
            record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _key(document: Any, name: str) -> dict[str, Any]:
    return next(row for row in document["keys"] if row["key"] == name)


def test_c0_1_every_fixture_and_vector_is_pinned_and_checked() -> None:
    manifest = json.loads((REPO_ROOT / FAMILY / "manifest.json").read_text())
    expectations = {record["expectation"] for record in manifest["artifacts"]}
    assert expectations == {"registry", "schema", "valid", "invalid", "vectors"}
    names = {record["path"] for record in manifest["artifacts"]}
    # P0 exit (spec 049 section 8.2): every fixture family the gate names exists.
    for wanted in (
        "valid/projection-model-call-field-statuses.json",  # empty vs absent, conflict, unknown identity
        "valid/projection-extension-step.json",
        "valid/projection-tentative-same-as.json",
        "valid/projection-run-open-branches.json",
        "valid/projection-run-unterminated.json",
        "valid/projection-run-segment-missing.json",
        "valid/projection-run-replayed-branch.json",
        "valid/projection-run-post-terminal.json",
        "valid/manifest-typescript-unsupported.json",
        "fixtures/vectors/resume-token-v1.json",
        "fixtures/vectors/run-marker-v1.json",
        "fixtures/vectors/manifest-span-v1.json",
        "fixtures/vectors/pseudonym-v2.json",
    ):
        assert wanted in names


def test_c0_1_invalid_fixture_with_the_wrong_error_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    manifest_path = root / FAMILY / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for record in manifest["artifacts"]:
        if record["path"] == "invalid/projection-conflict-chooses-a-value.json":
            record["expected_error"] = "coverage.projection.absent"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    _assert_code(root, "coverage.fixture.wrong_error")


def test_c0_1_accepted_invalid_fixture_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(
        root,
        "invalid/projection-absent-with-empty-value.json",
        lambda d: d["steps"][0]["layers"]["context"]["tools_offered"].pop("value"),
    )
    _assert_code(root, "coverage.fixture.accepted_invalid")


def test_c0_1_manifest_record_schema_is_generated_not_edited(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    path = root / MANIFEST_RECORD_SCHEMA
    schema = json.loads(path.read_text())
    del schema["properties"]["attributes"]["properties"]["fabric.manifest.key_id"]
    path.write_text(json.dumps(schema, indent=2) + "\n")
    _assert_code(root, "coverage.manifest_record.drift")
    validate_coverage_contracts(root, write=True)
    assert json.loads(path.read_text()) == json.loads(
        (REPO_ROOT / MANIFEST_RECORD_SCHEMA).read_text()
    )


def test_c0_1_manifest_key_must_admit_what_the_manifest_schema_allows(
    tmp_path: Path,
) -> None:
    root = _copy_tree(tmp_path)

    def narrow(document: Any) -> None:
        _key(document, "fabric.manifest.limits.max_body_bytes")["check"]["max"] = 1024

    _edit_registry(root, "keys", narrow)
    _assert_code(root, "coverage.keys.manifest_check")


def test_c0_1_manifest_span_form_round_trips(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(
        root,
        "fixtures/vectors/manifest-span-v1.json",
        lambda d: d["cases"][0]["attributes"].update(
            {"fabric.manifest.profile": "production"}
        ),
    )
    _assert_code(root, "coverage.vectors.manifest_span")


def test_c0_1_manifest_chain_pins_digests_and_fixes_policy_per_epoch(
    tmp_path: Path,
) -> None:
    root = _copy_tree(tmp_path)

    def change_policy_mid_epoch(document: Any) -> None:
        document["manifests"][2]["limits"]["max_body_bytes"] = 8388608
        document["digests"][2] = manifest_digest(document["manifests"][2])

    _rewrite(root, "fixtures/vectors/manifest-chain-v1.json", change_policy_mid_epoch)
    _assert_code(root, "coverage.vectors.chain")


def test_c0_2_vocabulary_growth_needs_the_schema_enums(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def grow(document: Any) -> None:
        document["reason"].append(
            {"value": "new_reason", "meaning": "A reason added without its schemas."}
        )

    _edit_registry(root, "vocab", grow)
    _assert_code(root, "coverage.schema.enum")


def test_c0_2_enum_checks_follow_their_vocabulary(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def drift(document: Any) -> None:
        _key(document, "fabric.step.kind")["check"]["values"].append("thinking")

    _edit_registry(root, "keys", drift)
    _assert_code(root, "coverage.keys.enum_source")


def test_c0_2_field_type_enums_are_copied_exactly(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def drift(document: Any) -> None:
        _key(document, "fabric.control.decision")["check"]["values"].remove("unknown")

    _edit_registry(root, "keys", drift)
    _assert_code(root, "coverage.keys.enum_source")


def test_c0_2_inference_methods_have_one_fixed_confidence(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def drift(document: Any) -> None:
        document["inference_method"][0]["confidence"] = "tentative"

    _edit_registry(root, "vocab", drift)
    _assert_code(root, "coverage.vocab.confidence")


def test_c0_2_every_admitted_key_rejects_free_text() -> None:
    reg = load_registries(REPO_ROOT)
    admitted = [row for row in reg["keys"]["keys"] if "check" in row]
    assert len(admitted) > 100
    for row in admitted:
        for text in FREE_TEXT:
            assert not check_value(row["check"], text), row["key"]
            assert not check_value(row["check"], text, labels="pseudonymous"), row[
                "key"
            ]


def test_c0_2_a_check_that_admits_free_text_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def loosen(document: Any) -> None:
        _key(document, "fabric.error.code")["check"]["pattern"] = "^.*$"

    _edit_registry(root, "keys", loosen)
    _assert_code(root, "coverage.keys.free_text")


def test_c0_3_pseudonym_v1_is_unchanged_and_v2_is_domain_separated() -> None:
    v1_path = REPO_ROOT / PSEUDONYM_V1_VECTORS
    capture = json.loads((REPO_ROOT / "contracts/capture/v1/manifest.json").read_text())
    pin = next(
        r
        for r in capture["artifacts"]
        if r["path"] == "fixtures/run-ids/run-id-pseudonym-v1.json"
    )
    assert (
        pin["sha256"]
        == "5d606abfae8566c98bb0f858a2c05fafea6faf0126b4241164a7ae5a043528e5"
    )
    assert hashlib.sha256(v1_path.read_bytes()).hexdigest() == pin["sha256"]
    for case in json.loads(v1_path.read_text())["cases"]:
        assert pseudonym_v1("r", case["run_id"], case["key"]) == case["pseudonym"]
    key, value = "fabric-test-id-key-not-a-secret", "resp_68af3e2b1c"
    provider = pseudonym_v2("p", "provider", value, key)
    assert provider is not None and len(provider) == 2 + 32
    assert provider[2:] != pseudonym_v1("r", value, key)[2:]
    assert provider != pseudonym_v2("p", "provider", value, "another-test-key")
    assert pseudonym_v2("p", "provider", value, None) is None
    vectors = json.loads(
        (REPO_ROOT / FAMILY / "fixtures/vectors/pseudonym-v2.json").read_text()
    )
    assert {c["function"] for c in vectors["cases"]} == {"v1", "v2", "legacy_provider"}


def test_c0_3_tampered_pseudonym_vector_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _rewrite(
        root,
        "fixtures/vectors/pseudonym-v2.json",
        lambda d: d["cases"][0].update(type="user"),
    )
    _assert_code(root, "coverage.vectors.pseudonym")


def test_c0_3_v2_vectors_cover_every_prefix_of_the_spec_table() -> None:
    vectors = json.loads(
        (REPO_ROOT / FAMILY / "fixtures/vectors/pseudonym-v2.json").read_text()
    )
    keyed = {
        (c["prefix"], c["type"])
        for c in vectors["cases"]
        if c["function"] == "v2" and c["pseudonym"]
    }
    assert keyed == set(PSEUDONYM_V2_TYPES.items())
    spec = (REPO_ROOT / SPEC).read_text(encoding="utf-8")
    for prefix, id_type in PSEUDONYM_V2_TYPES.items():
        assert f"| `{prefix}-` | `{id_type}` |" in spec, prefix
    for case in vectors["cases"]:
        if case["function"] == "v2" and case["pseudonym"]:
            assert case["pseudonym"] == pseudonym_v2(
                case["prefix"], case["type"], case["value"], case["key"]
            )
            assert re.fullmatch(rf"{case['prefix']}-[0-9a-f]{{32}}", case["pseudonym"])
    hexes = [
        c["pseudonym"].split("-", 1)[1] for c in vectors["cases"] if c["pseudonym"]
    ]
    assert len(set(hexes)) == len(hexes), "every vector is domain-separated"


def test_c0_3_v1_function_drift_is_detected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    path = root / PSEUDONYM_V1_VECTORS
    document = json.loads(path.read_text())
    document["cases"][0]["pseudonym"] = "r-" + "0" * 32
    path.write_text(json.dumps(document, indent=2) + "\n")
    _assert_code(root, "coverage.vectors.pseudonym")


def test_c0_4_every_key_is_closed_and_admitted_in_p0() -> None:
    reg = load_registries(REPO_ROOT)
    rows = reg["keys"]["keys"]
    assert not [row["key"] for row in rows if "check_pending" in row]
    for row in rows:
        if row["change"] != "reused" or row["key"] in {
            "fabric.event_id",
            "fabric.schema_version",
        }:
            assert "check" in row, row["key"]
    admissions = {
        row["key"]: row["check"].get("admission") for row in rows if "check" in row
    }
    # P0-A switched the tightening validators (spec 049 §4.2): no P0-A row remains.
    assert {k: v for k, v in admissions.items() if v} == {
        "fabric.file.path": "never",
        "fabric.heartbeat.kind": "existing",
        "fabric.wire.request_sha256": "existing",
        "fabric.wire.response_sha256": "existing",
    }
    heartbeat = next(row for row in rows if row["key"] == "fabric.heartbeat.kind")
    assert "segment_seal" in heartbeat["check"]["values"]
    clock = next(row for row in rows if row["key"] == "fabric.manifest.clock.domain")
    assert clock["check"] == {"type": "const", "value": "wall_utc"}
    receiver = [row["key"] for row in rows if row.get("owner") == "receiver"]
    assert receiver == ["fabric.source.authenticated"]


def test_c0a_4_clear_ids_are_rejected_under_a_pseudonymous_node() -> None:
    reg = load_registries(REPO_ROOT)
    checks = {row["key"]: row["check"] for row in reg["keys"]["keys"] if "check" in row}
    session, agent = checks["fabric.session_id"], checks["fabric.delegation.to_agent"]
    assert (
        session["identity_mode"] == {"clear": "existing"}
        and "identity_mode" not in agent
    )
    assert check_value(session, "sess-" + "a" * 32) and check_value(
        agent, "agt-" + "a" * 32
    )
    assert not check_value(session, "checkout-42") and not check_value(
        agent, "billing-agent"
    )
    assert check_value(session, "checkout-42", identity="clear")
    assert not check_value(agent, "billing-agent", identity="clear")


def test_c0_4_operator_labels_follow_capture_labels() -> None:
    reg = load_registries(REPO_ROOT)
    for key in (
        "fabric.control.policy_id",
        "fabric.run.agent_policy_id",
        "fabric.workflow.node",
    ):
        check = next(row["check"] for row in reg["keys"]["keys"] if row["key"] == key)
        assert check_value(check, "refund-approvals")
        assert not check_value(check, "refund-approvals", labels="pseudonymous")
        assert check_value(check, "lbl-" + "a" * 32, labels="pseudonymous")


def test_c0_4_a_spelled_out_regex_is_the_check_pattern(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def drift(document: Any) -> None:
        _key(document, "fabric.framework.name")["check"]["pattern"] = (
            "^@?[a-z0-9][a-z0-9._/-]{0,200}$"
        )

    _edit_registry(root, "keys", drift)
    _assert_code(root, "coverage.keys.pattern")


def test_c0_4_a_new_key_cannot_stay_pending(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def pend(document: Any) -> None:
        row = _key(document, "fabric.mcp.method")
        row["check_pending"] = row.pop("check") and "waiting"

    _edit_registry(root, "keys", pend)
    _assert_code(root, "coverage.keys.check")


def test_projection_field_keys_are_derived_from_the_registry() -> None:
    assert field_set_keys("usage.cache_read, cache_creation, reasoning tokens") == [
        "usage.cache_read",
        "usage.cache_creation",
        "usage.reasoning_tokens",
    ]


def test_c0_4_predecessor_admission_follows_capture_labels() -> None:
    reg = load_registries(REPO_ROOT)
    check = next(
        row["check"]
        for row in reg["keys"]["keys"]
        if row["key"] == "fabric.run.predecessors"
    )
    digest = "sha256:" + "ab" * 32
    clear = [f"seg-{'1' * 32}/billing-agent.prod/42/7/{digest}"]
    pseudonymous = [f"seg-{'1' * 32}/s-{'c' * 32}/42/7/{digest}"]
    assert check_value(check, clear) and not check_value(
        check, clear, labels="pseudonymous"
    )
    assert check_value(check, pseudonymous, labels="pseudonymous")
    assert not check_value(
        check, [f"seg-{'1' * 32}/s-{'c' * 32}/9223372036854775808/7/{digest}"]
    )


def test_resume_tokens_parse_exactly() -> None:
    entry = f"seg-{'a' * 32}/s-{'b' * 32}/4611686018427387905/-1/sha256:{'c' * 64}"
    token = parse_resume_token(f"fr2/{entry}/br-{'d' * 32}")
    assert token == {
        "segment_id": f"seg-{'a' * 32}",
        "source_id": f"s-{'b' * 32}",
        "epoch": 4611686018427387905,
        "last_sequence": -1,
        "manifest_digest": f"sha256:{'c' * 64}",
        "branch_id": f"br-{'d' * 32}",
    }
    assert parse_resume_token(f"fr2/{entry}/") is None
    assert parse_resume_token(entry) is None


def test_c0_5_contract_tree_is_release_qualifiable_and_drafts_stay_unpublished() -> (
    None
):
    contracts = REPO_ROOT / "contracts"
    _members, families = packaging.validate_contract_tree(
        contracts, manifest_name="manifest.json"
    )
    assert families["coverage"] == ("v1",)
    assert "v1" in families["capture"] and "v2" in families["content"]
    policy = json.loads(
        (REPO_ROOT / "scripts/release/release-policy.json").read_text()
    )["contracts"]
    assert (
        "coverage" not in policy["public_families"]
        and "capture" not in policy["public_families"]
    )
    assert policy["public_versions"]["content"] == ["v1"]
    public, public_families = packaging.validate_contract_tree(
        contracts,
        manifest_name="manifest.json",
        included_families=frozenset(policy["public_families"]),
        included_versions={
            k: frozenset(v) for k, v in policy["public_versions"].items()
        },
    )
    assert "coverage" not in public_families
    assert not any(
        m.relative_path.parts[:2] in {("coverage", "v1"), ("content", "v2")}
        for m in public
    )


# ------------------------------------------------------------------ spec 050 (P1) contract deltas
from contracts import p1_reference as ref  # noqa: E402
from contracts.validate_coverage_contracts import (  # noqa: E402
    record_checks,
    record_conditions,
    validate_vectors,
)

P1_ARTIFACTS = (
    "fixtures/vectors/seal-digest-v1.json",
    "fixtures/vectors/span-category-v1.json",
    "fixtures/vectors/seal-parity-v1.json",
    "fixtures/vectors/records-span-v1.json",
    "fixtures/vectors/resume-token-v2.json",
    "fixtures/vectors/record-evidence-v1.json",
    "schema/record-evidence-v1.schema.json",
    "evidence/fabric.test.items-v1.schema.json",
    "valid/evidence-test-items.json",
    "valid/evidence-clear-mode-id.json",
    "invalid/evidence-unknown-type.json",
    "invalid/evidence-extra-key.json",
    "invalid/evidence-free-text-over-bound.json",
    "invalid/evidence-too-deep.json",
    "invalid/evidence-too-many-items.json",
    "invalid/evidence-content-class-value.json",
    "invalid/evidence-clear-id-pseudonymous.json",
    "valid/projection-records-explicit-d2.json",
    "valid/projection-many-records.json",
    "fixtures/projection/chat.json",
    "fixtures/projection/chat-stream.json",
    "fixtures/projection/responses-hosted-tools-reasoning.json",
    "fixtures/projection/responses-stream.json",
    "fixtures/projection/responses-previous-response-resolved.json",
    "fixtures/projection/responses-previous-response-unresolved.json",
    "fixtures/projection/anthropic-thinking.json",
    "fixtures/projection/anthropic-redacted-thinking.json",
    "fixtures/projection/anthropic-server-tools.json",
    "fixtures/projection/embeddings.json",
    "fixtures/projection/chat-refusal.json",
    "fixtures/projection/responses-unknown-item.json",
    "fixtures/projection/responses-asset-references.json",
    "fixtures/projection/request-40mib-one-image.json",
    "fixtures/projection/response-70mib-side.json",
)


def _family_json(relative: str) -> Any:
    return json.loads((REPO_ROOT / FAMILY / relative).read_text(encoding="utf-8"))


def _vector_code(document: Any) -> str:
    reg = load_registries(REPO_ROOT)
    with pytest.raises(CoverageContractError) as caught:
        validate_vectors(document, reg, REPO_ROOT, {})
    return caught.value.code


def test_p1_every_section_4_3_artifact_is_pinned() -> None:
    manifest = json.loads((REPO_ROOT / FAMILY / "manifest.json").read_text())
    pinned = {record["path"]: record for record in manifest["artifacts"]}
    assert manifest["version"] == "1.1.0"
    for path in P1_ARTIFACTS:
        assert path in pinned, path
    assert (
        pinned["evidence/fabric.test.items-v1.schema.json"]["expectation"] == "schema"
    )
    assert pinned["fixtures/projection/chat.json"]["expectation"] == "vectors"


def test_p1_registry_rows() -> None:
    reg = load_registries(REPO_ROOT)
    fields = {f["id"]: f for f in reg["fields"]["fields"]}
    assert fields["X48"]["lives_in"] == "T `fabric.content.object_ids`"
    assert fields["X49"]["lives_in"] == "T `fabric.run.id_basis`"
    assert "emitted as given in clear mode" in fields["X08"]["definition"]
    assert fields["C35"]["lives_in"].startswith("T `fabric.wire.endpoint_id`")
    assert fields["C40"]["lives_in"] == "T `fabric.wire.provider_request_id`"
    assert not [f["id"] for f in fields.values() if "P0" in f["phase"]]
    keys = {k["key"]: k for k in reg["keys"]["keys"]}
    assert not [k for k, row in keys.items() if "P0" in row["phase"]]
    assert keys["fabric.capture.source"]["check"]["values"] == ["observed", "reported"]
    assert keys["fabric.run.segment_id"]["placement"] == [
        "exchange", "record", "loss", "run_start", "run_end", "segment_seal"
    ]  # fmt: skip
    assert "manifest" in keys["fabric.event_id"]["placement"]
    assert [r["value"] for r in reg["vocab"]["step_kind"]][:2] == ["run", "agent_turn"]
    roles = {r["role"]: r for r in reg["roles"]["roles"]}
    evidence = roles["record.evidence"]
    assert evidence["default_policy"] == "metadata" and evidence["cap"] == "1 MiB"
    assert evidence["allowed_modes"] == ["retain_original", "metadata_only", "omit"]
    assert reg["roles"]["registry_revision"] == 4
    assert [t["type"] for t in reg["fields"]["evidence_types"]] == [
        "fabric.test.items/v1"
    ]


def test_p1_records_table_has_no_content_key_and_matches_the_go_table() -> None:
    reg = load_registries(REPO_ROOT)
    table = record_checks(reg)
    assert "fabric.capture.input" in table and "fabric.attempt.uid" in table
    assert not any(
        marker in key
        for key in table
        for marker in ("content.ref", "arguments", "result", "message", "prompt")
    )
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 - the generated module only imports typing helpers
        (REPO_ROOT / "sdk/python/src/fabric/_records_keys_generated.py").read_text(),
        namespace,
    )
    assert set(namespace["RECORD_KEY_CHECKS"]) == set(table)
    assert dict(namespace["RECORD_KEY_CONDITIONS"]) == record_conditions(reg) == {}
    go = (
        REPO_ROOT
        / "components/otel-collector-fabric/processor/fabricguardprocessor/coverage_keys.go"
    ).read_text()
    block = go[
        go.index("var recordKeyValidators") : go.index("var recordKeyConditions")
    ]
    assert set(re.findall(r'^\t"([^"]+)":', block, re.M)) == set(table)


def test_p1_role_tables_are_generated_from_the_registry() -> None:
    reg = load_registries(REPO_ROOT)
    text = (REPO_ROOT / "sdk/python/src/fabric/_roles.py").read_text()
    assert "# BEGIN GENERATED" in text and "ROLE_ROWS" in text
    go = (
        REPO_ROOT
        / "components/otel-collector-fabric/exporter/fabriccontentexporter/evidence_types_generated.go"
    ).read_text()
    for row in reg["fields"]["evidence_types"]:
        assert f'"{row["type"]}"' in go


@pytest.mark.parametrize(
    ("name", "change", "code"),
    [
        (
            "fixtures/vectors/seal-digest-v1.json",
            lambda d: d["segments"][1]["entries"].pop(),
            "coverage.vectors.seal",
        ),
        (
            "fixtures/vectors/seal-digest-v1.json",
            lambda d: d["records"][1]["content"].reverse(),
            "coverage.vectors.seal",
        ),
        (
            "fixtures/vectors/span-category-v1.json",
            lambda d: d["cases"][0].update(category="fabric.capture_loss"),
            "coverage.vectors.category",
        ),
        (
            "fixtures/vectors/records-span-v1.json",
            lambda d: d["cases"][2]["dropped"].clear(),
            "coverage.vectors.records_span",
        ),
        (
            "fixtures/vectors/seal-parity-v1.json",
            lambda d: d["cases"][0]["expected_export"].update(name="fabric.activity"),
            "coverage.vectors.parity",
        ),
        (
            "fixtures/vectors/record-evidence-v1.json",
            lambda d: d["cases"][6].update(refusal=None),
            "coverage.vectors.evidence",
        ),
        (
            "fixtures/vectors/resume-token-v2.json",
            lambda d: d["run_identity"][8]["expected"].update(id_basis="token"),
            "coverage.vectors.run_identity",
        ),
        (
            "fixtures/vectors/resume-token-v2.json",
            lambda d: d["tokens"][-2].update(parsed={"version": 3}),
            "coverage.vectors.resume_token",
        ),
        (
            "fixtures/projection/chat.json",
            lambda d: d["expected"].update(finish_reasons=["stop"]),
            "coverage.vectors.model_call",
        ),
    ],
)
def test_p1_vector_drift_is_detected(
    name: str, change: Callable[[Any], Any], code: str
) -> None:
    document = _family_json(name)
    change(document)
    assert _vector_code(document) == code


def test_p1_reference_seal_and_record_digest() -> None:
    assert ref.seal_digest([]) == "sha256:" + hashlib.sha256(b"[]").hexdigest()
    entries = [[2, "loss:queue_full"], [1, "sha256:" + "ab" * 32]]
    assert ref.seal_digest(entries) == ref.seal_digest(list(reversed(entries)))
    with pytest.raises(ValueError):
        ref.seal_digest([[1, "a"], [1, "b"]])
    with pytest.raises(ValueError):
        ref.loss_entries(
            {
                "reason": "queue_full",
                "count": 1,
                "first_sequence": 3,
                "last_sequence": 4,
            }
        )
    span = {
        "name": "fabric.tool_call",
        "start_ns": 1,
        "end_ns": 2,
        "status": "ok",
        "attributes": {"a": 1},
    }
    stamped = dict(span, attributes={"a": 1, "fabric.source.authenticated": True})
    assert ref.record_digest(**span, content=[None]) == ref.record_digest(
        **stamped, content=[None]
    )
    with pytest.raises(ValueError):
        ref.record_digest(**dict(span, attributes={"a": 1.5}), content=[])
    with pytest.raises(ValueError):
        ref.record_digest(**dict(span, status="Error: boom"), content=[])


def test_p1_reference_rule_a_conditions() -> None:
    reg = load_registries(REPO_ROOT)
    table = {"fabric.step.kind": record_checks(reg)["fabric.step.kind"]}
    conditions = {"fabric.step.kind": {"capture_point_kinds": ["H"]}}
    kinds = {"exec.audit": ["H"], "sdk.records": ["R"]}
    attrs = {"fabric.step.kind": "terminal", "fabric.capture.point": "exec.audit@0.9.0"}
    kept, _ = ref.project_record_attributes(
        attrs, table, check_value, conditions=conditions, point_kinds=kinds
    )
    assert kept == {"fabric.step.kind": "terminal"}
    attrs["fabric.capture.point"] = "sdk.records@0.9.0"
    kept, dropped = ref.project_record_attributes(
        attrs, table, check_value, conditions=conditions, point_kinds=kinds
    )
    assert kept == {} and "fabric.step.kind" in dropped


def test_p1_reference_tokens_and_identity() -> None:
    entry = f"seg-{'1' * 32}/s-{'2' * 32}/7/41/sha256:{'ab' * 32}"
    token = ref.format_token("r-" + "3" * 32, entry, f"br-{'4' * 32}")
    assert token is not None and ref.parse_token(token)["branch_id"] == f"br-{'4' * 32}"
    assert ref.format_token("orders/42", entry) is None
    with pytest.raises(ValueError):
        ref.run_identity([], None, minted="not-minted")
    out = ref.run_identity([token], "ignored", key="k" * 16, minted="r-" + "5" * 32)
    assert (out["run_id"], out["id_basis"]) == ("r-" + "3" * 32, "token")


def test_p1_reference_evidence_envelope() -> None:
    doc = {
        "schema_version": ref.EVIDENCE_SCHEMA,
        "evidence_type": "fabric.test.items/v1",
        "items": [],
    }
    raw = ref.canonical_bytes(doc)
    assert ref.evidence_envelope_refusal(raw, ["fabric.test.items/v1"]) is None
    assert ref.evidence_envelope_refusal(raw + b" ", ["fabric.test.items/v1"]) == (
        "evidence_not_canonical"
    )
    assert ref.evidence_envelope_refusal(raw, []) == "evidence_type_unregistered"
    big = b" " * (ref.EVIDENCE_MAX_BYTES + 1)
    assert (
        ref.evidence_envelope_refusal(big, ["fabric.test.items/v1"])
        == "evidence_bounds"
    )
    schema = _family_json("evidence/fabric.test.items-v1.schema.json")
    item = {"name": "a", "count": 1, "actor": "agent:planner"}
    assert ref.evidence_item_errors({"items": [item]}, schema) == [0]
    assert (
        ref.evidence_item_errors({"items": [item]}, schema, identity_mode="clear") == []
    )


@pytest.mark.parametrize(
    ("registry", "change", "code"),
    [
        (
            "keys",
            lambda d: _key(d, "fabric.run.id_basis").update(
                placement=["record", "exchange"]
            ),
            "coverage.keys.placement",
        ),
        (
            "keys",
            lambda d: _key(d, "fabric.run.id_basis").update(
                capture_check={"type": "bool"}
            ),
            "coverage.keys.capture_check",
        ),
        (
            "keys",
            lambda d: _key(d, "fabric.step.kind").update(
                capture_points=["no.such.point"]
            ),
            "coverage.keys.condition",
        ),
        (
            "roles",
            lambda d: next(
                r for r in d["roles"] if r["role"] == "record.evidence"
            ).update(allowed_modes=["redact", "omit"]),
            "coverage.roles.modes",
        ),
        (
            "fields",
            lambda d: d["evidence_types"][0]["fields"][0].update(
                pointer="/items/*/nope"
            ),
            "coverage.evidence_types.fields",
        ),
        (
            "fields",
            lambda d: d["evidence_types"][0].update(capture_points=["wire.py.httpx"]),
            "coverage.evidence_types.points",
        ),
    ],
)
def test_p1_registry_rules_are_enforced(
    tmp_path: Path, registry: str, change: Callable[[Any], None], code: str
) -> None:
    root = _copy_tree(tmp_path)
    _edit_registry(root, registry, change)
    _assert_code(root, code)
