# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the draft four-layer coverage contracts (spec 049)."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts import action_record  # noqa: E402
from contracts.validate_coverage_contracts import (  # noqa: E402
    FAMILY,
    FREE_TEXT,
    MANIFEST_RECORD_SCHEMA,
    PSEUDONYM_V1_VECTORS,
    PSEUDONYM_V2_TYPES,
    REGISTRY,
    SPEC,
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
        # Spec 056: the action-record fixtures read these outside the family.
        action_record.REPORT_SCHEMA,
        action_record.ALLOWLIST_GO,
        action_record.PROCESSOR_GO,
        *(
            action_record.CAPTURE
            / f"fixtures/valid/spool-record-exec-subprocess-{phase}.json"
            for phase in ("start", "end")
        ),
        # Spec 056 M2: the interface goldens' production, container-create and remote
        # sandbox records
        *(
            action_record.CAPTURE / f"fixtures/valid/spool-record-{name}-{phase}.json"
            for name in (
                "exec-subprocess-production",
                "exec-subprocess-container-create",
                "remote-sandbox-commands-run",
                "remote-sandbox-run-code",
            )
            for phase in ("start", "end")
        ),
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
    assert (
        manifest["version"] == "1.3.0"
    )  # 1.2.0: spec 056 (WP6-01); 1.3.0: 056 M2 (WP6-11)
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
        "fabric.test.items/v1",
        "fabric.exec.observation/v1",  # spec 053 §3.2, registered by spec 056 WP6-01
        "fabric.http.observation/v1",  # spec 053 §3.2, registered by spec 056 WP6-11
        "fabric.sandbox.observation/v1",  # spec 056 §4.4.1 (WP6-11)
    ]


def test_p1_records_table_has_no_content_key_and_matches_the_go_table() -> None:
    reg = load_registries(REPO_ROOT)
    table = record_checks(reg)
    assert "fabric.capture.input" in table and "fabric.attempt.uid" in table
    assert not any(
        marker in key
        for key in table
        # fabric.sensor.result is the host record's closed success/failed/unknown enum
        if key != "fabric.sensor.result"
        for marker in ("content.ref", "arguments", "result", "message", "prompt")
    )
    namespace: dict[str, Any] = {}
    exec(  # noqa: S102 - the generated module only imports typing helpers
        (REPO_ROOT / "sdk/python/src/fabric/_records_keys_generated.py").read_text(),
        namespace,
    )
    assert set(namespace["RECORD_KEY_CHECKS"]) == set(table)
    # Spec 056 §5: the first conditional placements, exec.subprocess only; M2 (§5.1)
    # adds the exec namespace and created id, the http.nonmodel keys and the kind-S
    # host-record keys.
    exec_only = {"capture_points": ["exec.subprocess"]}
    host_only = {"capture_point_kinds": ["S"]}
    http_only = {"capture_points": ["http.nonmodel"]}
    conditions = record_conditions(reg)
    assert {k: v for k, v in conditions.items() if v == exec_only} == {
        k: exec_only
        for k in (
            "fabric.process.parent_pid",
            "fabric.process.start_ns",
            "fabric.process.pid_ns",
            "fabric.sandbox.created_id",
        )
    }
    assert {k for k, v in conditions.items() if v == http_only} == {
        "http.request.method",
        "http.response.status_code",
    }
    assert {k for k, v in conditions.items() if v == host_only} == {
        k for k in table if k.startswith("fabric.sensor.")
    } | {"fabric.tenant_id"}
    assert all(v in (exec_only, host_only, http_only) for v in conditions.values())
    assert {
        key: {column: list(values) for column, values in cond.items()}
        for key, cond in namespace["RECORD_KEY_CONDITIONS"].items()
    } == record_conditions(reg)
    go = (
        REPO_ROOT
        / "components/otel-collector-fabric/processor/fabricguardprocessor/coverage_keys.go"
    ).read_text()
    block = go[
        go.index("var recordKeyValidators") : go.index("var recordKeyConditions")
    ]
    assert set(re.findall(r'^\t"([^"]+)":', block, re.MULTILINE)) == set(table)


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


# ---------------------------------------------------------------- spec 056 (coverage/v1 1.2.0)
from contracts import action_reference as rules  # noqa: E402

ACTION = REPO_ROOT / FAMILY / action_record.ACTION


def _rule(name: str) -> dict[str, Any]:
    value = json.loads((ACTION / "rules" / f"{name}.json").read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_056_inference_methods_and_reasons_are_registered() -> None:
    reg = load_registries(REPO_ROOT)
    methods = {r["value"]: r["confidence"] for r in reg["vocab"]["inference_method"]}
    assert (
        methods["sequence_bracket"] == "tentative"
    )  # OD-5: only A0 and A1 are certain
    # A1 is certain only when one candidate matches; several matches are ambiguous and
    # tentative (an ambiguous link is never certain), so its confidence varies.
    assert methods["output_match"] == "varies"
    assert methods["process_anchor"] == methods["process_lineage"] == "varies"
    assert methods["pid_time_join"] == "tentative"  # 053 §6.3's join is unchanged
    reasons = {r["value"] for r in reg["vocab"]["reason"]}
    assert {
        "unattributed_effect", "ambiguous_attribution", "anchor_missing",
        "unexplained_host_event", "tool_result_missing", "channel_disabled",
        "no_effect_channel", "none_in_window", "remote_sandbox", "exchange_gap",
        "source_gap",
    } <= reasons  # fmt: skip
    keys = {row["key"]: row for row in reg["keys"]["keys"]}
    for key in ("fabric.process.parent_pid", "fabric.process.start_ns"):
        assert keys[key]["placement"] == ["record"]
        assert keys[key]["capture_points"] == ["exec.subprocess"]
    for key in ("fabric.process.pid", "fabric.execution.host_id"):
        assert "record" in keys[key]["placement"] and "capture_points" not in keys[key]
    exec_type = next(
        t
        for t in reg["fields"]["evidence_types"]
        if t["type"] == "fabric.exec.observation/v1"
    )
    assert exec_type["capture_points"] == ["exec.subprocess"]


def test_056_a_varying_method_still_refuses_a_fixed_one(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    _edit_registry(
        root,
        "vocab",
        lambda d: next(
            r for r in d["inference_method"] if r["value"] == "sequence_bracket"
        ).update(confidence="varies"),
    )
    _assert_code(root, "coverage.vocab.confidence")


def test_056_every_rule_and_edge_case_has_its_fixture() -> None:
    valid = {p.stem: _rule(p.stem) for p in (ACTION / "rules").glob("*.json")}
    covered = {r for doc in valid.values() for r in doc["rules"]}
    assert {"A0", "A1", "A2", "A3", "A4", "H1", "H2", "H3", "H4"} <= covered
    for edge in (
        "edge-parallel-distinct-outputs",
        "edge-parallel-metadata-only",
        "edge-clock-margin-boundary",
        "edge-background-thread",
        "edge-pid-reuse",
        "edge-exec-in-place",
        "edge-same-pid-other-parent",
        "edge-lineage-depth-17",
        "edge-agent-uncalled-host",
        "edge-a1-several-matches",
        "edge-lineage-pid-reuse",
        "ar1-run",
    ):
        assert edge in valid, edge  # fmt: skip
    invalid = {p.stem[:2] for p in (ACTION / "invalid").glob("*.json")}
    # M2 (WP6-11) adds h1-, h5- and sandbox-scope- refusals
    assert {"a0", "a1", "a2", "a3", "a4", "h1", "h2", "h3", "h4"} <= invalid
    manifest = json.loads((REPO_ROOT / FAMILY / "manifest.json").read_text())
    pinned = {r["path"]: r for r in manifest["artifacts"]}
    for path in (ACTION / "invalid").glob("*.json"):
        record = pinned[path.relative_to(REPO_ROOT / FAMILY).as_posix()]
        assert record["expectation"] == "invalid" and record["expected_error"]


def test_056_rule_fixtures_pin_the_rule_that_decides() -> None:
    def trace(name: str) -> dict[str, Any]:
        value: dict[str, Any] = _rule(name)["expected"]["trace"]
        return value

    assert list(trace("a0-reported-parent")["effects"].values()) == ["A0"]
    assert list(trace("a2-single-window")["effects"].values()) == ["A2"]
    assert list(trace("edge-parallel-distinct-outputs")["effects"].values()) == [
        "A1",
        "A1",
    ]
    assert list(trace("edge-parallel-metadata-only")["effects"].values()) == [
        "A3",
        "A3",
    ]
    assert list(trace("edge-background-thread")["effects"].values()) == ["A1", "A4"]
    assert list(trace("edge-pid-reuse")["anchors"].values()) == ["H2-ambiguous"]
    # Spec 056 §4.3 exec chains: an in-place re-exec is one process, anchored tentative on
    # its first exec; the later exec is lineage at depth 0. Another parent pid is not.
    assert list(trace("edge-exec-in-place")["anchors"].values()) == ["H2"]
    in_place = trace("edge-exec-in-place")["host_events"]
    assert list(in_place.values()) == ["H2", "H3", "H3"]
    assert list(trace("edge-same-pid-other-parent")["host_events"].values()) == [
        "H2", "unexplained", "unexplained"
    ]  # fmt: skip
    depth = _rule("edge-lineage-depth-17")["expected"]
    assert depth["attribution"]["lineage_truncated"] == 1
    assert depth["attribution"]["links"]["process_lineage"]["resolved"] == 16
    assert list(trace("edge-agent-uncalled-host")["host_events"].values()) == [
        "H4", "H4-uncalled"
    ]  # fmt: skip
    # Spec 056 rev 8 (0.11.2, B4): both boundaries are on the effect's own epoch, so the
    # clock margin does not widen them; the effect between them is in neither window.
    margin = _rule("edge-clock-margin-boundary")["expected"]
    assert margin["projection_links"] == []
    assert list(margin["trace"]["effects"].values()) == ["A4"]


def test_056_ar1_expectation_is_the_spec_table() -> None:
    """Spec 056 §6.2: the expected links and chain verdicts of AR-1."""
    doc = _rule("ar1-run")
    expected = doc["expected"]
    effects = doc["input"]["effects"]
    methods = [
        [(link["method"], link["confidence"]) for link in entry["links"]]
        for entry in expected["projection_links"]
    ]
    anchor = ("process_anchor", "certain")
    assert methods == [[("output_match", "certain"), anchor]] * 5 + [[anchor]]
    unattributed = expected["attribution"]["unattributed_effects"]["effects"]
    assert [e["attempt_uid"] for e in unattributed] == [effects[5]["attempt_uid"]]
    lineage = {
        e["event_id"]: e["links"][0]["target"]["id"]
        for e in expected["sensor_events"]
        if any(link["method"] == "process_lineage" for link in e.get("links", []))
    }
    by_label = {e["label"]: e["event_id"] for e in doc["input"]["host_events"]}
    assert lineage == {
        by_label["exec-curl"]: effects[1]["attempt_uid"],
        by_label["connect-curl"]: effects[1]["attempt_uid"],
        by_label["exec-python"]: effects[4]["attempt_uid"],
    }
    assert expected["attribution"]["unexplained_host_events"]["event_ids"] == [
        by_label["connect-uncalled"]
    ]
    assert {k: v.get("reasons", []) for k, v in expected["chains"].items()} == {
        "decisions": [], "actions": [], "effects": ["unattributed_effect"],
        "corroboration": ["unexplained_host_event"],
    }  # fmt: skip
    local = _rule("ar1-run-local-profile")["expected"]
    confidences = {
        link["confidence"]
        for entry in local["projection_links"]
        for link in entry["links"]
        if link["method"] == "process_anchor"
    }
    assert confidences == {"tentative"}  # no start time: never certain


def test_056_negative_variants() -> None:
    a = _rule("ar1-negative-a-no-host-source")["expected"]["chains"]
    assert a["corroboration"]["verdict"] == "not_observed"
    assert a["effects"] == _rule("ar1-run")["expected"]["chains"]["effects"]
    b = _rule("ar1-negative-b-effect-dropped")["expected"]["chains"]
    assert b["effects"]["reasons"][0] == "sequence_gap"
    # The lost position is on the epoch the exchanges share (050 §3.3): nothing proves it
    # was not an exchange, so decisions is partial(sequence_gap) as the verifier reports.
    assert b["decisions"] == {"verdict": "partial", "reasons": ["sequence_gap"]}
    c = _rule("ar1-negative-c-hook-disabled")["expected"]
    assert c["chains"]["effects"]["verdict"] == "not_observed"
    assert c["attribution"]["effects_not_observed"]["channel_disabled"] == 5
    d = _rule("ar1-negative-d-metadata-only")["expected"]
    assert d["attribution"]["output_match"] == {
        "state": "not_applicable", "reason": "privacy_policy"
    }  # fmt: skip
    assert list(d["trace"]["effects"].values())[2:4] == ["A3", "A3"]


def test_056_reference_boundaries() -> None:
    assert rules.same_tick(60_120_000_000, 60_123_217_448)
    assert not rules.same_tick(60_120_000_000, 60_130_000_000)
    doc = _rule("a1-output-match")
    inp = copy.deepcopy(doc["input"])
    output = "x" * (rules.MIN_MATCH_BYTES - 1) + " \n"
    inp["effects"][0]["stdout"] = output
    inp["exchanges"][1]["tool_results"][0]["text"] = "result: " + output
    assert list(
        rules.reconstruct(inp, action_record.call_id)["trace"]["effects"].values()
    ) == [
        "A2"
    ]  # 15 bytes after trailing whitespace: too short to match, never a weaker match
    inp["effects"][0]["stdout"] = "x" * rules.MIN_MATCH_BYTES + "\n"
    inp["exchanges"][1]["tool_results"][0]["text"] = (
        "result: " + "x" * rules.MIN_MATCH_BYTES
    )
    assert list(
        rules.reconstruct(inp, action_record.call_id)["trace"]["effects"].values()
    ) == ["A1"]
    h1 = copy.deepcopy(_rule("h1-anchor-exact")["input"])
    h1["host_events"][0]["process_start_ns"] += rules.TICK_NS  # a different process
    assert list(
        rules.reconstruct(h1, action_record.call_id)["trace"]["anchors"].values()
    ) == ["anchor_missing"]


def test_056_a_drifted_rule_expectation_is_refused(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    relative = (action_record.ACTION / "rules/a2-single-window.json").as_posix()
    _rewrite(
        root,
        relative,
        lambda d: d["expected"]["chains"]["effects"].update(verdict="complete"),
    )
    validate_coverage_contracts(root)  # unchanged values: still valid
    _rewrite(
        root,
        relative,
        lambda d: d["expected"]["projection_links"][0]["links"][0]["target"].update(
            id="p-" + "0" * 32
        ),
    )
    _assert_code(root, "coverage.action.expected")


def test_056_interface_goldens() -> None:
    golden = json.loads(
        (ACTION / "interface/exec-subprocess-records.json").read_text(encoding="utf-8")
    )
    start = golden["records"][0]["span"]["attributes"]
    assert golden["records"][0]["span"]["name"] == "fabric.activity"
    assert start["fabric.capture.point"].startswith("exec.subprocess@")
    assert start["fabric.capture.source"] == "observed"
    assert {"fabric.process.pid", "fabric.process.parent_pid", "fabric.process.start_ns",
            "fabric.execution.host_id"} <= set(start)  # fmt: skip
    roles = [b["role"] for r in golden["records"] for b in r["bodies"]]
    assert roles == [
        "terminal.argv", "terminal.context", "record.evidence",
        "terminal.stdout", "terminal.stderr", "record.evidence",
    ]  # fmt: skip
    context = json.loads(golden["records"][0]["bodies"][1]["utf8"])
    assert context["env_names"] == ["DATA_TOKEN", "PATH"]  # names only, never values
    local = json.loads(
        (ACTION / "interface/host-local-log-records.json").read_text(encoding="utf-8")
    )
    ids = [n["event_id"] if n else None for n in local["normalized"]]
    assert (
        ids[0].startswith("host-") and ids[3] is None
    )  # a loss record is not an event
    assert ids[4].startswith("hev-") and ids[5].startswith("rec-")
    assert all("process_start_ns" not in n for n in local["normalized"] if n)


def test_056_interface_golden_refuses_an_unadmitted_host_key(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    relative = (
        action_record.ACTION / "interface/host-local-log-records.json"
    ).as_posix()

    def add_key(doc: Any) -> None:
        record = doc["export"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
        record["attributes"].append(
            {"key": "process.command_line", "value": {"stringValue": "sh -c ls"}}
        )

    _rewrite(root, relative, add_key)
    _assert_code(root, "coverage.action.interface")


def test_056_several_a1_matches_are_tentative_and_ambiguous() -> None:
    """An ambiguous link is never certain (§4.1): A1 with two matches links both, each
    output_match, tentative, ambiguous."""
    doc = _rule("edge-a1-several-matches")["expected"]
    assert list(doc["trace"]["effects"].values()) == ["A1-ambiguous", "A1-ambiguous"]
    for entry in doc["projection_links"]:
        assert {(link["method"], link["confidence"], link["state"])
                for link in entry["links"]} == {("output_match", "tentative", "ambiguous")}  # fmt: skip
        assert len(entry["links"]) == 2
    assert doc["chains"]["effects"] == {
        "verdict": "partial",
        "reasons": ["ambiguous_attribution"],
    }


def test_056_a_reused_pid_leaves_the_lineage() -> None:
    """An unrelated exec of the anchored pid (another parent, a later start) proves pid
    reuse: it, its connect and its child are unexplained, never lineage."""
    doc = _rule("edge-lineage-pid-reuse")
    trace = doc["expected"]["trace"]["host_events"]
    by_label = {e["label"]: e["event_id"] for e in doc["input"]["host_events"]}
    assert trace[by_label["exec-sh"]] == "H1" and trace[by_label["exec-curl"]] == "H3"
    for label in ("exec-reused", "connect-reused", "exec-reused-child"):
        assert trace[by_label[label]] == "unexplained", label
    # The reference without the reuse rule would link all three: pin the difference.
    inp = copy.deepcopy(doc["input"])
    for event in inp["host_events"]:
        if event["label"] == "exec-reused":
            event["ppid"] = 4100  # the same parent and ...
            event["process_start_ns"] = inp["effects"][0][
                "process_start_ns"
            ]  # same tick
    again = rules.reconstruct(inp, action_record.call_id)["trace"]["host_events"]
    assert again[by_label["exec-reused"]] == "H3"  # then it is the same process


def test_056_window_margin_and_peerless_syscalls() -> None:
    """H4 and the unexplained list use the run window widened by both clock margins;
    socket() and bind() never count as connections to an uncalled peer."""
    doc = _rule("edge-agent-uncalled-host")
    inp = copy.deepcopy(doc["input"])
    margin = (
        inp["agent"]["clock_uncertainty_ns"]
        + inp["host_sources"][0]["clock_uncertainty_ns"]
    )
    uncalled = next(e for e in inp["host_events"] if e["label"] == "connect-uncalled")
    uncalled["time_ns"] = inp["run"]["window"][1] + margin
    trace = rules.reconstruct(inp, action_record.call_id)["trace"]["host_events"]
    assert trace[uncalled["event_id"]] == "H4-uncalled"
    uncalled["time_ns"] += 1
    trace = rules.reconstruct(inp, action_record.call_id)["trace"]["host_events"]
    assert trace[uncalled["event_id"]] == "outside_run"
    uncalled["time_ns"] -= 1
    uncalled["syscall"] = "bind"
    trace = rules.reconstruct(inp, action_record.call_id)["trace"]["host_events"]
    assert trace[uncalled["event_id"]] == "H4"


# ---------------------------------------------------------------- spec 056 M2 (coverage/v1 1.3.0)
from contracts import (  # noqa: E402
    action_record_m2,
    host_records,
)
from contracts.validate_coverage_contracts import (  # noqa: E402
    point_kinds as coverage_point_kinds,
    record_checks as coverage_record_checks,
    record_conditions as coverage_record_conditions,
)

M2_RULE_FIXTURES = (
    "h1-anchor-exact-production",
    "edge-production-other-namespace",
    "edge-nested-pid-namespace",
    "edge-start-tick-boundary",
    "h5-sandbox-report",
    "h5-pod-report",
    "h5-pod-report-other-node",
    "edge-mixed-namespace-modes",
    "edge-recorded-effect-without-pid-ns",
    "edge-thread-spawned-child",
    "edge-quiet-host-epoch",
    "edge-sandbox-peer-port",
    "edge-scope-late",
    "edge-sandbox-unlinked",
    "edge-sandbox-before-effect",
    "remote-sandbox-output-match",
    "edge-remote-sandbox-off",
    "ar1-run-production",
    "ar1-negative-f-remote-sandbox-off",
    "ar1-negative-g-container-id-not-reported",
)
M2_REFUSED = {
    "h5-sandbox-report-claims-inferred": "coverage.action.link",
    "h5-tentative": "coverage.action.confidence",
    "h1-across-pid-namespaces": "coverage.action.namespace",
    "sandbox-scope-listed-unexplained": "coverage.action.scope",
}


def _trace_by_label(doc: dict[str, Any]) -> dict[str, str]:
    labels = {e["event_id"]: e["label"] for e in doc["input"]["host_events"]}
    trace = doc["expected"]["trace"]["host_events"]
    return {labels[k]: v for k, v in trace.items()}


def test_056_m2_sensor_keys_are_s_scoped() -> None:
    """053 §6.2.3 keys are records keys only on a capture point of kind S; the upstream
    loss keys ride periodic heartbeats; the M2 agent keys are point-scoped."""
    reg = load_registries(REPO_ROOT)
    rows = {row["key"]: row for row in reg["keys"]["keys"]}
    sensor = {k for k in rows if k.startswith("fabric.sensor.")}
    upstream = {"fabric.sensor.upstream_lost", "fabric.sensor.upstream_loss_reason"}
    assert {
        "fabric.sensor.ns_pid", "fabric.sensor.ns_ppid", "fabric.sensor.pid_ns",
        "fabric.sensor.scope", "fabric.sensor.pod_id", "fabric.sensor.process_start_ns",
    } <= sensor  # fmt: skip
    for key in sensor - upstream:
        assert rows[key]["placement"] == ["record"], key
        assert rows[key]["capture_point_kinds"] == ["S"], key
    for key in upstream:
        assert rows[key]["placement"] == ["periodic"], key
        assert "capture_point_kinds" not in rows[key]
    reasons = rows["fabric.sensor.upstream_loss_reason"]["check"]["values"]
    assert reasons[-2:] == ["scope_late", "unknown"]
    assert rows["fabric.tenant_id"]["capture_point_kinds"] == ["S"]
    for key in ("fabric.process.pid_ns", "fabric.sandbox.created_id"):
        assert rows[key]["capture_points"] == ["exec.subprocess"]
    for key in ("http.request.method", "http.response.status_code"):
        assert rows[key]["capture_points"] == ["http.nonmodel"]
        assert rows[key]["placement"] == ["exchange", "record"]
    assert rows["fabric.network.host_id"]["placement"] == ["record"]
    points = {p["id"]: p for p in reg["points"]["capture_points"]}
    assert points["remote.sandbox"]["kind"] == "H"
    assert points["remote.sandbox"]["passivity_gate"] == "P4-SANDBOX"
    assert points["http.nonmodel"]["input"] == "records"
    methods = {r["value"]: r["confidence"] for r in reg["vocab"]["inference_method"]}
    assert methods["sandbox_report"] == "certain"
    # rule A: kept on a host record, dropped on an agent record of the same keys
    attrs = {"fabric.sensor.pid": 4121, "fabric.sensor.scope": "agent"}
    table = coverage_record_checks(reg)
    for point, kept in (("host.ebpf@0.11.0", True), ("exec.subprocess@0.11.0", False)):
        admitted, _ = ref.project_record_attributes(
            {**attrs, "fabric.capture.point": point},
            table,
            check_value,
            conditions=coverage_record_conditions(reg),
            point_kinds=coverage_point_kinds(reg),
        )
        assert ("fabric.sensor.pid" in admitted) is kept, point
    # the generated tables carry the same conditions (fabricguard, the SDK)
    go = (
        REPO_ROOT
        / "components/otel-collector-fabric/processor/fabricguardprocessor/coverage_keys.go"
    ).read_text()
    assert '"fabric.sensor.pid":' in go and '{"capture_point_kinds": {"S"}}' in go
    py = (REPO_ROOT / "sdk/python/src/fabric/_records_keys_generated.py").read_text()
    assert "'fabric.sensor.ns_pid'" in py or '"fabric.sensor.ns_pid"' in py


def test_056_m2_rule_fixtures_match_reference() -> None:
    """Every §6.1 M2 rule fixture exists, validates, and its expected output is the
    reference's; M1 fixtures keep their M1 expectations under the M2 rules."""
    names = {p.stem for p in (ACTION / "rules").glob("*.json")}
    assert set(M2_RULE_FIXTURES) <= names
    reg = load_registries(REPO_ROOT)
    for name in M2_RULE_FIXTURES:
        doc = _rule(name)
        assert doc["expected"] == rules.reconstruct(
            doc["input"], action_record.call_id
        ), name
        assert action_record.validate_document(doc, reg, REPO_ROOT)
    trace = _trace_by_label(_rule("h1-anchor-exact-production"))
    assert trace == {"exec-sh": "H1"}
    assert list(
        _rule("edge-production-other-namespace")["expected"]["trace"][
            "anchors"
        ].values()
    ) == ["anchor_missing"]
    nested = _trace_by_label(_rule("edge-nested-pid-namespace"))
    assert [
        nested[k] for k in ("exec-python-inner", "exec-sh-inner", "open-inner")
    ] == ["H3"] * 3
    tick = _rule("edge-start-tick-boundary")["expected"]["trace"]["anchors"]
    assert list(tick.values()) == ["H1", "anchor_missing"]
    mixed = _trace_by_label(_rule("edge-mixed-namespace-modes"))
    assert mixed == {"exec-sh-ebpf": "H1", "exec-sh-auditd": "H3", "connect-model-ebpf": "H4",
                     "connect-model-auditd": "unexplained"}  # fmt: skip
    assert list(
        _rule("edge-recorded-effect-without-pid-ns")["expected"]["trace"][
            "anchors"
        ].values()
    ) == ["anchor_missing"]
    assert set(
        _rule("edge-thread-spawned-child")["expected"]["trace"]["anchors"].values()
    ) == {"H1"}
    quiet = _rule("edge-quiet-host-epoch")["expected"]
    assert quiet["chains"]["corroboration"] == {"verdict": "complete"}
    assert [s["basis"] for s in quiet["trace"]["host_sources"].values()][1] == [
        "manifest",
        "declared",
    ]
    empty = _rule("edge-declared-source-empty")["expected"]["chains"]["corroboration"]
    assert empty == {"verdict": "partial", "reasons": ["source_gap"]}
    late = _rule("edge-scope-late")["expected"]["chains"]["corroboration"]
    assert late == {"verdict": "partial", "reasons": ["source_gap"]}
    port = _rule("edge-sandbox-peer-port")
    assert _trace_by_label(port) == {
        "connect-model": "H4",
        "connect-provider": "H4-sandbox",
    }
    assert port["expected"]["attribution"]["remote_sandbox_calls"]["count"] == 1
    unlinked = _rule("edge-sandbox-unlinked")["expected"]
    assert unlinked["attribution"]["sandbox_events_unlinked"] == {"count": 3}
    assert unlinked["attribution"]["unexplained_host_events"]["count"] == 0
    assert unlinked["chains"]["corroboration"] == {"verdict": "complete"}
    before = _trace_by_label(_rule("edge-sandbox-before-effect"))
    assert (before["exec-before"], before["exec-after"]) == ("sandbox-unlinked", "H5")
    remote = _rule("remote-sandbox-output-match")["expected"]
    assert remote["trace"]["anchors"] == {} and remote["chains"]["corroboration"] == {
        "verdict": "complete"
    }
    off = _rule("edge-remote-sandbox-off")["expected"]
    assert off["chains"]["effects"] == {
        "verdict": "partial",
        "reasons": ["remote_sandbox"],
    }
    assert off["attribution"]["effects_not_observed"]["channel_disabled"] == 1
    assert off["attribution"]["unexplained_host_events"]["count"] == 0
    ar1 = _rule("ar1-run-production")["expected"]
    assert {k: v.get("reasons", []) for k, v in ar1["chains"].items()} == {
        "decisions": [], "actions": [], "effects": ["unattributed_effect"],
        "corroboration": ["unexplained_host_event"],
    }  # fmt: skip
    assert ar1["attribution"]["sandbox_events_unlinked"] == {"count": 0}
    anchors = [link for e in ar1["projection_links"] for link in e["links"]
               if link["method"] == "process_anchor"]  # fmt: skip
    assert {(a["confidence"], a["state"]) for a in anchors} == {("certain", "resolved")}
    f = _rule("ar1-negative-f-remote-sandbox-off")["expected"]
    assert f["chains"]["effects"]["reasons"] == [
        "unattributed_effect",
        "remote_sandbox",
    ]
    assert f["attribution"]["remote_sandbox_calls"]["count"] == 2
    g = _rule("ar1-negative-g-container-id-not-reported")["expected"]
    assert g["attribution"]["sandbox_events_unlinked"] == {"count": 2}
    assert "sandbox_report" not in g["attribution"]["links"]
    assert g["chains"]["corroboration"] == ar1["chains"]["corroboration"]


def test_056_m2_h5_is_reported_and_certain() -> None:
    """Every sandbox_report link: part_of the attempt that reported the id, provenance
    reported, certain, resolved; on any host source; never before the effect."""
    seen = 0
    for path in sorted((ACTION / "rules").glob("*.json")):
        doc = _rule(path.stem)
        effects = {e["attempt_uid"]: e for e in doc["input"]["effects"]}
        events = {e["event_id"]: e for e in doc["input"]["host_events"]}
        for entry in doc["expected"]["sensor_events"]:
            for link in entry.get("links", []):
                if link["method"] != "sandbox_report":
                    continue
                seen += 1
                assert (link["type"], link["provenance"], link["confidence"], link["state"]) == (
                    "part_of", "reported", "certain", "resolved")  # fmt: skip
                effect = effects[link["target"]["id"]]
                event = events[entry["event_id"]]
                assert effect["created_sandbox_id"] in (
                    event.get("sandbox_id"),
                    event.get("pod_id"),
                )
                assert event["time_ns"] >= effect["start_ns"] - 3 * action_record.MS
    assert seen >= 10
    other = _rule("h5-pod-report-other-node")
    sources = {e["event_id"]: e["source_id"] for e in other["input"]["host_events"]}
    linked = {e["event_id"] for e in other["expected"]["sensor_events"]
              if any(link["method"] == "sandbox_report" for link in e.get("links", []))}  # fmt: skip
    assert {sources[e] for e in linked} == {action_record_m2.SOURCE_B}
    assert _trace_by_label(other)["exec-other-node-same-numbers"] == "unexplained"
    # a created id never upgrades content: the effect keeps its A1 output_match link
    links = other["expected"]["projection_links"][0]["links"]
    assert [link["method"] for link in links] == ["output_match", "process_anchor"]


def test_056_m2_refused_fixtures(tmp_path: Path) -> None:
    pinned = {
        r["path"]: r
        for r in json.loads((REPO_ROOT / FAMILY / "manifest.json").read_text())[
            "artifacts"
        ]
    }
    reg = load_registries(REPO_ROOT)
    for name, code in M2_REFUSED.items():
        path = ACTION / "invalid" / f"{name}.json"
        record = pinned[path.relative_to(REPO_ROOT / FAMILY).as_posix()]
        assert (record["expectation"], record["expected_error"]) == ("invalid", code)
        doc = json.loads(path.read_text(encoding="utf-8"))
        with pytest.raises(CoverageContractError) as caught:
            action_record.validate_document(doc, reg, REPO_ROOT)
        assert caught.value.code == code, name
        assert doc["expected"] != rules.reconstruct(doc["input"], action_record.call_id)


def test_056_m2_peer_address_and_sandbox_id_vectors() -> None:
    vectors = REPO_ROOT / FAMILY / "fixtures/vectors"
    peer = json.loads((vectors / "peer-address-v1.json").read_text(encoding="utf-8"))
    texts = {c["input"]: c["text"] for c in peer["cases"]}
    assert texts["::ffff:10.0.4.7"] == texts["::ffff:a00:407"] == "10.0.4.7"
    assert texts["2001:DB8:0:0:1:0:0:1"] == "2001:db8::1:0:0:1"
    assert texts["2001:db8:0:1:1:1:1:1"] == "2001:db8:0:1:1:1:1:1"
    assert texts["fe80::1%eth0"] is None and texts["10.0.4.7:443"] is None
    for case in peer["cases"]:
        assert host_records.peer_text(case["input"]) == case["text"]
        if "bytes_hex" in case:
            assert (
                host_records.peer_text(bytes.fromhex(case["bytes_hex"])) == case["text"]
            )
        if case["text"] is not None:
            assert case["host_id"] == pseudonym_v2(
                "hst", "host", case["text"], peer["key"]
            )
    sandbox = json.loads((vectors / "sandbox-id-v1.json").read_text(encoding="utf-8"))
    for case in sandbox["cgroups"]:
        assert host_records.sandbox_ids(case["path"]) == host_records.sandbox_ids(
            case["last_two"]
        )
        assert host_records.sandbox_ids(case["path"]) == (
            case["container_id"],
            case["pod_uid"],
        )
    names = {c["name"]: c for c in sandbox["outputs"]}
    for form in ("docker run -d (shell string)", "docker run -d (argv)", "podman create",
                 "kubectl run -o jsonpath, quoted in the shell", "kubectl apply -o json, a Pod"):  # fmt: skip
        assert names[form]["created_id"] is not None, form
    for form in ("a foreground docker run prints the container's output", "a compound shell command",
                 "kubectl -o json of a List", "output with two trailing newlines"):  # fmt: skip
        assert names[form]["created_id"] is None, form
    for case in sandbox["outputs"]:
        clear = host_records.created_clear_text(case["command"], case["stdout"])
        assert clear == case["clear"], case["name"]
    # both sides key the same clear text alike: a created id equals the emitter's id
    docker = names["docker run -d (argv)"]["created_id"]
    assert docker in {
        c["ids"].get("fabric.execution.sandbox_id") for c in sandbox["cgroups"]
    }
