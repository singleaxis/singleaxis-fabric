# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric.step-projection/v1`` (spec 050 §3.13, WP-32).

Every projection built here goes through :func:`project`, which validates it with the
contract validator's ``validate_projection`` (schema plus semantic rules): C1-3 and T1.
The ``projection-*`` valid fixtures of ``contracts/coverage/v1/valid`` are reproduced from
synthetic captures (the ``Capture`` builder of ``test_reconstruct_verifier``, with uuid4
object ids and P1 run_end statuses), one test per fixture, and C1-5 has one test per row of
the 049 §6.2 step and run decision tables.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from fabric._seal import canonical_bytes
from fabric.reconstruct import _project
from fabric.reconstruct.__main__ import main
from fabric.reconstruct._evidence import (
    EVIDENCE_TYPES,
    decode_evidence,
    resolve_pointer,
)
from fabric.reconstruct._graph import DEFAULT_OPEN_RUN_DEADLINE_S, RunGraph
from fabric.reconstruct._project import (
    FIELD_ROWS,
    KEY_ROWS,
    PROFILES,
    ROLE_FIELDS,
    RUN_RULES,
    STEP_RULES,
    ProjectionCollector,
    RunEval,
    StepEval,
    build_projection,
    decide,
    field_class,
)
from fabric.reconstruct._verify import reconstruct
from tests.test_reconstruct_verifier import (
    BASE_NS,
    COVERAGE,
    COVERAGE_REGISTRY,
    GENERATED_AT,
    REPO_ROOT,
    RUN,
    SYSTEM,
    TENANT,
    USER,
    Capture,
    chat_response,
    sha_hex,
    stamp,
    validate,
)

FAMILY = REPO_ROOT / "contracts" / "coverage" / "v1"
PROJECTION_SCHEMA = json.loads((FAMILY / "schema" / "step-projection-v1.schema.json").read_text())
REGISTRY = json.loads((FAMILY / "registry" / "field-registry-v1.json").read_text())
EVIDENCE_VECTOR = json.loads(
    (FAMILY / "fixtures" / "vectors" / "record-evidence-v1.json").read_text()
)
GOLDENS = FAMILY / "fixtures" / "projection"
KEY = b"fabric-test-id-key-not-a-secret"
S = 1_000_000_000
RUN_B = "r-" + "b" * 32


def fixture(name: str) -> dict[str, Any]:
    return dict(json.loads((FAMILY / "valid" / f"{name}.json").read_text()))


def golden(name: str) -> dict[str, Any]:
    return dict(json.loads((GOLDENS / f"{name}.json").read_text()))


def object_uuid(*parts: str) -> str:
    digest = hashlib.sha256("/".join(parts).encode()).digest()[:16]
    return str(uuid.UUID(bytes=digest, version=4))


class PCapture(Capture):
    """The verifier tests' capture worker, as P1 writes: uuid4 object ids, a
    ``fabric.run.scope_status`` on every P1 run_end, enriched exchange spans, and records
    bodies under a chosen role (``object_roles``, consumed in order)."""

    def __init__(self, root: Path, **kwargs: Any) -> None:
        super().__init__(root, **kwargs)
        self.object_roles: list[tuple[str, str]] = []  # (role, media type)

    def _put(
        self, exchange_id: str, sequence: int, run_id: str, role: str, data: bytes, *,
        media_type: str, content_encoding: str, truncated: bool,
    ) -> str:  # fmt: skip
        assert self.store is not None
        object_id = object_uuid(self.source_id, exchange_id, role)
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2", "object_id": object_id,
            "tenant_id": TENANT, "role": role, "media_type": media_type, "encoding": "binary",
            "content_encoding": content_encoding,
            "representation": "truncated" if truncated else "exact",
            "transformations": ["truncate"] if truncated else [], "provenance": "protocol",
            "boundary": "provider_bound", "source_id": self.source_id,
            "source_epoch": self.epoch, "source_sequence": sequence,
            "captured_at": stamp(self._ns(sequence)),
            "status": "truncated" if truncated else "stored", "run_id": run_id,
            "operation_id": exchange_id, "stored_byte_length": len(data),
            "stored_sha256": "sha256:" + sha_hex(data),
            "ref": self.store.evidence_ref_for(object_id),
        }  # fmt: skip
        if truncated:
            descriptor["source_byte_length"] = len(data) * 2
        else:
            descriptor["source_byte_length"] = len(data)
            descriptor["source_sha256"] = "sha256:" + sha_hex(data)
        self.store.put_bytes_object(descriptor, data)
        return object_id

    def _put_record_object(self, object_id: str, sequence: int, data: bytes | None) -> str | None:
        if not self.object_roles or data is None:
            return super()._put_record_object(object_id, sequence, data)
        role, media = self.object_roles.pop(0)
        assert self.store is not None
        digest = "sha256:" + sha_hex(data)
        self.store.put_bytes_object(
            {"schema_version": "fabric.content-object/v2", "object_id": object_id,
             "tenant_id": TENANT, "role": role, "media_type": media, "boundary": "caller",
             "provenance": "caller_reported", "source_id": self.source_id,
             "source_epoch": self.epoch, "source_sequence": sequence,
             "captured_at": stamp(self._ns(sequence)), "status": "stored",
             "representation": "exact", "stored_byte_length": len(data),
             "stored_sha256": digest, "ref": self.store.evidence_ref_for(object_id)},
            data,
        )  # fmt: skip
        return digest

    def run_end(self, run_id: str, scope_id: str | None = None, *, status: str = "ok") -> str:
        p1 = run_id in self.open_segments
        scope = super().run_end(run_id, scope_id)
        if p1:
            self.rows[-1]["attributes"]["fabric.run.scope_status"] = status
        return scope

    def call(
        self, request: Any, response: Any = None, *, run_id: str = RUN, model: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:  # fmt: skip
        """An enriched P1 exchange (WP-14 keys): endpoint, capture point and source."""
        row = self.exchange(request, response, run_id=run_id, **kwargs).span
        row["attributes"].update({
            "fabric.wire.endpoint_id": "openai.default",
            "fabric.capture.point": "wire.py.httpx@1.2.0",
            "fabric.capture.source": "observed",
        })  # fmt: skip
        if model is not None:
            row["attributes"]["gen_ai.response.model"] = model
        return row


@pytest.fixture
def capture(tmp_path: Path) -> PCapture:
    capture = PCapture(tmp_path)
    capture.manifest()
    return capture


def validate_projection(document: Mapping[str, Any]) -> None:
    """C1-3 / T1: the contract validator's schema and semantic rules."""
    COVERAGE.validate_projection(document, COVERAGE_REGISTRY, PROJECTION_SCHEMA)


def project(
    capture: Capture, *, evaluated_at: datetime | None = None,
    coverage: str = _project.DEFAULT_COVERAGE_PROFILE, **kwargs: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:  # fmt: skip
    """Reconstruct ``capture`` and build, validate and return ``(report, projection)``."""
    collector = ProjectionCollector()
    graphs: list[RunGraph] = []
    kwargs.setdefault("store", capture.store)
    report = reconstruct(
        [capture.write()], generated_at=GENERATED_AT, evaluated_at=evaluated_at,
        graphs_out=graphs, projection_sink=collector, **kwargs,
    )  # fmt: skip
    validate(report)
    projection = build_projection(
        report, graphs=graphs, reconstruction_sha256="sha256:" + "0" * 64,
        evaluated_at=evaluated_at or GENERATED_AT, coverage_profile=coverage, collector=collector,
    )  # fmt: skip
    assert projection is not None
    validate_projection(projection)
    return report, projection


def run_of(projection: Mapping[str, Any], run_id: str = RUN) -> dict[str, Any]:
    return next(dict(run) for run in projection["runs"] if run["run_id"] == run_id)


def steps_of(projection: Mapping[str, Any], kind: str) -> list[dict[str, Any]]:
    return [step for step in projection["steps"] if step["step_kind"] == kind]


def verdicts(entry: Mapping[str, Any]) -> dict[str, tuple[str, tuple[str, ...]]]:
    return {layer: (v["verdict"], tuple(v.get("reasons", ())))
            for layer, v in entry["layer_verdicts"].items()}  # fmt: skip


def field(step: Mapping[str, Any], key: str) -> dict[str, Any]:
    for fieldset in step["layers"].values():
        if key in fieldset:
            return dict(fieldset[key])
    raise KeyError(key)


def status(step: Mapping[str, Any], key: str) -> str:
    wrapper = field(step, key)
    reason = wrapper.get("reason")
    return str(wrapper["status"]) + (f"({reason})" if reason else "")


def simple_turn(user: str = "Weather in Paris?", rid: str = "chatcmpl-1") -> tuple[Any, Any]:
    request = {"model": "gpt-4o", "messages": [SYSTEM, {"role": "user", "content": user}]}
    return request, chat_response({"role": "assistant", "content": "18C."}, rid)


def start(
    capture: PCapture, run_id: str, segment: str, *predecessors: str, id_basis: str = "caller",
    extra: Mapping[str, Any] | None = None,
) -> str:  # fmt: skip
    scope = capture.run_start(
        run_id, segment_id=segment, predecessors=predecessors or ("none",), id_basis=id_basis
    )
    capture.rows[-1]["attributes"].update(extra or {})
    return scope


def seal(
    capture: PCapture, run_id: str, segment: str, *, terminal: bool = False, call: bool = True,
    extra: Mapping[str, Any] | None = None,
) -> str:  # fmt: skip
    """One model call in the open block, then close it and seal ``segment``; returns its
    predecessor entry."""
    if call:
        capture.call(*simple_turn(rid=f"chatcmpl-{capture.sequence}"), run_id=run_id)
    capture.run_end(run_id)
    capture.segment_seal(run_id, segment_id=segment, terminal=terminal)
    capture.rows[-1]["attributes"].update(extra or {})
    last = capture.sequence - 1
    return f"{segment}/{capture.source_id}/{capture.epoch}/{last}/{capture.manifest_digest}"


RESUMABLE = {"fabric.run.resumable": True}


def branched_run(capture: PCapture) -> list[str]:
    """A resumable root and two branches continuing it, every segment sealed non-terminal
    (the shape of ``projection-run-open-branches``)."""
    root, left, right = capture.new_segment(), capture.new_segment(), capture.new_segment()
    start(capture, RUN, root, extra={**RESUMABLE, "fabric.run.open_deadline_s": 259_200})
    entry = seal(capture, RUN, root, extra=RESUMABLE)
    start(capture, RUN, left, entry, id_basis="token")
    seal(capture, RUN, left, extra=RESUMABLE)
    start(capture, RUN, right, entry, id_basis="token")
    seal(capture, RUN, right, extra=RESUMABLE)
    capture.heartbeat()
    return [root, left, right]


def segment_shape(run: Mapping[str, Any]) -> list[tuple[str, bool | None, int]]:
    """``(state, terminal, number of predecessors)`` per segment, in id order."""
    return [(s["state"], s.get("terminal"), len(s["predecessors"]))
            for s in sorted(run["segments"], key=lambda s: s["segment_id"])]  # fmt: skip


def fixture_shape(name: str) -> tuple[str, dict[str, tuple[str, tuple[str, ...]]], list[Any]]:
    (run,) = fixture(name)["runs"]
    return run["run_state"], verdicts(run), sorted(segment_shape(run))


# --------------------------------------------------------------------------
# The registry twin
# --------------------------------------------------------------------------


def _registry_rows() -> dict[str, Mapping[str, Any]]:
    return {row["id"]: row for row in REGISTRY["fields"]}


def test_field_rows_are_the_registry_rows() -> None:
    rows = _registry_rows()
    for field_id, row in FIELD_ROWS.items():
        registry = rows[field_id]
        assert row.layer == registry["layer"], field_id
        assert list(row.keys) == COVERAGE.field_set_keys(registry["name"]), field_id
        assert row.observed_by == tuple(registry["observed_by"]), field_id
        assert row.required == registry["required"].startswith("R"), field_id
        status, _, reason = row.absent.partition("(")
        text = registry["status_if_hook_absent"]
        assert text.startswith(status) or (status, text) == ("unknown", "unresolved"), field_id
        assert reason.rstrip(")") in text, field_id


def test_required_tables_name_r_rows_of_the_kind() -> None:
    rows = _registry_rows()
    for field_id in _project.STEP_REQUIRED:
        assert rows[field_id]["required"] == "R", field_id
    for kind, field_ids in _project.KIND_REQUIRED.items():
        for field_id in field_ids:
            required = rows[field_id]["required"]
            assert required.startswith("R"), field_id
            # Either the parenthesis names the kind, or (N13, N14) the row is a plain R row
            # about the model boundary, or the kind is the row's only subject (N53, N60).
            assert kind in required or required == "R" or "(" in required, (kind, field_id)
    for field_id in _project.CONDITIONAL_REQUIRED:
        assert rows[field_id]["required"].startswith("R"), field_id


def test_profiles_are_the_registry_profiles() -> None:
    profiles = {p["id"]: p for p in REGISTRY["profiles"]}

    def resolved(profile_id: str) -> tuple[set[str], list[str]]:
        profile = profiles[profile_id]
        kinds, fields = set(profile["step_kinds"]), list(profile["run_fields"])
        if "extends" in profile:
            base_kinds, base_fields = resolved(profile["extends"])
            kinds |= base_kinds
            fields = base_fields + fields
        return kinds, fields

    assert set(PROFILES) == set(profiles)
    for profile_id, (kinds, run_fields) in PROFILES.items():
        assert (set(kinds), list(run_fields)) == resolved(profile_id), profile_id


def test_role_fields_are_registry_content_roles() -> None:
    for role, key in ROLE_FIELDS.items():
        registry = _registry_rows()[KEY_ROWS[key].field_id]
        assert f"`{role}`" in registry["lives_in"], (role, key)


def test_registry_revision_and_evidence_types_are_the_registry() -> None:
    assert REGISTRY["registry_revision"] == _project.REGISTRY_REVISION
    registered = {row["type"]: row for row in REGISTRY["evidence_types"]}
    assert set(EVIDENCE_TYPES) == set(registered)
    for name, row in EVIDENCE_TYPES.items():
        assert list(row["capture_points"]) == registered[name]["capture_points"]
        assert [list(f) for f in row["fields"]] == [
            [f["layer"], f["key"], f["pointer"]] for f in registered[name]["fields"]
        ]
        schema = json.loads((FAMILY / registered[name]["schema"]).read_text())
        schema.pop("title", None), schema.pop("description", None)
        for prop in schema["properties"].values():
            prop.pop("description", None)
        assert json.loads(json.dumps(row["schema"])) == schema


def test_model_field_keys_are_registry_keys_of_their_layer() -> None:
    from fabric.reconstruct._fields_model import _ALL_FIELD_IDS  # noqa: PLC0415

    for key, field_id in _ALL_FIELD_IDS.items():
        if key == "usage":
            continue
        assert KEY_ROWS[key].field_id == field_id, key


# --------------------------------------------------------------------------
# Evidence decoding (050 §3.4a item 6, R7, R9)
# --------------------------------------------------------------------------


def _raw(case: Mapping[str, Any]) -> bytes:
    if "raw" in case:
        return str(case["raw"]).encode()
    if "generate" in case:
        gen = case["generate"]
        return canonical_bytes(dict(gen["base"], items=[gen["item"]] * gen["count"]))
    return canonical_bytes(case["document"])


@pytest.mark.parametrize("case", EVIDENCE_VECTOR["cases"], ids=lambda c: c["name"])
def test_evidence_decoding_agrees_with_the_vectors(case: Mapping[str, Any]) -> None:
    decoded = decode_evidence(
        _raw(case), evidence_types=EVIDENCE_TYPES, provenance="reported",
        capture_point="sdk.records@0.9.0", identity_mode=case.get("identity_mode", "pseudonymous"),
    )  # fmt: skip
    assert (decoded.status == "ok") == (case["refusal"] is None)
    if case["refusal"] is not None:
        assert all(v.status == "not_captured" for v in decoded.fields.values())
        return
    assert list(decoded.item_errors) == case["item_errors"]
    if "fields" in case:
        assert {k: v.value for k, v in decoded.fields.items()} == case["fields"]
    bad = {decoded.item_errors[0]} if decoded.item_errors else set()
    items = json.loads(_raw(case))["items"]
    for name, value in decoded.fields.items():
        pointer = next(p for layer, key, p in EVIDENCE_TYPES["fabric.test.items/v1"]["fields"]
                       if f"{layer}.{key}" == name)  # fmt: skip
        carried = any(resolve_pointer({"items": [items[i]]}, pointer) for i in bad)
        assert value.status == ("not_captured" if carried else "captured"), name


def test_evidence_is_bounded_before_it_is_decoded() -> None:
    def decode(data: bytes) -> str:
        return decode_evidence(data, evidence_types=EVIDENCE_TYPES, provenance="observed",
                               capture_point="sdk.records").status  # fmt: skip

    assert decode(b"[" * 200_000 + b"]" * 200_000) == "parse_failed"  # never parsed
    assert decode(b'"' + b"a" * (1 << 20) + b'"') == "parse_failed"  # over 1 MiB
    assert decode(b"\xff") == "parse_failed"
    assert decode(b"{}") == "parse_failed"
    unknown = canonical_bytes({"schema_version": "fabric.record-evidence/v1",
                               "evidence_type": "acme.thing/v1", "items": []})  # fmt: skip
    assert decode(unknown) == "unknown_type"
    assert decode_evidence(b"{}", evidence_types={}, provenance="reported",
                           capture_point="sdk.records").status == "not_decoded"  # fmt: skip
    window = json.loads((FAMILY / "valid" / "evidence-continuation-window.json").read_text())
    decoded = decode_evidence(canonical_bytes(window), evidence_types=EVIDENCE_TYPES,
                              provenance="reported", capture_point="sdk.records")  # fmt: skip
    assert decoded.continuation == (7, False)
    assert [dict(ref) for ref in decoded.refs] == window["refs"]


# --------------------------------------------------------------------------
# The projection-* valid fixtures, reproduced from synthetic inputs
# --------------------------------------------------------------------------


def test_reproduces_projection_run_open_branches(capture: PCapture) -> None:
    branched_run(capture)
    _, projection = project(capture)
    run = run_of(projection)
    state, layer_verdicts, segments = fixture_shape("projection-run-open-branches")
    assert (run["run_state"], verdicts(run), sorted(segment_shape(run))) == (
        state, layer_verdicts, segments)  # fmt: skip
    assert run["resumable"] is True and run["open_run_deadline_s"] == 259_200
    started = datetime.fromtimestamp(BASE_NS // S, tz=UTC) + timedelta(seconds=0.9)
    assert datetime.fromisoformat(run["deadline_at"]) == started + timedelta(seconds=259_200)
    assert run["integrity_verdict"] == "complete_for_observed_scopes"


def test_reproduces_projection_run_unterminated(capture: PCapture) -> None:
    """The fixture's document ``evaluated_at`` lies before its own ``deadline_at`` (a
    contract-chain note, WAVE2-NOTES WP-31); the projection is evaluated after it."""
    branched_run(capture)
    late = GENERATED_AT + timedelta(days=4)
    _, projection = project(capture, evaluated_at=late)
    run = run_of(projection)
    state, layer_verdicts, segments = fixture_shape("projection-run-unterminated")
    assert (run["run_state"], verdicts(run), sorted(segment_shape(run))) == (
        state, layer_verdicts, segments)  # fmt: skip
    assert run["integrity_verdict"] == "partial"
    assert projection["evaluated_at"] > run["deadline_at"]


def test_reproduces_projection_run_segment_missing(capture: PCapture) -> None:
    root, lost, last = capture.new_segment(), capture.new_segment(), capture.new_segment()
    start(capture, RUN, root, extra=RESUMABLE)
    entry = seal(capture, RUN, root, extra=RESUMABLE)
    start(capture, RUN, last, entry.replace(root, lost), id_basis="token")
    seal(capture, RUN, last, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    run = run_of(projection)
    state, layer_verdicts, segments = fixture_shape("projection-run-segment-missing")
    assert (run["run_state"], verdicts(run), sorted(segment_shape(run))) == (
        state, layer_verdicts, segments)  # fmt: skip


def test_reproduces_projection_run_post_terminal(capture: PCapture) -> None:
    root, terminal, after = capture.new_segment(), capture.new_segment(), capture.new_segment()
    start(capture, RUN, root, extra=RESUMABLE)
    entry = seal(capture, RUN, root, extra=RESUMABLE)
    start(capture, RUN, terminal, entry, id_basis="token")
    ended = seal(capture, RUN, terminal, terminal=True, extra=RESUMABLE)
    start(capture, RUN, after, ended, id_basis="token")
    seal(capture, RUN, after)
    capture.heartbeat()
    _, projection = project(capture)
    run = run_of(projection)
    state, layer_verdicts, segments = fixture_shape("projection-run-post-terminal")
    assert (run["run_state"], verdicts(run), sorted(segment_shape(run))) == (
        state, layer_verdicts, segments)  # fmt: skip


def test_reproduces_projection_run_replayed_branch(capture: PCapture) -> None:
    root, left, right, join = (capture.new_segment() for _ in range(4))
    branch = "br-" + "1" * 32
    start(capture, RUN, root, extra=RESUMABLE)
    entry = seal(capture, RUN, root, extra={**RESUMABLE, "fabric.segment.branch_ids": [branch]})
    start(capture, RUN, left, entry, id_basis="token", extra={"fabric.run.branch_ids": [branch]})
    a = seal(capture, RUN, left, extra=RESUMABLE)
    start(capture, RUN, right, entry, id_basis="token", extra={"fabric.run.branch_ids": [branch]})
    b = seal(capture, RUN, right, extra=RESUMABLE)
    start(capture, RUN, join, a, b, id_basis="token")
    seal(capture, RUN, join, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    run = run_of(projection)
    state, layer_verdicts, segments = fixture_shape("projection-run-replayed-branch")
    assert (run["run_state"], verdicts(run), sorted(segment_shape(run))) == (
        state, layer_verdicts, segments)  # fmt: skip


def sealed_single(capture: PCapture, *calls: tuple[Any, ...], **kwargs: Any) -> str:
    """One terminal segment holding ``calls`` (``(request, response, extra kwargs)``)."""
    segment = capture.new_segment()
    start(capture, RUN, segment)
    for request, response, extra in calls:
        capture.call(request, response, **{**kwargs, **extra})
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    return segment


def test_reproduces_projection_model_call_field_statuses(capture: PCapture) -> None:
    case = golden("responses-hosted-tools-reasoning")
    sealed_single(capture, (case["request"], case["response"],
                            {"api": "openai.responses", "model": "gpt-4o-mini"}))  # fmt: skip
    _, projection = project(capture, id_key=KEY)
    run = run_of(projection)
    expected = fixture("projection-model-call-field-statuses")["runs"][0]
    assert (run["run_state"], verdicts(run)) == (expected["run_state"], verdicts(expected))
    (step,) = steps_of(projection, "model_call")
    assert verdicts(step) == verdicts(fixture("projection-model-call-field-statuses")["steps"][0])
    assert status(step, "reasoning.text") == "redacted(provider_encrypted)"
    assert field(step, "reasoning.text")["assertion_origin"] == "provider"
    summary = field(step, "reasoning.summary")
    assert summary["status"] == "captured" and summary["ref"]["pointer"] == "/output/0/summary"
    served = field(step, "model.served")
    assert served["status"] == "conflict" and "value" not in served
    assert {e["value"] for e in served["evidence"]} == {"gpt-4o-mini", "o4-mini-2025-04-16"}
    assert field(step, "usage.input_tokens")["value"] == 300
    assert field(step, "usage.basis")["value"] == "provider_reported"
    assert field(step, "instructions")["ref"]["pointer"] == "/instructions"
    request = field(step, "model.exchange.request")["ref"]
    assert request["role"] == "model.exchange.request" and request["sha256"].startswith("sha256:")
    hosted = steps_of(projection, "provider_tool_call")
    assert [field(s, "provider_tool.kind")["value"] for s in hosted] == [
        "web_search",
        "file_search",
    ]
    assert [s["source"]["subindex"] for s in hosted] == [1, 2]
    assert {s["parent_step_id"] for s in hosted} == {step["step_id"]}
    assert all(verdicts(s)["content"] == ("captured_for_declared_fields", ()) for s in hosted)


def test_reproduces_projection_extension_step(capture: PCapture) -> None:
    case = golden("responses-unknown-item")
    sealed_single(capture, (case["request"], case["response"], {"api": "openai.responses"}))
    _, projection = project(capture, id_key=KEY)
    (step,) = steps_of(projection, "extension")
    expected = fixture("projection-extension-step")["steps"][0]
    assert step["step_kind_extension"] == "x-openai.acme_widget_call"
    assert set(step["layers"]["content"]) == {"x-openai.result"}
    assert verdicts(step) == verdicts(expected)
    (unknown,) = step["layers"]["content"].values()
    assert (unknown["status"], unknown["reason"]) == ("unsupported", "unsupported_api")
    assert step["source"]["subindex"] == 1 and step["provenance"] == "observed"
    # The extension kind is outside the model-calls profile: the run is not lowered.
    assert verdicts(run_of(projection))["content"][0] != "unsupported"


def test_reproduces_projection_many_records(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.call(*simple_turn())
    attempt = capture.new_id()
    rows = [capture.record(attempt_uid=attempt) for _ in range(300)]
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (step,) = [s for s in steps_of(projection, "tool_call") if s["attempt_id"] == attempt]
    expected = fixture("projection-many-records")["steps"][0]
    assert len(step["event_ids"]) == len(expected["event_ids"]) == _project.MAX_EVENT_IDS
    by_sequence = sorted(rows, key=lambda r: r["attributes"]["fabric.source.sequence"])
    assert step["event_ids"] == [r["attributes"]["fabric.event_id"] for r in by_sequence[:64]]
    event_id = field(step, "event_id")
    assert event_id["collection"] == expected["layers"]["cross_cutting"]["event_id"]["collection"]
    assert step["source"]["source_sequence"] == by_sequence[0]["attributes"][
        "fabric.source.sequence"]  # fmt: skip
    assert verdicts(run_of(projection)) == verdicts(fixture("projection-many-records")["runs"][0])


def test_reproduces_projection_tentative_same_as(capture: PCapture) -> None:
    """An inferred input step (``new_user_message``) and two runs whose root steps share a
    W3C trace id (``same_as`` by ``trace_id_match``, tentative)."""
    first = [SYSTEM, USER]
    reply = {"role": "assistant", "content": "18C."}
    second = [*first, reply, {"role": "user", "content": "And Rome?"}]
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.call({"model": "gpt-4o", "messages": first}, chat_response(reply, "chatcmpl-1"))
    capture.call(
        {"model": "gpt-4o", "messages": second},
        chat_response({"role": "assistant", "content": "24C."}, "chatcmpl-2"),
    )
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    other = capture.new_segment()
    start(capture, RUN_B, other)
    capture.call(*simple_turn(), run_id=RUN_B)
    capture.run_end(RUN_B)
    capture.segment_seal(RUN_B, segment_id=other, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    expected = fixture("projection-tentative-same-as")["steps"][0]
    (inferred,) = steps_of(projection, "input")
    assert (inferred["provenance"], inferred["method"], inferred["confidence"]) == (
        expected["provenance"], expected["method"], expected["confidence"])  # fmt: skip
    (derived,) = [link for link in inferred["links"] if link["type"] == "derived_from"]
    second_call = [s for s in steps_of(projection, "model_call") if s["run_id"] == RUN][1]
    exchange_id = capture.exchanges[1].exchange_id
    assert derived["target"] == {"namespace": "exchange", "id": exchange_id}
    assert second_call["aliases"]["wire.exchange_id"].endswith("/" + exchange_id)
    payload = field(inferred, "input.payload")
    assert payload["status"] == "captured" and payload["ref"]["pointer"] == "/messages/3"
    assert verdicts(inferred) == verdicts(expected)
    assert inferred["attempt_id"] == _project.inferred_step_id(
        f"{second_call['attempt_id']}/request:/messages/3")  # fmt: skip
    roots = [s for s in steps_of(projection, "run") if "parent_step_id" not in s]
    same_as = sorted(link["target"]["id"] for s in roots for link in s.get("links", ())
                     if link["type"] == "same_as")  # fmt: skip
    assert same_as == sorted([RUN, RUN_B])
    assert all(link["method"] == "trace_id_match" and link["confidence"] == "tentative"
               for s in roots for link in s.get("links", ()))  # fmt: skip


# --------------------------------------------------------------------------
# C1-5: one case per row of the 049 §6.2 decision tables
# --------------------------------------------------------------------------


def step_row(governed: bool, *fields: tuple[str, str | None]) -> tuple[str, str, list[str]]:
    return decide(STEP_RULES, StepEval(governed, tuple(fields)))


@pytest.mark.parametrize(
    ("governed", "fields", "expected"),
    [
        (False, [("ok", None)], ("R1", "unverified", ["source_lost"])),
        (
            True,
            [("uncertain", "clock_uncertain"), ("gap", "store_failed")],
            ("R2", "unverified", ["clock_uncertain"]),
        ),
        (
            True,
            [("unsupported", "unsupported_version")],
            ("R3", "unsupported", ["unsupported_version"]),
        ),
        (
            True,
            [("unsupported", "unsupported_api"), ("ok", None)],
            ("R4", "partial", ["unsupported_api"]),
        ),
        (
            True,
            [("gap", "store_failed"), ("withheld", "privacy_policy")],
            ("R4", "partial", ["store_failed"]),
        ),
        (
            True,
            [("withheld", "provider_encrypted"), ("ok", None)],
            ("R5", "captured_with_withholding", ["provider_encrypted"]),
        ),
        (True, [("ok", None)], ("R6", "captured_for_declared_fields", [])),
        (True, [], ("R6", "captured_for_declared_fields", [])),
    ],
    ids=["R1", "R2", "R3", "R4-mixed", "R4-gap", "R5", "R6", "R6-empty"],
)
def test_step_decision_table(
    governed: bool, fields: Sequence[tuple[str, str | None]], expected: tuple[str, str, list[str]]
) -> None:
    assert step_row(governed, *fields) == expected


def run_eval(**changes: Any) -> RunEval:
    base: dict[str, Any] = {
        "integrity": "complete_for_observed_scopes", "run_state": "terminated",
        "steps": (("captured_for_declared_fields", ()),), "observed_steps": True,
        "run_level": None,
    }  # fmt: skip
    return RunEval(**{**base, **changes})


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"integrity": "unverified", "integrity_reasons": ("source_lost",)},
         ("RR1", "unverified", ["source_lost"])),
        ({"steps": (("unverified", ("source_lost",)),)}, ("RR1", "unverified", ["source_lost"])),
        ({"unauthenticated": True}, ("RR1a", "unverified", ["source_unauthenticated"])),
        ({"run_level": ("unverified", ("unknown",))}, ("RR2", "unverified", ["unknown"])),
        ({"steps": (), "observed_steps": False, "none_reasons": ("not_instrumented",)},
         ("RR3", "none_observed", ["not_instrumented"])),
        ({"run_state": "conflicted", "graph_reasons": ("segment_missing",)},
         ("RR3a", "partial", ["segment_missing"])),
        ({"graph_reasons": ("seal_mismatch",)}, ("RR3a", "partial", ["seal_mismatch"])),
        ({"run_state": "deadline_uncertain"}, ("RR3b", "unverified", ["clock_uncertain"])),
        ({"run_state": "unterminated"}, ("RR3c", "partial", ["run_unterminated"])),
        ({"steps": (("unsupported", ("unsupported_api",)),)},
         ("RR4", "unsupported", ["unsupported_api"])),
        ({"integrity": "partial"}, ("RR5", "partial", [])),
        ({"steps": (("unsupported", ("unsupported_api",)), ("captured_for_declared_fields", ()))},
         ("RR5", "partial", ["unsupported_api"])),
        ({"run_state": "open"}, ("RR5a", "open", [])),
        ({"steps": (("captured_with_withholding", ("privacy_policy",)),)},
         ("RR6", "captured_with_withholding", ["privacy_policy"])),
        ({}, ("RR7", "captured_for_declared_fields", [])),
    ],
    ids=["RR1-integrity", "RR1-step", "RR1a", "RR2", "RR3", "RR3a-graph", "RR3a-seal",
         "RR3b", "RR3c", "RR4", "RR5-integrity", "RR5-mixed", "RR5a", "RR6", "RR7"],
)  # fmt: skip
def test_run_decision_table(
    changes: Mapping[str, Any], expected: tuple[str, str, list[str]]
) -> None:
    assert decide(RUN_RULES, run_eval(**changes)) == expected


def test_tables_cover_every_049_row() -> None:
    assert [row[0] for row in STEP_RULES] == ["R1", "R2", "R3", "R4", "R5", "R6"]
    assert [row[0] for row in RUN_RULES] == [
        "RR1", "RR1a", "RR2", "RR3", "RR3a", "RR3b", "RR3c", "RR4", "RR5", "RR5a", "RR6", "RR7",
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("wrapper", "expected"),
    [
        ({"status": "captured"}, "ok"),
        ({"status": "captured", "confidence": "tentative"}, "uncertain"),
        ({"status": "absent"}, "ok"),
        ({"status": "not_applicable"}, "ok"),
        ({"status": "redacted", "reason": "provider_encrypted"}, "withheld"),
        ({"status": "not_captured", "reason": "provider_not_returned"}, "withheld"),
        ({"status": "not_captured", "reason": "provider_held"}, "gap"),
        ({"status": "truncated", "reason": "body_cap"}, "gap"),
        ({"status": "conflict"}, "gap"),
        ({"status": "unsupported", "reason": "unsupported_api"}, "unsupported"),
        ({"status": "unknown"}, "uncertain"),
        ({"status": "not_captured", "reason": "source_unauthenticated"}, "uncertain"),
    ],
)
def test_field_classes(wrapper: Mapping[str, Any], expected: str) -> None:
    assert field_class(wrapper) == expected


def test_r1_and_rr1_without_a_manifest(tmp_path: Path) -> None:
    capture = PCapture(tmp_path)  # a pre-P1 capture: no manifest, no segments
    for request, response in (simple_turn(), simple_turn("Rome?", "chatcmpl-2")):
        capture.exchange(request, response)
    capture.heartbeat()
    _, projection = project(capture)
    run = run_of(projection)
    assert run["run_state"] == "not_resumable_unclosed" and run["resumable"] is False
    for step in steps_of(projection, "model_call"):
        assert set(verdicts(step).values()) == {("unverified", ("source_lost",))}
        assert status(step, "event_id") == "unsupported(unsupported_version)"
        assert step["event_ids"] == [step["attempt_id"]]
        assert step["aliases"]["wire.exchange_id"].endswith("/ex-" + str(
            step["source"]["source_sequence"]))  # fmt: skip
        assert step["source"]["sequence_unit"] == "exchange"
    assert set(verdicts(run).values()) == {("unverified", ("source_lost",))}


def test_r2_without_a_store_byte_fields_are_unknown(capture: PCapture) -> None:
    sealed_single(capture, (*simple_turn(), {}))
    _, projection = project(capture, store=None)
    (step,) = steps_of(projection, "model_call")
    assert status(step, "model.exchange.request") == "unknown"
    assert status(step, "input.messages") == "unknown"
    assert verdicts(step)["content"][0] == "unverified"
    assert verdicts(run_of(projection))["content"][0] == "unverified"


def test_r4_and_rr5_an_unkeyed_tool_call_id_is_a_gap(capture: PCapture) -> None:
    request = {"model": "gpt-4o", "messages": [SYSTEM, USER]}
    call = {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_a", "type": "function",
         "function": {"name": "get_weather", "arguments": "{}"}}]}  # fmt: skip
    sealed_single(capture, (request, chat_response(call, "chatcmpl-1", "tool_calls"), {}))
    _, projection = project(capture)
    (step,) = steps_of(projection, "model_call")
    assert status(step, "tool_call.id") == "not_captured(missing_id_key)"
    assert verdicts(step)["content"] == ("partial", ("missing_id_key",))
    assert verdicts(run_of(projection))["content"] == ("partial", ("missing_id_key",))
    _, keyed = project(capture, id_key=KEY)
    (step,) = steps_of(keyed, "model_call")
    assert field(step, "tool_call.id")["value"][0].startswith("p-")
    assert verdicts(step)["content"] == ("captured_for_declared_fields", ())


def test_rr3_none_observed_for_a_records_only_run(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.record()  # a records attempt: no step kind of the model-calls profile
    seal(capture, RUN, segment, terminal=True, call=False)
    capture.heartbeat()
    _, projection = project(capture)
    run = run_of(projection)
    layer = verdicts(run)
    assert layer["context"][0] == "none_observed"
    assert layer["structure"][0] == "captured_for_declared_fields"  # S34 is a run field
    assert run["kinds_none_observed"] == ["embedding", "model_call", "provider_tool_call"]


def test_rr3b_deadline_uncertain(capture: PCapture) -> None:
    branched_run(capture)
    started = datetime.fromtimestamp(BASE_NS // S, tz=UTC) + timedelta(seconds=0.9)
    deadline = started + timedelta(seconds=259_200)
    _, projection = project(capture, evaluated_at=deadline, clock_uncertainty_ns=60 * S)
    run = run_of(projection)
    assert run["run_state"] == "deadline_uncertain"
    assert set(verdicts(run).values()) == {("unverified", ("clock_uncertain",))}


def test_rr5_integrity_partial_and_rr6_rr7(capture: PCapture) -> None:
    sealed_single(capture, (*simple_turn(), {}))
    _, clean = project(capture)
    assert set(verdicts(run_of(clean)).values()) == {("captured_for_declared_fields", ())}
    assert run_of(clean)["run_state"] == "terminated"


def test_rr5_a_lost_exchange_is_partial(tmp_path: Path) -> None:
    capture = PCapture(tmp_path)
    capture.manifest()
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.call(*simple_turn())
    capture.call(*simple_turn("Rome?", "chatcmpl-2"))
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    del capture.rows[capture.rows.index(capture.exchanges[1].span)]
    _, projection = project(capture)
    run = run_of(projection)
    assert run["integrity_verdict"] == "partial"
    assert {v for v, _ in verdicts(run).values()} == {"partial"}


def test_rr6_withholding_by_the_provider(capture: PCapture) -> None:
    case = golden("anthropic-redacted-thinking")
    sealed_single(capture, (case["request"], case["response"], {"api": "anthropic.messages"}))
    _, projection = project(capture, id_key=KEY)
    (step,) = steps_of(projection, "model_call")
    assert status(step, "reasoning.text") == "redacted(provider_redacted)"
    assert verdicts(run_of(projection))["content"] == (
        "captured_with_withholding", ("provider_redacted",))  # fmt: skip


# --------------------------------------------------------------------------
# Steps, aliases, parents and fields
# --------------------------------------------------------------------------


def test_records_attempt_ids_aliases_and_parents(capture: PCapture) -> None:
    segment = capture.new_segment()
    scope = start(capture, RUN, segment)
    parent = capture.record("agent_turn", step_id="turn-1",
                            attributes={"fabric.step.attempt_id": "try-1"})  # fmt: skip
    child = capture.record(attributes={"fabric.step.parent_id": "turn-1"})
    capture.exchange(*simple_turn())
    capture.exchanges[-1].span["parent_span_id"] = child["span_id"]
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    source = projection["steps"][0]["source"]["source_id"]
    (turn,) = steps_of(projection, "agent_turn")
    assert turn["step_id"] == f"records:{source}:turn-1"
    assert turn["attempt_id"] == parent["attributes"]["fabric.attempt.uid"]
    assert turn["aliases"]["records.step_id"] == f"{source}/turn-1"
    assert turn["aliases"]["records.step_attempt_id"] == f"{source}/try-1"
    assert turn["parent_step_id"] == f"run:{scope}"
    (tool,) = steps_of(projection, "tool_call")
    assert tool["parent_step_id"] == f"records:{source}:turn-1"
    assert tool["aliases"]["records.span_id"] == f"{source}/{child['span_id']}"
    (call,) = steps_of(projection, "model_call")
    assert call["parent_step_id"] == tool["step_id"]  # the records.span_id join
    (run_step,) = steps_of(projection, "run")
    assert (run_step["attempt_id"], run_step["step_id"]) == (scope, f"run:{scope}")
    assert field(run_step, "scope.exit_status")["value"] == "ok"
    assert run_step["source"]["source_sequence"] == 0  # first position its window holds


def test_inner_scope_parent_is_the_outer_scope(capture: PCapture) -> None:
    segment = capture.new_segment()
    outer = start(capture, RUN, segment)
    inner = capture.run_start(RUN, segment_id=segment, predecessors=())
    capture.rows[-1]["attributes"].pop("fabric.run.predecessors")
    capture.call(*simple_turn())
    capture.run_end(RUN, inner)
    capture.run_end(RUN, outer)
    capture.segment_seal(RUN, segment_id=segment, terminal=True, scope_id=outer)
    capture.heartbeat()
    _, projection = project(capture)
    parents = {s["scope_id"]: s.get("parent_step_id") for s in steps_of(projection, "run")}
    assert parents == {outer: None, inner: f"run:{outer}"}
    (call,) = steps_of(projection, "model_call")
    assert call["parent_step_id"] == f"run:{inner}"


def test_unclosed_records_attempt_is_running_unknown(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.call(*simple_turn())
    capture.record(attributes={"fabric.step.lifecycle_state": "running",
                               "fabric.step.status": "ok"})  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (tool,) = steps_of(projection, "tool_call")
    assert (tool["lifecycle_state"], tool["result_status"]) == ("running", "unknown")
    assert status(tool, "lifecycle.state") == "captured"
    assert status(tool, "result_status") == "unknown"  # a start without an end


def test_imported_values_outside_a_vocabulary_are_never_copied(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment)
    row = capture.call(*simple_turn())
    row["attributes"].update({"fabric.actor.type": "robot", "fabric.step.status": "great",
                              "fabric.step.lifecycle_state": "done"})  # fmt: skip
    capture.record(attributes={"fabric.actor.type": "robot", "fabric.step.kind": "dance"})
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (call,) = steps_of(projection, "model_call")
    assert call["actor"] == {"type": "unknown"}
    assert (call["lifecycle_state"], call["result_status"]) == ("completed", "ok")  # legacy map
    (record,) = steps_of(projection, "interaction")
    assert record["actor"] == {"type": "unknown"}


def test_evidence_object_fields_and_continuation_windows(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.call(*simple_turn())
    attempt = capture.new_id()
    for index in range(3):
        document = {"schema_version": "fabric.record-evidence/v1",
                    "evidence_type": "fabric.test.items/v1",
                    "items": [{"name": f"window.{index}", "count": index}],
                    "continuation": {"index": index, "final": index == 2}}  # fmt: skip
        capture.object_roles.append(
            ("record.evidence", "application/vnd.fabric.record-evidence+json")
        )
        capture.record(attempt_uid=attempt, objects=(canonical_bytes(document),))
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (step,) = [s for s in projection["steps"] if s["attempt_id"] == attempt]
    names = step["layers"]["content"]["x-fabric.test_item_names"]
    assert names["value"] == ["window.0", "window.1", "window.2"]
    assert names["collection"] == {"completeness": "complete", "observed_count": 3,
                                   "expected_count": 3}  # fmt: skip
    assert step["layers"]["decisions_effects"]["x-fabric.test_item_counts"]["value"] == [0, 1, 2]
    assert len(field(step, "content_object_ids")["value"]) == 3


def test_a_lost_evidence_window_is_a_partial_collection(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.call(*simple_turn())
    attempt = capture.new_id()
    for index in (0, 2):
        document = {"schema_version": "fabric.record-evidence/v1",
                    "evidence_type": "fabric.test.items/v1",
                    "items": [{"name": "w", "count": 1, "extra": "x"}] if index else [],
                    "continuation": {"index": index, "final": index == 2}}  # fmt: skip
        capture.object_roles.append(
            ("record.evidence", "application/vnd.fabric.record-evidence+json")
        )
        capture.record(attempt_uid=attempt, objects=(canonical_bytes(document),))
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (step,) = [s for s in projection["steps"] if s["attempt_id"] == attempt]
    names = step["layers"]["content"]["x-fabric.test_item_names"]
    assert (names["status"], names["reason"]) == ("not_captured", "parse_failed")  # bad item
    digests = step["layers"]["content"]["x-fabric.test_item_digests"]
    assert digests["collection"]["completeness"] == "partial"


def test_records_bodies_project_by_role(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.call(*simple_turn())
    capture.object_roles.append(("tool.call.arguments", "application/json"))
    capture.record(objects=(b'{"city":"Paris"}', None))
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (tool,) = steps_of(projection, "tool_call")
    arguments = field(tool, "tool.execution.arguments")
    assert arguments["status"] == "captured" and arguments["ref"]["role"] == "tool.call.arguments"
    # The descriptor-only object has role tool.result (no registry field): not projected; the
    # result field is the manifest's (sdk.records lists N17, a reporting point).
    assert status(tool, "tool.execution.result") == "not_captured(caller_omitted)"


def test_retry_link_and_attempt_kind(capture: PCapture) -> None:
    request, response = simple_turn()
    sealed_single(capture, (request, None, {"state": "error", "http_status": 500}),
                  (request, response, {}))  # fmt: skip
    _, projection = project(capture)
    failed, retried = steps_of(projection, "model_call")
    assert failed["result_status"] == "error"
    (link,) = [link for link in retried["links"] if link["type"] == "retries"]
    assert link["target"] == {"namespace": "attempt", "id": failed["attempt_id"]}
    assert link["confidence"] == "tentative"
    assert field(retried, "attempt.kind")["value"] == "retry"
    assert status(failed, "model.exchange.response") == "not_captured(store_failed)"
    assert status(failed, "error.type") == "unknown"  # R (on error), the span has none


def test_continuation_links_and_tools_changed(capture: PCapture) -> None:
    first = [SYSTEM, USER]
    reply = {"role": "assistant", "content": "18C."}
    tools = [{"type": "function", "function": {"name": "get_weather", "parameters": {}}}]
    sealed_single(
        capture,
        ({"model": "gpt-4o", "messages": first}, chat_response(reply, "chatcmpl-1"), {}),
        ({"model": "gpt-4o", "messages": [*first, reply, USER], "tools": tools},
         chat_response(reply, "chatcmpl-2"), {}),
    )  # fmt: skip
    _, projection = project(capture)
    one, two = steps_of(projection, "model_call")
    (link,) = two["links"]
    assert (link["type"], link["method"], link["target"]) == (
        "continues", "prefix_digest",
        {"namespace": "exchange", "id": capture.exchanges[0].exchange_id})  # fmt: skip
    assert one["aliases"]["wire.exchange_id"].endswith(capture.exchanges[0].exchange_id)
    changed = field(two, "tools_changed")
    assert (changed["value"], changed["method"], changed["confidence"]) == (
        True, "tools_digest_change", "certain")  # fmt: skip


def test_previous_response_dependency_resolution(capture: PCapture) -> None:
    """C39 (049 §6.3): ``resolved`` only when the named response is in the record; an
    unresolved dependency is ``not_captured(provider_held)``, a gap."""
    resolved = golden("responses-previous-response-resolved")
    unresolved = golden("responses-previous-response-unresolved")
    (named,) = resolved["known_responses"]
    earlier = {
        "id": named, "object": "response", "model": "gpt-4o", "status": "completed",
        "output": [{"type": "message", "id": "msg_0", "role": "assistant",
                    "content": [{"type": "output_text", "text": "Hi."}]}],
    }  # fmt: skip
    sealed_single(
        capture,
        ({"model": "gpt-4o", "input": "Hello"}, earlier, {"api": "openai.responses"}),
        (resolved["request"], resolved["response"], {"api": "openai.responses"}),
        (unresolved["request"], unresolved["response"], {"api": "openai.responses"}),
    )  # fmt: skip
    _, projection = project(capture, id_key=KEY)
    _, found, missing = steps_of(projection, "model_call")
    dependency = field(found, "context_dependencies")
    assert dependency["status"] == "captured"
    assert [item["resolution"]["value"] for item in dependency["items"]] == ["resolved"]
    assert dependency["items"][0]["provider_id"]["value"] == (
        resolved["expected"]["context_dependencies"][0]["provider_id"])  # fmt: skip
    assert status(missing, "context_dependencies") == "not_captured(provider_held)"
    assert [i["resolution"]["value"] for i in field(missing, "context_dependencies")["items"]] == [
        "unresolved", "unresolved"]  # fmt: skip
    assert verdicts(missing)["context"] == ("partial", ("provider_held",))


def test_store_disabled_is_not_configured(tmp_path: Path) -> None:
    capture = PCapture(tmp_path, store=False)
    capture.manifest()
    sealed_single(capture, (*simple_turn(), {}))
    _, projection = project(capture, store=None)
    (step,) = steps_of(projection, "model_call")
    assert status(step, "model.exchange.request") == "not_captured(not_configured)"
    assert status(step, "input.messages") == "not_captured(not_configured)"
    assert field(step, "store_reason")["value"] == "not_configured"


def test_embeddings_and_streams(capture: PCapture) -> None:
    case = golden("embeddings")
    stream = golden("chat-stream")
    sealed_single(
        capture,
        (case["request"], case["response"], {"api": "openai.embeddings"}),
        (stream["request"], stream["response"].encode() if isinstance(stream["response"], str)
         else stream["response"], {"response_media": "text/event-stream"}),
    )  # fmt: skip
    _, projection = project(capture, id_key=KEY)
    (embedding,) = steps_of(projection, "embedding")
    assert field(embedding, "embedding.input")["status"] == "captured"
    (chat,) = steps_of(projection, "model_call")
    assert field(chat, "stream.state")["value"] == "complete"


def test_manifest_drives_unobserved_fields(capture: PCapture) -> None:
    """A field the record lacks takes the governing manifest's word for its point."""
    manifest = capture_manifest_rows()
    for row in manifest:
        if row["id"] == "wire.py.httpx":
            row["fields"].remove("C35")
    capture.manifest(capture_points=manifest)
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.exchange(*simple_turn())  # no endpoint id on the span
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (step,) = steps_of(projection, "model_call")
    assert status(step, "model.endpoint_id") == "unsupported(unsupported_version)"
    assert field(step, "model.endpoint_id")["capture_point"] == "wire.py.httpx@1.2.0"
    assert verdicts(step)["context"] == ("partial", ("unsupported_version",))


def capture_manifest_rows() -> list[dict[str, Any]]:
    from tests.test_reconstruct_verifier import MANIFEST_VECTOR  # noqa: PLC0415

    rows = MANIFEST_VECTOR["cases"][0]["manifest"]["capture_points"]
    return list(json.loads(json.dumps(rows)))  # a deep copy: the vector is shared


def test_inactive_point_is_not_instrumented(capture: PCapture) -> None:
    rows = capture_manifest_rows()
    for row in rows:
        if row["id"] == "wire.py.httpx":
            row.update(state="installed_inactive", reason="not_instrumented")
    capture.manifest(capture_points=rows)
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.exchange(*simple_turn())
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=True)
    capture.heartbeat()
    _, projection = project(capture)
    (step,) = steps_of(projection, "model_call")
    assert status(step, "model.endpoint_id") == "not_captured(not_instrumented)"
    assert status(step, "model.provider") == "captured"  # evidence wins over the manifest


# --------------------------------------------------------------------------
# The document, the CLI and determinism
# --------------------------------------------------------------------------


def test_document_inputs(capture: PCapture) -> None:
    sealed_single(capture, (*simple_turn(), {}))
    _, projection = project(capture, id_key=KEY)
    assert projection["pseudonym_mode"] == "keyed"
    assert projection["key_id"].startswith("kid-")
    assert projection["content_inline"] is False
    (manifest,) = projection["inputs"]["manifests"]
    assert manifest["sha256"] == capture.manifest_digest
    assert projection["parser"]["name"] == "fabric.reconstruct"
    assert projection["field_registry"]["registry_revision"] == REGISTRY["registry_revision"]
    _, unkeyed = project(capture)
    assert unkeyed["pseudonym_mode"] == "unkeyed" and "key_id" not in unkeyed


def test_projection_is_deterministic(capture: PCapture) -> None:
    branched_run(capture)
    assert project(capture)[1] == project(capture)[1]


def test_build_projection_preconditions(capture: PCapture) -> None:
    sealed_single(capture, (*simple_turn(), {}))
    collector = ProjectionCollector()
    graphs: list[RunGraph] = []
    report = reconstruct([capture.write()], store=capture.store, generated_at=GENERATED_AT,
                         graphs_out=graphs, projection_sink=collector)  # fmt: skip
    common: dict[str, Any] = {"graphs": graphs, "reconstruction_sha256": "sha256:" + "0" * 64,
                              "evaluated_at": GENERATED_AT}  # fmt: skip
    assert build_projection(report, **common) is None  # no collector
    assert build_projection({"runs": []}, **common, collector=collector) is None
    from fabric.reconstruct import ReconstructInputError  # noqa: PLC0415

    with pytest.raises(ReconstructInputError):
        build_projection(report, **common, collector=collector, inline_content=True)
    with pytest.raises(ReconstructInputError):
        build_projection(report, **common, collector=collector,
                         coverage_profile="fabric.profile.nothing/v1")  # fmt: skip
    for profile in PROFILES:
        document = build_projection(report, **common, collector=collector,
                                    coverage_profile=profile)  # fmt: skip
        assert document is not None
        validate_projection(document)


def test_cli_writes_a_valid_projection(
    capture: PCapture, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sealed_single(capture, (*simple_turn(), {}))
    out, projection_path = tmp_path / "report.json", tmp_path / "projection.json"
    code = main([
        "--spans", str(capture.write()), "--store-root", str(tmp_path / "store"),
        "--tenant", TENANT, "--out", str(out), "--projection", str(projection_path),
        "--evaluated-at", "2026-10-08T09:10:00Z",
    ])  # fmt: skip
    assert code == 0, capsys.readouterr().err
    document = json.loads(projection_path.read_text())
    validate_projection(document)
    digest = "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest()
    assert document["inputs"]["reconstruction_sha256"] == digest
    assert oct(projection_path.stat().st_mode & 0o777) == "0o600"
    assert {s["step_kind"] for s in document["steps"]} == {"run", "model_call"}


def test_open_deadline_default_is_the_manifest_limit(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment, extra=RESUMABLE)
    seal(capture, RUN, segment, extra=RESUMABLE)
    capture.heartbeat()
    _, projection = project(capture)
    run = run_of(projection)
    assert run["run_state"] == "open"
    assert run["open_run_deadline_s"] == DEFAULT_OPEN_RUN_DEADLINE_S


# --------------------------------------------------------------------------
# T1: projections of the verifier suites' scenarios, under every coverage profile
# --------------------------------------------------------------------------


def _scenario_sealed_run(capture: PCapture) -> None:
    from tests.test_reconstruct_records import sealed_run  # noqa: PLC0415

    sealed_run(capture)


def _scenario_legacy(capture: PCapture) -> None:
    from tests.test_reconstruct_verifier import react_run  # noqa: PLC0415

    react_run(capture)


def _scenario_identity_merges(capture: PCapture) -> None:
    """A legacy rotation (merged into its predecessor's run) and a token_conflict fan-in."""
    first, rotated, other, fan_in = (capture.new_segment() for _ in range(4))
    start(capture, RUN, first, extra=RESUMABLE)
    a = seal(capture, RUN, first, extra=RESUMABLE)
    start(capture, RUN_B, rotated, a, id_basis="legacy")
    b = seal(capture, RUN_B, rotated, extra=RESUMABLE)
    run_c = "r-" + "c" * 32
    start(capture, run_c, other, extra=RESUMABLE)
    c = seal(capture, run_c, other, extra=RESUMABLE)
    start(capture, run_c, fan_in, b, c, id_basis="token_conflict")
    seal(capture, run_c, fan_in, terminal=True)
    capture.heartbeat()


def _scenario_losses_and_unsealed(capture: PCapture) -> None:
    segment, unsealed = capture.new_segment(), capture.new_segment()
    start(capture, RUN, segment)
    capture.call(*simple_turn())
    lost = capture.skip()
    capture.loss("queue_full", lost, segment_id=segment)
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, terminal=False)
    start(capture, RUN_B, unsealed)
    capture.call(*simple_turn(), run_id=RUN_B)
    capture.run_end(RUN_B)
    capture.heartbeat()


def _scenario_seal_mismatch(capture: PCapture) -> None:
    segment = capture.new_segment()
    start(capture, RUN, segment)
    capture.call(*simple_turn())
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment, digest="sha256:" + "e" * 64)
    capture.heartbeat()


def _scenario_unsealed_epoch(capture: PCapture) -> None:
    capture.manifest(1, unsealed_prior=(7,))
    sealed_single(capture, (*simple_turn(), {}))


def _scenario_production_unstamped(capture: PCapture) -> None:
    sealed_single(capture, (*simple_turn(), {}))


SCENARIOS: dict[str, tuple[Any, dict[str, Any]]] = {
    "sealed_run": (_scenario_sealed_run, {}),
    "legacy": (_scenario_legacy, {}),
    "identity_merges": (_scenario_identity_merges, {}),
    "losses_and_unsealed": (_scenario_losses_and_unsealed, {}),
    "seal_mismatch": (_scenario_seal_mismatch, {}),
    "unsealed_epoch": (_scenario_unsealed_epoch, {}),
    "production_unstamped": (_scenario_production_unstamped, {"profile": "production"}),
}


@pytest.mark.parametrize("profile", sorted(PROFILES))
@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_projection_validates(tmp_path: Path, name: str, profile: str) -> None:
    """T1 / C1-3 over the verifier suites' scenarios (``project`` validates each)."""
    capture = PCapture(tmp_path)
    if name != "legacy":
        capture.manifest()
    build, options = SCENARIOS[name]
    build(capture)
    _, projection = project(capture, coverage=profile, **options)
    for run in projection["runs"]:
        if run["run_state"] in ("open", "unterminated", "conflicted", "deadline_uncertain"):
            assert not {v for v, _ in verdicts(run).values()} & {
                "captured_for_declared_fields", "captured_with_withholding"}  # fmt: skip
    if name == "production_unstamped":
        assert {v for v, _ in verdicts(run_of(projection)).values()} == {"unverified"}


@pytest.mark.xfail(
    strict=True,
    reason="contract chain (WP-00): validate_projection counts a caller_join run's roots across "
    "its merged runs (G1 'more than one root'), while 050 §3.12 R1 and WP-31 keep one root per "
    "merged run id and the projection's segment shape carries no run id",
)
def test_caller_join_fan_in_projection_validates(capture: PCapture) -> None:
    first, second, joined = (capture.new_segment() for _ in range(3))
    start(capture, RUN, first, extra=RESUMABLE)
    a = seal(capture, RUN, first, extra=RESUMABLE)
    start(capture, RUN_B, second, extra=RESUMABLE)
    b = seal(capture, RUN_B, second, extra=RESUMABLE)
    start(capture, RUN, joined, a, b, id_basis="caller_join")
    seal(capture, RUN, joined, terminal=True)
    capture.heartbeat()
    project(capture)
