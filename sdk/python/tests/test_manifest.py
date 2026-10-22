# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture manifests (spec 050 §3.8, WP-13): build, digest, span mapping, chain, fork
template, state changes and per-epoch fixed fields, against the WP-00 contracts."""

from __future__ import annotations

import collections
import copy
import hashlib
import importlib.util
import itertools
import json
import os
import sys
import types
import weakref
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

import fabric._loss
import fabric._sequence
from fabric import _manifest, wire
from fabric._capture_types import COUNTERS, Marker, RecordsMisuseError
from fabric._loss import LossEmitter
from fabric._manifest import (
    BuildFacts,
    build_manifest,
    capture_point_changed,
    current_document,
    emit_initial,
    in_force,
    latest_seq,
    manifest_attributes,
    manifest_digest,
    manifest_from_attributes,
    manifest_marker,
    on_new_epoch,
)
from fabric._manifest_fields_generated import MANIFEST_FIELDS
from fabric._sequence import SourceAllocator, key_id
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire import DEFAULT_ENDPOINTS, WireConfig, WireHandle
from fabric.wire._policy import CapturePolicy, ContentGate

REPO_ROOT = Path(__file__).resolve().parents[3]
COVERAGE = REPO_ROOT / "contracts" / "coverage" / "v1"
CAPTURE = REPO_ROOT / "contracts" / "capture" / "v1"


def _load(name: str) -> types.ModuleType:
    path = REPO_ROOT / "scripts" / "contracts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


COV = _load("validate_coverage_contracts")
CAP = _load("validate_capture_contracts")
REG = {name: json.loads((COVERAGE / rel).read_text()) for name, rel in COV.REGISTRY.items()}
SCHEMA = json.loads((COVERAGE / COV.SCHEMAS["manifest"]).read_text())
CAP_SCHEMAS = {rel: json.loads((CAPTURE / rel).read_text()) for rel in CAP.SCHEMAS.values()}
CHECKS = {k["key"]: k.get("check") for k in REG["keys"]["keys"]}
SUPPLIES = {p["id"]: tuple(p["supplies"]) for p in REG["points"]["capture_points"]}


def validate(document: Mapping[str, Any]) -> None:
    """Every emitted manifest: schema plus the semantic rules (spec 049 §2.4, §2.8)."""
    COV.validate_manifest_document(document, REG, SCHEMA)
    for key, value in manifest_attributes(document).items():
        check = CHECKS.get(key)
        assert check is None or COV.check_value(check, value), key  # fabricguard admits it


def fixture_bytes(rel: str) -> bytes:
    return (COVERAGE / rel).read_bytes()


def file_form(document: Mapping[str, Any]) -> bytes:
    """The generator's file form (``json.dumps(indent=2)`` + newline)."""
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# --- the values the WP-00 generator configured its fixtures with --------------------------

KEY1 = b"fabric-test-id-key-not-a-secret"
EPOCH, EPOCH_B = 4611686018427387905, 7140025193451802113


def uid(n: str) -> str:
    h = hashlib.sha256(f"uuid-{n}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def sha_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def label(value: str, key: bytes | None) -> str:
    return fabric._sequence.label_pseudonym("s-", value, key)


FIXTURE_POINTS = (
    "fabric.self", "install.config", "wire.py.httpx", "explicit.call_recorder", "sdk.records",
    "run.scope", "mcp.client", "reconstruct.parse", "reconstruct.infer",
)  # fmt: skip
# The fixtures list the registry `supplies` (a superset) where this build lists its generated
# table; the point inventory, versions and clock ceiling are the generator's (049 era).
FIXTURE_FACTS = BuildFacts(
    sdk_version="0.9.0", runtime_name="cpython", runtime_version="3.12.13",
    points=FIXTURE_POINTS, fields=SUPPLIES, point_versions={"wire.py.httpx": "1.2.0"},
    states={"mcp.client": ("disabled", "hook_disabled")},
    clock_max_uncertainty_ns=300_000_000_000,
)  # fmt: skip


class SpyLoss:
    """The install's marker queue and ``final``."""

    def __init__(self) -> None:
        self.markers: list[Marker] = []
        self.finals: list[tuple[int, int]] = []

    def queue_marker(self, marker: Marker) -> bool:
        self.markers.append(marker)
        return True

    def final(self, allocator: SourceAllocator) -> None:
        self.finals.append(allocator.seal())


class StubTee:
    def __init__(self, allocator: SourceAllocator, spool_key_id: str | None = None) -> None:
        self.allocator, self.loss = allocator, SpyLoss()
        self.sender = types.SimpleNamespace(spool=types.SimpleNamespace(key_id=spool_key_id))


def configured_handle(
    *, production: bool = False, epoch: int = EPOCH
) -> tuple[WireHandle, StubTee]:  # fmt: skip
    """A handle configured as the fixtures were: two endpoints, a 1024-entry queue, no
    aiohttp tee; local with id key KEY1, or a production node without one."""
    endpoints = DEFAULT_ENDPOINTS[:2]
    if production:
        config = WireConfig(endpoints=endpoints, queue_max_items=1024, patch_aiohttp=False,
                            content_endpoint="https://node.example:4318", tenant_id="acme",
                            spool_dir="/tmp/fabric-manifest-test")  # fmt: skip
        policy = CapturePolicy("acme-capture", 3, sha_text("acme-capture@3"), {},
                               profile="production", encrypted_store_required=True)  # fmt: skip
        gate = ContentGate("production", "disabled", "missing_id_key", policy, True, False, None)
        source, spool_kid = label("node-a/claims-agent", None), "kid-5e6f7a8b"
    else:
        config = WireConfig(endpoints=endpoints, queue_max_items=1024, patch_aiohttp=False,
                            id_key=KEY1)  # fmt: skip
        policy = CapturePolicy("fabric.local-default", 1, sha_text("fabric.local-default@1"),
                               {}, implicit=True, profile="local")  # fmt: skip
        gate = ContentGate("local", "enabled", None, policy, False, True, key_id(KEY1))
        source, spool_kid = label("build-host-7/travel-agent", KEY1), None
    allocator = SourceAllocator(source, "wire")
    allocator.epoch = epoch
    tee = StubTee(allocator, spool_kid)
    handle = WireHandle(config, tee, patched=True, gate=gate)  # type: ignore[arg-type]
    handle.records = object()  # type: ignore[assignment]  # the records input is attached
    return handle, tee


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_manifest, "_CHAINS", weakref.WeakKeyDictionary())
    monkeypatch.setattr(_manifest, "_ZEROS", collections.OrderedDict())
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "0")
    for name in ("FABRIC_RECORDS_MAX_OBJECT_BYTES", "FABRIC_RUN_OPEN_DEADLINE_S",
                 "FABRIC_RECORDS_STRICT", "FABRIC_IDENTITY_MODE"):  # fmt: skip
        monkeypatch.delenv(name, raising=False)
    COUNTERS.reset()
    yield
    COUNTERS.reset()


def pinned_ids(monkeypatch: pytest.MonkeyPatch, *names: str, times: tuple[str, ...]) -> None:
    ids = iter([value for n in names for value in (uid(n), uid(f"{n}-event"))])
    stamps = iter(times)
    monkeypatch.setattr(_manifest, "_new_id", lambda: next(ids))
    monkeypatch.setattr(_manifest, "_now", lambda: next(stamps))


# --- tables pinned to the registry and schemas -------------------------------------------


def test_span_key_table_is_the_registry_manifest_property_column() -> None:
    rows = {k["manifest_property"]: k["key"] for k in REG["keys"]["keys"]
            if "manifest_property" in k}  # fmt: skip
    assert dict(_manifest.SPAN_KEYS) == rows
    leaves = set(COV._manifest_leaves(SCHEMA)) | {"capture_points/fields"}
    assert set(_manifest.SPAN_KEYS) == leaves  # every schema property maps to one key


def test_point_columns_reasons_and_classes_match_the_contracts() -> None:
    points = {p["id"]: p for p in REG["points"]["capture_points"]}
    assert set(_manifest.POINTS) == set(points)
    for pid, spec in _manifest.POINTS.items():
        row = points[pid]
        assert spec.kind in row["kind"].split("/")
        assert spec.process_global == row["process_global"].startswith("yes")
        assert spec.opt_in == ("opt-in" in row["activation"])
    item = SCHEMA["properties"]["capture_points"]["items"]["properties"]
    assert frozenset(item["reason"]["enum"]) == _manifest.POINT_REASONS
    assert frozenset(item["state"]["enum"]) == _manifest.POINT_STATES
    classes = set(SCHEMA["properties"]["uncaptured_classes"]["items"]["enum"])
    assert {*_manifest.UNCAPTURED_BASE, "aiohttp", *_manifest.UNCAPTURED_REST} <= classes
    for pid in _manifest.RUNTIME_POINTS:  # this build supplies a subset of the registry's
        assert set(MANIFEST_FIELDS[pid]) <= set(points[pid]["supplies"])


# --- fixtures reproduced byte for byte from a configured handle -------------------------


def test_local_epoch_start_fixture_from_a_configured_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, tee = configured_handle()
    pinned_ids(monkeypatch, "m0", times=("2026-10-19T09:00:00Z",))
    ref = emit_initial(handle, facts=FIXTURE_FACTS)
    document = current_document(handle.allocator)
    assert document is not None and ref is not None
    assert file_form(document) == fixture_bytes("valid/manifest-local-epoch-start.json")
    assert ref.digest == manifest_digest(document) == COV.manifest_digest(document)
    assert (ref.epoch, ref.manifest_seq, ref.after_source_sequence) == (EPOCH, 0, -1)
    validate(document)
    assert tee.loss.finals == []  # a first install seals nothing


def test_production_fixture_from_a_configured_handle() -> None:
    handle, _ = configured_handle(production=True)
    document = build_manifest(
        handle, EPOCH, seq=0, after=-1, previous_digest=None, manifest_id=uid("prod"),
        event_id=uid("prod-event"), emitted_at="2026-10-19T09:00:00Z", facts=FIXTURE_FACTS,
    )  # fmt: skip
    assert document is not None
    assert file_form(document) == fixture_bytes("valid/manifest-production-content-disabled.json")
    validate(document)


def test_unsealed_prior_epochs_fixture_truncates_the_list_and_keeps_the_count() -> None:
    handle, _ = configured_handle(epoch=EPOCH_B)
    document = build_manifest(
        handle, EPOCH_B, seq=0, after=-1, previous_digest=None,
        unsealed_prior=[{"epoch": e} for e in range(1069, 999, -1)],
        manifest_id=uid("unsealed"), event_id=uid("unsealed-event"),
        emitted_at="2026-10-19T09:00:00Z", facts=FIXTURE_FACTS,
    )  # fmt: skip
    assert document is not None
    assert file_form(document) == fixture_bytes("valid/manifest-unsealed-prior-epochs.json")
    validate(document)


def test_chain_vectors_and_state_change_fixture_from_capture_point_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vectors = json.loads(fixture_bytes("fixtures/vectors/manifest-chain-v1.json"))
    handle, tee = configured_handle()
    allocator = handle.allocator
    pinned_ids(
        monkeypatch,
        "m0",
        "m1",
        "m2",
        times=("2026-10-19T09:00:00Z", "2026-10-19T09:05:00Z", "2026-10-19T09:40:00Z"),
    )
    documents: list[dict[str, Any]] = []

    def latest() -> dict[str, Any]:
        document = current_document(allocator)
        assert document is not None
        return document

    emit_initial(handle, facts=FIXTURE_FACTS)
    documents.append(latest())
    for _ in range(42):
        allocator.allocate()
    assert capture_point_changed(handle, "mcp.client", "active") is not None
    documents.append(latest())
    assert file_form(documents[1]) == fixture_bytes("valid/manifest-state-change.json")
    assert capture_point_changed(handle, "mcp.client", "active") is not None  # no change
    assert len(tee.loss.markers) == 2  # ... and no manifest
    for _ in range(56):
        allocator.allocate()
    capture_point_changed(handle, "wire.py.httpx", "failed", "internal_error")
    documents.append(latest())
    assert documents == vectors["manifests"]
    assert [manifest_digest(d) for d in documents] == vectors["digests"]
    assert latest_seq(allocator) == 2
    for document in documents:
        validate(document)
    for previous, document in itertools.pairwise(documents):
        assert COV._epoch_fixed(previous) == COV._epoch_fixed(document)  # rule 5
        assert document["after_source_sequence"] >= previous["after_source_sequence"]


def test_span_vectors_map_both_ways() -> None:
    vectors = json.loads(fixture_bytes("fixtures/vectors/manifest-span-v1.json"))
    for case in vectors["cases"]:
        assert manifest_attributes(case["manifest"]) == case["attributes"], case["name"]
        assert manifest_from_attributes(case["attributes"]) == case["manifest"], case["name"]


# --- the marker ---------------------------------------------------------------------------


def test_manifest_marker_is_a_valid_spool_marker() -> None:
    handle, tee = configured_handle()
    emit_initial(handle)
    (marker,) = tee.loss.markers
    document = current_document(handle.allocator)
    assert document is not None
    assert marker.kind == "manifest" and marker.event_id == document["event_id"]
    assert (marker.epoch, marker.last_sequence) == (EPOCH, -1)
    assert marker.manifest_id is None and marker.manifest_seq is None  # closed on manifests
    assert marker.manifest is not None
    attributes = {k: list(v) if isinstance(v, tuple) else v for k, v in marker.manifest.items()}
    assert manifest_from_attributes(attributes) == dict(document)
    spool = {
        "schema_version": "fabric.wire-spool-record/v1", "record_kind": "marker",
        "source": {"source_id": marker.source_id, "source_epoch": marker.epoch},
        "order": 1, "written_at_unix_nano": 1791331203000000000,
        "marker": {"kind": "manifest", "last_sequence": marker.last_sequence,
                   "event_id": marker.event_id, "manifest": attributes},
    }  # fmt: skip
    CAP.validate_document(spool, CAP_SCHEMAS)
    assert manifest_marker(document) == marker


# --- this build's manifest from a real install ------------------------------------------


@pytest.fixture()
def installed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[list[Marker]]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    markers: list[Marker] = []
    real = emitter.queue_marker

    def spy(marker: Marker) -> bool:
        markers.append(marker)
        return real(marker)

    monkeypatch.setattr(emitter, "queue_marker", spy)
    yield markers
    wire.uninstall()
    emitter.close(1.0)


def _install(tmp_path: Path, **overrides: Any) -> WireHandle:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    return wire.install(WireConfig(store=store, **overrides))


def _manifests(markers: list[Marker]) -> list[dict[str, Any]]:
    out = []
    for marker in markers:
        if marker.kind == "manifest" and marker.manifest is not None:
            attributes = {k: list(v) if isinstance(v, tuple) else v
                          for k, v in marker.manifest.items()}  # fmt: skip
            out.append(manifest_from_attributes(attributes))
    return out


def test_install_emits_a_valid_manifest_zero_of_this_build(
    installed: list[Marker], tmp_path: Path
) -> None:
    handle = _install(tmp_path, id_key=KEY1)
    (document,) = _manifests(installed)
    validate(document)
    assert document["source_epoch"] == handle.allocator.epoch
    assert (document["manifest_seq"], document["after_source_sequence"]) == (0, -1)
    rows = {p["id"]: p for p in document["capture_points"]}
    assert tuple(rows) == _manifest.RUNTIME_POINTS
    for pid, row in rows.items():
        assert row["fields"] == list(MANIFEST_FIELDS[pid])  # the per-build table
    assert rows["wire.py.httpx"]["state"] == "active"
    assert document["clock"] == {"domain": "wall_utc", "uncertainty_ns": 0}
    assert document["limits"]["records_max_object_bytes"] == 16777216
    assert document["limits"]["open_run_deadline_s"] == 604800
    assert document["key_id"] == key_id(KEY1)
    assert document["source_auth"] == "unbound"
    assert "api.openai.com" not in json.dumps(document)  # only the endpoint-set digest
    ref = in_force(handle.allocator)
    assert ref is not None and ref.digest == manifest_digest(document)


def test_records_only_install_reports_wire_points_installed_inactive(
    installed: list[Marker], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "250")
    monkeypatch.setenv("FABRIC_RECORDS_MAX_OBJECT_BYTES", "1024")
    monkeypatch.setenv("FABRIC_RUN_OPEN_DEADLINE_S", "3600")
    _install(tmp_path, patch_httpx=False, patch_aiohttp=False)
    (document,) = _manifests(installed)
    validate(document)
    rows = {p["id"]: p for p in document["capture_points"]}
    for pid in ("wire.py.httpx", "wire.py.aiohttp"):
        assert (rows[pid]["state"], rows[pid]["reason"]) == ("installed_inactive", "not_configured")
    assert "aiohttp" in document["uncaptured_classes"]
    assert document["clock"]["uncertainty_ns"] == 250_000_000
    assert document["limits"]["records_max_object_bytes"] == 1024
    assert document["limits"]["open_run_deadline_s"] == 3600
    assert document["pseudonym_mode"] == "unkeyed" and "key_id" not in document


def test_state_change_on_a_live_install_chains_and_keeps_fixed_fields(
    installed: list[Marker], tmp_path: Path
) -> None:
    handle = _install(tmp_path)
    allocator = handle.allocator
    for _ in range(3):
        allocator.allocate()
    ref = capture_point_changed(handle, "wire.py.aiohttp", "failed", "internal_error")
    assert ref is not None and (ref.manifest_seq, ref.after_source_sequence) == (1, 2)
    first, second = _manifests(installed)
    validate(second)
    assert second["previous_manifest_sha256"] == manifest_digest(first)
    assert COV._epoch_fixed(first) == COV._epoch_fixed(second)
    assert latest_seq(allocator) == 1


def test_misuse_fails_open_and_raises_only_in_strict(
    installed: list[Marker], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path)
    assert capture_point_changed(handle, "exec.ptrace", "active") is None
    assert capture_point_changed(handle, "sdk.records", "broken") is None  # type: ignore[arg-type]
    assert capture_point_changed(handle, "sdk.records", "failed", "because") is None
    assert COUNTERS.api_misuse == 3
    assert len(_manifests(installed)) == 1
    monkeypatch.setenv("FABRIC_RECORDS_STRICT", "1")
    with pytest.raises(RecordsMisuseError):
        capture_point_changed(handle, "exec.ptrace", "active")


def test_a_manifest_that_cannot_be_built_is_none_with_a_class_only_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handle, _ = configured_handle()
    handle.gate = None
    assert build_manifest(handle, EPOCH, seq=0, after=-1, previous_digest=None) is None
    assert "capture manifest not built (ValueError)" in caplog.text
    assert build_manifest(configured_handle()[0], EPOCH, seq=1, after=3,
                          previous_digest=None) is None  # an unchained manifest  # fmt: skip
    assert COUNTERS.internal_errors == 2


def test_otel_disabled_install_has_no_manifest(
    installed: list[Marker], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    handle = _install(tmp_path)
    assert not handle.capturing and _manifests(installed) == []
    assert capture_point_changed(handle, "sdk.records", "failed", "internal_error") is None


# --- epochs: re-install, post-final, fork -----------------------------------------------


def test_reinstall_starts_a_fresh_epoch(installed: list[Marker], tmp_path: Path) -> None:
    handle = _install(tmp_path)
    allocator = handle.allocator
    first_epoch = allocator.epoch
    allocator.allocate()
    wire.uninstall()
    allocator.allocate()  # a straggler allocated in the post-final epoch before re-install
    straggler_epoch = allocator.epoch
    again = _install(tmp_path)
    assert again.allocator is allocator
    first, *changes, second = _manifests(installed)
    # WP-14: unpatching aiohttp at uninstall is a state change of the first epoch (§3.8)
    assert all(change["source_epoch"] == first["source_epoch"] for change in changes)
    assert second["source_epoch"] == allocator.epoch
    assert second["source_epoch"] not in (first_epoch, straggler_epoch)
    assert (second["manifest_seq"], second["after_source_sequence"]) == (0, -1)
    assert "previous_manifest_sha256" not in second
    validate(second)


def test_reinstall_never_issues_two_manifest_zeros_for_one_epoch(tmp_path: Path) -> None:
    handle, tee = configured_handle()
    emit_initial(handle)
    again, _ = configured_handle()  # same source and epoch, nothing allocated
    again._tee_or_none.allocator = handle.allocator  # type: ignore[union-attr]
    again._tee_or_none.loss = tee.loss  # type: ignore[union-attr]
    ref = emit_initial(again)
    assert tee.loss.finals == [(EPOCH, -1)]  # the old epoch is sealed with final first
    assert ref is not None and ref.epoch != EPOCH and ref.manifest_seq == 0


def test_post_final_epoch_gets_manifest_zero_on_first_allocation(
    installed: list[Marker], tmp_path: Path
) -> None:
    handle = _install(tmp_path)
    allocator = handle.allocator
    old = allocator.epoch
    handle._tee.loss.final(allocator)
    assert latest_seq(allocator) is None  # nothing issued for the new epoch yet
    ref = on_new_epoch(allocator)
    assert ref is not None and ref.epoch == allocator.epoch != old and ref.manifest_seq == 0
    assert on_new_epoch(allocator) == ref  # idempotent
    assert in_force(allocator) == ref
    assert len(_manifests(installed)) == 2


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork only")
def test_forked_child_gets_its_own_manifest_zero(installed: list[Marker], tmp_path: Path) -> None:
    handle = _install(tmp_path)
    allocator = handle.allocator
    capture_point_changed(handle, "explicit.call_recorder", "active")
    parent = in_force(allocator)
    assert parent is not None and parent.manifest_seq == 1
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child reports through the pipe
        try:
            document = current_document(allocator)
            child = {"document": document, "ref_epoch": allocator.epoch,
                     "markers": len(installed)}  # fmt: skip
            os.write(write_fd, json.dumps(child).encode())
        finally:
            os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as pipe:
        child = json.loads(pipe.read())
    os.waitpid(pid, 0)
    document = child["document"]
    assert document["source_epoch"] == child["ref_epoch"] != parent.epoch
    assert document["source_id"] == allocator.source_id
    assert (document["manifest_seq"], document["after_source_sequence"]) == (0, -1)
    assert "previous_manifest_sha256" not in document
    rows = {p["id"]: p for p in document["capture_points"]}
    assert rows["explicit.call_recorder"]["state"] == "active"  # the states in force at fork
    parent_doc = current_document(allocator)
    assert parent_doc is not None
    fixed = {k: v for k, v in COV._epoch_fixed(document).items() if k != "source_epoch"}
    parent_fixed = COV._epoch_fixed(parent_doc)
    assert fixed == {k: v for k, v in parent_fixed.items() if k != "source_epoch"}
    validate(document)
    assert child["markers"] == len(installed) + 1  # queued in the child's after-fork hook


# --- environment limits ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 16777216), ("1", 1), ("16777216", 16777216), ("0", 16777216),
     ("16777217", 16777216), ("lots", 16777216)],
)  # fmt: skip
def test_records_max_object_bytes(value: str | None, expected: int) -> None:
    env = {} if value is None else {"FABRIC_RECORDS_MAX_OBJECT_BYTES": value}
    assert _manifest.records_max_object_bytes(env) == expected


def test_open_run_deadline_and_clock_defaults() -> None:
    assert _manifest.open_run_deadline_s({}) == 604800
    assert _manifest.open_run_deadline_s({"FABRIC_RUN_OPEN_DEADLINE_S": "59"}) == 604800
    assert _manifest.clock_uncertainty_ns({}) == 1_000_000_000  # OD-3
    assert _manifest.clock_uncertainty_ns({"FABRIC_CLOCK_UNCERTAINTY_MS": "-1"}) == 1_000_000_000


def test_endpoint_set_digest_never_carries_a_hostname() -> None:
    digest = _manifest.endpoint_set_digest(DEFAULT_ENDPOINTS[:2])
    assert digest == sha_text("api.openai.com|api.anthropic.com")
    assert _manifest.endpoint_set_digest(DEFAULT_ENDPOINTS) != digest


def test_clear_identity_mode_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "clear")  # R8: an explicit opt-in, recorded
    document = build_manifest(configured_handle()[0], EPOCH, seq=0, after=-1,
                              previous_digest=None)  # fmt: skip
    assert document is not None and document["identity_mode"] == "clear"
    validate(document)


def test_digest_is_order_free_and_documents_are_independent() -> None:
    handle, _ = configured_handle()
    document = build_manifest(handle, EPOCH, seq=0, after=-1, previous_digest=None)
    assert document is not None
    shuffled = dict(reversed(list(copy.deepcopy(document).items())))
    assert manifest_digest(shuffled) == manifest_digest(document)
    document["limits"]["max_body_bytes"] = 1
    again = build_manifest(handle, EPOCH, seq=0, after=-1, previous_digest=None)
    assert again is not None and again["limits"]["max_body_bytes"] == 33554432
