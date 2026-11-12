# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §13.1: the diagnostics catalogue is complete and the only source of ids.

Every id the CLI and the SDK emit is in the catalogue with a non-empty fix; the catalogue
has no Python id the code never emits; the packaged copy is the contract byte for byte; the
docs page lists every entry. Spec 055 §4.7: an entry's optional ``sdk`` list names the SDKs
that emit it (absent: Python). TypeScript-only entries are exempt here; the TypeScript
SDK's own test requires those to be emitted by TypeScript code."""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema

from fabric import _catalogue, _catalogue_data
from fabric.wire import _diagnose

from ._diagnostics_doc import render

REPO = Path(__file__).resolve().parents[3]
CONTRACT = REPO / "contracts" / "diagnostics" / "v1"
SOURCE = REPO / "sdk" / "python" / "src" / "fabric"
_ID = re.compile(r"\bF[CWERN]-[0-9]{3}\b")


def _catalogue_document() -> dict[str, object]:
    document: dict[str, object] = json.loads((CONTRACT / "messages-v1.json").read_text("utf-8"))
    return document


def _for_python(entry: dict[str, object]) -> bool:
    """Spec 055 §4.7: an entry without ``sdk`` is a Python entry."""
    sdks = entry.get("sdk", ["python"])
    return isinstance(sdks, list) and "python" in sdks


def _emitted_ids() -> set[str]:
    ids: set[str] = set()
    for path in SOURCE.rglob("*.py"):
        if path.name != "_catalogue_data.py":  # the catalogue itself, not an emitter
            ids.update(_ID.findall(path.read_text("utf-8")))
    return ids


def test_packaged_catalogue_is_the_contract() -> None:
    """The wheel ships code only (057 B8): a generated module equal to the contract
    (regenerate with sdk/python/scripts/sync_contract_data.py)."""
    assert _catalogue_document() == _catalogue_data.CATALOGUE


def test_catalogue_matches_its_schema_with_unique_ids_and_names() -> None:
    document = _catalogue_document()
    schema = json.loads((CONTRACT / "schema" / "messages-v1.schema.json").read_text("utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)
    entries = document["messages"]
    assert isinstance(entries, list)
    assert len({e["id"] for e in entries}) == len(entries)
    assert len({e["name"] for e in entries}) == len(entries)
    assert all(e["fix"].strip() and e["text"].strip() for e in entries)


def test_every_emitted_id_is_catalogued_and_every_catalogued_id_is_emitted() -> None:
    emitted = _emitted_ids()
    messages = _catalogue.messages()
    catalogued = {
        e for e, entry in messages.items() if not entry.get("retired") and _for_python(entry)
    }
    assert emitted - set(messages) == set(), "emitted ids missing from the catalogue"
    assert catalogued - emitted == set(), "catalogue ids no code emits"
    typescript_only = {e for e, entry in messages.items() if not _for_python(entry)}
    assert emitted & typescript_only == set(), "Python emits a TypeScript-only id"


def test_sdk_lists_name_known_sdks_on_sdk_entries_only() -> None:
    """Spec 055 §4.7: ``sdk`` is optional, lists python and/or typescript, and appears only
    on FW- (SDK) entries; the Node.js-only entries are catalogued for TypeScript alone."""
    for message_id, entry in _catalogue.messages().items():
        if "sdk" in entry:
            assert message_id.startswith("FW-"), message_id
            assert entry["sdk"] and set(entry["sdk"]) <= {"python", "typescript"}, message_id
    node_only = {
        e for e, entry in _catalogue.messages().items() if entry.get("sdk") == ["typescript"]
    }
    assert {_catalogue.message(e)["name"] for e in node_only} == {
        "node_capture_not_installed", "node_runtime_unqualified", "node_platform_unsupported",
        "node_native_unusable", "node_hook_disabled", "node_worker_unattached",
        "node_autoload_off", "node_redacted_roles", "node_spool_backlog",
    }  # fmt: skip


def test_every_configuration_reason_has_a_catalogued_id() -> None:
    for _needle, reason_id, hint in _diagnose._FIXES:
        assert reason_id in _catalogue.messages()
        assert hint.strip()
    assert _diagnose.GENERIC_REASON_ID in _catalogue.messages()


def test_catalogue_texts_carry_no_interpolated_values() -> None:
    """Texts and fixes are fixed strings: no format placeholder can carry a value."""
    for entry in _catalogue.messages().values():
        for text in (entry["text"], entry["fix"]):
            assert "%s" not in text and "{" not in text.replace('{"', ""), entry["id"]


def test_docs_page_is_generated_from_the_catalogue() -> None:
    page = REPO / str(_catalogue_document()["docs"])
    assert page.read_text("utf-8") == render(), (
        "docs/diagnostics.md is stale: run `python -m tests._diagnostics_doc > "
        "../../docs/diagnostics.md` from sdk/python"
    )
    for message_id in _catalogue.messages():
        assert f"### {message_id}\n" in page.read_text("utf-8")
