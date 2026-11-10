# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-7: the built-in endpoint table (§8.1) and its qualification fixtures.

A row ships only when every qualification fixture it names passes wire parsing and
reconstruction for its dialect: the recorded request goes through the real tee to the
row's own host, the recorded response comes back, and the offline reader rebuilds a
complete, verified exchange from the spans and the stored bytes."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import jsonschema
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric.content_store import LocalFilesystemContentStore
from fabric.reconstruct import reconstruct
from fabric.wire import _config, _diagnose, _endpoint_table
from fabric.wire._attrs import endpoint_label

from .test_capture_integration import JsonlSpanExporter

REPO = Path(__file__).resolve().parents[3]
CONTRACT = REPO / "contracts" / "providers" / "v1"
TABLE = json.loads((CONTRACT / "builtin-endpoints.json").read_text("utf-8"))
SCHEMA = json.loads((CONTRACT / "schema" / "builtin-endpoints-v1.schema.json").read_text("utf-8"))
TENANT = "tenant-table"
# A host each row matches (a suffix row needs a concrete name under it).
_EXAMPLE_HOST = {".openai.azure.com": "fabric-qual.openai.azure.com"}
# Where each dialect's client posts under the row's base path.
_AZURE_PATH = "/openai/deployments/qual/chat/completions"


def _fixture(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((CONTRACT / "fixtures" / f"{name}.json").read_text())
    return document


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)


def test_packaged_table_is_the_contract() -> None:
    """The wheel ships code only (057 B8): the table is a generated module equal to the
    contract (regenerate with sdk/python/scripts/sync_contract_data.py)."""
    assert _endpoint_table.TABLE == TABLE


def test_table_matches_its_schema_and_has_unique_ids() -> None:
    jsonschema.Draft202012Validator(SCHEMA).validate(TABLE)
    ids = [row["endpoint_id"] for row in TABLE["rows"]]
    assert len(ids) == len(set(ids))
    candidates = {row["endpoint_id"] for row in TABLE["candidates"]}
    assert not candidates & set(ids), "a candidate row is also shipped"


def test_sdk_loads_the_table_not_the_fallback() -> None:
    # A load failure silently falls back to the legacy rows (capture never fails for it);
    # the version proves the packaged table itself was read.
    assert _config.ENDPOINT_TABLE_VERSION == TABLE["table_version"] >= 1
    defaults = [row["endpoint_id"] for row in TABLE["rows"] if row["default"]]
    assert [m.endpoint_id for m in _config.DEFAULT_ENDPOINTS] == defaults
    assert wire.DEFAULT_ENDPOINTS == _config.DEFAULT_ENDPOINTS
    assert wire.WireConfig().endpoints == _config.DEFAULT_ENDPOINTS


def test_legacy_rows_are_unchanged_from_earlier_releases() -> None:
    """I8: the three rows of earlier releases keep their ids, hosts and provider names."""
    legacy = {m.endpoint_id: m for m in _config.LEGACY_ENDPOINTS}
    assert list(legacy) == TABLE["legacy_endpoint_ids"]
    rows = {m.endpoint_id: m for m in _config.table_matchers(TABLE, defaults_only=False)}
    for endpoint_id, matcher in legacy.items():
        assert rows[endpoint_id] == matcher


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "DEFAULT_ENDPOINTS"), ("table", "DEFAULT_ENDPOINTS"), ("legacy", "LEGACY_ENDPOINTS"),
     (" LEGACY ", "LEGACY_ENDPOINTS")],
)  # fmt: skip
def test_builtin_endpoints_variable(value: str | None, expected: str) -> None:
    environ = {} if value is None else {"FABRIC_WIRE_BUILTIN_ENDPOINTS": value}
    config, _ = _config.config_from_env(environ)
    assert config.endpoints == getattr(_config, expected)


def test_unknown_builtin_endpoints_value_names_the_fix() -> None:
    with pytest.raises(ValueError, match="FABRIC_WIRE_BUILTIN_ENDPOINTS") as caught:
        _config.config_from_env({"FABRIC_WIRE_BUILTIN_ENDPOINTS": "all"})
    why, hint = _diagnose.describe(caught.value)
    assert _diagnose.reason_id(why) == "FW-020"
    assert hint is not None and "legacy" in hint


@pytest.mark.parametrize(
    "table",
    [
        {"schema": "fabric.builtin-endpoints/v1", "table_version": 1, "rows": [{}]},
        {"schema": "fabric.builtin-endpoints/v1", "table_version": 1, "rows": []},
        {"schema": "fabric.builtin-endpoints/v2", "table_version": 1, "rows": TABLE["rows"]},
        {"schema": "fabric.builtin-endpoints/v1", "table_version": True, "rows": TABLE["rows"]},
        {**TABLE, "rows": [{**TABLE["rows"][0], "default": False}]},  # no default row at all
        {**TABLE, "rows": [{**TABLE["rows"][0], "dialect": "gemini"}]},
    ],
)  # fmt: skip
def test_a_broken_table_falls_back_to_the_legacy_rows(table: dict[str, Any]) -> None:
    """Never an empty endpoint set: a table that does not load records the legacy rows."""
    assert _config._load_table(table) == (0, _config.LEGACY_ENDPOINTS)


def test_every_shipped_row_names_existing_fixtures_of_its_dialect() -> None:
    for row in TABLE["rows"]:
        assert row["qualification"], row["endpoint_id"]
        for name in row["qualification"]:
            fixture = _fixture(name)
            assert fixture["dialect"] == row["dialect"], (row["endpoint_id"], name)
            assert fixture["status"] == 200


def _row_cases() -> list[tuple[str, str]]:
    return [(row["endpoint_id"], name) for row in TABLE["rows"] for name in row["qualification"]]


def _url(row: dict[str, Any], fixture: dict[str, Any]) -> str:
    host = row["hosts"][0] if row.get("hosts") else _EXAMPLE_HOST[row["host_suffixes"][0]]
    scheme = row["schemes"][0]
    if row["endpoint_id"] == "azure-openai":
        return f"{scheme}://{host}{row['path_prefix']}{_AZURE_PATH}?api-version=2024-10-21"
    suffix = fixture["suffix"]
    if not row["path_prefix"]:  # the providers' own APIs live under /v1
        suffix = "/v1" + suffix
    return f"{scheme}://{host}{row['path_prefix']}{suffix}"


@pytest.mark.parametrize(("endpoint_id", "fixture_name"), _row_cases())
def test_row_qualifies_through_capture_and_reconstruction(
    tmp_path: Path, endpoint_id: str, fixture_name: str
) -> None:
    row = next(r for r in TABLE["rows"] if r["endpoint_id"] == endpoint_id)
    fixture = _fixture(fixture_name)
    request_body = base64.b64decode(fixture["request_b64"])
    response_body = base64.b64decode(fixture["response_b64"])
    (matcher,) = _config.table_matchers({"rows": [row]})
    spans = tmp_path / "spans.jsonl"
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(spans)))
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    handle = wire.install(store=store, tracer_provider=provider, endpoints=(matcher,),
                          patch_httpx=False)  # fmt: skip

    def replay(request: httpx.Request) -> httpx.Response:
        assert request.content == request_body
        return httpx.Response(200, content=response_body,
                              headers={"content-type": fixture["response_media_type"]})  # fmt: skip

    transport = wire.WireTransport(httpx.MockTransport(replay))
    with httpx.Client(transport=transport) as client, wire.run("qualify-" + fixture_name):
        response = client.post(_url(row, fixture), content=request_body,
                               headers={"content-type": "application/json"})  # fmt: skip
        assert response.content == response_body
    assert handle.flush(10.0)
    handle.close()
    provider.shutdown()

    document = reconstruct([spans], store=store, tenant_id=TENANT)
    (run,) = document["runs"]
    # A recorded turn that calls a tool ends there: its call is unmatched, as a fact (info).
    assert [g for g in run["gaps"] if g["effect"] != "info"] == [], run["gaps"]
    (exchange,) = run["exchanges"]
    # The row's dialect parsed the recorded bytes completely, and every stored object
    # verified against its digest.
    api = {"openai": "openai.chat_completions", "anthropic": "anthropic.messages"}
    assert (exchange["api"], exchange["parse_status"]) == (api[row["dialect"]], "ok")
    assert exchange["response_state"] == "complete"
    assert exchange["output_message_count"] >= 1
    assert all(obj["verification"] == "verified" for obj in exchange["objects"].values())
    span_ids = {line["attributes"].get("fabric.wire.endpoint_id")
                for line in map(json.loads, spans.read_text().splitlines())}  # fmt: skip
    # C35 as emitted: a built-in row is <name>.default, never a host name.
    assert endpoint_label(matcher, builtin=True, key=None) in span_ids
    assert endpoint_label(matcher, builtin=True, key=None).endswith(".default")
    request_json = json.loads(request_body)
    if "tools" in request_json:  # the recorded response called the tool: the reader saw it
        assert exchange["tool_call_ids_emitted"], exchange
