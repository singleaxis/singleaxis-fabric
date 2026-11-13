# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Cross-language wire vectors for the TypeScript wire core (spec 055 §6.1, §6.2, §8;
unit 055-t2), produced from the Python writer itself:

- ``contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json``: canonical and ASCII JSON
  (escaping, code-point key order, integral floats, int64), ids of surrogatepass values,
  ``FWSPOOL1`` record frames, an ``FWSPOOLB`` batch, ``FWSPENC1`` sealed envelopes under a
  fixed test key and nonce (and the wrong-basename and unknown-key cases), the
  ``FWLEDGR1`` ledger header and an ``FWLSLOT1`` slot, and ``FWEPOCH1`` registration
  files. ``validate_capture_contracts.py`` re-checks every byte with its own reading of
  the formats.
- ``sdk/typescript/test/wire/fixtures/match-table.json``: requests and the endpoint and
  API ``wire/_match.py`` picks for them, for the built-in ``table`` and ``legacy`` rows.
- ``sdk/typescript/test/wire/fixtures/config-env.json``: the Python-to-TypeScript
  environment mapping, and for each environment case what ``python -m fabric.wire
  status`` decides: valid (with the resolved settings) or invalid with the catalogue id
  ``wire/_diagnose.py`` gives the message.

Usage: ``python scripts/contracts/generate_ts_wire_vectors.py [--check]``. Needs the
Python SDK (``pip install -e sdk/python``) and ``cryptography``. The test key, nonce,
pid, times and ids below are fixed test values, never secrets.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
SPOOL_BYTES = REPO / "contracts/capture/v1/fixtures/vectors/spool-bytes-v1.json"
TS_FIXTURES = REPO / "sdk/typescript/test/wire/fixtures"
MATCH_TABLE = TS_FIXTURES / "match-table.json"
CONFIG_ENV = TS_FIXTURES / "config-env.json"

TEST_SPOOL_KEY = bytes(range(32))  # a fixed test key: never a deployment's
TEST_NONCE = bytes.fromhex("000102030405060708090a0b")  # fixed only in these vectors
OTHER_KEY = bytes(range(32, 64))
TEST_ID_KEY = "fabric-test-id-key-not-a-secret"


def _hex(data: bytes) -> str:
    return data.hex()


# --------------------------------------------------------------------------- JSON
_JSON_CASES = (
    (
        "ordering by code point, not UTF-16 unit",
        '{"\\ud83d\\ude00":1,"\\uffff":2,"b":3,"a":4,"":5}',
    ),
    (
        "escaping of quote, backslash and control characters",
        '["q\\"b\\\\s\\/n\\n\\r\\t\\b\\f\\u0000\\u001f\\u007f"]',
    ),
    (
        "non-ASCII text is literal UTF-8",
        '{"k":"caf\\u00e9 \\u65e5\\u672c \\ud83d\\ude80 \\u2028"}',
    ),
    (
        "int64 bounds and beyond 2^53",
        "[0,-1,9007199254740993,9223372036854775807,-9223372036854775808]",
    ),
    (
        "integral and other floats",
        "[1.0,-0.0,0.5,100.0,1e16,1e15,1.5e-7,0.0001,1e-05,123456789.125,1e100]",
    ),
    (
        "nested objects and empty containers",
        '{"z":{"b":[],"a":{}},"a":[null,true,false]}',
    ),
    ("a lone surrogate", '["\\ud800x"]'),
)


def _json_cases() -> list[dict[str, Any]]:
    out = []
    for name, text in _JSON_CASES:
        value = json.loads(text)
        for ascii_only in (False, True):
            case: dict[str, Any] = {
                "name": name,
                "input": text,
                "ensure_ascii": ascii_only,
            }
            try:
                encoded = json.dumps(
                    value,
                    ensure_ascii=ascii_only,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                case["output_hex"] = _hex(encoded)
            except UnicodeEncodeError:
                case["refused"] = True
            out.append(case)
    return out


def _id_cases() -> list[dict[str, Any]]:
    from contracts import p1_reference as ref  # noqa: PLC0415
    from fabric._sequence import pseudonym_v2  # noqa: PLC0415

    values = ("order-1", "ordre spécial/1", "\ud800lone", "emoji \U0001f680", "")
    out: list[dict[str, Any]] = []
    for value in values:
        escaped = json.dumps(value)  # ASCII escapes: a lone surrogate survives the file
        out.append(
            {
                "function": "encode_opaque_id",
                "value": escaped,
                "expected": ref.encode_opaque_id(value),
            }
        )
        out.append(
            {
                "function": "run_pseudonym",
                "value": escaped,
                "key": TEST_ID_KEY,
                "expected": ref.run_pseudonym(value, TEST_ID_KEY),
            }
        )
        out.append(
            {
                "function": "pseudonym_v2",
                "prefix": "sess",
                "value": escaped,
                "key": TEST_ID_KEY,
                "expected": pseudonym_v2("sess", value, TEST_ID_KEY.encode()),
            }
        )
    return out


# --------------------------------------------------------------------------- spool bytes
def _fixture(name: str) -> dict[str, Any]:
    path = REPO / "contracts/capture/v1/fixtures/valid" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _with_bodies(
    doc: dict[str, Any], texts: list[bytes]
) -> tuple[dict[str, Any], list[bytes]]:
    """``doc`` with its stored bodies replaced by ``texts`` (lengths, offsets, digests)."""
    doc = json.loads(json.dumps(doc))
    offset, bodies = 0, []
    stored = [
        b for b in doc.get("bodies", []) if b["descriptor"].get("status") == "stored"
    ]
    for body, text in zip(stored, texts, strict=True):
        digest = "sha256:" + hashlib.sha256(text).hexdigest()
        descriptor = body["descriptor"]
        descriptor["stored_byte_length"], descriptor["stored_sha256"] = (
            len(text),
            digest,
        )
        if "source_sha256" in descriptor:
            descriptor["source_byte_length"], descriptor["source_sha256"] = (
                len(text),
                digest,
            )
    for body in doc.get("bodies", []):
        stored_body = body["descriptor"].get("status") == "stored"
        text = texts[stored.index(body)] if stored_body else b""
        body["offset"], body["length"] = offset, len(text)
        offset += len(text)
        bodies.append(text)
    return doc, bodies


def _records() -> list[tuple[str, dict[str, Any], list[bytes]]]:
    exchange, exchange_bodies = _with_bodies(
        _fixture("spool-record-exchange.json"),
        [
            b'{"model":"gpt-4o","messages":[{"role":"user","content":"caf\xc3\xa9?"}]}',
            b'{"id":"chatcmpl-1","choices":[{"message":{"content":"Oui."}}]}',
        ],
    )
    record = _fixture("spool-record-record-typescript.json")
    texts = [b'{"query":"flights"}', b'{"result":["UA 1"]}', b'{"note":"x"}']
    stored = sum(
        1 for b in record.get("bodies", []) if b["descriptor"].get("status") == "stored"
    )
    record, record_bodies = _with_bodies(record, texts[:stored])
    return [
        ("exchange", exchange, exchange_bodies),
        ("record", record, record_bodies),
        ("loss", _fixture("spool-record-loss-segment.json"), []),
        ("segment_seal", _fixture("spool-record-segment-seal-terminal.json"), []),
    ]


def _spool_sections() -> dict[str, Any]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    from fabric.wire import _ledger, _registration, _spool  # noqa: PLC0415
    from fabric.wire._keys import envelope_key_id  # noqa: PLC0415

    records, frames = [], {}
    for name, doc, bodies in _records():
        pieces = _spool.frame(doc, bodies)
        data = b"".join(pieces)
        header, _blob = _spool.unframe(data)  # the reader accepts it
        assert header == doc
        frames[name] = pieces
        records.append(
            {
                "name": name,
                "header": doc,
                "bodies_hex": [_hex(b) for b in bodies],
                "frame_hex": _hex(data),
            }
        )
    batch_names = ["exchange", "record"]
    batch = b"".join(_spool.batch_frame([frames[n] for n in batch_names]))
    assert len(_spool.unframe_all(batch)) == len(batch_names)
    key_id = envelope_key_id(TEST_SPOOL_KEY)
    sealed = []
    for name, plain, basename in (
        ("record", b"".join(frames["exchange"]), "00000000000000000007-1.rec"),
        ("batch", batch, "00000000000000000009-2.rec"),
    ):
        aad = _spool.ENVELOPE_MAGIC + key_id.encode("ascii") + basename.encode("ascii")
        body = AESGCM(TEST_SPOOL_KEY).encrypt(TEST_NONCE, plain, aad)
        data = _spool.ENVELOPE_MAGIC + key_id.encode("ascii") + TEST_NONCE + body
        assert _spool.unseal(data, basename, AESGCM(TEST_SPOOL_KEY), key_id) == plain
        sealed.append(
            {
                "name": name,
                "basename": basename,
                "key_id": key_id,
                "nonce_hex": _hex(TEST_NONCE),
                "plain_hex": _hex(plain),
                "sealed_hex": _hex(data),
            }
        )
    refused = []
    data = bytes.fromhex(sealed[0]["sealed_hex"])
    with contextlib.suppress(_spool.CorruptRecordError):
        _spool.unseal(
            data, "00000000000000000008-1.rec", AESGCM(TEST_SPOOL_KEY), key_id
        )
        raise AssertionError("a renamed record must not authenticate")
    refused.append(
        {
            "name": "wrong basename",
            "sealed": "record",
            "opened_as": "00000000000000000008-1.rec",
            "error": "corrupt",
        }
    )
    other = envelope_key_id(OTHER_KEY)
    with contextlib.suppress(_spool.UndecryptableRecordError):
        _spool.unseal(data, sealed[0]["basename"], AESGCM(OTHER_KEY), other)
        raise AssertionError("another key id must stay pending")
    refused.append(
        {
            "name": "unknown key id",
            "sealed": "record",
            "key_hex": _hex(OTHER_KEY),
            "key_id": other,
            "error": "undecryptable",
        }
    )
    ledger_records = [records[2]["header"], records[3]["header"]]
    slot = _ledger._encode("4242-0a0b0c0d", ledger_records)
    assert slot is not None and _ledger.decode_slot(slot) == ledger_records
    header = _ledger._HEAD.pack(_ledger.MAGIC, _ledger.SLOTS, _ledger.SLOT_BYTES)
    registrations = []
    for epoch, source in (
        (4611686018427387905, "s-b94f348e8d6890782b2af72c847dc77b"),
        (1, "billing-agent.prod"),
        ((1 << 63) - 1, "wire-3f9a1c2b7d4e5f60"),
    ):
        data = _registration.encode(
            epoch, source, pid=4242, registered_at_unix_nano=1791331200000000000
        )
        assert _registration.decode(data) is not None
        registrations.append(
            {
                "epoch": epoch,
                "source_id": source,
                "pid": 4242,
                "registered_at_unix_nano": 1791331200000000000,
                "file_hex": _hex(data),
            }
        )
    return {
        "records": records,
        "batches": [
            {
                "name": "exchange and record",
                "records": batch_names,
                "batch_hex": _hex(batch),
            }
        ],
        "sealed": sealed,
        "refused": refused,
        "ledger": {
            "header_bytes": _ledger.HEADER_BYTES,
            "slot_bytes": _ledger.SLOT_BYTES,
            "slots": _ledger.SLOTS,
            "header_hex": _hex(header),
            "slot": {
                "owner": "4242-0a0b0c0d",
                "records": ["loss", "segment_seal"],
                "slot_hex": _hex(slot),
            },
        },
        "registrations": registrations,
    }


def spool_bytes() -> dict[str, Any]:
    return {
        "schema_version": "fabric.spool-bytes-vectors/v1",
        "rule": (
            "Spec 055 §6.1-§6.2: the bytes the Python writer produces, which TypeScript "
            "reproduces exactly. json: json.dumps(value, sort_keys=True, separators=(',', "
            "':'), ensure_ascii) of json.loads(input), UTF-8, or refused (a lone surrogate "
            "has no UTF-8 form); ids: encode_opaque_id, run_pseudonym and pseudonym_v2 of "
            "the JSON-escaped value (UTF-8 surrogatepass); records: FWSPOOL1 | u32be(header "
            "length) | header (sort_keys, literal UTF-8) | bodies | sha256; batches: FWSPOOLB "
            "| u32be(count) | (u64be(length) | frame)* | sha256; sealed: FWSPENC1 | key id | "
            "nonce | AES-256-GCM(plain, aad = FWSPENC1 | key id | basename), key id = kid- + "
            "8 hex of HMAC-SHA256(key, 'fabric-spool/v1/kid'); ledger: the >8sII header and "
            "an FWLSLOT1 slot (u32be length | ASCII JSON {owner, records} | sha256, zero "
            "padded); registrations: the 4096-byte FWEPOCH1 file (little-endian fields, "
            "sha256 of bytes 0-255 at 4064). The spool key and nonce are fixed test values."
        ),
        "spool_key_hex": _hex(TEST_SPOOL_KEY),
        "json": _json_cases(),
        "ids": _id_cases(),
        **_spool_sections(),
    }


# --------------------------------------------------------------------------- matcher table
_REQUESTS = (
    ("POST", "https", "api.openai.com", None, "/v1/chat/completions"),
    ("POST", "https", "API.OpenAI.com", 443, "/v1/responses"),
    ("POST", "https", "api.openai.com", 8443, "/v1/embeddings"),
    ("GET", "https", "api.openai.com", None, "/v1/chat/completions"),
    ("POST", "http", "api.openai.com", None, "/v1/chat/completions"),
    ("POST", "https", "api.openai.com", None, "/v1/models"),
    ("POST", "https", "api.openai.com", None, "/v1/completions"),
    ("POST", "https", "api.anthropic.com", None, "/v1/messages"),
    ("POST", "https", "api.anthropic.com", None, "/v1/chat/completions"),
    (
        "POST",
        "https",
        "eastus.openai.azure.com",
        None,
        "/openai/deployments/gpt/chat/completions",
    ),
    (
        "POST",
        "https",
        "openai.azure.com",
        None,
        "/openai/deployments/gpt/chat/completions",
    ),
    ("POST", "https", "evil-openai.azure.com.example", None, "/v1/chat/completions"),
    ("POST", "https", "models.example.com", None, "/llm/v1/chat/completions"),
    ("POST", "http", "models.example.com", 8080, "/llm/v1/chat/completions"),
    ("POST", "http", "models.example.com", 80, "/llm/v1/chat/completions"),
    ("POST", "https", "models.example.com", None, "/other/v1/chat/completions"),
    ("POST", "https", "x.corp.example", None, "/messages"),
    ("POST", "https", "corp.example", None, "/messages"),
    ("POST", "https", "api.mistral.ai", None, "/v1/chat/completions"),
)
_EXTRA = (
    '[{"endpoint_id":"my-model","dialect":"openai","hosts":["models.example.com"],'
    '"schemes":["https","http"],"ports":[443,8080],"path_prefix":"/llm",'
    '"provider_name":"my-model"},{"endpoint_id":"corp","dialect":"anthropic",'
    '"host_suffixes":[".corp.example"],"provider_name":"corp"}]'
)


def match_table() -> dict[str, Any]:
    from fabric.wire._config import (  # noqa: PLC0415
        DEFAULT_ENDPOINTS,
        LEGACY_ENDPOINTS,
        parse_endpoints,
    )
    from fabric.wire._match import EndpointIndex  # noqa: PLC0415

    def matcher(m: Any) -> dict[str, Any]:
        return {
            "endpoint_id": m.endpoint_id,
            "dialect": m.dialect,
            "hosts": sorted(m.hosts),
            "host_suffixes": sorted(m.host_suffixes),
            "schemes": sorted(m.schemes),
            "ports": None if m.ports is None else sorted(m.ports),
            "path_prefix": m.path_prefix,
            "provider_name": m.provider_name,
        }

    sets = {"table": DEFAULT_ENDPOINTS, "legacy": LEGACY_ENDPOINTS}
    out: dict[str, Any] = {
        "schema_version": "fabric.ts-match-table/v1",
        "rule": "wire/_match.py EndpointIndex.match on each request, per endpoint set; "
        "generated by scripts/contracts/generate_ts_wire_vectors.py",
        "extra_endpoints": _EXTRA,
        "sets": {},
    }
    for name, builtin in sets.items():
        matchers = tuple(builtin) + parse_endpoints(_EXTRA)
        index = EndpointIndex(matchers)
        cases = []
        for method, scheme, host, port, path in _REQUESTS:
            found = index.match(method, scheme, host, port, path)
            cases.append(
                {
                    "method": method,
                    "scheme": scheme,
                    "host": host,
                    "port": port,
                    "path": path,
                    "endpoint_id": found[0].endpoint_id if found else None,
                    "api": found[1] if found else None,
                }
            )
        out["sets"][name] = {"builtin": [matcher(m) for m in builtin], "cases": cases}
    return out


# --------------------------------------------------------------------------- environment
# Python env name -> (Python WireConfig field, TypeScript WireSettings field); TS-only and
# Python-only names say so. Unset and empty are the same for every name here.
MAPPING: tuple[tuple[str, str | None, str | None], ...] = (
    ("FABRIC_WIRE_AUTOLOAD", None, "autoload"),
    ("FABRIC_WIRE_DIAGNOSTICS", None, "diagnostics"),
    ("FABRIC_WIRE_BUILTIN_ENDPOINTS", "endpoints", "endpoints"),
    ("FABRIC_WIRE_ENDPOINTS", "extra_endpoints", "extraEndpoints"),
    ("FABRIC_WIRE_LABELS", "labels", "labels"),
    ("FABRIC_IDENTITY_MODE", None, "identityMode"),
    ("FABRIC_WIRE_ID_KEY", "id_key", "secrets.idKey"),
    ("FABRIC_WIRE_ID_KEY_FILE", "id_key", "secrets.idKey"),
    ("FABRIC_WIRE_SPOOL_KEY", "spool_key", "secrets.spoolKey"),
    ("FABRIC_WIRE_SPOOL_KEY_FILE", "spool_key", "secrets.spoolKey"),
    ("FABRIC_TOKENIZATION_KEY", "tokenization_key", "secrets.tokenizationKey"),
    ("FABRIC_TOKENIZATION_KEY_FILE", "tokenization_key", "secrets.tokenizationKey"),
    ("FABRIC_WIRE_STORE", "store", "store"),
    ("FABRIC_WIRE_CONTENT_ENDPOINT", "content_endpoint", "contentEndpoint"),
    ("FABRIC_TENANT_ID", "tenant_id", "tenantId"),
    ("FABRIC_SOURCE_ID", "source_id", "sourceId"),
    ("FABRIC_WIRE_SPOOL_DIR", "spool_dir", "spoolDir"),
    ("FABRIC_WIRE_SPOOL_MAX_BYTES", "spool_max_bytes", "spoolMaxBytes"),
    ("FABRIC_WIRE_SPOOL_MAX_RECEIPTS", "spool_max_receipts", "spoolMaxReceipts"),
    (
        "FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY",
        "spool_durable_boundary",
        "spoolDurableBoundary",
    ),
    (
        "FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT",
        "spool_migrate_plaintext",
        "spoolMigratePlaintext",
    ),
    ("FABRIC_CAPTURE_POLICY", "capture_policy", "capturePolicyPath"),
    ("FABRIC_REDACTION_ENDPOINT", "redaction", "redactionEndpoint"),
    ("FABRIC_REDACTION_TOKEN_FILE", "redaction", "redactionTokenFile"),
    ("FABRIC_WIRE_MODEL_ALLOWLIST", "model_allowlist", "modelAllowlist"),
    ("FABRIC_WIRE_MAX_BODY_BYTES", "max_body_bytes", "maxBodyBytes"),
    ("FABRIC_WIRE_MAX_RETAIN_BYTES", "max_retain_bytes", "maxRetainBytes"),
    ("FABRIC_WIRE_PART_MIN_BYTES", "part_min_bytes", "partMinBytes"),
    ("FABRIC_WIRE_QUEUE_MAX_ITEMS", "queue_max_items", "queueMaxItems"),
    ("FABRIC_WIRE_SHUTDOWN_TIMEOUT_S", "shutdown_timeout_s", "shutdownTimeoutMs"),
    ("FABRIC_WIRE_DRAIN_ON_EXIT_S", "drain_on_exit_s", "drainOnExitMs"),
    ("FABRIC_WIRE_CONTENT_BATCH_BODIES", "content_batch_bodies", "contentBatchBodies"),
    ("FABRIC_WIRE_CONTENT_CONCURRENCY", "content_concurrency", "contentConcurrency"),
    ("FABRIC_WIRE_PROXY", None, "proxy"),
    ("FABRIC_OTLP_ENDPOINT", None, "otlp"),
    ("FABRIC_OTLP_CERTIFICATE", None, "otlp.certificate"),
    ("FABRIC_OTLP_CLIENT_CERTIFICATE", None, "otlp.clientCertificate"),
    ("FABRIC_OTLP_CLIENT_KEY", None, "otlp.clientKey"),
    ("FABRIC_OTLP_HEADERS_FILE", None, "otlp.headers"),
    ("OTEL_EXPORTER_OTLP_ENDPOINT", None, "otlp"),
    ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", None, "otlp"),
    ("OTEL_EXPORTER_OTLP_HEADERS", None, "otlp.headers"),
    ("OTEL_EXPORTER_OTLP_TIMEOUT", None, "otlp.timeoutMs"),
    ("OTEL_EXPORTER_OTLP_COMPRESSION", None, "otlp.compression"),
    ("OTEL_SDK_DISABLED", None, "otelSdkDisabled"),
    ("FABRIC_RUN_ID", None, "runId"),
    ("FABRIC_RUN_RESUME_TOKEN", None, "resumeTokens"),
    ("FABRIC_RUN_OPEN_DEADLINE_S", None, "openDeadlineS"),
    ("FABRIC_RECORDS_STRICT", None, "recordsStrict"),
    ("FABRIC_RECORDS_MAX_OBJECT_BYTES", None, "recordsMaxObjectBytes"),
    ("FABRIC_CLOCK_UNCERTAINTY_MS", None, "clockUncertaintyNs"),
    ("FABRIC_WIRE_PROVIDER_REQUEST_ID", None, "providerRequestId"),
    ("FABRIC_WIRE_STATUS_FILE", None, "statusFile"),
    ("FABRIC_WIRE_UNDICI", None, "undici"),
    ("FABRIC_WIRE_NODE_HTTP", None, "nodeHttp"),
    ("FABRIC_WIRE_TRACER", "tracer_mode", None),
    ("FABRIC_WIRE_AIOHTTP", "patch_aiohttp", None),
)

_SPOOL = "/var/empty/fabric-ts-config-fixture/spool"
_B64_32 = base64.b64encode(bytes(range(32))).decode()
# Files a case names as {dir}/<name>; the TypeScript test writes the same files.
FILES: dict[str, str] = {
    "id-key": TEST_ID_KEY + "\n",
    "id-key-short": "short\n",
    "spool-key-b64": _B64_32 + "\n",
    "spool-key-wrong": "not a key of 32 bytes\n",
    "headers": "authorization=Bearer test-token-not-a-secret\nx-tenant=tenant-a\n",
    "headers-bad": "no equals sign here\n",
    "cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    "policy-bad": "{not json",
}
_ENDPOINTS_OK = (
    '[{"endpoint_id":"my-model","dialect":"openai","hosts":["models.example.com"]}]'
)

# (name, environment); {dir} is the directory holding FILES.
CASES: tuple[tuple[str, dict[str, str]], ...] = (
    ("nothing set", {}),
    (
        "empty values are unset",
        {
            "FABRIC_WIRE_BUILTIN_ENDPOINTS": "",
            "FABRIC_WIRE_ENDPOINTS": "",
            "FABRIC_WIRE_LABELS": "",
            "FABRIC_WIRE_ID_KEY": "",
            "FABRIC_WIRE_SPOOL_KEY": "",
            "FABRIC_WIRE_STORE": "",
        },
    ),
    ("legacy built-in rows", {"FABRIC_WIRE_BUILTIN_ENDPOINTS": "legacy"}),
    (
        "built-in value is case-folded and trimmed",
        {"FABRIC_WIRE_BUILTIN_ENDPOINTS": " Legacy "},
    ),
    ("extra endpoint", {"FABRIC_WIRE_ENDPOINTS": _ENDPOINTS_OK}),
    ("clear labels", {"FABRIC_WIRE_LABELS": "clear"}),
    ("id key by value", {"FABRIC_WIRE_ID_KEY": TEST_ID_KEY}),
    ("id key from a file (058 name)", {"FABRIC_WIRE_ID_KEY_FILE": "{dir}/id-key"}),
    (
        "empty id key value with a file",
        {"FABRIC_WIRE_ID_KEY": "", "FABRIC_WIRE_ID_KEY_FILE": "{dir}/id-key"},
    ),
    (
        "spool key from a base64 file",
        {"FABRIC_WIRE_SPOOL_KEY_FILE": "{dir}/spool-key-b64"},
    ),
    ("spool key by value", {"FABRIC_WIRE_SPOOL_KEY": _B64_32}),
    (
        "node mode",
        {
            "FABRIC_WIRE_STORE": "node",
            "FABRIC_WIRE_CONTENT_ENDPOINT": "http://127.0.0.1:4318",
            "FABRIC_TENANT_ID": "tenant-a",
            "FABRIC_WIRE_SPOOL_DIR": _SPOOL,
        },
    ),
    (
        "node mode implied by the content endpoint",
        {
            "FABRIC_WIRE_CONTENT_ENDPOINT": "https://node.example:4318",
            "FABRIC_TENANT_ID": "tenant-a",
            "FABRIC_WIRE_SPOOL_DIR": _SPOOL,
        },
    ),
    (
        "numeric settings",
        {
            "FABRIC_WIRE_MAX_BODY_BYTES": "1048576",
            "FABRIC_WIRE_MAX_RETAIN_BYTES": "2097152",
            "FABRIC_WIRE_QUEUE_MAX_ITEMS": "65536",
            "FABRIC_WIRE_SHUTDOWN_TIMEOUT_S": "1.5",
            "FABRIC_WIRE_DRAIN_ON_EXIT_S": "30",
            "FABRIC_WIRE_CONTENT_BATCH_BODIES": "256",
            "FABRIC_WIRE_CONTENT_CONCURRENCY": "16",
        },
    ),
    ("model allowlist", {"FABRIC_WIRE_MODEL_ALLOWLIST": " gpt-4o , claude-* ,"}),
    (
        "FABRIC_OTLP_* wins over OTEL_EXPORTER_OTLP_*",
        {
            "FABRIC_OTLP_ENDPOINT": "http://127.0.0.1:4318/",
            "FABRIC_OTLP_HEADERS_FILE": "{dir}/headers",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example:4318",
            "OTEL_EXPORTER_OTLP_HEADERS": "x-otel=1",
            "FABRIC_WIRE_SPOOL_DIR": _SPOOL,
        },
    ),
    (
        "OTEL_EXPORTER_OTLP_* without FABRIC_OTLP_*",
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example:4318",
            "OTEL_EXPORTER_OTLP_HEADERS": "x-otel=1, Authorization=Basic%20abc",
            "OTEL_EXPORTER_OTLP_TIMEOUT": "2.5",
            "FABRIC_WIRE_SPOOL_DIR": _SPOOL,
        },
    ),
    (
        "signal endpoint wins over the general one",
        {
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://traces.example/v1/traces",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example:4318",
            "FABRIC_WIRE_SPOOL_DIR": _SPOOL,
        },
    ),
    ("OTEL_SDK_DISABLED", {"OTEL_SDK_DISABLED": "true"}),
    # malformed values
    ("unknown built-in endpoint set", {"FABRIC_WIRE_BUILTIN_ENDPOINTS": "all"}),
    ("endpoints not JSON", {"FABRIC_WIRE_ENDPOINTS": "models.example.com"}),
    ("endpoints not an array", {"FABRIC_WIRE_ENDPOINTS": '{"endpoint_id":"x"}'}),
    (
        "endpoint entry missing its dialect",
        {"FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"x","hosts":["h"]}]'},
    ),
    (
        "endpoint entry with an unknown field",
        {
            "FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"x","dialect":"openai","hosts":["h"],"url":"u"}]'
        },
    ),
    (
        "endpoint id with capitals",
        {
            "FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"My","dialect":"openai","hosts":["h"]}]'
        },
    ),
    (
        "endpoint port 0",
        {
            "FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"x","dialect":"openai","hosts":["h"],"ports":[0]}]'
        },
    ),
    (
        "endpoint scheme ftp",
        {
            "FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"x","dialect":"openai","hosts":["h"],"schemes":["ftp"]}]'
        },
    ),
    (
        "endpoint without hosts",
        {"FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"x","dialect":"openai"}]'},
    ),
    (
        "endpoint id repeats a built-in",
        {
            "FABRIC_WIRE_ENDPOINTS": '[{"endpoint_id":"openai","dialect":"openai","hosts":["h"]}]'
        },
    ),
    ("unknown labels mode", {"FABRIC_WIRE_LABELS": "hashed"}),
    ("short id key", {"FABRIC_WIRE_ID_KEY": "short"}),
    (
        "id key value and file",
        {"FABRIC_WIRE_ID_KEY": TEST_ID_KEY, "FABRIC_WIRE_ID_KEY_FILE": "{dir}/id-key"},
    ),
    ("id key file missing", {"FABRIC_WIRE_ID_KEY_FILE": "{dir}/missing"}),
    ("id key file too short", {"FABRIC_WIRE_ID_KEY_FILE": "{dir}/id-key-short"}),
    ("spool key not base64", {"FABRIC_WIRE_SPOOL_KEY": "not base64!"}),
    (
        "spool key value and file",
        {
            "FABRIC_WIRE_SPOOL_KEY": _B64_32,
            "FABRIC_WIRE_SPOOL_KEY_FILE": "{dir}/spool-key-b64",
        },
    ),
    ("spool key file missing", {"FABRIC_WIRE_SPOOL_KEY_FILE": "{dir}/missing"}),
    (
        "spool key file of the wrong size",
        {"FABRIC_WIRE_SPOOL_KEY_FILE": "{dir}/spool-key-wrong"},
    ),
    (
        "short tokenization key",
        {"FABRIC_TOKENIZATION_KEY": base64.b64encode(b"short").decode()},
    ),
    ("max body bytes not a number", {"FABRIC_WIRE_MAX_BODY_BYTES": "32MiB"}),
    ("max body bytes 0", {"FABRIC_WIRE_MAX_BODY_BYTES": "0"}),
    ("queue entries above the cap", {"FABRIC_WIRE_QUEUE_MAX_ITEMS": "65537"}),
    ("shutdown timeout not a number", {"FABRIC_WIRE_SHUTDOWN_TIMEOUT_S": "soon"}),
    ("drain on exit above an hour", {"FABRIC_WIRE_DRAIN_ON_EXIT_S": "3601"}),
    ("content batch of 0 bodies", {"FABRIC_WIRE_CONTENT_BATCH_BODIES": "0"}),
    ("node mode without a content endpoint", {"FABRIC_WIRE_STORE": "node"}),
    ("s3 store", {"FABRIC_WIRE_STORE": "s3://bucket/prefix"}),
    (
        "relative file store",
        {"FABRIC_WIRE_STORE": "file://relative/dir", "FABRIC_TENANT_ID": "tenant-a"},
    ),
    ("store encryption set in the agent", {"FABRIC_WIRE_STORE_SSE": "aws:kms"}),
    (
        "content endpoint plaintext to a remote host",
        {
            "FABRIC_WIRE_STORE": "node",
            "FABRIC_WIRE_CONTENT_ENDPOINT": "http://node.example:4318",
            "FABRIC_TENANT_ID": "tenant-a",
            "FABRIC_WIRE_SPOOL_DIR": _SPOOL,
        },
    ),
    (
        "content endpoint with credentials",
        {
            "FABRIC_WIRE_STORE": "node",
            "FABRIC_WIRE_CONTENT_ENDPOINT": "https://u:p@node.example:4318",
            "FABRIC_TENANT_ID": "tenant-a",
            "FABRIC_WIRE_SPOOL_DIR": _SPOOL,
        },
    ),
    (
        "node mode without a tenant",
        {
            "FABRIC_WIRE_CONTENT_ENDPOINT": "https://node.example:4318",
            "FABRIC_WIRE_SPOOL_DIR": _SPOOL,
        },
    ),
    (
        "content endpoint with a file store",
        {
            "FABRIC_WIRE_STORE": "file:///var/empty/store",
            "FABRIC_TENANT_ID": "tenant-a",
            "FABRIC_WIRE_CONTENT_ENDPOINT": "https://node.example:4318",
        },
    ),
    ("source id with a space", {"FABRIC_SOURCE_ID": "my agent"}),
    ("tenant id starting with a dash", {"FABRIC_TENANT_ID": "-tenant"}),
    ("relative spool directory", {"FABRIC_WIRE_SPOOL_DIR": "spool"}),
    (
        "spool bound below two bodies",
        {"FABRIC_WIRE_SPOOL_DIR": _SPOOL, "FABRIC_WIRE_SPOOL_MAX_BYTES": "1024"},
    ),
    (
        "durable boundary without a spool",
        {"FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY": "/var"},
    ),
    (
        "durable boundary not an ancestor",
        {"FABRIC_WIRE_SPOOL_DIR": _SPOOL, "FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY": "/tmp"},
    ),
    ("model allowlist with a URL", {"FABRIC_WIRE_MODEL_ALLOWLIST": "https://x/y"}),
    (
        "FABRIC_OTLP_* setting without FABRIC_OTLP_ENDPOINT",
        {"FABRIC_OTLP_HEADERS_FILE": "{dir}/headers", "FABRIC_WIRE_SPOOL_DIR": _SPOOL},
    ),
    (
        "FABRIC_OTLP_ENDPOINT with a query",
        {"FABRIC_OTLP_ENDPOINT": "https://node.example:4318/?k=v"},
    ),
    (
        "FABRIC_OTLP_ENDPOINT plaintext to a remote host",
        {"FABRIC_OTLP_ENDPOINT": "http://node.example:4318"},
    ),
    (
        "FABRIC_OTLP_CERTIFICATE missing",
        {
            "FABRIC_OTLP_ENDPOINT": "https://node.example:4318",
            "FABRIC_OTLP_CERTIFICATE": "{dir}/missing",
        },
    ),
    (
        "FABRIC_OTLP_CLIENT_KEY without its certificate",
        {
            "FABRIC_OTLP_ENDPOINT": "https://node.example:4318",
            "FABRIC_OTLP_CLIENT_KEY": "{dir}/cert",
        },
    ),
    (
        "FABRIC_OTLP_HEADERS_FILE malformed",
        {
            "FABRIC_OTLP_ENDPOINT": "https://node.example:4318",
            "FABRIC_OTLP_HEADERS_FILE": "{dir}/headers-bad",
        },
    ),
    (
        "FABRIC_OTLP_HEADERS_FILE missing",
        {
            "FABRIC_OTLP_ENDPOINT": "https://node.example:4318",
            "FABRIC_OTLP_HEADERS_FILE": "{dir}/missing",
        },
    ),
    (
        "OTEL headers malformed",
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example:4318",
            "OTEL_EXPORTER_OTLP_HEADERS": "novalue",
        },
    ),
    (
        "OTEL timeout not a number",
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example:4318",
            "OTEL_EXPORTER_OTLP_TIMEOUT": "ten",
        },
    ),
    (
        "OTEL compression unknown",
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example:4318",
            "OTEL_EXPORTER_OTLP_COMPRESSION": "lz4",
        },
    ),
    (
        "OTEL endpoint with credentials",
        {"OTEL_EXPORTER_OTLP_ENDPOINT": "https://u:p@otel.example:4318"},
    ),
    (
        "redaction endpoint not loopback",
        {"FABRIC_REDACTION_ENDPOINT": "http://redact.example:8080"},
    ),
    (
        "redaction token file without an endpoint",
        {"FABRIC_REDACTION_TOKEN_FILE": "{dir}/headers"},
    ),
    ("capture policy missing", {"FABRIC_CAPTURE_POLICY": "{dir}/missing"}),
    ("capture policy not JSON", {"FABRIC_CAPTURE_POLICY": "{dir}/policy-bad"}),
)

_CLEAR_PREFIXES = ("FABRIC_", "OTEL_")


@contextlib.contextmanager
def _environment(env: Mapping[str, str]) -> Iterator[None]:
    saved = dict(os.environ)
    try:
        for name in list(os.environ):
            if name.startswith(_CLEAR_PREFIXES):
                del os.environ[name]
        os.environ.update(env)
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _resolved(env: Mapping[str, str]) -> dict[str, Any]:
    """The settings Python resolves for a valid case, in the TypeScript field names."""
    from fabric import tracing  # noqa: PLC0415
    from fabric.wire import _env_defaults  # noqa: PLC0415
    from fabric.wire._config import config_from_env  # noqa: PLC0415

    config, _mode = config_from_env(os.environ)
    config = _env_defaults(config)

    def digest(key: bytes | None) -> str | None:
        return None if key is None else hashlib.sha256(key).hexdigest()

    otlp = tracing.otlp_signal_settings("traces", os.environ)
    return {
        "endpoints": [m.endpoint_id for m in config.endpoints],
        "extraEndpoints": [m.endpoint_id for m in config.extra_endpoints],
        "labels": config.labels,
        "sourceId": config.source_id,
        "tenantId": config.tenant_id,
        "contentEndpoint": config.content_endpoint,
        "spoolDir": config.spool_dir,
        "modelAllowlist": list(config.model_allowlist),
        "maxBodyBytes": config.max_body_bytes,
        "maxRetainBytes": config.max_retain_bytes,
        "queueMaxItems": config.queue_max_items,
        "shutdownTimeoutMs": round(config.shutdown_timeout_s * 1000),
        "drainOnExitMs": round(config.drain_on_exit_s * 1000),
        "contentBatchBodies": config.content_batch_bodies,
        "contentConcurrency": config.content_concurrency,
        "idKeySha256": digest(config.id_key),
        "spoolKeySha256": digest(config.spool_key),
        "otlp": {
            "route": otlp.route,
            "endpoint": otlp.endpoint,
            "endpointName": otlp.endpoint_name,
            "headers": dict(otlp.headers),
            "timeoutMs": round(otlp.timeout_s * 1000),
        },
    }


def config_env() -> dict[str, Any]:
    from fabric.wire._status import _wire_status  # noqa: PLC0415

    cases = []
    with tempfile.TemporaryDirectory(prefix="f055-t2-") as directory:
        for name, text in FILES.items():
            Path(directory, name).write_text(text, encoding="utf-8")
        for name, env in CASES:
            real = {k: v.replace("{dir}", directory) for k, v in env.items()}
            with _environment(real):
                wire, _warnings, _capturing = _wire_status()
                case: dict[str, Any] = {"name": name, "env": env}
                if wire["configuration"] == "invalid":
                    case["outcome"] = "invalid"
                    case["reason_id"] = wire["reason_id"]
                else:
                    case["outcome"] = wire["capture"]
                    if wire["capture"] == "enabled":
                        case["resolved"] = _resolved(real)
            cases.append(case)
    return {
        "schema_version": "fabric.ts-config-env/v1",
        "rule": "Spec 055 §4.2, §4.7: the Python-to-TypeScript environment mapping, and what "
        "python -m fabric.wire status decides for each environment (fabric.wire._status "
        "_wire_status; the catalogue id is wire/_diagnose.py reason_id of the message). "
        "{dir} holds files. TypeScript reports FW-025 where Python reports its generic FW-001. "
        "Generated by scripts/contracts/generate_ts_wire_vectors.py.",
        "mapping": [{"env": e, "python": p, "typescript": t} for e, p, t in MAPPING],
        "files": FILES,
        "cases": cases,
    }


# --------------------------------------------------------------------------- driver
def render(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def outputs() -> dict[Path, str]:
    return {
        SPOOL_BYTES: render(spool_bytes()),
        MATCH_TABLE: render(match_table()),
        CONFIG_ENV: render(config_env()),
    }


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = 0
    for path, text in outputs().items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        if check:
            stale += 1
            print(
                f"{path.relative_to(REPO)} differs: run python {Path(__file__).relative_to(REPO)}"
            )
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(REPO)}")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.path.insert(0, str(REPO / "scripts"))
    raise SystemExit(main(sys.argv[1:]))
