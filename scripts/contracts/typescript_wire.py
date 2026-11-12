# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §8 (unit 055-t1): the TypeScript wire capture contract rows' fixtures and checks.

Generated here (``generate_p0_contracts.py`` calls :func:`generate`; ``--check`` keeps them
reproducible):

- coverage/v1 TypeScript manifests: active ``wire.ts.undici``, active ``wire.ts.node_http``,
  both, production with content disabled, Node 22, Node 24 with an old bundled undici, the
  native addon missing, an unattached worker isolate and a key rotation; and the refused
  ones: an epoch rounded through a float64, an unregistered point, a Python point in a
  TypeScript manifest and an active claim on a build the qualification table does not list;
- coverage/v1 step projections with registered TypeScript evidence, and the refused ones
  (an unregistered point, a false complete on an open run);
- the ``fabric.wire-qualification/v1`` table fixtures (§9.4);
- capture/v1 spool records from one TypeScript source: a wire exchange and a records-input
  record (mixed input), a split exchange with a redacted review copy, and the refused ones
  (an unregistered point, an agent-stamped authentication flag, a review copy that keeps the
  original's digest).

The family validators delegate the TypeScript-specific rules here: exact integers in a
manifest, the language of a wire point, an active claim backed by the qualification table
(``sdk/typescript/wire-qualification.json``), the table's own semantics, and registry
resolution of a ``<id>@<version>`` capture-point value (the telemetry key's pattern alone
does not establish a registered point).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
QUALIFICATION_TABLE = Path("sdk/typescript/wire-qualification.json")
QUALIFICATION_SCHEMA = "schema/wire-qualification-v1.schema.json"
QUALIFICATION = "fabric.wire-qualification/v1"
TS_POINTS = ("wire.ts.undici", "wire.ts.node_http")
TS_VERSION = "1.0.0"
GATE_POINTS = {
    "TS-1U": ("wire.ts.undici",),
    "TS-1H": ("wire.ts.node_http",),
    "TS-1D": TS_POINTS,
}
NODE_FLOOR = 24  # spec 055 §3.1: the owner-approved major-version floor
POINT_VALUE = re.compile(
    r"^(?P<id>[a-z][a-z0-9_.]{0,63})@(?P<version>[0-9A-Za-z.+-]{1,32})$"
)
Fail = Callable[[str, str, str], Any]

INVALID_COVERAGE = {
    "invalid/manifest-typescript-epoch-rounded.json": "coverage.manifest.integer",
    "invalid/manifest-typescript-python-point.json": "coverage.manifest.capture_point",
    "invalid/manifest-typescript-unqualified-active.json": "coverage.manifest.qualification",
    "invalid/manifest-typescript-unregistered-point.json": "coverage.manifest.capture_point",
    "invalid/projection-typescript-false-complete.json": "coverage.projection.run_state",
    "invalid/projection-typescript-unregistered-point.json": "coverage.projection.capture_point",
    "invalid/wire-qualification-active-without-report.json": "coverage.schema",
    "invalid/wire-qualification-gate-without-active-tuple.json": "coverage.qualification.gate",
    "invalid/wire-qualification-node-22-tuple.json": "coverage.qualification.tuple",
    "invalid/wire-qualification-tuple-without-publication.json": "coverage.qualification.tuple",
}  # fmt: skip
INVALID_CAPTURE = {
    "fixtures/invalid/spool-record-exchange-typescript-agent-authenticated.json": "capture.schema",
    "fixtures/invalid/spool-record-exchange-typescript-redacted-keeps-original-digest.json": "capture.schema",
    "fixtures/invalid/spool-record-exchange-typescript-unregistered-point.json": "capture.capture_point",
}  # fmt: skip


# ===================================================================== checks
def point_id(value: Any) -> str | None:
    """The id of an ``<id>@<version>`` capture-point value, or ``None`` when malformed."""
    match = POINT_VALUE.fullmatch(value) if isinstance(value, str) else None
    return match["id"] if match else None


def registered(value: Any, reg: Mapping[str, Any]) -> bool:
    """Whether ``value`` (``<id>@<version>``) names a row of capture-points-v1.json."""
    pid = point_id(value)
    return pid is not None and any(
        p["id"] == pid for p in reg["points"]["capture_points"]
    )


def load_table(root: Path = REPO) -> dict[str, Any]:
    table: dict[str, Any] = json.loads(
        (root / QUALIFICATION_TABLE).read_text(encoding="utf-8")
    )
    return table


def _floats(value: Any, path: str) -> str | None:
    if isinstance(value, float):
        return path
    if isinstance(value, Mapping):
        for key, item in value.items():
            if (found := _floats(item, f"{path}.{key}")) is not None:
                return found
    if isinstance(value, list):
        for index, item in enumerate(value):
            if (found := _floats(item, f"{path}[{index}]")) is not None:
                return found
    return None


def check_manifest_numbers(document: Mapping[str, Any], fail: Fail) -> None:
    """Every number in a manifest is an exact integer literal. JSON Schema ``integer``
    admits ``4.611686018427388e+18``; that is an int64 epoch rounded through a float64
    (a JavaScript ``Number``), so a value-preserving reader refuses any fraction or
    exponent before the schema runs (spec 055 §6.1, §8)."""
    where = _floats(document, "$")
    if where is not None:
        fail(
            "coverage.manifest.integer",
            where,
            "a manifest number is an exact integer literal; a fraction or exponent "
            "means an int64 went through a float64 and may be rounded",
        )


def _version(text: str) -> tuple[int, ...] | None:
    parts = text.split(".")
    return tuple(int(p) for p in parts) if all(p.isdigit() for p in parts) else None


def check_manifest_points(
    document: Mapping[str, Any], fail: Fail, table: Mapping[str, Any] | None = None
) -> None:
    """A wire point belongs to its SDK's language, and a TypeScript wire point is
    ``active`` only on a Node build the qualification table backs (spec 055 §3.1): Node 24
    or later, and for ``wire.ts.undici`` a build whose audit row publishes both body-chunk
    channels. A build the table does not list is unsupported, never inferred."""
    language = document["sdk"]["language"]
    runtime = document["runtime"]
    for index, point in enumerate(document["capture_points"]):
        where, pid = f"$.capture_points[{index}]", point["id"]
        family = {"wire.ts.": "typescript", "wire.py.": "python"}
        owner = next(
            (lang for pre, lang in family.items() if pid.startswith(pre)), None
        )
        if owner is not None and owner != language:
            fail(
                "coverage.manifest.capture_point",
                where,
                f"{pid} is a {owner} capture point in a {language} manifest",
            )
        if pid not in TS_POINTS or point["state"] != "active":
            continue
        version = _version(runtime["version"])
        if runtime["name"] != "nodejs" or version is None or version[0] < NODE_FLOOR:
            fail(
                "coverage.manifest.qualification",
                where,
                f"{pid} is active only on Node.js {NODE_FLOOR} or later",
            )
        if pid == "wire.ts.undici":
            audits = (table if table is not None else load_table())["audits"]
            if not any(
                a["node"] == runtime["version"] and a["result"] == "both_body_channels"
                for a in audits
            ):
                fail(
                    "coverage.manifest.qualification",
                    where,
                    f"Node {runtime['version']} has no audit row publishing both "
                    "body-chunk channels in sdk/typescript/wire-qualification.json",
                )


def validate_qualification(
    document: Mapping[str, Any],
    schema: Mapping[str, Any],
    fail: Fail,
    schema_errors: Callable[[Any, Mapping[str, Any]], None],
) -> None:
    """``fabric.wire-qualification/v1`` (spec 055 §9.4): the schema, then a tuple only for
    an audited publication on Node 24 or later, and a passed gate only with an active
    tuple of its points."""
    schema_errors(document, schema)
    audits = document["audits"]
    keys = [(a["node"], a["platform"], a["undici_origin"], a["undici"]) for a in audits]
    if len(set(keys)) != len(keys):
        fail("coverage.qualification.audit", "$.audits", "one row per exact build")
    for index, row in enumerate(document["tuples"]):
        where = f"$.tuples[{index}]"
        version = _version(row["node"])
        if version is None or version[0] < NODE_FLOOR:
            fail(
                "coverage.qualification.tuple",
                where,
                f"no capture point runs below Node.js {NODE_FLOOR}",
            )
        if row["point"] != "wire.ts.undici":
            continue
        if not any(
            (a["node"], a["platform"], a["undici"], a["undici_origin"], a["boundary"])
            == (row["node"], row["platform"], row["undici"], row["undici_origin"],
                row["boundary"])
            and a["result"] == "both_body_channels"
            for a in audits
        ):  # fmt: skip
            fail(
                "coverage.qualification.tuple",
                where,
                "an undici tuple needs an audit row of the same build and boundary "
                "that publishes both body-chunk channels",
            )
    for gate, points in GATE_POINTS.items():
        if document["gates"][gate] != "passed":
            continue
        if not any(
            t["claim"] == "active" and t["point"] in points for t in document["tuples"]
        ):
            fail(
                "coverage.qualification.gate",
                f"$.gates.{gate}",
                "a passed gate needs an active tuple of its capture points",
            )


# ===================================================================== generation
KEY2 = "another-test-key"
BUILD_MIN, BUILD_NEW, BUILD_OLD, BUILD_22 = "24.4.0", "24.22.3", "24.0.0", "22.23.5"


def _uid(n: str) -> str:
    h = hashlib.sha256(f"uuid-{n}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


def _mutate(document: Any, change: Callable[[Any], Any]) -> Any:
    out = copy.deepcopy(document)
    change(out)
    return out


def _point(
    reg: Mapping[str, Any], pid: str, state: str = "active", reason: str | None = None,
    version: str = TS_VERSION,
) -> dict[str, Any]:  # fmt: skip
    row = next(p for p in reg["points"]["capture_points"] if p["id"] == pid)
    out: dict[str, Any] = {
        "id": pid,
        "version": version,
        "kind": row["kind"],
        "state": state,
        "process_global": row["process_global"].startswith("yes"),
        "opt_in": "opt-in" in row["activation"],
        "fields": list(row["supplies"]),
    }
    if reason:
        out["reason"] = reason
    return out


def typescript_manifests(
    reg: Mapping[str, Any], m0: Mapping[str, Any], prod: Mapping[str, Any],
    key_id: Callable[[str], str],
) -> dict[str, dict[str, Any]]:  # fmt: skip
    """The valid TypeScript manifests of spec 055 §8, from the Python epoch-start one."""

    def manifest(name: str, node: str, points: list[dict[str, Any]],
                 uncaptured: list[str], base: Mapping[str, Any] = m0) -> dict[str, Any]:  # fmt: skip
        doc = copy.deepcopy(dict(base))
        doc.update(
            manifest_id=_uid(f"ts-{name}"),
            event_id=_uid(f"ts-{name}-event"),
            sdk={"language": "typescript", "version": "0.13.0"},
            runtime={"name": "nodejs", "version": node},
            capture_points=[_point(reg, "fabric.self"), _point(reg, "install.config"),
                            *points, _point(reg, "sdk.records"), _point(reg, "run.scope")],
            uncaptured_classes=uncaptured,
        )  # fmt: skip
        return doc

    undici, node_http = "wire.ts.undici", "wire.ts.node_http"
    common = ["axios", "websocket", "non_post_endpoints", "unmatched_endpoints"]
    off = ("disabled", "hook_disabled")
    unsupported = [
        _point(reg, undici, "unsupported", "unsupported_version"),
        _point(reg, node_http, "unsupported", "unsupported_version"),
    ]
    out = {
        "active-undici": manifest(
            "active-undici", BUILD_MIN,
            [_point(reg, undici), _point(reg, node_http, *off)], ["node_http", *common],
        ),
        "active-node-http": manifest(
            "active-node-http", BUILD_NEW,
            [_point(reg, undici, *off), _point(reg, node_http)], ["custom_fetch", *common],
        ),
        "active-both": manifest(
            "active-both", BUILD_NEW, [_point(reg, undici), _point(reg, node_http)], common,
        ),
        "production-content-disabled": manifest(
            "production-content-disabled", BUILD_NEW,
            [_point(reg, undici), _point(reg, node_http, *off)], ["node_http", *common], prod,
        ),
        "node-22": manifest(
            "node-22", BUILD_22, unsupported, ["node_http", "node_below_24", *common]
        ),
        "node-24-old-undici": manifest(
            "node-24-old-undici", BUILD_OLD, unsupported, ["node_http", *common]
        ),
        "native-missing": manifest(
            "native-missing", BUILD_NEW,
            [_point(reg, undici, "unsupported", "unsupported_runtime"),
             _point(reg, node_http, "unsupported", "unsupported_runtime")],
            ["node_http", *common],
        ),
        "unattached-worker": manifest(
            "unattached-worker", BUILD_NEW,
            [_point(reg, undici), _point(reg, node_http, *off)],
            ["node_http", "node_worker_unattached", *common],
        ),
    }  # fmt: skip
    for name in ("node-22", "node-24-old-undici", "native-missing"):
        # Without a wire point nothing reaches the content store: metadata only.
        out[name].update(content_capture="metadata_only", content_capture_reason="not_configured",
                         inputs=["records"])  # fmt: skip
        out[name].pop("capture_policy", None)
    # A key rotation starts a new epoch under the new key (049 §2.4: fixed per epoch).
    rotated = copy.deepcopy(out["active-undici"])
    rotated.update(
        manifest_id=_uid("ts-key-rotation"),
        event_id=_uid("ts-key-rotation-event"),
        source_epoch=rotated["source_epoch"] + 1,
        emitted_at="2026-10-19T11:00:00Z",
        key_id=key_id(KEY2),
    )
    out["key-rotation"] = rotated
    return out


def _qualification_fixtures() -> dict[str, dict[str, Any]]:
    channels = [
        "undici:request:create", "undici:request:bodySent", "undici:request:headers",
        "undici:request:trailers", "undici:client:sendHeaders",
        "undici:client:beforeConnect", "undici:client:connected",
    ]  # fmt: skip
    body = ["undici:request:bodyChunkSent", "undici:request:bodyChunkReceived"]

    def audit(node: str, undici: str, both: bool) -> dict[str, Any]:
        return {
            "node": node, "undici": undici, "undici_origin": "bundled",
            "platform": "linux-x64-glibc",
            "published": sorted(channels + (body if both else [])),
            "request_body_published": both, "response_body_published": both,
            "boundary": "pre_decompression" if both else None,
            "result": "both_body_channels" if both else "missing_body_channels",
        }  # fmt: skip

    def tuple_(node: str, undici: str, claim: str = "audited") -> dict[str, Any]:
        return {"point": "wire.ts.undici", "node": node, "undici": undici,
                "undici_origin": "bundled", "platform": "linux-x64-glibc",
                "boundary": "pre_decompression", "claim": claim}  # fmt: skip

    audited = {
        "schema_version": QUALIFICATION,
        "gates": {"TS-1U": "not_passed", "TS-1D": "not_passed", "TS-1H": "not_passed"},
        "audit_script": "scripts/typescript/audit-undici-channels.mjs",
        "audits": [audit(BUILD_22, "6.29.1", False), audit(BUILD_OLD, "7.8.0", False),
                   audit(BUILD_MIN, "7.11.0", True)],
        "tuples": [tuple_(BUILD_MIN, "7.11.0")],
    }  # fmt: skip
    report = "sha256:" + hashlib.sha256(b"ts-1u passivity report").hexdigest()
    claimed = _mutate(audited, lambda d: (
        d["gates"].update({"TS-1U": "passed", "TS-1D": "passed"}),
        d["tuples"][0].update(claim="active", report_sha256=report),
        d["tuples"].append({"point": "wire.ts.node_http", "node": BUILD_MIN,
                            "platform": "linux-x64-glibc",
                            "boundary": "pre_decompression", "claim": "audited"}),
    ))  # fmt: skip
    return {
        "valid/wire-qualification-audited.json": audited,
        "valid/wire-qualification-claimed.json": claimed,
        "invalid/wire-qualification-active-without-report.json": _mutate(
            claimed, lambda d: d["tuples"][0].pop("report_sha256")
        ),
        "invalid/wire-qualification-gate-without-active-tuple.json": _mutate(
            audited, lambda d: d["gates"].update({"TS-1U": "passed"})
        ),
        "invalid/wire-qualification-node-22-tuple.json": _mutate(
            audited,
            lambda d: d["tuples"].append(
                {
                    "point": "wire.ts.node_http",
                    "node": BUILD_22,
                    "platform": "linux-x64-glibc",
                    "boundary": "pre_decompression",
                    "claim": "audited",
                }
            ),
        ),
        "invalid/wire-qualification-tuple-without-publication.json": _mutate(
            audited, lambda d: d["tuples"].append(tuple_(BUILD_OLD, "7.8.0"))
        ),
    }


def _replace_point(document: Any, old: str, new: str) -> Any:
    return json.loads(json.dumps(document).replace(f'"{old}"', f'"{new}"'))


def _coverage_fixtures(
    reg: Mapping[str, Any], read_json: Callable[[Path], Any],
    manifests: Mapping[str, Any], key_id: Callable[[str], str],
) -> dict[str, Any]:  # fmt: skip
    cov = Path("contracts/coverage/v1")
    ts = typescript_manifests(reg, manifests["m0"], manifests["prod"], key_id)
    out: dict[str, Any] = {
        f"valid/manifest-typescript-{n}.json": d for n, d in ts.items()
    }
    base = ts["active-undici"]
    out["invalid/manifest-typescript-unqualified-active.json"] = _mutate(
        base, lambda d: d["runtime"].update(version=BUILD_OLD)
    )
    out["invalid/manifest-typescript-unregistered-point.json"] = _mutate(
        base, lambda d: d["capture_points"].insert(
            3, dict(_point(reg, "wire.ts.undici"), id="wire.ts.fetch"))
    )  # fmt: skip
    out["invalid/manifest-typescript-python-point.json"] = _mutate(
        base, lambda d: d["capture_points"].insert(3, _point(reg, "wire.py.httpx"))
    )
    out["invalid/manifest-typescript-epoch-rounded.json"] = _mutate(
        # What JSON.stringify of a Number holding 2^62 + 1 rounds to, as a float literal.
        base,
        lambda d: d.update(source_epoch=float(base["source_epoch"])),
    )
    model = read_json(cov / "valid/projection-model-call-field-statuses.json")
    projection = _replace_point(
        model, "wire.py.httpx@1.2.0", f"wire.ts.undici@{TS_VERSION}"
    )
    out["valid/projection-typescript-model-call.json"] = projection
    out["invalid/projection-typescript-unregistered-point.json"] = _replace_point(
        model, "wire.py.httpx@1.2.0", f"wire.ts.fetch@{TS_VERSION}"
    )
    out["invalid/projection-typescript-false-complete.json"] = _mutate(
        # An open run (deadline set) whose layers claim everything was captured.
        projection,
        lambda d: d["runs"][0].update(run_state="open"),
    )
    out.update(_qualification_fixtures())
    return out


def _capture_fixtures(read_json: Callable[[Path], Any]) -> dict[str, Any]:
    cap = Path("contracts/capture/v1/fixtures")
    point = f"wire.ts.undici@{TS_VERSION}"
    enriched = read_json(cap / "valid/spool-record-exchange-enriched.json")
    exchange = _mutate(enriched, lambda d: d["span"]["attributes"].update(
        {"fabric.capture.point": point}))  # fmt: skip
    record = read_json(cap / "valid/spool-record-record-bodies.json")
    # Mixed input: the records-input record shares the exchange's source and epoch.
    record = _mutate(record, lambda d: (
        d["span"]["attributes"].update({"fabric.capture.point": f"sdk.records@{TS_VERSION}",
                                        "fabric.source.sequence": 2}),
        [b["descriptor"].update(source_sequence=2) for b in d["bodies"]],
    ))  # fmt: skip
    split = read_json(cap / "valid/spool-record-exchange-split.json")
    extra = {k: v for k, v in exchange["span"]["attributes"].items()
             if k not in split["span"]["attributes"]}  # fmt: skip
    review = read_json(cap / "valid/content-log-record-review-copy.json")["attributes"]
    review = {k: v for k, v in review.items() if k != "event_class"}
    review["object_id"] = _uid("ts-review-copy")

    def add_review(d: Any) -> None:
        d["span"]["attributes"].update(extra)
        offset = sum(b["length"] for b in d["bodies"])
        d["bodies"].append({"descriptor": review, "offset": offset,
                            "length": review["stored_byte_length"]})  # fmt: skip

    redacted = _mutate(split, add_review)
    request = redacted["bodies"][0]["descriptor"]
    out = {
        "valid/spool-record-exchange-typescript.json": exchange,
        "valid/spool-record-record-typescript.json": record,
        "valid/spool-record-exchange-typescript-split-redacted.json": redacted,
        "invalid/spool-record-exchange-typescript-unregistered-point.json": _mutate(
            exchange, lambda d: d["span"]["attributes"].update(
                {"fabric.capture.point": f"wire.ts.fetch@{TS_VERSION}"})
        ),
        "invalid/spool-record-exchange-typescript-agent-authenticated.json": _mutate(
            exchange, lambda d: d["span"]["attributes"].update(
                {"fabric.source.authenticated": True})
        ),
        "invalid/spool-record-exchange-typescript-redacted-keeps-original-digest.json": _mutate(
            redacted, lambda d: d["bodies"][-1]["descriptor"].update(
                source_sha256=request["source_sha256"],
                source_byte_length=request["source_byte_length"])
        ),
    }  # fmt: skip
    return out


def generate(
    put: Callable[[Path, Any], None],
    read_json: Callable[[Path], Any],
    reg: Mapping[str, Any],
    manifests: Mapping[str, Any],
    key_id: Callable[[str], str],
) -> None:
    for rel, document in _coverage_fixtures(reg, read_json, manifests, key_id).items():
        put(Path("contracts/coverage/v1") / rel, document)
    for rel, document in _capture_fixtures(read_json).items():
        put(Path("contracts/capture/v1/fixtures") / rel, document)
