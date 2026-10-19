# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate the draft four-layer coverage contracts (contracts/coverage/v1, spec 049).

The registries under ``contracts/coverage/v1/registry`` are the single source of
the spec 049 field inventory, vocabularies, capture points, content roles and
telemetry keys. This validator checks that they are internally consistent,
that they agree with the two coverage schemas and with the content-v2 schema,
that every JSON artifact is pinned by the family manifest, and that every
generated block in ``specs/049-four-layer-capture-coverage.md`` equals its
rendering from the registries. ``--write`` regenerates those blocks.

Spec 049 P0 conformance lives here too:

- C0-1/C0-2: every telemetry-key ``check`` (the machine-readable admission
  fabricguard applies) is closed, rejects free text, and agrees with the
  vocabulary, field type, validator text or manifest schema it comes from;
- the valid/invalid projection and manifest fixtures, checked by the
  semantic rules below (empty versus absent, conflict, extension kinds,
  inference confidence, run states and segment graphs, manifest states);
- the vectors: manifest chains, the manifest span form (round trip through
  the telemetry keys and ``contracts/capture/v1`` manifest-record schema),
  resume tokens and predecessor entries, run-marker attribute sets and the
  pseudonym v2 function (C0-3).

It does not claim that any runtime emits these documents.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import unquote

from jsonschema import Draft202012Validator, FormatChecker

FAMILY = Path("contracts/coverage/v1")
SPEC = Path("specs/049-four-layer-capture-coverage.md")
CONTENT_SCHEMA = Path("contracts/content/v2/schema/content-object-v2.schema.json")
# The span form of the capture manifest is generated from the coverage manifest
# schema and the telemetry-key registry (spec 049 section 2.8).
MANIFEST_RECORD_SCHEMA = Path("contracts/capture/v1/schema/capture-manifest-record-v1.schema.json")
PSEUDONYM_V1_VECTORS = Path("contracts/capture/v1/fixtures/run-ids/run-id-pseudonym-v1.json")
EXPECTATIONS = {"registry", "schema", "valid", "invalid", "vectors"}
INT64_MAX = 9223372036854775807
# A check that admits this, or any of these, is not closed (spec 049 §4.2:
# "admit each key with its validator and reject free text").
FREE_TEXT = ("Jane Doe asked about her prescription", "Bearer sk-live-0123456789", "",
             "https://user:secret@example.com/a?b=c", "{\"prompt\": \"hi\"}")
RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$")
REGISTRY = {
    "fields": "registry/field-registry-v1.json",
    "vocab": "registry/vocabularies-v1.json",
    "roles": "registry/content-roles-v1.json",
    "points": "registry/capture-points-v1.json",
    "keys": "registry/telemetry-keys-v1.json",
}
SCHEMAS = {
    "projection": "schema/step-projection-v1.schema.json",
    "manifest": "schema/capture-manifest-v1.schema.json",
}
FIELD_KEYS = {
    "id", "layer", "name", "type", "observed_by", "default_policy", "privacy_class",
    "required", "status_if_hook_absent", "phase", "lives_in", "definition",
}
LAYERS = {"X": "cross_cutting", "C": "context", "S": "structure", "N": "content",
          "D": "decisions_effects"}
TITLES = {"X": "fields:X", "C": "fields:C", "S": "fields:S", "N": "fields:N", "D": "fields:D"}
OUT_OF_SCOPE = "out of scope"
STORE_REASON_MAP = {"no_store": "not_configured"}
# capture points that are not one of the two inputs
NON_INPUTS = {"fabric", "config", "offline", "sensor", "qualified"}
MEDIA_RE = re.compile(r"^(\*|[a-z0-9!#$&^_.+-]+/(\*|[a-z0-9!#$&^_.+-]+))$")
BLOCK_RE = re.compile(
    r"<!-- generated:(?P<name>[a-z_:A-Z]+):begin -->\n(?P<body>.*?)<!-- generated:(?P=name):end -->",
    re.S,
)
# vocabulary name -> JSON pointer-ish path of the enum in the projection schema
PROJECTION_ENUMS = {
    "coverage_status": ("$defs", "field", "properties", "status", "enum"),
    "reason": ("$defs", "field", "properties", "reason", "enum"),
    "provenance": ("$defs", "field", "properties", "provenance", "enum"),
    "assertion_origin": ("$defs", "field", "properties", "assertion_origin", "enum"),
    "inference_method": ("$defs", "field", "properties", "method", "enum"),
    "link_type": ("$defs", "link", "properties", "type", "enum"),
    "link_state": ("$defs", "link", "properties", "state", "enum"),
    "step_kind": ("$defs", "step", "properties", "step_kind", "enum"),
    "actor_type": ("$defs", "step", "properties", "actor", "properties", "type", "enum"),
    "lifecycle_state": ("$defs", "step", "properties", "lifecycle_state", "enum"),
    "result_status": ("$defs", "step", "properties", "result_status", "enum"),
    "layer_verdict": ("$defs", "run_verdict", "properties", "verdict", "enum"),
    "capture_input": ("$defs", "step", "properties", "source", "properties", "input", "enum"),
}


FIELD_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")


def field_set_keys(name: str) -> list[str]:
    """Projection field-set keys of one registry row (spec 049 section 3, rule R63-10).

    Split on commas; trim; spaces become underscores; a part without a dot
    takes the namespace (text before the last dot) of the row's first part.
    """
    parts = [part.strip().replace(" ", "_") for part in name.split(",")]
    first = parts[0]
    namespace = first.rsplit(".", 1)[0] + "." if "." in first else ""
    return [part if "." in part or not namespace else namespace + part for part in parts]


@dataclass(frozen=True)
class CoverageContractError(ValueError):
    """Stable, automation-safe validation failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.message}"


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoverageContractError("coverage.document.unreadable", str(path), str(exc)) from exc


def _dig(document: Mapping[str, Any], path: Sequence[str]) -> Any:
    value: Any = document
    for key in path:
        value = value[key]
    return value


# ------------------------------------------------------------------ rendering
def _esc(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(_esc(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def _code_list(values: Sequence[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "—"


def _ranges(ids: Sequence[str]) -> str:
    """``C01, C02, C03, S05`` -> ``C01–C03, S05`` (input in registry order)."""
    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            out.append(run[0] if len(run) == 1 else f"{run[0]}–{run[-1]}")
            run.clear()

    for fid in ids:
        if run and fid[0] == run[-1][0] and int(fid[1:]) == int(run[-1][1:]) + 1:
            run.append(fid)
        else:
            flush()
            run.append(fid)
    flush()
    return ", ".join(out) if out else "—"


def _field_name(name: str) -> str:
    return name if ("," in name or ";" in name) else f"`{name}`"


def render_blocks(reg: Mapping[str, Any]) -> dict[str, str]:
    blocks: dict[str, str] = {}
    vocab = reg["vocab"]
    for name, rows in vocab.items():
        if name in ("schema_version", "registry_revision"):
            continue
        if name == "capture_point_kind":
            blocks[f"vocab:{name}"] = _table(
                ["Kind", "Name", "Provenance", "Meaning"],
                [(r["value"], f"`{r['name']}`", r["provenance"], r["meaning"]) for r in rows],
            )
        else:
            blocks[f"vocab:{name}"] = _table(
                ["Value", "Meaning"], [(f"`{r['value']}`", r["meaning"]) for r in rows]
            )
    fields = reg["fields"]["fields"]
    for prefix, block in TITLES.items():
        blocks[block] = _table(
            ["#", "Field", "Type", "Observed by", "Policy", "Privacy", "Req", "If hook absent",
             "Phase", "Lives in", "Definition"],
            [
                (f["id"], _field_name(f["name"]), f["type"], _code_list(f["observed_by"]),
                 f["default_policy"], f["privacy_class"], f["required"],
                 f["status_if_hook_absent"], f["phase"], f["lives_in"], f["definition"])
                for f in fields
                if f["id"][0] == prefix
            ],
        )
    blocks["points"] = _table(
        ["Capture point", "Kind", "Input", "Runtime", "Process-global", "Activation", "State",
         "Observes", "Cannot observe", "Passivity gate", "Supplies"],
        [
            (f"`{p['id']}`", p["kind"], p["input"], p["runtime"], p["process_global"], p["activation"],
             p["state"], p["observes"], p["cannot_observe"], p["passivity_gate"],
             _ranges(p["supplies"]))
            for p in reg["points"]["capture_points"]
        ],
    )
    blocks["roles"] = _table(
        ["Role", "Status", "Layer", "Boundary", "Provenance", "Media types", "Default policy",
         "Cap", "Phase", "Holds"],
        [
            (f"`{r['role']}`", r["status"], r["layer"], ", ".join(r["boundary"]),
             ", ".join(r["provenance"]), ", ".join(f"`{m}`" for m in r["media_types"]),
             r["default_policy"], r["cap"], r["phase"], r.get("holds", ""))
            for r in reg["roles"]["roles"]
        ],
    )
    blocks["keys"] = _table(
        ["Key", "Change", "Field", "Validator", "Phase", "Manifest property", "Note"],
        [
            (f"`{k['key']}`", k["change"], k["field"], k["validator"], k["phase"],
             f"`{k['manifest_property']}`" if "manifest_property" in k else "", k.get("note", ""))
            for k in reg["keys"]["keys"]
        ],
    )
    return blocks


# ------------------------------------------------------------------ checks
def _fail(code: str, path: str, message: str) -> None:
    raise CoverageContractError(code, path, message)


def load_registries(root: Path) -> dict[str, Any]:
    family = root / FAMILY
    return {name: _load(family / rel) for name, rel in REGISTRY.items()}


def check_manifest(root: Path) -> list[str]:
    family = root / FAMILY
    manifest = _load(family / "manifest.json")
    if set(manifest) != {"contract", "version", "digest_scope", "artifacts"}:
        _fail("coverage.manifest.shape", "manifest.json", "closed manifest fields")
    pinned: set[str] = set()
    for record in manifest["artifacts"]:
        rel = record["path"]
        if rel in pinned:
            _fail("coverage.manifest.path", rel, "duplicate path")
        pinned.add(rel)
        digest = hashlib.sha256((family / rel).read_bytes()).hexdigest()
        if digest != record["sha256"]:
            _fail("coverage.manifest.digest", rel, "SHA-256 does not match exact file bytes")
    actual = {p.relative_to(family).as_posix() for p in family.rglob("*.json")
              if p.name != "manifest.json"}
    if actual != pinned:
        _fail("coverage.manifest.coverage", "manifest.json", f"unpinned or missing: {sorted(actual ^ pinned)}")
    return sorted(pinned)


def check_registries(root: Path, reg: Mapping[str, Any]) -> None:
    family = root / FAMILY
    schemas = {name: _load(family / rel) for name, rel in SCHEMAS.items()}
    for name, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
    vocab = reg["vocab"]
    points = reg["points"]["capture_points"]
    point_ids = [p["id"] for p in points]
    if len(set(point_ids)) != len(point_ids):
        _fail("coverage.points.duplicate", "capture-points", "duplicate capture point id")
    kinds = {r["value"] for r in vocab["capture_point_kind"]}
    fields = reg["fields"]["fields"]
    ids = [f["id"] for f in fields]
    if len(set(ids)) != len(ids):
        _fail("coverage.fields.duplicate", "field-registry", "duplicate field id")
    policies = {r["value"] for r in vocab["policy"]}
    projection_keys: set[str] = set()
    for f in fields:
        for key in field_set_keys(f.get("name", "")):
            if not FIELD_KEY_RE.fullmatch(key) or key in projection_keys:
                _fail("coverage.fields.key", f.get("id", "?"), f"projection key {key!r} invalid or duplicate")
            projection_keys.add(key)
    for f in fields:
        fid = f.get("id", "?")
        if set(f) != FIELD_KEYS:
            _fail("coverage.fields.shape", fid, f"keys {sorted(set(f) ^ FIELD_KEYS)}")
        if not re.fullmatch(r"[XCSND][0-9]{2}", fid) or LAYERS[fid[0]] != f["layer"]:
            _fail("coverage.fields.id", fid, "id pattern or layer mismatch")
        if not isinstance(f["observed_by"], list):
            _fail("coverage.fields.observed_by", fid, "must be a list of capture-point ids")
        if not f["observed_by"] and f["phase"] != OUT_OF_SCOPE:
            _fail("coverage.fields.observed_by", fid, "no capture point supplies this field")
        for pid in f["observed_by"]:
            if pid not in point_ids:
                _fail("coverage.fields.observed_by", fid, f"unknown capture point {pid}")
        if f["phase"] != OUT_OF_SCOPE and f["default_policy"] not in policies:
            _fail("coverage.fields.policy", fid, "default policy not in vocabulary")
    for p in points:
        if not set(p["kind"].split("/")) <= kinds:
            _fail("coverage.points.kind", p["id"], "kind not in vocabulary")
        inputs = {r["value"] for r in vocab["capture_input"]} | NON_INPUTS
        if not {x.strip() for x in str(p.get("input", "")).split(",")} <= inputs:
            _fail("coverage.points.input", p["id"], "input not in capture_input vocabulary")
        derived = [f["id"] for f in fields if p["id"] in f["observed_by"]]
        if p.get("supplies") != derived:
            _fail("coverage.points.supplies", p["id"], "supplies differs from the fields that name this capture point")
    manifest_kinds = set(_dig(schemas["manifest"], ("properties", "capture_points", "items",
                                                     "properties", "kind", "enum")))
    if not {k for p in points for k in p["kind"].split("/")} <= manifest_kinds:
        _fail("coverage.schema.manifest_kind", "capture-manifest", "kind enum misses a registry kind")
    for name, path in PROJECTION_ENUMS.items():
        values = [r["value"] for r in vocab[name]]
        if list(_dig(schemas["projection"], path)) != values:
            _fail("coverage.schema.enum", name, "projection schema enum differs from the vocabulary")
    for row in vocab["inference_method"]:
        if row.get("confidence") not in ("certain", "tentative") or f"Confidence `{row['confidence']}`" not in row["meaning"]:
            _fail("coverage.vocab.confidence", row["value"], "each inference method has one fixed confidence")
    run_only = {r["value"] for r in vocab["run_only_verdicts"]}
    step_enum = list(_dig(schemas["projection"], ("$defs", "step_verdict", "properties", "verdict", "enum")))
    if step_enum != [r["value"] for r in vocab["layer_verdict"] if r["value"] not in run_only]:
        _fail("coverage.schema.enum", "step_verdict", "step verdicts must exclude the run-only verdicts")
    reasons = [r["value"] for r in vocab["reason"]]
    manifest_reason = _dig(schemas["manifest"], ("properties", "capture_points", "items",
                                                  "properties", "reason", "enum"))
    if list(manifest_reason) != reasons:
        _fail("coverage.schema.enum", "manifest reason", "manifest reason enum differs from the vocabulary")
    content = _load(root / CONTENT_SCHEMA)
    existing = list(content["properties"]["role"]["enum"])
    boundaries = set(content["properties"]["boundary"]["enum"])
    provenance = set(content["properties"]["provenance"]["enum"])
    roles = reg["roles"]["roles"]
    names = [r["role"] for r in roles]
    if len(set(names)) != len(names):
        _fail("coverage.roles.duplicate", "content-roles", "duplicate role")
    # content-v2 2.1.0 carries every role of the table, existing roles first
    # (spec 049 §4.3 rule 7): a role is a table row plus goldens.
    if [r["role"] for r in roles] != existing or [r["status"] for r in roles] != sorted(
        (r["status"] for r in roles), key=lambda status: status != "existing"
    ):
        _fail("coverage.roles.existing", "content-roles", "content-v2 roles differ from the role table")
    for r in roles:
        for key in ("layer", "boundary", "provenance", "media_types", "default_policy", "cap",
                    "phase", "telemetry_forbidden"):
            if key not in r or r[key] in (None, "", []):
                _fail("coverage.roles.incomplete", r["role"], f"missing {key}")
        if not set(r["boundary"]) <= boundaries or not set(r["provenance"]) <= provenance:
            _fail("coverage.roles.enum", r["role"], "boundary or provenance not in content-v2")
        if r["default_policy"] not in policies or r["telemetry_forbidden"] is not True:
            _fail("coverage.roles.policy", r["role"], "bad default policy or telemetry flag")
        if not all(MEDIA_RE.fullmatch(m) for m in r["media_types"]):
            _fail("coverage.roles.media_type", r["role"], "media type pattern")
    keys = reg["keys"]["keys"]
    if len({k["key"] for k in keys}) != len(keys):
        _fail("coverage.keys.duplicate", "telemetry-keys", "duplicate key")
    for k in keys:
        if k["field"] not in ids or k["change"] not in ("new", "changed", "reused"):
            _fail("coverage.keys.field", k["key"], "unknown field or change kind")
    # every attribute of the fabric.capture_manifest span needs an exact key row,
    # otherwise fabricguard strips it at the Node
    mapped = {k["manifest_property"] for k in keys if "manifest_property" in k}
    for prop in _manifest_leaves(schemas["manifest"]):
        if prop not in mapped:
            _fail("coverage.keys.manifest", prop, "manifest property has no telemetry key row")
    # store_reason values map onto coverage reasons (no_store -> not_configured)
    for value in (r["value"] for r in vocab["store_reason"]):
        if STORE_REASON_MAP.get(value, value) not in reasons:
            _fail("coverage.vocab.store_reason", value, "store reason has no coverage-reason mapping")


def _manifest_leaves(schema: Mapping[str, Any], prefix: str = "") -> list[str]:
    """Leaf property paths of the manifest schema (objects recurse, arrays are leaves)."""
    leaves: list[str] = []
    for name, sub in schema.get("properties", {}).items():
        path = f"{prefix}{name}"
        branches = [b for b in sub.get("oneOf", []) if b.get("type") == "object"]
        node = branches[0] if branches else sub
        if node.get("type") == "object" and "properties" in node:
            leaves += _manifest_leaves(node, path + "/")
        else:
            leaves.append(path)
    return leaves


# ------------------------------------------------------------------ key checks (C0-1, C0-2, C0-4)
CHECK_TYPES = {"enum", "const", "bool", "int", "string", "datetime", "array", "never"}
ADMISSIONS = {"existing", "never", "P0-A"}


def check_value(check: Mapping[str, Any], value: Any, *, labels: str = "clear") -> bool:
    """Whether a telemetry value passes a registry ``check`` (fabricguard's admission).

    ``labels`` is the Node's ``capture_labels`` mode: under ``pseudonymous`` a
    source id embedded in a value (``capture_labels.group``) must have its
    ``s-`` form, as spec 048 J1 requires of ``fabric.source_id`` itself.
    """
    kind = check["type"]
    if kind == "never":
        return False
    if kind == "enum":
        return isinstance(value, str) and value in check["values"]
    if kind == "const":
        return type(value) is type(check["value"]) and value == check["value"]
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "int":
        return (isinstance(value, int) and not isinstance(value, bool)
                and -INT64_MAX - 1 <= value <= INT64_MAX and value >= check["min"]
                and value <= check.get("max", INT64_MAX))
    if kind == "datetime":
        return isinstance(value, str) and _rfc3339(value)
    if kind == "string":
        if not isinstance(value, str):
            return False
        match = re.fullmatch(check["pattern"], value)
        if match is None:
            return False
        for group in check.get("int64_groups", []):
            if match.group(group) is not None and int(match.group(group)) > INT64_MAX:
                return False
        rule = check.get("capture_labels")
        if rule and labels == "pseudonymous":
            # Without a group the whole value is an operator label (048 J1 rule,
            # spec 049 §4.2 LABEL exposure); with one, only the embedded source id.
            subject = match.group(rule["group"]) if "group" in rule else value
            if subject is not None:
                return re.fullmatch(rule["pseudonymous_pattern"], subject) is not None
        return True
    if kind == "array":
        return (isinstance(value, list) and check.get("min_items", 0) <= len(value) <= check["max_items"]
                and (not check.get("unique") or len(set(map(json.dumps, value))) == len(value))
                and all(check_value(check["items"], item, labels=labels) for item in value))
    raise ValueError(kind)


def _rfc3339(value: str) -> bool:
    if RFC3339.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(re.sub(r"\.[0-9]+", "", value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _check_shape(check: Any, where: str) -> None:
    if not isinstance(check, dict) or check.get("type") not in CHECK_TYPES:
        _fail("coverage.keys.check", where, "check needs a known type")
    kind = check["type"]
    allowed = {
        "enum": {"type", "values", "source"},
        "const": {"type", "value", "span"},
        "bool": {"type"},
        "int": {"type", "min", "max"},
        "string": {"type", "pattern", "examples", "int64_groups", "capture_labels", "source"},
        "datetime": {"type", "examples"},
        "array": {"type", "items", "max_items", "min_items", "unique", "examples"},
        "never": {"type"},
    }[kind] | {"admission"}
    if "admission" in check and check["admission"] not in ADMISSIONS:
        _fail("coverage.keys.check", where, f"unknown admission {check['admission']!r}")
    if (kind == "never") != (check.get("admission") == "never"):
        _fail("coverage.keys.check", where, "a never check is exactly the never admission")
    if not set(check) <= allowed:
        _fail("coverage.keys.check", where, f"unknown check properties {sorted(set(check) - allowed)}")
    if kind == "enum" and (not check.get("values") or len(set(check["values"])) != len(check["values"])
                           or not isinstance(check.get("source"), str)):
        _fail("coverage.keys.check", where, "enum needs unique values and a source")
    if kind == "int" and (not isinstance(check.get("min"), int) or check.get("max", INT64_MAX) < check["min"]):
        _fail("coverage.keys.check", where, "int needs min <= max")
    if kind == "string":
        try:
            re.compile(check["pattern"])
        except (KeyError, re.error) as exc:
            _fail("coverage.keys.check", where, f"bad pattern: {exc}")
        if not check["pattern"].startswith("^") or not check["pattern"].endswith("$"):
            _fail("coverage.keys.check", where, "patterns are anchored")
    if kind == "array":
        if not isinstance(check.get("max_items"), int) or check["max_items"] < 1:
            _fail("coverage.keys.check", where, "array needs max_items")
        _check_shape(check["items"], where + ".items")
    if kind in {"string", "datetime", "array"} and not check.get("examples"):
        _fail("coverage.keys.check", where, "string, datetime and array checks carry examples")


def check_examples(check: Mapping[str, Any]) -> list[Any]:
    """Values that must pass a check: its examples, enum values, bounds, consts."""
    kind = check["type"]
    if kind == "never":
        return []
    if kind == "enum":
        return list(check["values"])
    if kind == "const":
        return [check["value"]]
    if kind == "bool":
        return [True, False]
    if kind == "int":
        return [check["min"]] + ([check["max"]] if "max" in check else [])
    return list(check["examples"])


def _schema_node(schema: Mapping[str, Any], path: str) -> Mapping[str, Any]:
    node: Mapping[str, Any] = schema
    for part in path.split("/"):
        node = node["properties"][part]
        node = next((b for b in node.get("oneOf", []) if b.get("type") == "object"), node)
    return node


def _check_covers_schema(check: Mapping[str, Any], prop: Mapping[str, Any], where: str) -> None:
    """A manifest key admits every value the manifest schema allows (spec 049 §2.8)."""
    kind = check["type"]
    allowed = list(prop.get("enum", [])) + ([prop["const"]] if "const" in prop else [])
    if allowed:
        admitted = check["values"] if kind == "enum" else [check.get("value")]
        if not set(allowed) <= set(admitted):
            _fail("coverage.keys.manifest_check", where, "check admits less than the manifest schema")
        return
    expected = {"boolean": "bool", "integer": "int", "string": "string", "array": "array"}.get(prop.get("type"))
    if prop.get("format") == "date-time":
        expected = "datetime"
    if kind != expected:
        _fail("coverage.keys.manifest_check", where, f"check type {kind} differs from the schema")
    if kind == "int" and (check["min"] > prop.get("minimum", -INT64_MAX - 1)
                          or check.get("max", INT64_MAX) < prop.get("maximum", INT64_MAX)):
        _fail("coverage.keys.manifest_check", where, "integer check is narrower than the schema")
    if kind == "string" and "pattern" in prop:
        for example in check["examples"]:
            if re.search(prop["pattern"], example) is None:
                _fail("coverage.keys.manifest_check", where, "example outside the schema pattern")
    if kind == "array" and isinstance(prop.get("items"), dict) and "enum" in prop["items"]:
        _check_covers_schema(check["items"], prop["items"], where + ".items")


def _enum_source_ok(row: Mapping[str, Any], check: Mapping[str, Any], reg: Mapping[str, Any],
                    manifest_schema: Mapping[str, Any]) -> bool:
    source, values = check["source"], check["values"]
    field = next(f for f in reg["fields"]["fields"] if f["id"] == row["field"])
    if source.startswith("vocabulary:"):
        return values == [r["value"] for r in reg["vocab"][source.split(":", 1)[1]]]
    if source == "field_type":
        groups = re.findall(r"enum ([a-z0-9_]+(?:/[a-z0-9_]+)+)", field["type"])
        return values in [g.split("/") for g in groups]
    if source == "field_definition":
        return all(re.search(rf"\b{re.escape(v)}\b", field["definition"]) for v in values)
    if source == "validator":
        return all(f"`{v}`" in row["validator"] for v in values)
    if source.startswith("registry:"):
        return values == list(reg["keys"][source.split(":", 1)[1]])
    if source.startswith("schema:"):
        node = _schema_node(manifest_schema, source.split(":", 1)[1])
        node = node.get("items", node)
        return values == list(node["enum"])
    return False


# The reused keys spec 049 rev 6.3 (R63-11) gives a new P0 validator.
REUSED_CHECKED = {"fabric.event_id", "fabric.schema_version"}
BACKTICK_REGEX = re.compile(r"`(\^[^`]*\$)`")


def check_key_checks(root: Path, reg: Mapping[str, Any]) -> None:
    """Every new or changed key carries a closed check or says why it is pending."""
    manifest_schema = _load(root / FAMILY / SCHEMAS["manifest"])
    for row in reg["keys"]["keys"]:
        key, where = row["key"], f"telemetry-keys:{row['key']}"
        has_check, pending = "check" in row, "check_pending" in row
        if row["change"] == "reused":
            if pending or has_check != (key in REUSED_CHECKED):
                _fail("coverage.keys.check", where, "reused keys keep their validator unless R63-11 adds one")
            if not has_check:
                continue
        elif has_check == pending or (pending and not str(row["check_pending"]).strip()):
            _fail("coverage.keys.check", where, "exactly one of check or check_pending")
        if pending:
            if row["change"] == "new":
                _fail("coverage.keys.check", where, "every new key is admitted in P0 (spec 049 §4.2, R63-8)")
            continue
        check = row["check"]
        _check_shape(check, where)
        for example in check_examples(check):
            if not check_value(check, example):
                _fail("coverage.keys.example", where, f"example {example!r} fails its check")
        for text in FREE_TEXT + (["Jane Doe"], {"a": "b"}):
            if check_value(check, text):
                _fail("coverage.keys.free_text", where, f"check admits free text {text!r}")
        nested = check["items"] if check["type"] == "array" else check
        if nested["type"] == "enum" and not _enum_source_ok(row, nested, reg, manifest_schema):
            _fail("coverage.keys.enum_source", where, f"enum differs from its source {nested['source']}")
        # A validator that spells out its regex is the check's pattern, verbatim.
        spelled = BACKTICK_REGEX.findall(row["validator"])
        if spelled and check["type"] == "string":
            labels = check.get("capture_labels", {})
            used = {check["pattern"]} | ({labels["pseudonymous_pattern"]} if "group" not in labels and labels else set())
            if not used <= set(spelled):
                _fail("coverage.keys.pattern", where, "check pattern differs from the regex the validator names")
        prop = row.get("manifest_property")
        if prop and prop not in {"capture_points", "capture_points/fields", "unsealed_prior_epochs"}:
            _check_covers_schema(check, _schema_node(manifest_schema, prop), where)
        if row.get("owner") == "receiver" and row["validator"].find("stripped") < 0:
            _fail("coverage.keys.owner", where, "receiver-owned keys say they are stripped from agents")


# ------------------------------------------------------------------ manifest span form
def _manifest_key_rows(reg: Mapping[str, Any]) -> dict[str, str]:
    """manifest property -> telemetry key."""
    return {k["manifest_property"]: k["key"] for k in reg["keys"]["keys"] if "manifest_property" in k}


def _get_path(document: Mapping[str, Any], path: str) -> Any:
    node: Any = document
    for part in path.split("/"):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def manifest_to_span(manifest: Mapping[str, Any], reg: Mapping[str, Any]) -> dict[str, Any]:
    """The closed attributes of the ``fabric.capture_manifest`` span (spec 049 §2.8)."""
    keys = _manifest_key_rows(reg)
    attributes: dict[str, Any] = {}
    for prop, key in keys.items():
        if prop == "capture_points":
            attributes[key] = [
                f"{p['id']}@{p['version']}:{p['kind']}:{p['state']}:{int(p['process_global'])}"
                f":{int(p['opt_in'])}:{p.get('reason', '-')}" for p in manifest["capture_points"]
            ]
        elif prop == "capture_points/fields":
            attributes[key] = [f"{p['id']}={','.join(p['fields'])}" for p in manifest["capture_points"]]
        elif prop == "unsealed_prior_epochs":
            attributes[key] = [str(epoch) for epoch in manifest["unsealed_prior_epochs"]]
        else:
            value = _get_path(manifest, prop)
            if value is not None:
                attributes[key] = value
    return attributes


def span_to_manifest(attributes: Mapping[str, Any], reg: Mapping[str, Any]) -> dict[str, Any]:
    """Inverse of :func:`manifest_to_span`: the manifest a reader rebuilds."""
    keys = _manifest_key_rows(reg)
    manifest: dict[str, Any] = {}
    for prop, key in keys.items():
        if key not in attributes or prop in {"capture_points", "capture_points/fields"}:
            continue
        value = attributes[key]
        if prop == "unsealed_prior_epochs":
            value = [int(epoch) for epoch in value]
        node = manifest
        parts = prop.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    fields = dict(item.split("=", 1) for item in attributes.get(keys["capture_points/fields"], []))
    points = []
    for item in attributes.get(keys["capture_points"], []):
        head, kind, state, process_global, opt_in, reason = item.rsplit(":", 5)
        point_id, version = head.split("@", 1)
        point = {"id": point_id, "version": version, "kind": kind, "state": state,
                 "process_global": process_global == "1", "opt_in": opt_in == "1",
                 "fields": [f for f in fields.get(point_id, "").split(",") if f]}
        if reason != "-":
            point["reason"] = reason
        points.append(point)
    manifest["capture_points"] = points
    return manifest


def _record_attribute_schema(prop: str, node: Mapping[str, Any], check: Mapping[str, Any] | None) -> dict[str, Any]:
    if prop in {"capture_points", "capture_points/fields", "unsealed_prior_epochs"}:
        assert check is not None
        return {"type": "array", "maxItems": check["max_items"],
                "items": {"type": "string", "pattern": check["items"]["pattern"]}}
    return {k: v for k, v in node.items() if k != "description"}


def _required_path(schema: Mapping[str, Any], path: str) -> bool:
    """Whether every level of ``path`` is required and none is nullable."""
    node: Mapping[str, Any] = schema
    for part in path.split("/"):
        if part not in node.get("required", []):
            return False
        node = node["properties"][part]
        if "oneOf" in node:
            return False
    return True


def render_manifest_record_schema(reg: Mapping[str, Any], manifest_schema: Mapping[str, Any]) -> dict[str, Any]:
    """``fabric.capture-manifest-record/v1``: the manifest as span attributes."""
    keys = _manifest_key_rows(reg)
    checks = {k["key"]: k.get("check") for k in reg["keys"]["keys"]}
    properties: dict[str, Any] = {}
    required: list[str] = []
    dependent: dict[str, list[str]] = {}
    for prop, key in keys.items():
        node = {} if prop == "capture_points/fields" else _schema_node(manifest_schema, prop)
        properties[key] = _record_attribute_schema(prop, node, checks.get(key))
    for prop, key in keys.items():
        if prop == "capture_points/fields" or _required_path(manifest_schema, prop):
            required.append(key)
    policy = _schema_node(manifest_schema, "capture_policy")
    policy_keys = [keys[f"capture_policy/{name}"] for name in policy["required"]]
    for name in policy["properties"]:
        dependent[keys[f"capture_policy/{name}"]] = [k for k in policy_keys if k != keys[f"capture_policy/{name}"]]
    seq, previous = keys["manifest_seq"], keys["previous_manifest_sha256"]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://singleaxis.ai/contracts/capture/v1/capture-manifest-record-v1.schema.json",
        "title": "Fabric capture manifest record v1 (draft, spec 049 §2.8)",
        "description": (
            "The fabric.capture_manifest span: the closed attribute set that carries one "
            "fabric.capture-manifest/v1 document (contracts/coverage/v1). Generated by "
            "scripts/contracts/validate_coverage_contracts.py from the coverage manifest schema and "
            "the telemetry-key registry (manifest_property); do not edit by hand. capture_points travel "
            "as '<id>@<version>:<kind>:<state>:<process_global 0/1>:<opt_in 0/1>:<reason or ->' strings "
            "and their field ids as '<id>=<field id>,...'; unsealed prior epochs as decimal strings. "
            "A manifest never carries fabric.wire.exchange_id, fabric.heartbeat.last_sequence or "
            "fabric.loss.reason, so it never occupies or explains a source position."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "name", "attributes"],
        "properties": {
            "schema_version": {"const": "fabric.capture-manifest-record/v1"},
            "name": {"const": "fabric.capture_manifest"},
            "attributes": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(required),
                "properties": dict(sorted(properties.items())),
                "dependentRequired": dict(sorted(dependent.items())),
                "if": {"properties": {seq: {"minimum": 1}}, "required": [seq]},
                "then": {"required": [previous]},
            },
        },
    }


def check_manifest_record_schema(root: Path, reg: Mapping[str, Any], *, write: bool = False) -> None:
    manifest_schema = _load(root / FAMILY / SCHEMAS["manifest"])
    expected = render_manifest_record_schema(reg, manifest_schema)
    path = root / MANIFEST_RECORD_SCHEMA
    if write:
        path.write_text(json.dumps(expected, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    if not path.is_file() or _load(path) != expected:
        _fail("coverage.manifest_record.drift", str(MANIFEST_RECORD_SCHEMA),
              "capture/v1 manifest-record schema differs from its rendering (run with --write)")


# ------------------------------------------------------------------ fixtures
def _schema_errors(document: Any, schema: Mapping[str, Any]) -> None:
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document),
                    key=lambda error: tuple(str(part) for part in error.absolute_path))
    if errors:
        first = errors[0]
        _fail("coverage.schema", "$" + "".join(f".{part}" for part in first.absolute_path), first.message)


def _fields_of(layers: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    out: list[tuple[str, Mapping[str, Any]]] = []

    def visit(prefix: str, fieldset: Mapping[str, Any]) -> None:
        for name, wrapper in fieldset.items():
            out.append((f"{prefix}.{name}", wrapper))
            for index, item in enumerate(wrapper.get("items", [])):
                visit(f"{prefix}.{name}.items[{index}]", item)

    for layer, fieldset in layers.items():
        visit(layer, fieldset)
    return out


def _confidence(reg: Mapping[str, Any]) -> dict[str, str]:
    return {r["value"]: r["confidence"] for r in reg["vocab"]["inference_method"]}


SAME_AS_METHODS = {"trace_id_match", "cross_run_previous_response"}
NOT_CHOSEN = {"value", "ref", "refs"}
GRAPH_REASONS = {"segment_missing", "segment_conflict", "post_terminal_activity"}
CLAIMS = {"captured_for_declared_fields", "captured_with_withholding"}


def validate_projection(document: Mapping[str, Any], reg: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    """Semantic rules of ``fabric.step-projection/v1`` the schema cannot express."""
    _schema_errors(document, schema)
    confidence = _confidence(reg)
    manifests = {m["manifest_id"] for m in document["inputs"]["manifests"]}
    runs = {run["run_id"] for run in document["runs"]}
    attempts: set[str] = set()

    def links_ok(links: Sequence[Mapping[str, Any]], where: str) -> None:
        parents = 0
        for index, link in enumerate(links):
            at = f"{where}.links[{index}]"
            parents += link["type"] == "parent"
            if link["provenance"] == "inferred" and confidence[link["method"]] != link["confidence"]:
                _fail("coverage.projection.confidence", at, f"{link['method']} has fixed confidence "
                      f"{confidence[link['method']]}")
            if link["type"] == "same_as" and link["provenance"] == "inferred" and (
                    link["method"] not in SAME_AS_METHODS or link["confidence"] != "tentative"):
                _fail("coverage.projection.same_as", at, "an inferred same_as is tentative, by "
                      "trace_id_match or cross_run_previous_response only")
            if link["state"] == "ambiguous" and len(link.get("candidates", [])) < 2:
                _fail("coverage.projection.link", at, "ambiguous links list every candidate")
        if parents > 1:
            _fail("coverage.projection.link", where, "at most one parent link")

    layer_keys: dict[str, set[str]] = {}
    for row in reg["fields"]["fields"]:
        layer_keys.setdefault(row["layer"], set()).update(field_set_keys(row["name"]))

    def fields_ok(layers: Mapping[str, Any], where: str) -> None:
        for layer, fieldset in layers.items():
            for key in fieldset:
                if not key.startswith("x-") and key not in layer_keys.get(layer, set()):
                    _fail("coverage.projection.field_key", f"{where}.{layer}.{key}",
                          "field-set keys are derived from the registry rows of their layer (spec 049 §3)")
        for name, wrapper in _fields_of(layers):
            at = f"{where}.{name}"
            status = wrapper["status"]
            if status in {"absent", "not_applicable", "unknown"} and NOT_CHOSEN & set(wrapper):
                _fail("coverage.projection.absent", at, f"status {status} carries no value; an empty "
                      "value is captured, never absent")
            if status == "absent" and wrapper.get("parse") not in {None, "parsed"}:
                _fail("coverage.projection.absent", at, "absent needs a complete, parsed carrier")
            if status == "conflict" and NOT_CHOSEN & set(wrapper):
                _fail("coverage.projection.conflict", at, "a conflict keeps every assertion and chooses none")
            if wrapper.get("provenance") == "inferred" and confidence[wrapper["method"]] != wrapper["confidence"]:
                _fail("coverage.projection.confidence", at, f"{wrapper['method']} has fixed confidence "
                      f"{confidence[wrapper['method']]}")

    for index, step in enumerate(document["steps"]):
        where = f"$.steps[{index}]"
        if step["attempt_id"] in attempts:
            _fail("coverage.projection.attempt", where, "one entry per attempt_id")
        attempts.add(step["attempt_id"])
        if ("step_kind_extension" in step) != (step["step_kind"] == "extension"):
            _fail("coverage.projection.extension", where, "step_kind_extension names exactly an extension step")
        if step["run_id"] not in runs:
            _fail("coverage.projection.inputs", where, "step of an unlisted run")
        if "source" in step and "manifest_id" in step["source"] and step["source"]["manifest_id"] not in manifests:
            _fail("coverage.projection.inputs", where, "governing manifest is not a named input")
        if step["provenance"] == "inferred" and confidence[step["method"]] != step["confidence"]:
            _fail("coverage.projection.confidence", where, "inferred step confidence is fixed by its method")
        links_ok(step.get("links", []), where)
        fields_ok(step["layers"], where + ".layers")

    for index, run in enumerate(document["runs"]):
        where = f"$.runs[{index}]"
        fields_ok(run["fields"], where + ".fields")
        state = run["run_state"]
        verdicts = run["layer_verdicts"].values()
        reasons = {reason for verdict in verdicts for reason in verdict.get("reasons", [])}
        if any(v["verdict"] == "open" for v in verdicts) and state != "open":
            _fail("coverage.projection.run_state", where, "an open verdict needs run_state open")
        if state in {"open", "unterminated", "conflicted", "deadline_uncertain"} and any(
                v["verdict"] in CLAIMS for v in verdicts):
            _fail("coverage.projection.run_state", where, f"run_state {state} never claims capture")
        if "run_unterminated" in reasons and state != "unterminated":
            _fail("coverage.projection.run_reason", where, "run_unterminated is the reason of an unterminated run")
        if GRAPH_REASONS & reasons and state != "conflicted":
            _fail("coverage.projection.run_reason", where, "segment graph reasons belong to a conflicted run")
        if "clock_uncertain" in reasons and state not in {"deadline_uncertain", "conflicted"}:
            _fail("coverage.projection.run_reason", where, "clock_uncertain needs an uncertain deadline or G4")
        if state in {"open", "unterminated", "deadline_uncertain"} and (
                run.get("resumable") is not True or "deadline_at" not in run):
            _fail("coverage.projection.run_state", where, f"{state} is a resumable run with a deadline")
        if state == "not_resumable_unclosed" and run.get("resumable") is True:
            _fail("coverage.projection.run_state", where, "not_resumable_unclosed is not resumable")
        segments = run["segments"]
        terminals = [s for s in segments if s.get("terminal")]
        roots = [s for s in segments if s["predecessors"] == ["none"]]
        consumers: dict[str, int] = {}
        for segment in segments:
            if "none" in segment["predecessors"] and segment["predecessors"] != ["none"]:
                _fail("coverage.projection.segments", where, "none is the only predecessor of a root")
            for entry in segment["predecessors"]:
                if entry != "none" and _parse_predecessor(entry) is None:
                    _fail("coverage.projection.segments", where, f"bad predecessor entry {entry!r}")
            for branch in segment.get("consumes_branch_ids", []):
                consumers[branch] = consumers.get(branch, 0) + 1
        graph_conflict = (len(roots) > 1 or any(n > 1 for n in consumers.values())
                          or any(s["state"] in {"missing", "conflict"} for s in segments)
                          or len(terminals) > 1)
        if graph_conflict and state != "conflicted":
            _fail("coverage.projection.segments", where, "G1/G2/G7: the segment graph makes the run conflicted")
        if state == "terminated" and len(terminals) != 1:
            _fail("coverage.projection.segments", where, "G5: a terminated run has exactly one terminal segment")
        if state in {"open", "unterminated", "not_resumable_unclosed"} and terminals:
            _fail("coverage.projection.segments", where, f"{state} has no terminal segment")


def validate_manifest_document(document: Mapping[str, Any], reg: Mapping[str, Any],
                               schema: Mapping[str, Any]) -> None:
    """Semantic rules of ``fabric.capture-manifest/v1`` (spec 049 §2.4, §2.8, §2.9, §7.3)."""
    _schema_errors(document, schema)
    registry = {p["id"]: p for p in reg["points"]["capture_points"]}
    seen: set[str] = set()
    for index, point in enumerate(document["capture_points"]):
        where = f"$.capture_points[{index}]"
        known = registry.get(point["id"])
        if known is None or point["id"] in seen:
            _fail("coverage.manifest.capture_point", where, "unknown or repeated capture point")
        seen.add(point["id"])
        if point["kind"] not in known["kind"].split("/"):
            _fail("coverage.manifest.capture_point", where, "kind differs from the registry")
        if not set(point["fields"]) <= set(known["supplies"]):
            _fail("coverage.manifest.capture_point", where, "declares a field the capture point does not supply")
    if document["content_capture"] != "enabled" and "content_capture_reason" not in document:
        _fail("coverage.manifest.content_capture", "$.content_capture_reason",
              "disabled content capture states its reason (spec 049 §7.3)")
    if document["content_capture"] == "enabled" and not document.get("capture_policy"):
        _fail("coverage.manifest.content_capture", "$.capture_policy",
              "content capture runs under a capture policy (X31; fabric.local-default when none)")
    if (document["pseudonym_mode"] == "keyed") != ("key_id" in document):
        _fail("coverage.manifest.pseudonym", "$.key_id", "a keyed manifest names its key id, an unkeyed one none")
    if document["manifest_seq"] == 0 and (document["after_source_sequence"] != -1
                                          or "previous_manifest_sha256" in document):
        _fail("coverage.manifest.sequence", "$.manifest_seq",
              "manifest 0 precedes every sequence and has no predecessor")
    listed, count = len(document["unsealed_prior_epochs"]), document["unsealed_prior_epoch_count"]
    if count < listed or (count <= 64 and count != listed):
        _fail("coverage.manifest.unsealed", "$.unsealed_prior_epoch_count",
              "the count is exact; the list is truncated only beyond 64")


EPOCH_VARIABLE = {"manifest_id", "event_id", "emitted_at", "manifest_seq", "after_source_sequence",
                  "previous_manifest_sha256", "capture_points"}


def _epoch_fixed(manifest: Mapping[str, Any]) -> Any:
    """What spec 049 §2.4 rule 5 fixes per epoch: everything but capture-point state."""
    fixed = {k: v for k, v in manifest.items() if k not in EPOCH_VARIABLE}
    fixed["capture_points"] = [{k: v for k, v in p.items() if k not in {"state", "reason"}}
                               for p in manifest["capture_points"]]
    return fixed


def manifest_digest(document: Mapping[str, Any]) -> str:
    canonical = json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ resume tokens and predecessors
SEGMENT_ENTRY = re.compile(
    r"^(?P<segment_id>seg-[0-9a-f]{32})/(?P<source_id>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})/"
    r"(?P<epoch>[1-9][0-9]{0,18})/(?P<last_sequence>-1|0|[1-9][0-9]{0,18})/"
    r"(?P<manifest_digest>sha256:[0-9a-f]{64})$"
)
BRANCH_ID = re.compile(r"^br-[0-9a-f]{32}$")


def _parse_predecessor(entry: str) -> dict[str, Any] | None:
    match = SEGMENT_ENTRY.fullmatch(entry)
    if match is None or int(match["epoch"]) > INT64_MAX or int(match["last_sequence"]) > INT64_MAX:
        return None
    return {"segment_id": match["segment_id"], "source_id": match["source_id"], "epoch": int(match["epoch"]),
            "last_sequence": int(match["last_sequence"]), "manifest_digest": match["manifest_digest"]}


def parse_resume_token(token: str) -> dict[str, Any] | None:
    """``fr2/<segment>/<source>/<epoch>/<last_sequence>/sha256:<hex>[/br-<hex>]`` (spec 049 §2.10)."""
    if not token.startswith("fr2/"):
        return None
    body = token[4:]
    branch = None
    head, _, tail = body.rpartition("/")
    if BRANCH_ID.fullmatch(tail):
        body, branch = head, tail
    parsed = _parse_predecessor(body)
    if parsed is None:
        return None
    parsed["branch_id"] = branch
    return parsed


def parse_token_list(text: str, *, carrier: str) -> list[dict[str, Any]] | None:
    """A join is comma-separated; in W3C ``baggage`` the value is percent-encoded."""
    if carrier == "baggage":
        text = unquote(text, errors="strict")
    tokens = [parse_resume_token(t) for t in text.split(",")]
    return None if any(t is None for t in tokens) else tokens  # type: ignore[return-value]


# ------------------------------------------------------------------ pseudonyms (C0-3)
def pseudonym_v1(prefix: str, value: str, key: str | None) -> str:
    data = value.encode("utf-8")
    raw = hmac.new(key.encode("utf-8"), data, hashlib.sha256) if key else hashlib.sha256(data)
    return f"{prefix}-{raw.hexdigest()[:32]}"


# Spec 049 §2.9 rule 2 (rev 6.3, R63-3): prefix -> type string of function v2.
PSEUDONYM_V2_TYPES = {
    "sess": "session", "usr": "user", "act": "actor", "conv": "conversation", "turn": "turn",
    "trg": "trigger", "dsp": "dispatch", "agt": "agent", "tgt": "target", "hst": "host",
    "sbx": "sandbox", "mcps": "mcp_session", "rpc": "jsonrpc", "dbn": "db_namespace",
    "txn": "db_transaction", "mst": "memory_store", "mkey": "memory_key", "p": "provider",
}


def pseudonym_v2(prefix: str, id_type: str, value: str, key: str | None) -> str | None:
    """``prefix-`` + 32 hex of HMAC(k_type, value), k_type = HMAC(key, "fabric-id/v2/" + type).

    The key is UTF-8; the value is the caller's string exactly as given, UTF-8
    with ``surrogatepass`` (spec 049 §2.9 rule 2, derivation input).
    """
    if not key:
        return None  # spec 049 §2.9 rule 5: v2 ids are omitted without a key
    k_type = hmac.new(key.encode("utf-8"), f"fabric-id/v2/{id_type}".encode("utf-8"), hashlib.sha256).digest()
    digest = hmac.new(k_type, value.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
    return f"{prefix}-{digest[:32]}"


def key_id(key: str) -> str:
    return "kid-" + hmac.new(key.encode("utf-8"), b"fabric-id/v2/kid", hashlib.sha256).hexdigest()[:8]


def validate_vectors(document: Mapping[str, Any], reg: Mapping[str, Any], root: Path,
                     schemas: Mapping[str, Mapping[str, Any]]) -> None:
    kind = document.get("schema_version")
    if kind == "fabric.capture-manifest-chain-vectors/v1":
        previous = None
        for index, manifest in enumerate(document["manifests"]):
            validate_manifest_document(manifest, reg, schemas["manifest"])
            if manifest["manifest_seq"] != index or (
                    previous is not None and manifest.get("previous_manifest_sha256") != manifest_digest(previous)):
                _fail("coverage.vectors.chain", f"$.manifests[{index}]",
                      "manifest_seq is contiguous and chains the canonical digest of its predecessor")
            if previous is not None and manifest["after_source_sequence"] < previous["after_source_sequence"]:
                _fail("coverage.vectors.chain", f"$.manifests[{index}]", "effective positions never go back")
            if previous is not None and (_epoch_fixed(manifest) != _epoch_fixed(previous)):
                _fail("coverage.vectors.chain", f"$.manifests[{index}]",
                      "within one epoch only capture-point state may change (spec 049 §2.4 rule 5)")
            previous = manifest
        if document["digests"] != [manifest_digest(m) for m in document["manifests"]]:
            _fail("coverage.vectors.chain", "$.digests", "pinned manifest digests differ")
    elif kind == "fabric.capture-manifest-span-vectors/v1":
        record_schema = _load(root / MANIFEST_RECORD_SCHEMA)
        checks = {k["key"]: k.get("check") for k in reg["keys"]["keys"]}
        for index, case in enumerate(document["cases"]):
            where = f"$.cases[{index}]"
            manifest, attributes = case["manifest"], case["attributes"]
            validate_manifest_document(manifest, reg, schemas["manifest"])
            _schema_errors({"schema_version": "fabric.capture-manifest-record/v1",
                            "name": "fabric.capture_manifest", "attributes": attributes}, record_schema)
            if manifest_to_span(manifest, reg) != attributes:
                _fail("coverage.vectors.manifest_span", where, "attributes differ from the manifest's span form")
            expected = {k: v for k, v in manifest.items() if v is not None}
            if span_to_manifest(attributes, reg) != expected:
                _fail("coverage.vectors.manifest_span", where, "span form does not round-trip")
            for key, value in attributes.items():
                if checks.get(key) is not None and not check_value(checks[key], value):
                    _fail("coverage.vectors.manifest_span", f"{where}.{key}", "fabricguard would strip this value")
    elif kind == "fabric.resume-token-vectors/v1":
        for index, case in enumerate(document["tokens"]):
            if parse_resume_token(case["token"]) != case["parsed"]:
                _fail("coverage.vectors.resume_token", f"$.tokens[{index}]", f"{case['name']}: parse differs")
        for index, case in enumerate(document["predecessors"]):
            parsed = None if case["entry"] == "none" else _parse_predecessor(case["entry"])
            if (case["entry"] == "none" or parsed is not None) != case["valid"] or (parsed and parsed != case["parsed"]):
                _fail("coverage.vectors.predecessor", f"$.predecessors[{index}]", f"{case['name']}: parse differs")
        for index, case in enumerate(document["carriers"]):
            parsed = parse_token_list(case["value"], carrier=case["carrier"])
            expected = None if case["tokens"] is None else [parse_resume_token(t) for t in case["tokens"]]
            if parsed != expected or (expected is not None and None in expected):
                _fail("coverage.vectors.carrier", f"$.carriers[{index}]", f"{case['name']}: carrier parse differs")
    elif kind == "fabric.run-marker-vectors/v1":
        checks = {k["key"]: k.get("check") for k in reg["keys"]["keys"]}
        for index, case in enumerate(document["admitted"]):
            for key, value in case["attributes"].items():
                check = checks.get(key)
                if check is not None and not check_value(check, value, labels=case["capture_labels"]):
                    _fail("coverage.vectors.marker", f"$.admitted[{index}].{key}", f"{case['name']}: rejected")
        for index, case in enumerate(document["stripped"]):
            check = checks.get(case["key"])
            if check is None or check_value(check, case["value"], labels=case["capture_labels"]):
                _fail("coverage.vectors.marker", f"$.stripped[{index}]", f"{case['name']}: admitted")
    elif kind == "fabric.pseudonym-vectors/v2":
        v1 = _load(root / PSEUDONYM_V1_VECTORS)
        for index, case in enumerate(document["cases"]):
            where = f"$.cases[{index}]"
            if case["function"] == "v2":
                if PSEUDONYM_V2_TYPES.get(case["prefix"]) != case["type"]:
                    _fail("coverage.vectors.pseudonym", where, f"{case['name']}: prefix and type disagree with §2.9")
                got = pseudonym_v2(case["prefix"], case["type"], case["value"], case["key"])
            elif case["function"] == "legacy_provider":
                got = "p-" + hashlib.sha256(case["value"].encode("utf-8")).hexdigest()[:16]
            else:
                got = pseudonym_v1(case["prefix"], case["value"], case["key"])
            if got != case["pseudonym"]:
                _fail("coverage.vectors.pseudonym", where, f"{case['name']}: pseudonym differs")
        covered = {c["prefix"] for c in document["cases"] if c["function"] == "v2" and c["pseudonym"]}
        if covered != set(PSEUDONYM_V2_TYPES):
            _fail("coverage.vectors.pseudonym", "$.cases", f"no keyed v2 vector for {sorted(set(PSEUDONYM_V2_TYPES) - covered)}")
        for index, case in enumerate(document["key_ids"]):
            if key_id(case["key"]) != case["key_id"]:
                _fail("coverage.vectors.key_id", f"$.key_ids[{index}]", "key id differs")
        for index, case in enumerate(v1["cases"]):
            if pseudonym_v1("r", case["run_id"], case["key"]) != case["pseudonym"]:
                _fail("coverage.vectors.pseudonym", f"v1.cases[{index}]", "v1 function changed")
        for index, (left, right) in enumerate(document["distinct"]):
            names = {c["name"]: c["pseudonym"] for c in document["cases"]}
            if names[left][names[left].index("-"):] == names[right][names[right].index("-"):]:
                _fail("coverage.vectors.separation", f"$.distinct[{index}]", f"{left} and {right} share a pseudonym")
    else:
        _fail("coverage.vectors.unknown", "$.schema_version", f"unknown vector document {kind!r}")


def validate_fixture(document: Mapping[str, Any], reg: Mapping[str, Any], root: Path,
                     schemas: Mapping[str, Mapping[str, Any]]) -> None:
    kind = document.get("schema_version")
    if kind == "fabric.step-projection/v1":
        validate_projection(document, reg, schemas["projection"])
    elif kind == "fabric.capture-manifest/v1":
        validate_manifest_document(document, reg, schemas["manifest"])
    else:
        _fail("coverage.fixture.unknown", "$.schema_version", f"unknown fixture document {kind!r}")


def validate_artifacts(root: Path, reg: Mapping[str, Any]) -> list[str]:
    family = root / FAMILY
    manifest = _load(family / "manifest.json")
    schemas = {name: _load(family / rel) for name, rel in SCHEMAS.items()}
    validated: list[str] = []
    for record in manifest["artifacts"]:
        expectation, error = record.get("expectation"), record.get("expected_error")
        if expectation not in EXPECTATIONS or (expectation == "invalid") != (isinstance(error, str) and bool(error)):
            _fail("coverage.manifest.record", record["path"], "bad expectation/error binding")
        if expectation in {"registry", "schema"}:
            continue
        document = _load(family / record["path"])
        if expectation == "vectors":
            validate_vectors(document, reg, root, schemas)
        elif expectation == "valid":
            validate_fixture(document, reg, root, schemas)
        else:
            try:
                validate_fixture(document, reg, root, schemas)
            except CoverageContractError as exc:
                if exc.code != error:
                    _fail("coverage.fixture.wrong_error", record["path"], f"expected {error}, got {exc.code}: {exc}")
            else:
                _fail("coverage.fixture.accepted_invalid", record["path"], "invalid fixture accepted")
        validated.append(record["path"])
    return validated


def check_spec(root: Path, reg: Mapping[str, Any], *, write: bool = False) -> list[str]:
    path = root / SPEC
    text = path.read_text(encoding="utf-8")
    expected = render_blocks(reg)
    found = {m["name"]: m["body"] for m in BLOCK_RE.finditer(text)}
    missing = sorted(set(expected) - set(found))
    if missing:
        _fail("coverage.spec.block_missing", str(SPEC), f"no generated block for {missing}")
    if write:
        def sub(match: re.Match[str]) -> str:
            name = match["name"]
            body = expected.get(name, match["body"])
            return f"<!-- generated:{name}:begin -->\n{body}<!-- generated:{name}:end -->"

        path.write_text(BLOCK_RE.sub(sub, text), encoding="utf-8")
        return sorted(expected)
    for name, body in expected.items():
        if found[name] != body:
            _fail("coverage.spec.drift", str(SPEC), f"generated block {name} differs from the registry")
    return sorted(expected)


def validate_coverage_contracts(repo_root: Path, *, write: bool = False) -> list[str]:
    """Validate the family and the spec's generated blocks; return what was checked."""
    reg = load_registries(repo_root)
    check_registries(repo_root, reg)
    check_key_checks(repo_root, reg)
    check_manifest_record_schema(repo_root, reg, write=write)
    pinned = check_manifest(repo_root)
    validate_artifacts(repo_root, reg)
    blocks = check_spec(repo_root, reg, write=write)
    return [f"coverage/{p}" for p in pinned] + [f"spec/{b}" for b in blocks]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--write", action="store_true",
                        help="regenerate the spec 049 blocks and the capture/v1 manifest-record schema")
    args = parser.parse_args(argv)
    try:
        checked = validate_coverage_contracts(args.repo_root, write=args.write)
    except CoverageContractError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"ok: {len(checked)} coverage artifacts and spec blocks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
