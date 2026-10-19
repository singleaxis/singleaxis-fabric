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

It does not claim that any runtime emits these documents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator

FAMILY = Path("contracts/coverage/v1")
SPEC = Path("specs/049-four-layer-capture-coverage.md")
CONTENT_SCHEMA = Path("contracts/content/v2/schema/content-object-v2.schema.json")
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
    if [r["role"] for r in roles if r["status"] == "existing"] != existing:
        _fail("coverage.roles.existing", "content-roles", "existing roles differ from content-v2")
    for r in roles:
        for key in ("layer", "boundary", "provenance", "media_types", "default_policy", "cap",
                    "phase", "telemetry_forbidden"):
            if key not in r or r[key] in (None, "", []):
                _fail("coverage.roles.incomplete", r["role"], f"missing {key}")
        if r["status"] == "new" and r["role"] in existing:
            _fail("coverage.roles.overlap", r["role"], "new role already exists")
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
    pinned = check_manifest(repo_root)
    blocks = check_spec(repo_root, reg, write=write)
    return [f"coverage/{p}" for p in pinned] + [f"spec/{b}" for b in blocks]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--write", action="store_true", help="regenerate the spec 049 blocks")
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
