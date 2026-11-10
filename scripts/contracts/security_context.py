# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-0 (with spec 052 WP3-0) contract artifacts: reference functions, the
generated fixtures and vectors, and the checks the family validators delegate here.

Reference functions (the SDK and the reader must agree with the vectors they produce):

- :func:`jcs`: RFC 8785 JSON Canonicalization Scheme, used only for grant documents;
- :func:`normalise_grant` / :func:`grant_digest`: spec 057 §5.2 (every list sorted and
  de-duplicated, ``request_ref`` dropped; sha256 of the JCS bytes);
- :func:`pseudonymise_grant`: spec 057 §7.2 structural pseudonymisation (paths and globs
  ``pth-``, network hosts ``net-``, credential names ``crd-``, MCP ``server_ref`` ``src-``;
  keyed v2, 049 §2.9);
- :func:`observation_v1_to_v2`: spec 052 §4.2.4 (ControlObservation v1 documents to v2).

Generated here (``generate_p0_contracts.py`` calls :func:`generate`; ``--check`` keeps them
reproducible): the grant vectors, the schema case tables (a valid case for every enum
value and an invalid case for every required-by-kind rule), the v1→v2 control-observation
vectors, the spec 052 P3 golden records (one per E1 scenario), the capture/v1 mapping
profile and reconstruction fixtures, and the activity 2.1.0 contract beside 2.0.0.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from collections.abc import Callable, Mapping, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any, NoReturn

from jsonschema import Draft202012Validator, FormatChecker

COVERAGE = Path("contracts/coverage/v1")
CAPTURE = Path("contracts/capture/v1")
ACTIVITY_V2 = Path("contracts/activity/v2")
ACTIVITY = Path("contracts/activity/v2.1")
POLICY_SCHEMA = Path(
    "contracts/deployment-policy/v1/schema/deployment-policy-v1.schema.json"
)
GRANT_SCHEMA = "schema/grant-snapshot-v1.schema.json"
OBSERVATION_SCHEMA = "schema/control-observation-v2.schema.json"
SAFETY_MAP = "registry/provider-safety-map-v1.json"
KEY1 = (
    "fabric-test-id-key-not-a-secret"  # the coverage vectors' test key (never a secret)
)
CASES = "fabric.schema-cases/v1"
GRANT_VECTORS = "fabric.grant-snapshot-vectors/v1"
OBS_VECTORS = "fabric.control-observation-mapping-vectors/v1"
GOLDEN = "fabric.records-golden/v1"
SAFETY_FIXTURE = "fabric.provider-safety-fixture/v1"
AUTHENTICATION = "unverified_caller_report"

Fail = Callable[[str, str, str], NoReturn]


# ===================================================================== JCS (RFC 8785)
def _number(value: float) -> str:
    """ECMAScript Number serialisation (RFC 8785 §3.2.2.3)."""
    if isinstance(value, bool):
        raise TypeError("bool is not a number")
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise ValueError("integer outside the IEEE 754 exact range")
        return str(value)
    if not math.isfinite(value):
        raise ValueError("JCS refuses NaN and infinities")
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    sign = "-" if value < 0 else ""
    digits, exponent = Decimal(repr(abs(value))).normalize().as_tuple()[1:]
    text = "".join(str(d) for d in digits)
    point = len(text) + int(exponent)  # position of the decimal point in ``text``
    if -6 < point <= 21:
        if point <= 0:
            return f"{sign}0.{'0' * -point}{text}"
        if point >= len(text):
            return f"{sign}{text}{'0' * (point - len(text))}"
        return f"{sign}{text[:point]}.{text[point:]}"
    mantissa = text[0] + ("." + text[1:] if len(text) > 1 else "")
    power = point - 1
    return f"{sign}{mantissa}e{'+' if power > 0 else '-'}{abs(power)}"


def _string(value: str) -> str:
    out = ['"']
    for char in value:
        code = ord(char)
        if char in ('"', "\\"):
            out.append("\\" + char)
        elif code < 0x20:
            out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(
                code, f"\\u{code:04x}"))  # fmt: skip
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _utf16_key(key: str) -> list[int]:
    return list(key.encode("utf-16-be"))


def _jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda item: _utf16_key(item[0]))
        return "{" + ",".join(_string(k) + ":" + _jcs(v) for k, v in items) + "}"
    raise TypeError(f"JCS cannot serialise {type(value).__name__}")


def jcs(value: Any) -> bytes:
    """The RFC 8785 canonical UTF-8 bytes of a JSON value."""
    return _jcs(value).encode("utf-8")


# ===================================================================== grants (spec 057 §5.2, §7.2)
def normalise_grant(document: Mapping[str, Any]) -> Any:
    """Every list sorted (by the JCS bytes of its items) and de-duplicated, at every depth;
    ``request_ref`` dropped, so two requests with the same offered set normalise equal."""

    def walk(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            items = {jcs(walk(v)): walk(v) for v in value}
            return [items[k] for k in sorted(items)]
        return value

    out = walk(document)
    out.pop("request_ref", None)
    return out


def grant_digest(document: Mapping[str, Any]) -> str:
    """``sha256:`` + hex of the JCS bytes of the normalised clear document (G11)."""
    return "sha256:" + hashlib.sha256(jcs(normalise_grant(document))).hexdigest()


def _pseudonym(prefix: str, id_type: str, value: str, key: str) -> str:
    from contracts import validate_coverage_contracts as coverage  # noqa: PLC0415

    out = coverage.pseudonym_v2(prefix, id_type, value, key)
    assert out is not None
    return out


def grant_id(digest: str, key: str) -> str:
    """G01: the keyed ``grt-`` pseudonym of the grant digest text."""
    return _pseudonym("grt", "grant", digest, key)


PATH_FIELDS = (("filesystem", "roots"), ("filesystem", "read"), ("filesystem", "write"),
               ("filesystem", "deny"), ("roots",))  # fmt: skip
HOST_FIELDS = (("network", "allow"), ("network", "deny"))


def pseudonymise_grant(
    document: Mapping[str, Any], key: str, *, paths: bool = True, hosts: bool = True,
    credentials: bool = True, sources: bool = True,
) -> Any:  # fmt: skip
    """Spec 057 §7.2: replace, in place of each value, every path or glob with ``pth-``,
    every network host or pattern with ``net-``, every credential name with ``crd-`` and
    every MCP ``server_ref`` with ``src-`` (keyed v2, deterministic under one key). Other
    fields stay as written."""
    out = copy.deepcopy(dict(document))

    def replace(field: Sequence[str], prefix: str, id_type: str) -> None:
        node: Any = out
        for part in field[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict) and isinstance(node.get(field[-1]), list):
            node[field[-1]] = [
                _pseudonym(prefix, id_type, v, key) for v in node[field[-1]]
            ]

    if paths:
        for field in PATH_FIELDS:
            replace(field, "pth", "path_rule")
    if hosts:
        for field in HOST_FIELDS:
            replace(field, "net", "net_rule")
    if credentials:
        for item in out.get("credentials", []):
            item["name"] = _pseudonym("crd", "credential", item["name"], key)
    if sources:
        for item in out.get("mcp_servers", []):
            if "server_ref" in item:
                item["server_ref"] = _pseudonym(
                    "src", "extension_source", item["server_ref"], key
                )
    return out


# ===================================================================== ControlObservation v1 -> v2
V1_FIELDS = frozenset({
    "control_id", "action_id", "external_policy_id", "external_policy_version",
    "external_policy_digest", "reviewed_artifact_digest", "decision", "issuer_id", "proof_ref",
})  # fmt: skip


def observation_v1_to_v2(v1: Mapping[str, Any]) -> dict[str, Any]:
    """Spec 052 §4.2.4: a v1 document (or v1-style construction) as v2."""
    out: dict[str, Any] = {"schema_version": "fabric.external-control-observation/v2"}
    for name in sorted(V1_FIELDS - {"decision", "issuer_id"}):
        if v1.get(name) is not None:
            out[name] = v1[name]
    decision = v1.get("decision", "unknown")
    out["decision"] = "escalate" if decision == "requires_review" else decision
    out["kind"], out["phase"] = "policy", "observation"
    if v1.get("issuer_id") is not None:
        out["issuer_id"] = v1["issuer_id"]
        out["decided_by_id"] = v1["issuer_id"]
        out["decided_by_type"] = "external_service"
    out["policy_scope"] = "external_action_control"
    out["authentication"] = AUTHENTICATION
    out["enforced_by_fabric"] = False
    return dict(sorted(out.items()))


# ===================================================================== vocabulary helpers
def _vocab(reg: Mapping[str, Any], name: str) -> list[str]:
    return [r["value"] for r in reg["vocab"][name]]


# The 052 §4.2.2 phase × decision matrix, with spec 057's `error` (any stage; outside
# request and revocation, as `unknown`).
MATRIX = {
    "request": ("pending", "escalate", "unknown"),
    "resolution": ("allow", "deny", "modify", "escalate", "timeout", "cancelled", "unknown",
                   "error"),
    "revocation": ("revoked",),
    "observation": ("allow", "deny", "modify", "escalate", "timeout", "unknown", "error"),
}  # fmt: skip


# ===================================================================== schema case tables
def _schema_enums(schema: Mapping[str, Any]) -> set[str]:
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            for k, v in node.items():
                if k == "enum" and isinstance(v, list):
                    found.update(x for x in v if isinstance(x, str))
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema.get("properties", {}))
    walk(schema.get("$defs", {}))
    return found


def _strings(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, Mapping):
        return set().union(*(_strings(v) for v in value.values()), set())
    if isinstance(value, list):
        return set().union(*(_strings(v) for v in value), set())
    return set()


def _case(
    name: str, document: Any, valid: bool, rule: str | None = None
) -> dict[str, Any]:
    out = {"name": name, "valid": valid, "document": document}
    if rule is not None:
        out["rule"] = rule
    return out


SHA = "3f" * 32


def _declared() -> dict[str, Any]:
    return {
        "schema_version": "fabric.grant-snapshot/v1", "basis": "declared",
        "source": {"boundary": "api", "name": "acme-agent", "version": "3.2.0"},
        "execution_mode": "supervised", "approval_policy": "per_tool",
        "permission_mode": "ask_on_write",
        "tools": {"allow": [{"rule": "read_file"}, {"rule": "shell(git status *)"}],
                  "deny": [{"rule": "shell(curl *)"}], "ask": [{"rule": "write_file"}]},
        "mcp_servers": [{"server": "repo-tools", "transport": "stdio",
                         "server_ref": "npx -y @acme/repo-tools-mcp", "tools_allow": ["search"],
                         "tools_deny": [], "scope": "project"}],
        "filesystem": {"roots": ["/work"], "read": ["/work/**"], "write": ["/work/out/**"],
                       "deny": ["/work/.env"]},
        "network": {"default": "deny", "allow": ["api.internal.example"], "deny": []},
        "sandbox": {"kind": "container", "name": "agent-sbx", "enabled": True},
        "credentials": [{"name": "GITHUB_TOKEN", "kind": "env", "scopes": ["repo:read"]}],
        "models": {"allow": ["model-a"], "deny": []},
        "limits": [{"kind": "tool_calls", "limit": 200, "window": "run"}],
        "x-acme": {"policy_bundle": "agents-prod"},
    }  # fmt: skip


def _offered() -> dict[str, Any]:
    return {
        "schema_version": "fabric.grant-snapshot/v1", "basis": "offered",
        "source": {"boundary": "llm_wire", "endpoint_id": "anthropic.default"},
        "tools_offered": [{"name": "read_file", "type": "function", "definition_sha256": SHA},
                          {"name": "shell", "type": "function", "definition_sha256": "4e" * 32}],
        "tool_choice": {"mode": "auto", "allowed_count": None, "parallel": True},
        "instructions_digest": "sha256:" + "9e" * 32,
        "request_ref": {"exchange_id": "x-0001", "locator": "/tools"},
    }  # fmt: skip


def _listed() -> dict[str, Any]:
    return {
        "schema_version": "fabric.grant-snapshot/v1", "basis": "listed",
        "source": {"boundary": "mcp_wire", "name": "repo-tools"},
        "server": {"name": "repo-tools", "version": "1.4.0"},
        "tools_listed": [{"name": "search", "read_only_hint": True},
                         {"name": "delete_branch", "destructive_hint": True},
                         {"name": "open_pr", "open_world_hint": True, "idempotent_hint": False}],
        "roots": ["/work"],
    }  # fmt: skip


def grant_cases() -> list[dict[str, Any]]:
    cases = [_case("declared full", _declared(), True), _case("offered", _offered(), True),
             _case("listed", _listed(), True)]  # fmt: skip
    for value in (
        "autonomous",
        "supervised",
        "approval_required",
        "read_only",
        "unknown",
    ):
        cases.append(
            _case(
                f"execution_mode {value}", dict(_declared(), execution_mode=value), True
            )
        )
    for value in ("none", "per_tool", "per_side_effect", "all", "unknown"):
        cases.append(
            _case(
                f"approval_policy {value}",
                dict(_declared(), approval_policy=value),
                True,
            )
        )
    for value in ("api", "otlp", "operator_snapshot", "other"):
        doc = dict(_declared(), source={"boundary": value})
        if value == "operator_snapshot":
            doc["source"]["path_ref"] = "pth-" + "0a" * 16
        cases.append(_case(f"declared source {value}", doc, True))
    cases.append(
        _case(
            "offered source otlp", dict(_offered(), source={"boundary": "otlp"}), True
        )
    )
    cases.append(
        _case("listed source otlp", dict(_listed(), source={"boundary": "otlp"}), True)
    )
    for value in ("auto", "none", "required", "specific", "allowed_subset", "unknown"):
        choice = {"mode": value, "allowed_count": 1 if value in ("specific", "allowed_subset") else None,
                  "parallel": False}  # fmt: skip
        cases.append(
            _case(f"tool_choice {value}", dict(_offered(), tool_choice=choice), True)
        )
    for value in ("function", "custom", "provider_hosted", "mcp", "computer", "other"):
        doc = _offered()
        doc["tools_offered"] = [{"name": "t", "type": value}]
        cases.append(_case(f"tool type {value}", doc, True))
    for value in ("none", "process", "container", "vm", "remote", "unknown"):
        cases.append(
            _case(f"sandbox {value}", dict(_declared(), sandbox={"kind": value}), True)
        )
    for value in ("allow", "deny", "unknown"):
        cases.append(
            _case(
                f"network default {value}",
                dict(_declared(), network={"default": value}),
                True,
            )
        )
    for value in ("env", "file", "secret_store", "token", "other"):
        cases.append(_case(f"credential kind {value}",
                           dict(_declared(), credentials=[{"name": "X", "kind": value}]), True))  # fmt: skip
    for value in ("stdio", "streamable_http", "sse", "other"):
        cases.append(_case(f"mcp transport {value}",
                           dict(_declared(), mcp_servers=[{"server": "s", "transport": value}]), True))  # fmt: skip
    for value in ("managed", "user", "project", "local", "session", "unknown"):
        cases.append(_case(f"mcp scope {value}",
                           dict(_declared(), mcp_servers=[{"server": "s", "scope": value}]), True))  # fmt: skip
    bad = [
        ("unknown basis", dict(_declared(), basis="granted"), "enum"),
        ("offered without tools_offered", {k: v for k, v in _offered().items() if k != "tools_offered"},
         "offered requires tools_offered"),
        ("offered carrying declared rules", dict(_offered(), tools={"allow": [{"rule": "x"}]}),
         "offered forbids declared fields"),
        ("offered from mcp_wire", dict(_offered(), source={"boundary": "mcp_wire"}),
         "offered boundary"),
        ("listed without tools or roots", {k: v for k, v in _listed().items()
                                           if k not in ("tools_listed", "roots")},
         "listed requires tools_listed or roots"),
        ("listed carrying tool_choice", dict(_listed(), tool_choice={"mode": "auto"}),
         "listed forbids offered fields"),
        ("listed from llm_wire", dict(_listed(), source={"boundary": "llm_wire"}), "listed boundary"),
        ("declared carrying tools_offered", dict(_declared(), tools_offered=[{"name": "t", "type": "function"}]),
         "declared forbids offered fields"),
        ("declared carrying request_ref", dict(_declared(), request_ref={"exchange_id": "x"}),
         "declared forbids request_ref"),
        ("declared from llm_wire", dict(_declared(), source={"boundary": "llm_wire"}), "declared boundary"),
        ("credential value", dict(_declared(), credentials=[{"name": "X", "value": "ghp_secret"}]),
         "credential values are never recorded"),
        ("tool_choice mode", dict(_offered(), tool_choice={"mode": "any"}), "enum"),
        ("sandbox kind", dict(_declared(), sandbox={"kind": "jail"}), "enum"),
        ("network default", dict(_declared(), network={"default": "maybe"}), "enum"),
        ("source boundary", dict(_declared(), source={"boundary": "framework"}), "enum"),
        ("unknown top-level key", dict(_declared(), rules_text="..."), "closed document"),
        ("float limit", dict(_declared(), limits=[{"kind": "x", "limit": 1.5}]), "integers only"),
    ]  # fmt: skip
    cases += [_case(name, doc, False, rule) for name, doc, rule in bad]
    return cases


def _observation(**extra: Any) -> dict[str, Any]:
    base = {
        "schema_version": "fabric.external-control-observation/v2", "control_id": "approval:42",
        "kind": "policy", "phase": "observation", "decision": "deny",
        "policy_scope": "external_action_control", "authentication": AUTHENTICATION,
        "enforced_by_fabric": False,
    }  # fmt: skip
    base.update(extra)
    return base


def observation_cases(reg: Mapping[str, Any]) -> list[dict[str, Any]]:
    cases = []
    for phase, decisions in MATRIX.items():
        for decision in decisions:
            extra: dict[str, Any] = {"phase": phase, "decision": decision}
            if decision == "error":
                extra["error_class"] = "exception"
            cases.append(_case(f"{phase} {decision}", _observation(**extra), True))
    for kind in _vocab(reg, "control_kind"):
        extra = {"kind": kind}
        if kind == "provider_safety":
            extra.update(
                signal="content_filter",
                derivation="literal",
                evidence_event_ids=["7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e31"],
            )
        if kind == "os_access":
            extra.update(
                gated_kind="process", engine={"name": "kernel", "version": None}
            )
        cases.append(_case(f"kind {kind}", _observation(**extra), True))
    for stage in _vocab(reg, "control_stage"):
        cases.append(_case(f"stage {stage}", _observation(stage=stage), True))
    for gated in _vocab(reg, "gated_kind"):
        cases.append(_case(f"gated {gated}", _observation(gated_kind=gated), True))
    for mode in _vocab(reg, "control_mode"):
        cases.append(_case(f"mode {mode}", _observation(mode=mode), True))
    for error in _vocab(reg, "control_error_class"):
        cases.append(
            _case(
                f"error_class {error}",
                _observation(decision="error", error_class=error),
                True,
            )
        )
    for signal in _vocab(reg, "control_signal"):
        cases.append(_case(f"signal {signal}", _observation(
            kind="provider_safety", signal=signal, derivation="literal",
            evidence_event_ids=["7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e31"]), True))  # fmt: skip
    for derivation in _vocab(reg, "control_derivation"):
        extra = {"derivation": derivation}
        if derivation in (
            "literal",
            "configured_extract",
            "configured_marker",
            "configured_exit_map",
        ):
            extra["evidence_event_ids"] = ["7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e31"]
        cases.append(_case(f"derivation {derivation}", _observation(**extra), True))
    for actor in _vocab(reg, "actor_type"):
        cases.append(
            _case(f"decided_by {actor}", _observation(decided_by_type=actor), True)
        )
    cases.append(_case("full 057 fields", _observation(
        stage="pre_tool", engine={"name": "fs-write", "version": "1.0"}, gated_kind="tool_call",
        gated_tool_call_id="toolu_01", latency_ms=0.04, reason_code="path.outside_root",
        mode="enforcing", grant_id="grt-" + "1b" * 16, derivation="wrapped_check",
        reason_ref="0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01", resolves="approval:41",
        action_id="delete-branch", gated_step_id="step-7", decided_by_id="act-1",
        external_policy_id="refunds", external_policy_version=7,
        external_policy_digest="sha256:" + SHA, reviewed_artifact_digest="sha256:" + SHA,
        issuer_id="policy-svc", proof_ref="proof:abc"), True))  # fmt: skip
    bad = [
        ("request allow", _observation(phase="request", decision="allow"), "phase x decision"),
        ("request error", _observation(phase="request", decision="error", error_class="other"),
         "phase x decision"),
        ("revocation deny", _observation(phase="revocation", decision="deny"), "phase x decision"),
        ("observation pending", _observation(decision="pending"), "phase x decision"),
        ("observation revoked", _observation(decision="revoked"), "phase x decision"),
        ("provider_safety without signal", _observation(kind="provider_safety"), "provider_safety requires signal"),
        ("signal on a policy row", _observation(signal="refusal"), "signal only on provider_safety"),
        ("error without error_class", _observation(decision="error"), "error requires error_class"),
        ("error_class on a deny", _observation(error_class="timeout"), "error_class only on error"),
        ("derived row without evidence", _observation(derivation="configured_marker"),
         "derived rows require evidence_event_ids"),
        ("os_access not on a process", _observation(kind="os_access", gated_kind="tool_call"),
         "os_access gates a process"),
        ("forged enforcement", _observation(enforced_by_fabric=True), "D11 constant"),
        ("forged authentication", _observation(authentication="verified"), "D11 constant"),
        ("requires_review is v1 only", _observation(decision="requires_review"), "enum"),
        ("approve is an input alias only", _observation(kind="approval", decision="approve"), "enum (OD-3)"),
        ("bad reason code", _observation(reason_code="Path Outside Root"), "reason_code pattern"),
        ("negative latency", _observation(latency_ms=-1), "latency >= 0"),
        ("unknown stage", _observation(stage="during"), "enum"),
    ]  # fmt: skip
    cases += [_case(name, doc, False, rule) for name, doc, rule in bad]
    return cases


def _policy_doc(section: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "fabric.deployment-policy/v1", "policy_id": "acme-capture",
        "policy_version": 1, "tenant_id": "tenant-a", "workload_id": "agent-1",
        "privacy": {"model.exchange.request": "retain_original"},
        "storage": {"backend": "local", "region": "local", "key_id": "kid-1"},
        "retention": {"days": 30}, "required_integrations": [],
        "deployment": {"profile": "local", "image_digest": "local", "tls_required": False,
                       "encrypted_store_required": False},
        "security_context": dict(section),
    }  # fmt: skip


def policy_cases() -> list[dict[str, Any]]:
    full = {
        "control_hosts": [
            {"host": "policy.internal.example", "label": "policy-svc", "control_kind": "policy",
             "decision_pointer": "/decision", "decision_map": [
                 {"value": "ALLOW", "decision": "allow"}, {"value": "DENY", "decision": "deny"},
                 {"value": "REWRITE", "decision": "modify"}, {"value": "ASK", "decision": "escalate"}]},
            {"host": "guard.internal.example:8443", "label": "guard", "control_kind": "guardrail"},
        ],
        "control_addresses": [{"address": "10.0.3.0/24", "label": "policy-svc", "control_kind": "policy"},
                              {"address": "fd00::10", "label": "approvals", "control_kind": "approval"}],
        "hook_programs": [{"path": "/opt/hooks/pre-shell.sh", "label": "pre-shell-check",
                           "exit_map": {"0": "passed", "2": "blocked", "3": "modified", "4": "escalated",
                                        "-1": "errored"}},
                          {"basename": "lint-hook", "label": "linter"}],
        "watched_paths": [
            {"path": "/work/.agent/permissions.json", "match": "exact", "label": "agent-acl", "class": "permission_config"},
            {"path": "/work/.agent/hooks", "match": "prefix", "label": "hooks", "class": "hook_config"},
            {"path": "/work/.agent/skills", "match": "prefix", "label": "skills", "class": "extension_dir"},
            {"path": "/home/agent/.netrc", "match": "exact", "label": "netrc", "class": "credential_file"},
            {"path": "/etc/agent", "match": "prefix", "label": "etc", "class": "other"}],
        "tool_result_markers": [
            {"label": "fs-acl", "prefix": "permission denied", "kind": "permission_check", "decision": "deny",
             "reason_code": "path.outside_root"},
            {"label": "approval-gate", "equals": "approval required", "decision": "escalate"},
            {"label": "json-gate", "json": {"pointer": "/status", "values": ["denied", 403]}}],
        "grant": {"pseudonymise": {"paths": True, "hosts": False, "credentials": True,
                                   "sources": True}},
    }  # fmt: skip
    cases = [
        _case("full security_context", _policy_doc(full), True),
        _case("empty security_context", _policy_doc({}), True),
    ]
    for kind in ("rate_limit", "budget", "other"):
        cases.append(_case(f"control kind {kind}", _policy_doc({"control_hosts": [
            {"host": "x.example", "label": "x", "control_kind": kind}]}), True))  # fmt: skip
    for kind in (
        "guardrail",
        "policy",
        "permission_request",
        "approval",
        "rate_limit",
        "budget",
        "other",
    ):
        cases.append(_case(f"marker kind {kind}", _policy_doc({"tool_result_markers": [
            {"label": "m", "equals": "no", "kind": kind}]}), True))  # fmt: skip
    marker = {"label": "m", "equals": "no"}
    bad = [
        ("marker states allow", {"tool_result_markers": [dict(marker, decision="allow")]}, "a marker never states allow"),
        ("marker with two rules", {"tool_result_markers": [dict(marker, prefix="n")]}, "exactly one matching rule"),
        ("marker without a rule", {"tool_result_markers": [{"label": "m"}]}, "exactly one matching rule"),
        ("marker regex field", {"tool_result_markers": [dict(marker, regex="no.*")]}, "no regular expressions"),
        ("wildcard host", {"control_hosts": [{"host": "*.example", "label": "x", "control_kind": "policy"}]},
         "exact match only"),
        ("pointer without map", {"control_hosts": [{"host": "x.example", "label": "x", "control_kind": "policy",
                                                    "decision_pointer": "/d"}]}, "pointer and map together"),
        ("extract maps unknown", {"control_hosts": [{"host": "x.example", "label": "x", "control_kind": "policy",
                                                     "decision_pointer": "/d",
                                                     "decision_map": [{"value": "x", "decision": "unknown"}]}]},
         "an extracted decision is allow, deny, modify or escalate"),
        ("hook path and basename", {"hook_programs": [{"path": "/a", "basename": "a", "label": "a"}]},
         "path or basename"),
        ("hook exit map outcome", {"hook_programs": [{"basename": "a", "label": "a", "exit_map": {"0": "ok"}}]},
         "hook outcome enum"),
        ("watched relative path", {"watched_paths": [{"path": "work/x", "match": "exact", "label": "x",
                                                      "class": "other"}]}, "absolute paths"),
        ("watch class", {"watched_paths": [{"path": "/x", "match": "exact", "label": "x", "class": "secrets"}]},
         "enum"),
        ("unknown section", {"guardrails": []}, "closed section"),
        ("control kind", {"control_hosts": [{"host": "x.example", "label": "x", "control_kind": "judge"}]}, "enum"),
        ("over 256 entries", {"watched_paths": [{"path": f"/p{i}", "match": "exact", "label": "x", "class": "other"}
                                                for i in range(257)]}, "at most 256 entries"),
    ]  # fmt: skip
    cases += [
        _case(name, _policy_doc(section), False, rule) for name, section, rule in bad
    ]
    return cases


def _case_table(schema: str, cases: list[dict[str, Any]], note: str) -> dict[str, Any]:
    return {"schema_version": CASES, "schema": schema, "note": note, "cases": cases}


def validate_case_table(document: Mapping[str, Any], root: Path, fail: Fail) -> None:
    """Every case validates as stated, and every enum value of the schema's properties
    appears in at least one valid case (a valid fixture for every enum value)."""
    if set(document) != {"schema_version", "schema", "note", "cases"}:
        fail("coverage.vectors.cases", "$", "closed case table")
    schema = json.loads((root / document["schema"]).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    seen: set[str] = set()
    names: set[str] = set()
    for index, case in enumerate(document["cases"]):
        if case["name"] in names:
            fail("coverage.vectors.cases", f"$.cases[{index}]", "duplicate case name")
        names.add(case["name"])
        errors = list(validator.iter_errors(case["document"]))
        if case["valid"] and errors:
            fail("coverage.vectors.cases", f"$.cases[{index}]",
                 f"{case['name']}: valid case rejected: {errors[0].message}")  # fmt: skip
        if not case["valid"] and not errors:
            fail(
                "coverage.vectors.cases",
                f"$.cases[{index}]",
                f"{case['name']}: invalid case accepted",
            )
        if not case["valid"] and not case.get("rule"):
            fail(
                "coverage.vectors.cases",
                f"$.cases[{index}]",
                "an invalid case names its rule",
            )
        if case["valid"]:
            seen |= _strings(case["document"])
    target = schema
    if document["schema"].endswith("deployment-policy-v1.schema.json"):
        target = schema["properties"]["security_context"]
    missing = sorted(_schema_enums(target) - seen)
    if missing:
        fail(
            "coverage.vectors.cases",
            "$.cases",
            f"no valid case for enum values {missing}",
        )


# ===================================================================== grant vectors
def grant_vectors() -> dict[str, Any]:
    jcs_cases = [
        ("member order", {"b": 1, "a": [3, "x"], "c": None}),
        ("utf-16 key order", {"€": 1, "\r": 2, "דּ": 3, "1": 4, "\U0001f600": 5, "\u0080": 6, "ö": 7}),
        ("string escapes", {"s": "line\nbreak\t\"q\" \\ \u0001 \u001f \u007f é \U0001f600"}),
        ("integers", {"n": [0, -1, 9007199254740991]}),
        ("ecmascript numbers", {"n": [1.5, -0.25, 1e21, 1e-7, 0.000001, 123456789.125, 1e30]}),
        ("literals", {"t": True, "f": False, "z": None}),
    ]  # fmt: skip
    jcs_out = [
        {"name": n, "value": v, "canonical": jcs(v).decode("utf-8")}
        for n, v in jcs_cases
    ]
    offered_a = _offered()
    offered_b = copy.deepcopy(offered_a)
    offered_b["tools_offered"].reverse()
    offered_b["tools_offered"].append(copy.deepcopy(offered_b["tools_offered"][0]))
    offered_b["request_ref"] = {"exchange_id": "x-0002", "locator": "/tools"}
    offered_c = copy.deepcopy(offered_a)
    offered_c["tools_offered"] = offered_c["tools_offered"][:1]
    declared = _declared()
    declared_shuffled = copy.deepcopy(declared)
    declared_shuffled["filesystem"]["read"] = ["/work/**", "/work/**"]
    declared_shuffled["tools"]["allow"].reverse()
    digests = []
    for name, doc in [("offered A", offered_a), ("offered A reordered, duplicated, other request", offered_b),
                      ("offered A minus one tool", offered_c), ("declared", declared),
                      ("declared shuffled with a duplicate", declared_shuffled), ("listed", _listed())]:  # fmt: skip
        digest = grant_digest(doc)
        digests.append({"name": name, "document": doc,
                        "normalised_jcs": jcs(normalise_grant(doc)).decode("utf-8"),
                        "digest": digest, "key": KEY1, "grant_id": grant_id(digest, KEY1)})  # fmt: skip
    dedup = [
        {
            "a": "offered A",
            "b": "offered A reordered, duplicated, other request",
            "equal": True,
        },
        {"a": "offered A", "b": "offered A minus one tool", "equal": False},
        {"a": "declared", "b": "declared shuffled with a duplicate", "equal": True},
    ]
    pseudo = []
    for name, groups in [
        ("all groups", {}),
        ("hosts clear", {"hosts": False}),
        ("sources clear", {"sources": False}),
        (
            "nothing",
            {"paths": False, "hosts": False, "credentials": False, "sources": False},
        ),
    ]:
        pseudo.append(
            {
                "name": name,
                "document": declared,
                "key": KEY1,
                "groups": groups,
                "pseudonymised": pseudonymise_grant(declared, KEY1, **groups),
            }
        )
    pseudo.append(
        {
            "name": "listed roots",
            "document": _listed(),
            "key": KEY1,
            "groups": {},
            "pseudonymised": pseudonymise_grant(_listed(), KEY1),
        }
    )
    return {
        "schema_version": GRANT_VECTORS,
        "note": "Spec 057 §5.2, §7.2: JCS (RFC 8785) canonical bytes; grant digests over the "
                "normalised clear document (lists sorted and de-duplicated, request_ref dropped), "
                "so an identical offered set gives one digest whatever the request; keyed grt- ids; "
                "structural pseudonymisation of paths (pth-), hosts (net-), credential names "
                "(crd-) and MCP server_ref launch commands or URLs (src-). The key is a test key.",
        "jcs": jcs_out, "digests": digests, "dedup": dedup, "pseudonymise": pseudo,
    }  # fmt: skip


def validate_grant_vectors(document: Mapping[str, Any], root: Path, fail: Fail) -> None:
    for i, case in enumerate(document["jcs"]):
        if jcs(case["value"]).decode("utf-8") != case["canonical"]:
            fail(
                "coverage.vectors.grant", f"$.jcs[{i}]", f"{case['name']}: JCS differs"
            )
    schema = json.loads((root / COVERAGE / GRANT_SCHEMA).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    by_name = {}
    for i, case in enumerate(document["digests"]):
        if list(validator.iter_errors(case["document"])):
            fail(
                "coverage.vectors.grant",
                f"$.digests[{i}]",
                "document fails the grant schema",
            )
        if (jcs(normalise_grant(case["document"])).decode("utf-8") != case["normalised_jcs"]
                or grant_digest(case["document"]) != case["digest"]
                or grant_id(case["digest"], case["key"]) != case["grant_id"]):  # fmt: skip
            fail(
                "coverage.vectors.grant",
                f"$.digests[{i}]",
                f"{case['name']}: digest or id differs",
            )
        by_name[case["name"]] = case["digest"]
    for i, pair in enumerate(document["dedup"]):
        if (by_name[pair["a"]] == by_name[pair["b"]]) != pair["equal"]:
            fail(
                "coverage.vectors.grant",
                f"$.dedup[{i}]",
                "offered-set de-duplication differs",
            )
    for i, case in enumerate(document["pseudonymise"]):
        got = pseudonymise_grant(case["document"], case["key"], **case["groups"])
        if got != case["pseudonymised"] or list(validator.iter_errors(got)):
            fail(
                "coverage.vectors.grant",
                f"$.pseudonymise[{i}]",
                f"{case['name']}: differs",
            )


# ===================================================================== v1 -> v2 vectors
def observation_vectors() -> dict[str, Any]:
    v1_full = {"control_id": "approval:42", "action_id": "refund-REF-1", "external_policy_id": "refunds",
               "external_policy_version": 3, "external_policy_digest": "sha256:" + SHA,
               "reviewed_artifact_digest": "sha256:" + "4e" * 32, "decision": "requires_review",
               "issuer_id": "policy-svc", "proof_ref": "proof:1"}  # fmt: skip
    cases = []
    for name, v1 in [
        ("v1 requires_review", v1_full),
        ("v1 allow, no proof", dict(v1_full, decision="allow", proof_ref=None)),
        ("v1 deny", dict(v1_full, decision="deny")),
        ("v1 unknown", dict(v1_full, decision="unknown")),
    ]:
        v1_doc = {"schema_version": "fabric.external-control-observation/v1",
                  **{k: v for k, v in sorted(v1.items()) if v is not None},
                  "policy_scope": "external_action_control", "authentication": AUTHENTICATION,
                  "enforcement_performed_by_fabric": False}  # fmt: skip
        cases.append({"name": name, "v1": v1_doc, "v2": observation_v1_to_v2(v1)})
    return {"schema_version": OBS_VECTORS,
            "note": "Spec 052 §4.2.4 (O3-5): v1 documents still load and map to v2: requires_review "
                    "to escalate, phase observation, kind policy, issuer_id to decided_by_id with "
                    "decided_by_type external_service. to_dict() emits v2.",
            "cases": cases}  # fmt: skip


def validate_observation_vectors(
    document: Mapping[str, Any], root: Path, fail: Fail
) -> None:
    schema = json.loads(
        (root / COVERAGE / OBSERVATION_SCHEMA).read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    for i, case in enumerate(document["cases"]):
        v1 = {k: v for k, v in case["v1"].items() if k in V1_FIELDS}
        if observation_v1_to_v2(v1) != case["v2"] or list(
            validator.iter_errors(case["v2"])
        ):
            fail(
                "coverage.vectors.observation",
                f"$.cases[{i}]",
                f"{case['name']}: v2 differs",
            )


# ===================================================================== spec 052 P3 golden records
_UID = "7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e{:02x}"


def _control_record(
    n: int, kind: str, phase: str, decision: str, **attrs: Any
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "fabric.step.kind": "control",
        "fabric.control.id": attrs.pop("control_id", _UID.format(n)),
        "fabric.control.kind": kind, "fabric.control.phase": phase,
        "fabric.control.decision": decision,
        "fabric.control.authentication": AUTHENTICATION,
        "fabric.control.enforced_by_fabric": False,
        "fabric.actor.type": attrs.pop("actor_type", "unknown"),
    }  # fmt: skip
    out.update(attrs)
    return {"attempt_uid": _UID.format(0x80 + n), "attributes": out}


CTL_A = (
    "ctl-" + "a1" * 16
)  # the keyed control id of one clear approval id (cross-process join)


def golden_scenarios() -> list[dict[str, Any]]:
    tool = {
        "attempt_uid": _UID.format(0xF0),
        "attributes": {"fabric.step.kind": "tool_call"},
    }
    return [
        {"scenario": "allow", "records": [tool, _control_record(
            1, "policy", "observation", "allow", **{"fabric.control.gated_step_id": tool["attempt_uid"],
                                                   "fabric.step.links": [f"gates/attempt/{tool['attempt_uid']}"]})],
         "expect": {"decisions": {_UID.format(1): "allow"}, "gates": {_UID.format(1): "resolved"}}},
        {"scenario": "deny-no-step", "records": [
            _control_record(2, "approval", "request", "pending", control_id=CTL_A,
                            **{"fabric.control.action_id": "axn-" + "0d" * 16}),
            _control_record(3, "approval", "resolution", "deny", actor_type="human_approver",
                            **{"fabric.control.resolves": CTL_A, "fabric.control.action_id": "axn-" + "0d" * 16,
                               "fabric.step.links": [f"resolves/external/{CTL_A}"]})],
         "expect": {"resolution_state": {CTL_A: "resolved"}, "gated_step": {_UID.format(3): "absent"}}},
        {"scenario": "modify", "records": [_control_record(4, "guardrail", "observation", "modify")],
         "expect": {"decisions": {_UID.format(4): "modify"}}},
        {"scenario": "pending-resolved-cross-process", "records": [
            _control_record(5, "approval", "request", "pending", control_id=CTL_A),
            dict(_control_record(6, "approval", "resolution", "allow", actor_type="human_approver",
                                 **{"fabric.control.resolves": CTL_A}), process="B")],
         "expect": {"resolution_state": {CTL_A: "resolved"}}},
        {"scenario": "pending-at-end", "records": [
            _control_record(7, "permission_request", "request", "pending", control_id="ctl-" + "b2" * 16)],
         "expect": {"resolution_state": {"ctl-" + "b2" * 16: "pending"}}},
        {"scenario": "revoked", "records": [
            _control_record(8, "approval", "request", "pending", control_id="ctl-" + "c3" * 16),
            _control_record(9, "approval", "resolution", "allow", control_id="ctl-" + "c4" * 16,
                            **{"fabric.control.resolves": "ctl-" + "c3" * 16}),
            _control_record(10, "approval", "revocation", "revoked",
                            **{"fabric.control.resolves": "ctl-" + "c4" * 16})],
         "expect": {"resolution_state": {"ctl-" + "c3" * 16: "revoked"}}},
        {"scenario": "timeout", "records": [
            _control_record(11, "approval", "request", "pending", control_id="ctl-" + "d5" * 16),
            _control_record(12, "approval", "resolution", "timeout", actor_type="system",
                            **{"fabric.control.resolves": "ctl-" + "d5" * 16})],
         "expect": {"decisions": {_UID.format(12): "timeout"}, "actors": {_UID.format(12): "system"},
                    "resolution_state": {"ctl-" + "d5" * 16: "resolved"}}},
        {"scenario": "conflicting-approvers", "records": [
            _control_record(13, "approval", "request", "pending", control_id="ctl-" + "e6" * 16),
            _control_record(14, "approval", "resolution", "allow", **{"fabric.control.resolves": "ctl-" + "e6" * 16}),
            _control_record(15, "approval", "resolution", "deny", **{"fabric.control.resolves": "ctl-" + "e6" * 16})],
         "expect": {"resolution_state": {"ctl-" + "e6" * 16: "conflict"}}},
        {"scenario": "guardrail-observation", "records": [
            _control_record(16, "guardrail", "observation", "deny"), dict(tool)],
         "expect": {"decisions": {_UID.format(16): "deny"}, "executed_after": True}},
    ]  # fmt: skip


def golden_documents() -> dict[str, dict[str, Any]]:
    out = {}
    for scenario in golden_scenarios():
        out[f"fixtures/records/p3/{scenario['scenario']}.json"] = {
            "schema_version": GOLDEN,
            "spec": "052 §7.2 (WP3-0)",
            "scenario": scenario["scenario"],
            "records": scenario["records"],
            "expect": scenario["expect"],
        }
    return out


def validate_golden(
    document: Mapping[str, Any], reg: Mapping[str, Any], fail: Fail
) -> None:
    """Every record attribute is a records-class key whose value passes its check (rule
    A: fabricguard keeps it), and every control record carries both D11 constants."""
    from contracts import validate_coverage_contracts as coverage  # noqa: PLC0415

    checks = coverage.record_checks(reg)
    for i, record in enumerate(document["records"]):
        attrs = record["attributes"]
        for key, value in attrs.items():
            if key not in checks or not coverage.check_value(checks[key], value):
                fail(
                    "coverage.golden.attribute",
                    f"$.records[{i}].{key}",
                    "not admitted by rule A",
                )
        if attrs.get("fabric.step.kind") == "control" and (
            attrs.get("fabric.control.authentication") != AUTHENTICATION
            or attrs.get("fabric.control.enforced_by_fabric") is not False
        ):
            fail(
                "coverage.golden.invariant",
                f"$.records[{i}]",
                "a control record carries D11",
            )


# ===================================================================== provider safety map
def check_safety_map(root: Path, reg: Mapping[str, Any], fail: Fail) -> None:
    doc = json.loads((root / COVERAGE / SAFETY_MAP).read_text(encoding="utf-8"))
    signals, stages = (
        set(_vocab(reg, "control_signal")),
        set(_vocab(reg, "control_stage")),
    )
    seen = set()
    if doc.get("schema_version") != "fabric.provider-safety-map/v1":
        fail("coverage.safety_map", SAFETY_MAP, "schema_version")
    for i, row in enumerate(doc["rows"]):
        where = f"{SAFETY_MAP}:rows[{i}]"
        if set(row) != {
            "id",
            "dialect",
            "field",
            "match",
            "signal",
            "stage",
            "decision",
            "fixture_id",
            "status",
        }:
            fail("coverage.safety_map", where, "closed row")
        if (
            row["id"] in seen
            or row["signal"] not in signals
            or row["stage"] not in stages
        ):
            fail("coverage.safety_map", where, "id, signal or stage")
        if row["decision"] not in ("allow", "deny", "modify") or row["status"] not in (
            "pending_fixture",
            "confirmed",
        ):
            fail(
                "coverage.safety_map",
                where,
                "a map row never yields unknown; status pending_fixture or confirmed",
            )
        if (
            row["status"] == "confirmed"
            and not (root / COVERAGE / row["fixture_id"]).is_file()
        ):
            fail(
                "coverage.safety_map",
                where,
                "a confirmed row names its recorded fixture",
            )
        seen.add(row["id"])


def validate_safety_fixture(
    document: Mapping[str, Any], root: Path, fail: Fail
) -> None:
    """A provider safety-map row's response fixture (spec 057 WP7-5): it names a confirmed
    row of the map and that row's dialect, and lists response cases with the rows each
    projects: at least one case yields the row, at least one (the field absent or benign)
    yields none, and every projected row is a map row of the same dialect with the map's
    signal and stage (``modify`` only where the map allows it). The SDK's dialect rule is
    run against every case by ``sdk/python/tests/test_reconstruct_wire_derivation.py``."""
    rows = {
        row["id"]: row
        for row in json.loads(
            (root / COVERAGE / SAFETY_MAP).read_text(encoding="utf-8")
        )["rows"]
    }
    where = f"fixture {document.get('row_id')}"
    if set(document) != {"schema_version", "row_id", "api", "dialect", "provenance", "source",
                         "note", "request", "cases"}:  # fmt: skip
        fail("coverage.safety_fixture", where, "closed fixture")
    row = rows.get(document["row_id"])
    if (
        row is None
        or row["status"] != "confirmed"
        or row["dialect"] != document["dialect"]
    ):
        fail(
            "coverage.safety_fixture",
            where,
            "names a confirmed map row and its dialect",
        )
    if row["fixture_id"] != f"fixtures/provider-safety/{document['row_id']}.json":
        fail("coverage.safety_fixture", where, "the map row names this fixture")
    if document["provenance"] not in ("recorded", "documented_shape"):
        fail(
            "coverage.safety_fixture", where, "provenance recorded or documented_shape"
        )
    yields = empty = False
    for case in document["cases"]:
        if set(case) - {"name", "response", "stream", "rows"} or not isinstance(
            case["rows"], list
        ):
            fail("coverage.safety_fixture", where, "closed case")
        empty = empty or not case["rows"]
        for item in case["rows"]:
            mapped = rows.get(item.get("row"))
            if (
                mapped is None
                or mapped["dialect"].split("_", 1)[-1]
                != row["dialect"].split("_", 1)[-1]
            ):
                fail(
                    "coverage.safety_fixture",
                    where,
                    "a projected row of the same dialect",
                )
            assert mapped is not None
            decisions = {mapped["decision"], "modify"} if "modify" in mapped["match"] else {
                mapped["decision"]}  # fmt: skip
            if (item["signal"], item["stage"]) != (
                mapped["signal"],
                mapped["stage"],
            ) or (item["decision"] not in decisions):
                fail(
                    "coverage.safety_fixture",
                    where,
                    "signal, stage and decision of the map",
                )
            yields = yields or item["row"] == document["row_id"]
    if not (yields and empty):
        fail(
            "coverage.safety_fixture",
            where,
            "a case with the row and a case without it",
        )


# ===================================================================== dispatch from the validators
def validate_coverage_document(
    document: Mapping[str, Any], reg: Mapping[str, Any], root: Path, fail: Fail
) -> bool:
    kind = document.get("schema_version")
    if kind == CASES:
        validate_case_table(document, root, fail)
    elif kind == GRANT_VECTORS:
        validate_grant_vectors(document, root, fail)
    elif kind == OBS_VECTORS:
        validate_observation_vectors(document, root, fail)
    elif kind == GOLDEN:
        validate_golden(document, reg, fail)
    elif kind == SAFETY_FIXTURE:
        validate_safety_fixture(document, root, fail)
    else:
        return False
    return True


# ===================================================================== activity 2.1.0
def _activity_schema() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    base = json.loads(
        (root / ACTIVITY_V2 / "schema/activity-sequence-v2.schema.json").read_text()
    )
    reg = {
        "vocab": json.loads(
            (root / COVERAGE / "registry/vocabularies-v1.json").read_text()
        )
    }
    s = copy.deepcopy(base)
    s["$id"] = (
        "https://schemas.singleaxis.dev/fabric/activity/v2.1/activity-sequence-v2.1.schema.json"
    )
    s["title"] = "Fabric activity envelope v2.1 conformance sequence"
    s["description"] = (
        "Activity 2.1.0 (spec 057 §5.7): additive beside 2.0.0. version and schema_version accept "
        "2.0.0 and 2.1.0; event_type gains grant.snapshot, control.decision, hook.completed and "
        "extension.loaded; activity gains four optional objects, each required by exactly its event "
        "type and forbidden on every other. A 2.0.0 document is valid under 2.1.0. Producers emit "
        "the four event types only to a destination that declares 2.1.0. Every control object "
        "carries enforced_by_fabric=false and authentication=unverified_caller_report."
    )
    s["properties"]["version"] = {"enum": ["2.0.0", "2.1.0"]}
    env = s["$defs"]["activityEnvelope"]
    env["$anchor"] = "activity-envelope-v2"
    env["properties"]["schema_version"] = {"enum": ["2.0.0", "2.1.0"]}
    env["properties"]["event_type"]["enum"] += ["grant.snapshot", "control.decision",
                                                 "hook.completed", "extension.loaded"]  # fmt: skip
    v = lambda name: _vocab(reg, name)  # noqa: E731
    label = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"}
    version = {
        "type": ["string", "null"],
        "pattern": "^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$",
    }
    reason = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._:-]{0,63}$"}

    def pseudo(prefix: str) -> dict[str, Any]:
        return {"type": "string", "pattern": f"^{prefix}-[0-9a-f]{{32}}$"}

    count = {"type": "integer", "minimum": 0}
    uuid = {"$ref": "#/$defs/uuid"}
    s["$defs"]["controlActivity"] = {
        "type": "object", "additionalProperties": False,
        "required": ["control_id", "kind", "phase", "decision", "derivation", "enforced_by_fabric", "authentication"],
        "properties": {
            "control_id": {"type": "string", "pattern": "^(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|ctl-[0-9a-f]{32})$"},
            "kind": {"enum": v("control_kind")}, "phase": {"enum": ["request", "resolution", "revocation", "observation"]},
            "stage": {"enum": v("control_stage")}, "decision": {"enum": v("control_decision")},
            "signal": {"enum": v("control_signal")}, "derivation": {"enum": v("control_derivation")},
            "mode": {"enum": v("control_mode")}, "error_class": {"enum": v("control_error_class")},
            "engine": {"type": "object", "additionalProperties": False, "required": ["name"],
                       "properties": {"name": label, "version": version}},
            "gated": {"type": "object", "additionalProperties": False, "required": ["kind"],
                      "properties": {"kind": {"enum": v("gated_kind")}, "step_id": {"type": "string", "minLength": 1, "maxLength": 256},
                                     "tool_call_id": pseudo("p"), "action_id": pseudo("axn")}},
            "resolves": {"type": "string", "minLength": 1, "maxLength": 256},
            "grant_id": pseudo("grt"), "latency_ms": {"type": "number", "minimum": 0},
            "reason_code": reason, "evidence_event_ids": {"type": "array", "maxItems": 8, "uniqueItems": True, "items": uuid},
            "assertion_origin": {"enum": ["application", "provider", "service", "human", "unknown"]},
            "enforced_by_fabric": {"const": False}, "authentication": {"const": AUTHENTICATION},
        },
        "allOf": [
            {"if": {"properties": {"kind": {"const": "provider_safety"}}}, "then": {"required": ["signal"]}},
            {"if": {"properties": {"decision": {"const": "error"}}}, "then": {"required": ["error_class"]}},
            {"if": {"properties": {"phase": {"const": "request"}}}, "then": {"properties": {"decision": {"enum": list(MATRIX["request"])}}}},
            {"if": {"properties": {"phase": {"const": "resolution"}}}, "then": {"properties": {"decision": {"enum": list(MATRIX["resolution"])}}}},
            {"if": {"properties": {"phase": {"const": "revocation"}}}, "then": {"properties": {"decision": {"enum": list(MATRIX["revocation"])}}}},
            {"if": {"properties": {"phase": {"const": "observation"}}}, "then": {"properties": {"decision": {"enum": list(MATRIX["observation"])}}}},
        ],
    }  # fmt: skip
    s["$defs"]["grantActivity"] = {
        "type": "object", "additionalProperties": False, "required": ["basis", "trigger", "source_boundary"],
        "properties": {
            "grant_id": pseudo("grt"), "basis": {"enum": v("grant_basis")}, "trigger": {"enum": v("grant_trigger")},
            "previous_id": pseudo("grt"), "source_boundary": {"enum": v("grant_source_boundary")},
            "permission_mode": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$"},
            "execution_mode": {"enum": ["autonomous", "supervised", "approval_required", "read_only", "unknown"]},
            "approval_policy": {"enum": ["none", "per_tool", "per_side_effect", "all", "unknown"]},
            "tool_choice": {"enum": v("tool_choice_mode")}, "sandbox_kind": {"enum": v("sandbox_kind")},
            "network_default": {"enum": ["allow", "deny", "unknown"]},
            "counts": {"type": "object", "additionalProperties": False, "properties": {
                k: count for k in ("tools_allow", "tools_deny", "tools_ask", "tools_offered", "tools_listed",
                                   "mcp_servers", "fs_rules", "net_rules", "credentials", "model_rules")}},
        },
    }  # fmt: skip
    s["$defs"]["hookActivity"] = {
        "type": "object", "additionalProperties": False, "required": ["name", "phase", "basis", "outcome"],
        "properties": {
            "name": label, "phase": {"enum": ["pre_model", "post_model", "pre_tool", "post_tool", "pre_decision", "post_decision"]},
            "basis": {"enum": v("hook_basis")}, "event_name": label, "outcome": {"enum": v("hook_outcome")},
            "modified": {"type": "boolean"}, "exit_code": {"type": "integer", "minimum": -2147483648, "maximum": 2147483647},
            "signal": {"type": "integer", "minimum": 1}, "program_label": label, "gated_tool_call_id": pseudo("p"),
            "extension_id": pseudo("ext"), "reason_code": reason,
            "input_sha256": {"$ref": "#/$defs/sha256"}, "output_sha256": {"$ref": "#/$defs/sha256"},
        },
        "allOf": [{"if": {"properties": {"outcome": {"const": "modified"}}}, "then": {"properties": {"modified": {"const": True}}}}],
    }  # fmt: skip
    s["$defs"]["extensionActivity"] = {
        "type": "object", "additionalProperties": False, "required": ["kind", "observed_via", "signature_status"],
        "properties": {
            "extension_id": pseudo("ext"), "kind": {"enum": v("extension_kind")},
            "name": {"type": "string", "pattern": "^[A-Za-z0-9@][A-Za-z0-9._:/@-]{0,127}$"}, "version": version,
            "source_kind": {"enum": v("extension_source_kind")}, "source_ref": pseudo("src"),
            "manifest_sha256": {"$ref": "#/$defs/sha256"}, "signature_status": {"enum": v("signature_status")},
            "scope": {"enum": v("extension_scope")}, "enabled": {"type": "boolean"},
            "observed_via": {"enum": v("extension_observed_via")},
            "contributes": {"type": "object", "additionalProperties": False, "properties": {
                k: count for k in ("tools", "hooks", "commands", "mcp_servers", "subagents")}},
        },
    }  # fmt: skip
    act = env["properties"]["activity"]
    for name, ref in (
        ("grant", "grantActivity"),
        ("control", "controlActivity"),
        ("hook", "hookActivity"),
        ("extension", "extensionActivity"),
    ):
        act["properties"][name] = {"$ref": f"#/$defs/{ref}"}
    pairs = (
        ("grant.snapshot", "grant"),
        ("control.decision", "control"),
        ("hook.completed", "hook"),
        ("extension.loaded", "extension"),
    )
    rules = []
    for event_type, name in pairs:
        others = [{"required": [o]} for _, o in pairs if o != name]
        rules.append(
            {
                "if": {
                    "properties": {"event_type": {"const": event_type}},
                    "required": ["event_type"],
                },
                "then": {
                    "properties": {
                        "activity": {"required": [name], "not": {"anyOf": others}}
                    }
                },
            }
        )
    rules.append(
        {
            "if": {
                "properties": {"event_type": {"enum": [e for e, _ in pairs]}},
                "required": ["event_type"],
            },
            "then": {"properties": {"schema_version": {"const": "2.1.0"}}},
            "else": {
                "properties": {
                    "activity": {
                        "not": {"anyOf": [{"required": [n]} for _, n in pairs]}
                    }
                }
            },
        }
    )
    env["allOf"] = rules
    return s


def _activity_event(n: int, event_type: str, activity: dict[str, Any], semantics: str = "reported",
                    version: str = "2.1.0") -> dict[str, Any]:  # fmt: skip
    return {
        "contract": "singleaxis.fabric.activity-envelope", "schema_version": version,
        "event_id": f"5b0c1d2e-3f40-4a51-8b62-{n:012x}", "event_type": event_type,
        "identity": {"tenant_id": "tenant-a", "system_id": "support", "agent_id": "agent-1",
                     "deployment_id": "dep-1", "environment": "prod", "release_id": "r-1"},
        "correlation": {"causal_references": []},
        "source": {"source_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", "kind": "sdk",
                   "component": "fabric-python", "component_version": "0.12.1"},
        "original_timestamp": "2026-11-09T10:00:00Z", "source_sequence": n,
        "capture_semantics": semantics, "content": {"mode": "metadata", "classification": "none"},
        "activity": activity,
    }  # fmt: skip


def activity_documents(reg: Mapping[str, Any]) -> dict[str, Any]:
    """The 2.1.0 schema, manifest and fixtures: a valid sequence carrying every enum value
    of the four new objects (and one 2.0.0 event), and invalid cross-type objects."""
    v = lambda name: _vocab(reg, name)  # noqa: E731
    inv = {"enforced_by_fabric": False, "authentication": AUTHENTICATION}
    events: list[dict[str, Any]] = []

    def add(
        event_type: str, activity: dict[str, Any], semantics: str = "reported"
    ) -> None:
        events.append(_activity_event(len(events), event_type, activity, semantics))

    events.append(
        _activity_event(0, "tool.request", {"outcome": "requested"}, version="2.0.0")
    )
    ctl = lambda **x: {"control_id": "ctl-" + "a1" * 16, "kind": "policy", "phase": "observation",  # noqa: E731
                       "decision": "deny", "derivation": "reported", **inv, **x}  # fmt: skip
    for phase, decisions in MATRIX.items():
        for decision in decisions:
            extra = {"error_class": "exception"} if decision == "error" else {}
            add(
                "control.decision",
                {
                    "outcome": "succeeded",
                    "control": ctl(phase=phase, decision=decision, **extra),
                },
            )
    for kind in v("control_kind"):
        extra = {"signal": "refusal"} if kind == "provider_safety" else {}
        add(
            "control.decision",
            {"outcome": "succeeded", "control": ctl(kind=kind, **extra)},
        )
    for name in (
        "control_stage",
        "control_signal",
        "control_derivation",
        "control_mode",
    ):
        field = name.split("_", 1)[1]
        for value in v(name):
            extra: dict[str, Any] = {field: value}
            if field == "signal":
                extra["kind"] = "provider_safety"
            add("control.decision", {"outcome": "succeeded", "control": ctl(**extra)})
    for value in v("control_error_class"):
        add(
            "control.decision",
            {
                "outcome": "succeeded",
                "control": ctl(decision="error", error_class=value),
            },
        )
    for value in v("gated_kind"):
        add(
            "control.decision",
            {"outcome": "succeeded", "control": ctl(gated={"kind": value})},
        )
    add("control.decision", {"outcome": "succeeded", "control": ctl(
        kind="provider_safety", stage="output", signal="content_filter", derivation="literal",
        engine={"name": "azure-openai-prod", "version": None}, gated={"kind": "model_call", "step_id": "stp-1"},
        evidence_event_ids=["7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e31"], assertion_origin="provider",
        reason_code="violence")}, "observed")  # fmt: skip
    for origin in ("application", "service", "human", "unknown"):
        add(
            "control.decision",
            {"outcome": "succeeded", "control": ctl(assertion_origin=origin)},
        )
    grant = lambda **x: {"grant_id": "grt-" + "41" * 16, "basis": "declared", "trigger": "run_start",  # noqa: E731
                         "source_boundary": "api", **x}  # fmt: skip
    for name, field in (("grant_basis", "basis"), ("grant_trigger", "trigger"),
                        ("grant_source_boundary", "source_boundary"), ("tool_choice_mode", "tool_choice"),
                        ("sandbox_kind", "sandbox_kind")):  # fmt: skip
        for value in v(name):
            add(
                "grant.snapshot",
                {"outcome": "succeeded", "grant": grant(**{field: value})},
            )
    for value in ("allow", "deny", "unknown"):
        add(
            "grant.snapshot",
            {"outcome": "succeeded", "grant": grant(network_default=value)},
        )
    for value in (
        "autonomous",
        "supervised",
        "approval_required",
        "read_only",
        "unknown",
    ):
        add(
            "grant.snapshot",
            {"outcome": "succeeded", "grant": grant(execution_mode=value)},
        )
    for value in ("none", "per_tool", "per_side_effect", "all", "unknown"):
        add(
            "grant.snapshot",
            {"outcome": "succeeded", "grant": grant(approval_policy=value)},
        )
    add("grant.snapshot", {"outcome": "succeeded", "grant": grant(
        previous_id="grt-" + "40" * 16, permission_mode="ask_on_write",
        counts={"tools_allow": 2, "tools_deny": 1, "credentials": 1})})  # fmt: skip

    def hook(**x):
        return {
            "name": "pre-shell",
            "phase": "pre_tool",
            "basis": "process",
            "outcome": "passed",
            **x,
        }

    for value in v("hook_outcome"):
        extra = {"modified": True} if value == "modified" else {}
        add(
            "hook.completed",
            {"outcome": "succeeded", "hook": hook(outcome=value, **extra)},
        )
    for value in v("hook_basis"):
        add("hook.completed", {"outcome": "succeeded", "hook": hook(basis=value)})
    for value in (
        "pre_model",
        "post_model",
        "post_tool",
        "pre_decision",
        "post_decision",
    ):
        add("hook.completed", {"outcome": "succeeded", "hook": hook(phase=value)})
    add("hook.completed", {"outcome": "succeeded", "hook": hook(
        exit_code=2, outcome="blocked", program_label="pre-shell-check", gated_tool_call_id="p-" + "0f" * 16,
        extension_id="ext-" + "1b" * 16, reason_code="shell.blocked", event_name="PreToolUse",
        input_sha256="3f" * 32, output_sha256="3f" * 32)}, "observed")  # fmt: skip
    ext = lambda **x: {"extension_id": "ext-" + "1b" * 16, "kind": "mcp_server", "observed_via": "reported",  # noqa: E731
                       "signature_status": "unknown", **x}  # fmt: skip
    for name, field in (
        ("extension_kind", "kind"),
        ("extension_source_kind", "source_kind"),
        ("signature_status", "signature_status"),
        ("extension_scope", "scope"),
        ("extension_observed_via", "observed_via"),
    ):
        for value in v(name):
            add(
                "extension.loaded",
                {"outcome": "succeeded", "extension": ext(**{field: value})},
            )
    add("extension.loaded", {"outcome": "succeeded", "extension": ext(
        name="repo-tools", version="1.4.0", source_ref="src-" + "3a" * 16, manifest_sha256="3f" * 32,
        enabled=True, contributes={"tools": 3, "hooks": 0})}, "observed")  # fmt: skip
    for i, event in enumerate(events):
        event["source_sequence"] = i
        event["event_id"] = f"5b0c1d2e-3f40-4a51-8b62-{i:012x}"
    valid = {
        "contract": "singleaxis.fabric.activity-sequence",
        "version": "2.1.0",
        "sequence_id": "0c1d2e3f-4051-4627-8839-4a5b6c7d8e9f",
        "events": events,
    }

    def seq(*evs: dict[str, Any]) -> dict[str, Any]:
        return {
            "contract": "singleaxis.fabric.activity-sequence",
            "version": "2.1.0",
            "sequence_id": "0c1d2e3f-4051-4627-8839-4a5b6c7d8e9f",
            "events": list(evs),
        }

    g = {"outcome": "succeeded", "grant": grant()}
    c = {"outcome": "succeeded", "control": ctl()}
    h = {"outcome": "succeeded", "hook": hook()}
    x = {"outcome": "succeeded", "extension": ext()}
    invalid = {
        "invalid/control-decision-carries-grant.json": seq(_activity_event(0, "control.decision", {**c, "grant": g["grant"]})),
        "invalid/grant-snapshot-without-grant.json": seq(_activity_event(0, "grant.snapshot", {"outcome": "succeeded"})),
        "invalid/hook-completed-carries-control.json": seq(_activity_event(0, "hook.completed", {**h, "control": c["control"]})),
        "invalid/extension-loaded-carries-hook.json": seq(_activity_event(0, "extension.loaded", {**x, "hook": h["hook"]})),
        "invalid/tool-request-carries-extension.json": seq(_activity_event(0, "tool.request", {"outcome": "requested", "extension": x["extension"]})),
        "invalid/control-decision-as-2.0.0.json": seq(_activity_event(0, "control.decision", c, version="2.0.0")),
        "invalid/control-forged-enforcement.json": seq(_activity_event(0, "control.decision", {"outcome": "succeeded", "control": ctl(enforced_by_fabric=True)})),
        "invalid/control-request-allow.json": seq(_activity_event(0, "control.decision", {"outcome": "succeeded", "control": ctl(phase="request", decision="allow")})),
    }  # fmt: skip
    schema = _activity_schema()
    files: dict[str, Any] = {
        "schema/activity-sequence-v2.1.schema.json": schema,
        "valid/security-context-sequence.json": valid,
    }
    files.update(invalid)
    return files


ACTIVITY_INVALID_ERROR = "data-plane.schema.invalid"


def activity_manifest(files: Mapping[str, bytes]) -> str:
    rows = []
    for rel in sorted(
        files,
        key=lambda r: (not r.startswith("schema/"), not r.startswith("valid/"), r),
    ):
        expectation = rel.split("/", 1)[0].rstrip("/")
        expectation = {"schema": "schema", "valid": "valid", "invalid": "invalid"}[
            expectation
        ]
        role = {"schema": "activity-schema", "valid": "valid-" + Path(rel).stem,
                "invalid": "invalid-" + Path(rel).stem}[expectation]  # fmt: skip
        row = {"path": rel, "role": role, "sha256": hashlib.sha256(files[rel]).hexdigest(),
               "expectation": expectation}  # fmt: skip
        if expectation == "invalid":
            row["expected_error"] = ACTIVITY_INVALID_ERROR
        rows.append("    " + json.dumps(row))
    return ('{\n  "contract": "singleaxis.fabric.activity",\n  "version": "2.1.0",\n'
            '  "digest_scope": "exact_file_bytes",\n  "artifacts": [\n' + ",\n".join(rows) + "\n  ]\n}\n")  # fmt: skip


# ===================================================================== capture/v1 fixtures
def _profile(**extra: Any) -> dict[str, Any]:
    doc = {
        "schema_version": "fabric.otlp-mapping-profile/v1", "profile_id": "example-gateway",
        "profile_version": 1, "unmapped": "drop",
        "rules": [{
            "match": {"span_name": "gateway.policy_check", "attributes": {"gateway.kind": "policy"}},
            "record": "control", "assertion_origin": "service",
            "map": [
                {"source": "gateway.verdict", "target": "fabric.control.decision",
                 "values": [{"from": "PASS", "to": "allow"}, {"from": "BLOCK", "to": "deny"}]},
                {"source": "gateway.policy_name", "target": "fabric.control.engine.name"},
                {"source": "gateway.call_id", "target": "fabric.control.gated_tool_call_id",
                 "pseudonymise": "provider"},
                {"source": "gateway.ms", "target": "fabric.control.latency_ms"},
            ],
            "set": [{"target": "fabric.control.kind", "value": "policy"},
                    {"target": "fabric.control.derivation", "value": "reported"}],
        }],
    }  # fmt: skip
    doc.update(extra)
    return doc


def capture_documents(base_report: Mapping[str, Any]) -> dict[str, Any]:
    report = copy.deepcopy(dict(base_report))
    run = report["runs"][0]
    run.setdefault("chains", {"decisions": {"verdict": "complete"}, "actions": {"verdict": "not_observed"},
                              "effects": {"verdict": "not_observed"},
                              "corroboration": {"verdict": "not_observed"}})  # fmt: skip
    run["chains"]["controls"] = {
        "verdict": "partial",
        "reasons": ["ambiguous_attribution", "control_pending_at_end"],
    }
    run["verdict"] = "partial"  # spec 057 §6.4: a partial controls chain bounds the run
    run["security_context"] = {
        "grants": {"offered": 2, "listed": 1, "declared": 1},
        "controls": [{"kind": "permission_check", "decision": "deny", "derivation": "wrapped_check", "count": 2},
                     {"kind": "approval", "decision": "pending", "derivation": "reported", "count": 1}],
        "control_links": {"pending_single": 1, "pending_set": 1, "ref_join": 1},
        "hooks": [{"basis": "process", "outcome": "blocked", "count": 1}],
        "extensions": [{"kind": "mcp_server", "observed_via": "mcp_initialize", "signature_status": "unknown", "count": 1}],
        "facts": [{"code": "control_pending_at_end", "count": 1, "event_ids": ["7d444840-9dc0-4a1f-9c1e-2b8a6f0d5e31"]},
                  {"code": "tool_called_not_offered", "count": 1, "event_ids": ["0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a01"]}],
    }  # fmt: skip
    bad_reason = copy.deepcopy(report)
    bad_reason["runs"][0]["chains"]["controls"] = {
        "verdict": "partial",
        "reasons": ["policy_violation"],
    }
    bad_fact = copy.deepcopy(report)
    bad_fact["runs"][0]["security_context"]["facts"] = [
        {"code": "violation", "count": 1, "event_ids": []}
    ]
    # Spec 057 §6.4 (WP7-2): the run verdict ignores a partial controls chain; a
    # fact-backed reason without its fact.
    unbounded = copy.deepcopy(report)
    unbounded["runs"][0]["verdict"] = "complete_for_observed_scopes"
    unbacked = copy.deepcopy(report)
    unbacked["runs"][0]["chains"]["controls"]["reasons"].append("control_unmatched")
    invariant = _profile()
    invariant["rules"][0]["set"].append(
        {"target": "fabric.control.enforced_by_fabric", "value": False}
    )
    keep = _profile(unmapped="keep")
    clear_id = _profile()
    del clear_id["rules"][0]["map"][2]["pseudonymise"]
    return {
        "fixtures/valid/otlp-mapping-profile-example.json": _profile(),
        "fixtures/invalid/otlp-mapping-profile-invariant-target.json": invariant,
        "fixtures/invalid/otlp-mapping-profile-keeps-unmapped.json": keep,
        "fixtures/invalid/otlp-mapping-profile-clear-identifier.json": clear_id,
        "fixtures/valid/run-reconstruction-security-context.json": report,
        "fixtures/invalid/run-reconstruction-controls-unknown-reason.json": bad_reason,
        "fixtures/invalid/run-reconstruction-security-context-unknown-fact.json": bad_fact,
        "fixtures/invalid/run-reconstruction-controls-unbounded-verdict.json": unbounded,
        "fixtures/invalid/run-reconstruction-controls-reason-without-fact.json": unbacked,
    }


INVALID_CAPTURE = {
    "fixtures/invalid/otlp-mapping-profile-invariant-target.json": "capture.schema",
    "fixtures/invalid/otlp-mapping-profile-keeps-unmapped.json": "capture.schema",
    "fixtures/invalid/otlp-mapping-profile-clear-identifier.json": "capture.mapping_profile.identity",
    "fixtures/invalid/run-reconstruction-controls-unknown-reason.json": "capture.schema",
    "fixtures/invalid/run-reconstruction-security-context-unknown-fact.json": "capture.schema",
    "fixtures/invalid/run-reconstruction-controls-unbounded-verdict.json": "capture.reconstruction.verdict",
    "fixtures/invalid/run-reconstruction-controls-reason-without-fact.json": "capture.reconstruction.chains",
}
INVALID_COVERAGE: dict[str, str] = {}


# ===================================================================== generation entry point
def generate(put_text: Callable[[Path, str], None], read_json: Callable[[Path], Any],
             registries: Mapping[str, Any]) -> None:  # fmt: skip
    """Write every spec 057 WP7-0 / spec 052 WP3-0 derived artifact."""
    reg = registries

    def put(path: Path, document: Any) -> None:
        put_text(path, json.dumps(document, indent=2, ensure_ascii=False) + "\n")

    put(COVERAGE / "fixtures/vectors/grant-snapshot-v1.json", grant_vectors())
    put(
        COVERAGE / "fixtures/vectors/control-observation-v1-v2.json",
        observation_vectors(),
    )
    put(COVERAGE / "fixtures/vectors/schema-cases-grant-snapshot-v1.json", _case_table(
        "contracts/coverage/v1/" + GRANT_SCHEMA, grant_cases(),
        "Spec 057 §5.2: a valid case for every enum value and an invalid case for every "
        "required-by-basis rule of the grant document."))  # fmt: skip
    put(COVERAGE / "fixtures/vectors/schema-cases-control-observation-v2.json", _case_table(
        "contracts/coverage/v1/" + OBSERVATION_SCHEMA, observation_cases(reg),
        "Spec 052 §4.2.2/§4.2.4, spec 057 §5.3: every phase x decision cell, every kind, stage, "
        "gated kind, mode, error class, signal and derivation; the required-by-kind rules "
        "(provider_safety signal, error error_class, derived-row evidence) and the D11 constants."))  # fmt: skip
    put(COVERAGE / "fixtures/vectors/schema-cases-deployment-policy-security-context.json", _case_table(
        POLICY_SCHEMA.as_posix(), policy_cases(),
        "Spec 057 §8: the capture-policy security_context section (exact-match classification "
        "lists; denial markers never state allow)."))  # fmt: skip
    for rel, document in golden_documents().items():
        put(COVERAGE / rel, document)
    base = read_json(CAPTURE / "fixtures/valid/run-reconstruction-attempts.json")
    for rel, document in capture_documents(base).items():
        put(CAPTURE / rel, document)
    files = {rel: (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode()
             for rel, doc in activity_documents(reg).items()}  # fmt: skip
    for rel, content in files.items():
        put_text(ACTIVITY / rel, content.decode())
    put_text(ACTIVITY / "manifest.json", activity_manifest(files))
