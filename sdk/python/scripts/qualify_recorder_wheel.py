#!/usr/bin/env python3
"""Qualify an exact Python recorder wheel or source distribution."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

FORBIDDEN_MEMBERS = {
    "fabric/_chain.py",
    "fabric/_uds.py",
    "fabric/cli.py",
    "fabric/deployment.py",
    "fabric/escalation.py",
    "fabric/eval.py",
    "fabric/guardrails.py",
    "fabric/judge.py",
    "fabric/judge_runner.py",
    "fabric/nemo.py",
    "fabric/policy.py",
    "fabric/presidio.py",
    "fabric/stream.py",
    "fabric/tool_auth.py",
    "fabric/adapters/agent_framework.py",
    "fabric/adapters/langgraph.py",
}
FORBIDDEN_PREFIXES = (
    "fabric/guardrail_adapters/",
    "fabric/judge_adapters/",
    "fabric/policy_adapters/",
    "fabric/queue_transports/",
)
FORBIDDEN_EXTRAS = {
    "agent-framework",
    "aws",
    "cedar",
    "crewai",
    "deepeval",
    "lakera",
    "langgraph",
    "nats",
    "opa",
    "ragas",
    "redis",
}
FORBIDDEN_ROOT_SYMBOLS = {
    "CedarAdapter",
    "CheckerVerdict",
    "DeepEvalJudge",
    "DrainableTransport",
    "EngineVerdict",
    "EntitySummary",
    "EscalationMode",
    "EscalationRequested",
    "EscalationSummary",
    "EvalRecord",
    "GuardrailAction",
    "GuardrailBlocked",
    "GuardrailChecker",
    "GuardrailError",
    "GuardrailNotConfiguredError",
    "GuardrailPhase",
    "GuardrailResult",
    "GuardrailSnapshot",
    "HTTPGuardrailChecker",
    "HTTPPolicyAdapter",
    "JudgeContext",
    "JudgeRequest",
    "JudgeRunner",
    "JudgeWorker",
    "LakeraGuardChecker",
    "LocalQueueTransport",
    "NATSQueueTransport",
    "NemoAction",
    "NemoClient",
    "NemoError",
    "NemoResult",
    "PolicyAdapterError",
    "PolicyDecision",
    "PolicyDecisionSnapshot",
    "PolicyEngine",
    "PolicyEvaluation",
    "PresidioClient",
    "QueueTransport",
    "RagasJudge",
    "RedactionError",
    "RedactionResult",
    "RedisStreamTransport",
    "SQSQueueTransport",
    "ScoreParseError",
    "SimpleLLMJudge",
    "StreamRedactor",
    "ToolAuthorization",
    "ToolAuthorizer",
    "ToolAuthorizerError",
    "ToolCallDenied",
    "ToolCallSnapshot",
    "UDSNemoClient",
    "UDSPresidioClient",
}
FORBIDDEN_DECISION_METHODS = {
    "aauthorize_tool_call",
    "aevaluate_policy",
    "aguard_input",
    "aguard_output_chunk",
    "aguard_output_final",
    "aqueue_judge",
    "authorize_tool_call",
    "evaluate_policy",
    "guard_input",
    "guard_output_chunk",
    "guard_output_final",
    "queue_judge",
    "raise_for_block",
    "raise_for_escalation",
    "record_block",
    "record_eval",
    "request_escalation",
}


def _canonical_member(name: str) -> str:
    """Map wheel and sdist package paths to one comparable namespace."""
    marker = "/src/fabric/"
    if marker in name:
        return "fabric/" + name.split(marker, maxsplit=1)[1]
    if name.startswith("fabric/"):
        return name
    return name


def _read_artifact(path: Path) -> tuple[list[str], dict[str, bytes], str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            payloads = {name: archive.read(name) for name in names if not name.endswith("/")}
        return names, payloads, "wheel"
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if any(member.issym() or member.islnk() for member in members):
                raise ValueError("sdist contains a symbolic or hard link")
            names = [member.name for member in members]
            tar_payloads: dict[str, bytes] = {}
            for member in members:
                if not member.isfile():
                    continue
                handle = archive.extractfile(member)
                if handle is None:  # pragma: no cover - tarfile invariant
                    raise ValueError(f"unable to read sdist member: {member.name}")
                tar_payloads[member.name] = handle.read()
        return names, tar_payloads, "sdist"
    raise ValueError("artifact must be a .whl or .tar.gz file")


def qualify(path: Path) -> dict[str, object]:
    artifact_bytes = path.read_bytes()
    members, payloads, kind = _read_artifact(path)
    if len(members) != len(set(members)):
        raise ValueError(f"{kind} contains duplicate archive members")
    if any(
        PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts for name in members
    ):
        raise ValueError(f"{kind} contains an unsafe archive path")

    canonical_payloads = {_canonical_member(name): data for name, data in payloads.items()}
    canonical_members = {_canonical_member(name) for name in members}
    required = {"fabric/__init__.py", "fabric/client.py", "fabric/decision.py"}
    missing = required.difference(canonical_members)
    if missing:
        raise ValueError(f"{kind} is missing recorder modules: {sorted(missing)}")
    forbidden = sorted(
        name
        for name in canonical_members
        if name in FORBIDDEN_MEMBERS or name.startswith(FORBIDDEN_PREFIXES)
    )
    if forbidden:
        raise ValueError(f"{kind} contains excluded legacy modules: {forbidden}")
    if any(name.endswith(".dist-info/entry_points.txt") for name in members):
        raise ValueError("recorder SDK artifact must not publish a console entry point")

    metadata_names = [
        name for name in members if name.endswith((".dist-info/METADATA", "/PKG-INFO"))
    ]
    if kind == "wheel":
        metadata_names = [name for name in metadata_names if name.endswith(".dist-info/METADATA")]
    if len(metadata_names) != 1:
        raise ValueError(f"{kind} must contain exactly one package metadata file")
    metadata = BytesParser().parsebytes(payloads[metadata_names[0]])
    extras = set(metadata.get_all("Provides-Extra", []))
    leaked_extras = sorted(FORBIDDEN_EXTRAS.intersection(extras))
    if leaked_extras:
        raise ValueError(f"{kind} publishes legacy capability extras: {leaked_extras}")

    package_root = canonical_payloads["fabric/__init__.py"].decode("utf-8")
    leaked_symbols = sorted(
        symbol
        for symbol in FORBIDDEN_ROOT_SYMBOLS
        if re.search(rf'^[ ]*"{re.escape(symbol)}",?$', package_root, re.MULTILINE)
    )
    if leaked_symbols:
        raise ValueError(f"{kind} package root exports legacy symbols: {leaked_symbols}")

    decision = canonical_payloads["fabric/decision.py"].decode("utf-8")
    leaked_methods = sorted(
        method
        for method in FORBIDDEN_DECISION_METHODS
        if re.search(rf"^[ ]+def {re.escape(method)}\(", decision, re.MULTILINE)
        or re.search(rf"^[ ]+async def {re.escape(method)}\(", decision, re.MULTILINE)
    )
    if leaked_methods:
        raise ValueError(f"{kind} Decision publishes legacy methods: {leaked_methods}")

    return {
        "schema_version": "fabric.python-recorder-artifact-qualification/v1",
        "artifact_kind": kind,
        "filename": path.name,
        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "size": len(artifact_bytes),
        "member_count": len(members),
        "qualified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    print(json.dumps(qualify(args.artifact), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
