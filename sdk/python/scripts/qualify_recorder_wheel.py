#!/usr/bin/env python3
"""Check critical module presence and scope boundaries in an exact SDK archive.

This structural qualification does not execute the artifact or prove that its
module contents work. Installed-artifact smoke tests remain a separate gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
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
    "fabric/capture_capabilities.py",
    "fabric/adapters/agent_framework.py",
    "fabric/adapters/crewai.py",
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
# Spec 047 wire capture: the env-gated autoload ships only as
# fabric/_autoload/sitecustomize.py. Anything Python would execute merely
# because the package is installed (a *.pth file, or a sitecustomize /
# usercustomize module reachable from site-packages) is forbidden.
AUTOLOAD_MEMBER = "fabric/_autoload/sitecustomize.py"
STARTUP_HOOK_NAMES = {"sitecustomize.py", "usercustomize.py"}
# Spec 048 F1: only the Fabric Node writes content to cloud stores, so the
# capture path (tee, spool, sender, content client, sequencing, loss) never
# imports a cloud SDK. fabric.reconstruct and S3ContentStore keep boto3 lazy.
CAPTURE_MEMBER_PREFIXES = ("fabric/wire/", "fabric/_autoload/")
CAPTURE_MEMBERS = {"fabric/_loss.py", "fabric/_sequence.py", "fabric/_model_names.py"}
CLOUD_SDK_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+(?:boto3|botocore|aiobotocore)\b"
    r"|import_module\(\s*[\"'](?:boto3|botocore|aiobotocore)\b",
    re.MULTILINE,
)

# Run in a fresh interpreter against the extracted artifact: importing
# fabric and fabric.wire must patch nothing, start no thread, import
# neither httpx/httpx2, the tee transport, the spool/sender/content client,
# requests, the OTLP protos nor a cloud SDK, and never trigger the autoload
# — even with FABRIC_WIRE_AUTOLOAD=1 set.
_IMPORT_PROBE = """
import json, os, sys, threading
root = os.path.realpath(sys.argv[1])
sys.path.insert(0, root)
threads = threading.active_count()
import fabric
import fabric.wire
problems = []
if not os.path.realpath(fabric.__file__).startswith(root + os.sep):
    problems.append("fabric was not imported from the artifact")
for name in ("httpx", "httpx2", "fabric._autoload", "fabric._autoload.sitecustomize",
             "fabric.wire._transport", "fabric.reconstruct", "fabric.wire._spool",
             "fabric.wire._sender", "fabric.wire._content", "requests",
             "opentelemetry.proto", "boto3", "botocore"):
    if name in sys.modules:
        problems.append("import fabric/fabric.wire loaded " + name)
if threading.active_count() != threads:
    problems.append("import fabric/fabric.wire started a thread")
if fabric.wire.current_handle() is not None:
    problems.append("import fabric.wire installed the wire tee")
import importlib
for flavor in ("httpx", "httpx2"):
    try:
        module = importlib.import_module(flavor)
    except ImportError:
        continue
    for method in (module.HTTPTransport.handle_request,
                   module.AsyncHTTPTransport.handle_async_request):
        if getattr(method, "__fabric_wire_patch__", False):
            problems.append(flavor + " transport is patched after import")
print(json.dumps(problems))
"""

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


def _probe_imports(path: Path, kind: str) -> None:
    """Import the extracted artifact in a fresh interpreter (see ``_IMPORT_PROBE``)."""
    with tempfile.TemporaryDirectory(prefix="fabric-qualify-") as scratch:
        root = Path(scratch)
        if kind == "wheel":
            with zipfile.ZipFile(path) as archive:
                archive.extractall(root)  # noqa: S202 - member paths validated above
        else:
            with tarfile.open(path, mode="r:gz") as archive:
                archive.extractall(root, filter="data")
        package_roots = sorted(init.parent.parent for init in root.rglob("fabric/__init__.py"))
        if len(package_roots) != 1:
            raise ValueError(f"{kind} must contain exactly one fabric package")
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("FABRIC_", "PYTHON"))
        }
        env["FABRIC_WIRE_AUTOLOAD"] = "1"
        result = subprocess.run(  # noqa: S603 - fixed interpreter, fixed probe
            [sys.executable, "-c", _IMPORT_PROBE, str(package_roots[0])],
            capture_output=True,
            text=True,
            env=env,
            cwd=scratch,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError(f"{kind} import probe failed: {result.stderr.strip()[-2000:]}")
        problems = json.loads(result.stdout.strip().splitlines()[-1])
        if problems:
            raise ValueError(f"{kind} import has side effects: {problems}")


def _check_capture_imports(payloads: dict[str, bytes], kind: str) -> None:
    """Spec 048 F1: no wire-capture module imports a cloud SDK."""
    cloud_imports = sorted(
        name
        for name, data in payloads.items()
        if name.endswith(".py")
        and (name.startswith(CAPTURE_MEMBER_PREFIXES) or name in CAPTURE_MEMBERS)
        and CLOUD_SDK_IMPORT.search(data.decode("utf-8", "replace"))
    )
    if cloud_imports:
        raise ValueError(f"{kind} wire capture imports a cloud SDK: {cloud_imports}")


def qualify(path: Path, *, import_probe: bool = True) -> dict[str, object]:
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
    # The governed-content surface ships in every release artifact — a
    # package missing these modules is not a qualified recorder build.
    required = {
        "fabric/__init__.py",
        "fabric/client.py",
        "fabric/decision.py",
        "fabric/_content.py",
        "fabric/_content_sink.py",
        "fabric/_content_writer.py",
        "fabric/content_store/__init__.py",
        "fabric/content_store/base.py",
        "fabric/content_store/local.py",
        "fabric/content_store/s3.py",
        "fabric/resolver.py",
        "fabric/adapters/byte_boundary.py",
        "fabric/byte_evidence.py",
        "fabric/byte_resolver.py",
        "fabric/byte_spool.py",
        "fabric/call_recorder.py",
        "fabric/call_otlp.py",
        "fabric/source_spool.py",
        "fabric/metadata_delivery.py",
        "fabric/content_join.py",
        "fabric/deployment_policy.py",
        "fabric/governed_store.py",
        "fabric/governed_reconstruction.py",
        # Spec 047 §12.7: the wire tee and its env-gated autoload ship.
        "fabric/wire/__init__.py",
        "fabric/_autoload/__init__.py",
        AUTOLOAD_MEMBER,
        # Spec 048: node-mode spool, sender, content client, model exposure.
        "fabric/wire/_spool.py",
        "fabric/wire/_sender.py",
        "fabric/wire/_content.py",
        "fabric/_loss.py",
        "fabric/_sequence.py",
        "fabric/_model_names.py",
        # D2 coexistence: the explicit-wins flag both capture lines share.
        "fabric/_capture_scope.py",
    }
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
    startup_hooks = sorted(
        name
        for name in members
        if name.endswith(".pth")
        or (
            PurePosixPath(name).name in STARTUP_HOOK_NAMES
            and _canonical_member(name) != AUTOLOAD_MEMBER
        )
    )
    if startup_hooks:
        raise ValueError(f"{kind} contains interpreter startup hooks: {startup_hooks}")
    _check_capture_imports(canonical_payloads, kind)
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

    if import_probe:
        _probe_imports(path, kind)

    return {
        "schema_version": "fabric.python-recorder-artifact-qualification/v1",
        "artifact_kind": kind,
        "filename": path.name,
        "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "size": len(artifact_bytes),
        "member_count": len(members),
        "qualified": True,
        "qualification_scope": "critical_module_presence_and_legacy_exclusion",
        "runtime_behavior_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument(
        "--no-import-probe",
        action="store_true",
        help="skip importing the extracted artifact (content checks only)",
    )
    args = parser.parse_args()
    result = qualify(args.artifact, import_probe=not args.no_import_probe)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
