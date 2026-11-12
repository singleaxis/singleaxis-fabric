# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 boundary rules B1-B9 (§2.1) and the no-auto-wrapping rule (§4.10.3), WP7-3.

Each rule has its enforcing test here or names the suite that holds it:

- **B1 record only.** No records API returns a decision value (its handle carries ids and
  ``recorded`` only); an AST scan of every module spec 057 added finds no ``sleep``,
  ``wait``, ``Event``, ``Condition``, thread ``join`` or blocking queue ``put``.
- **B2 same object back.** The ``control_check`` wrapper returns the check's value and
  re-raises its exception by identity (sync, ``async`` and context manager); no module on
  the request path imports the reader, and recording never loads it.
- **B3 capture failure never reaches the agent.** Every spec 057 records API under a
  recorder that raises, a capture queue whose blocking ``put`` would wait, and a full
  queue: no exception, no wait.
- **B4 latency.** ``test_records_passivity.py`` (every records API, on and off, with the
  blocking control).
- **B5 invariants.** ``enforced_by_fabric`` and ``authentication`` are constants: no
  records API takes them, and every control record of every path carries both.
- **B6 no evaluation in the reader.** The word scan over every string the reader can
  print (its source literals) and over every reader golden.
- **B7 no control artifact.** ``scripts/tests/test_recorder_release_boundary.py`` (the
  new module paths and package metadata, and no mapping profile or classification list
  in any artifact).
- **B8 opt-in.** No spec 057 capture point, classification list or derivation is active
  in a default install; the records points stay off the published manifest (§9.1).
- **B9 no framework dependency.** The import graph of the new modules (stdlib and
  ``fabric`` only), the capture-point name pattern, and no framework, agent SDK or
  guardrail library name in a 057 module, identifier or test file name.
- **No auto-wrapping.** Importing and autoloading Fabric, and using every records API,
  leaves every attribute of a fixture application module identical; the SDK has no import
  hook, ``sys.setprofile``/``settrace`` call, stack inspection or name-based matching.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import time
import traceback
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import fabric._rec_check as rec_check
import fabric._rec_controls as rec_controls
import fabric._rec_extension as rec_extension
import fabric._rec_grant as rec_grant
import fabric._rec_run as rec_run
from fabric import Fabric, FabricConfig, records
from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric._manifest import DEFAULT_STATES, POINTS, RUNTIME_POINTS

from ._security_capture import capture, spans

SDK = Path(__file__).resolve().parents[1]
SRC = SDK / "src" / "fabric"
TESTS = SDK / "tests"
ROOT = SDK.parents[1]

#: Every module spec 057 (P0a-P0c, P1a) added to the SDK.
NEW_MODULES = (
    "_rec_check.py", "_rec_controls.py", "_rec_extension.py", "_rec_grant.py", "_rec_run.py",
    "_records_api.py", "_security_policy.py", "records/__init__.py", "records/_handles.py",
    "records/_vocab.py", "records/_walker.py", "reconstruct/_controls.py",
    "reconstruct/_security.py", "reconstruct/_derive.py", "reconstruct/dialects/__init__.py",
    "reconstruct/dialects/offered_grant.py", "reconstruct/dialects/safety_map.py",
    "reconstruct/dialects/tool_result.py",
)  # fmt: skip
#: The ones on the agent's request path (everything but the offline reader).
REQUEST_PATH = tuple(m for m in NEW_MODULES if not m.startswith("reconstruct/"))
#: B9: an agent framework, agent SDK or guardrail library name, as a module, identifier or
#: file name would spell it (lower case, separators removed before matching).
FRAMEWORKS = (
    "langchain", "langgraph", "langsmith", "llamaindex", "crewai", "autogen", "ag2",
    "semantickernel", "haystack", "smolagents", "pydanticai", "openaiagents", "agentssdk",
    "claudeagentsdk", "claudecode", "dspy", "agno", "letta", "mastra", "googleadk",
    "strandsagents", "guardrailsai", "nemoguardrails", "llamaguard", "presidio", "lakera",
    "rebuff", "llmguard",
)  # fmt: skip
#: B9 (§2.1): the capture-point name pattern.
POINT_NAME = re.compile(
    r"^(records|reconstruct|wire|http|mcp|exec|host|otlp|classify)\.[a-z0-9_.]+$"
)
#: B6 (§2.1): words reader output never contains.
FORBIDDEN_WORDS = re.compile(r"violation|unauthori|non-compliant|breach|policy failure", re.I)


def _tree(relative: str) -> ast.Module:
    return ast.parse((SRC / relative).read_text(encoding="utf-8"), filename=relative)


def _dotted(node: ast.AST) -> str:
    """``a.b.c`` for a name or attribute chain, else ``""``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()
    yield
    COUNTERS.reset()


def test_the_new_module_list_is_complete() -> None:
    """Every module named above exists; a 057 module added later must join the list."""
    for relative in NEW_MODULES:
        assert (SRC / relative).is_file(), relative
    found = {p.relative_to(SRC).as_posix() for p in SRC.rglob("*.py")}
    for relative in found:
        if re.fullmatch(r"_rec_[a-z_]+\.py|records/.*\.py|reconstruct/dialects/.*\.py", relative):
            assert relative in NEW_MODULES, relative


# ============================================================================ B1
_WAITS = frozenset({"sleep", "wait", "wait_for", "Event", "Condition", "Barrier",
                    "Semaphore", "BoundedSemaphore", "select", "poll", "input"})  # fmt: skip


def _waits(tree: ast.Module) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = node.id if isinstance(node, ast.Name) else node.attr
            if name in _WAITS:
                found.append(f"{name}@{node.lineno}")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names]
            if any(n.split(".")[-1] in _WAITS for n in names):
                found.append(f"import {names}@{node.lineno}")
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attr, args, keywords = node.func.attr, node.args, {k.arg for k in node.keywords}
        receiver = node.func.value
        literal = isinstance(receiver, ast.Constant) and isinstance(receiver.value, str)
        if attr == "join" and not literal and (
            not args or "timeout" in keywords
            or (len(args) == 1 and isinstance(args[0], ast.Constant)
                and isinstance(args[0].value, (int, float)))
        ):  # fmt: skip
            found.append(f"join@{node.lineno}")  # a thread or process join, not str.join
        if attr == "put" and "block" not in keywords:
            found.append(f"put@{node.lineno}")  # a blocking queue put; put_nowait is fine
    return found


@pytest.mark.parametrize("relative", NEW_MODULES)
def test_b1_no_new_module_waits_sleeps_or_blocks(relative: str) -> None:
    assert _waits(_tree(relative)) == [], relative


def test_b1_the_scan_finds_a_wait() -> None:
    """The scan's own control: each form it forbids is found."""
    code = ("import threading, time, queue\nfrom threading import Event\n"
            "time.sleep(1)\nthreading.Event().wait()\nt.join()\nq.put(1)\n"
            "c = threading.Condition()\n")  # fmt: skip
    found = _waits(ast.parse(code))
    for form in ("sleep", "wait", "join", "put", "Condition", "Event"):
        assert any(f.startswith(form) or form in f for f in found), (form, found)
    assert _waits(ast.parse("', '.join(x)\nq.put(1, block=False)\nq.put_nowait(1)\n")) == []


def _handles() -> list[tuple[str, Any]]:
    """One handle of every records API (recorded, under a capture handle)."""
    config = FabricConfig(tenant_id="t", agent_id="a", profile="permissive")
    client = Fabric(config, tracer=fabric_tracer())
    out: list[tuple[str, Any]] = [
        ("record_control", records.record_control("policy", decision="deny")),
        ("record_grant", records.record_grant({"basis": "declared",
                                               "tools": {"allow": [{"rule": "x"}]}})),
        ("record_extension", records.record_extension("skill", "s", version="1")),
        ("record_run_context", records.record_run_context(execution_mode="supervised")),
    ]  # fmt: skip
    with client.decision(session_id="s", request_id="r") as decision:
        out.append(("Decision.record_control", decision.record_control("policy")))
        decision.record_hook("h", "pre_tool")  # both return None: nothing to hand back
        decision.record_skill("k", "1")
        out.extend((("Decision.record_hook", None), ("Decision.record_skill", None)))
    return out


def fabric_tracer() -> Any:
    from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415

    return TracerProvider().get_tracer("boundary")


_DECISION_WORDS = re.compile(r"decision|allow|deny|approv|verdict|permit|block|outcome", re.I)


def test_b1_no_records_api_returns_a_decision_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """052 E5: every handle exposes ids and ``recorded`` only, and no field of it holds a
    decision value (the hook and skill APIs return nothing at all)."""
    with capture(monkeypatch):
        handles = _handles()
    for api, handle in handles:
        if handle is None:  # Decision.record_hook / record_skill return None
            assert api in ("Decision.record_hook", "Decision.record_skill"), api
            continue
        public = [n for n in dir(handle) if not n.startswith("_")]
        for name in public:
            assert not _DECISION_WORDS.search(name), (api, name)
            value = getattr(handle, name)
            if callable(value):
                continue
            assert value is None or isinstance(value, (str, bool)), (api, name, value)
            if isinstance(value, str):
                assert value not in ("allow", "deny", "modify", "escalate", "pending"), (api, name)


def test_b1_records_apis_take_no_wait_or_callback_parameter() -> None:
    for fn in (records.record_control, records.record_grant, records.record_extension,
               records.record_run_context, records.control_check):  # fmt: skip
        params = set(inspect.signature(fn).parameters)
        assert not params & {"timeout", "wait", "block", "callback", "on_decision"}, fn


# ============================================================================ B2
class _Value:
    pass


def test_b2_wrapper_returns_and_raises_the_same_objects(monkeypatch: pytest.MonkeyPatch) -> None:
    value, error = _Value(), PermissionError("refused")

    def check() -> _Value:
        return value

    async def check_async() -> _Value:
        return value

    def refuse() -> None:
        raise error

    wrapped = records.control_check(control="acl")
    with capture(monkeypatch) as handle:
        assert wrapped(check)() is value
        assert asyncio.run(wrapped(check_async)()) is value
        with pytest.raises(PermissionError) as raised:
            wrapped(refuse)()
        assert raised.value is error
        frames = [f.name for f in traceback.extract_tb(raised.value.__traceback__)]
        assert frames[-1] == "refuse"  # the check's own frame, never replaced

        def block() -> None:
            with records.control_check() as scope:
                scope.result = value
                refuse()

        with pytest.raises(PermissionError) as in_block:
            block()
        assert in_block.value is error
        assert len(spans(handle, "control")) == 4


def _imports(tree: ast.Module, relative: str) -> set[str]:
    """Absolute module names a module imports (relative imports resolved)."""
    package = ["fabric", *relative.split("/")[:-1]]
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = package[: len(package) - node.level + 1] if node.level else []
            module = ".".join([*base, *(node.module.split(".") if node.module else [])])
            out.add(module)
            out.update(f"{module}.{a.name}" for a in node.names)
    return out


#: The operator CLI's read commands (spec 058 5.6 to 5.8: ``fabric verify``, ``show`` and
#: ``doctor``) run the reader in the operator's own process, after the agent has ended.
#: They are the only modules outside ``fabric/reconstruct`` that may import it. Nothing the
#: agent's process loads imports them (the tests below pin that).
READER_COMMAND_MODULES = frozenset(
    {"cli/_read.py", "cli/_show.py", "cli/_transcript.py", "cli/_verify.py"}
)


def _imports_reader(imported: set[str]) -> bool:
    return any(m == "fabric.reconstruct" or m.startswith("fabric.reconstruct.") for m in imported)


def test_b2_no_request_path_module_imports_the_reader() -> None:
    """No derivation rule (``reconstruct.parse``) is importable from a module the agent's
    process runs: no SDK module outside ``fabric/reconstruct`` imports it, except the
    operator CLI's read commands, which never run in the agent's process."""
    for path in SRC.rglob("*.py"):
        relative = path.relative_to(SRC).as_posix()
        if relative.startswith("reconstruct/") or relative in READER_COMMAND_MODULES:
            continue
        imported = _imports(ast.parse(path.read_text(encoding="utf-8")), relative)
        assert not _imports_reader(imported), relative


def test_b2_the_reader_commands_are_reachable_only_from_the_operator_cli() -> None:
    """The exemption above stays narrow: each exempt module does import the reader (a stale
    entry fails), no module outside ``fabric/cli`` imports one of them, and inside the CLI
    they are loaded only when ``verify``, ``show`` or ``doctor`` runs."""
    exempt = {"fabric." + name[:-3].replace("/", ".") for name in READER_COMMAND_MODULES}
    for name in READER_COMMAND_MODULES:
        tree = ast.parse((SRC / name).read_text(encoding="utf-8"))
        assert _imports_reader(_imports(tree, name)), name
    for path in SRC.rglob("*.py"):
        relative = path.relative_to(SRC).as_posix()
        if relative.startswith("cli/"):
            continue
        imported = _imports(ast.parse(path.read_text(encoding="utf-8")), relative)
        assert not imported & exempt, relative
    # `fabric run` (the launcher the agent is started through) and every other command's
    # import path load neither the reader nor a read command.
    code = (
        "import json, sys\n"
        "import fabric.cli, fabric.cli._run, fabric.cli._runstate\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('fabric.reconstruct')"
        f" or m in {sorted(exempt)!r})))"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=60
    )
    assert json.loads(out.stdout) == []


def test_b2_recording_never_loads_the_reader(tmp_path: Path) -> None:
    code = """
import json, os, sys
os.environ["FABRIC_IDENTITY_MODE"] = "pseudonymous"
from opentelemetry.sdk.trace import TracerProvider
from fabric import LocalFilesystemContentStore, hooks, records, wire
store = LocalFilesystemContentStore(root=sys.argv[1], tenant_id="t")
handle = wire.install(store=store, tracer_provider=TracerProvider(), patch_aiohttp=False,
                      id_key=b"fabric-test-id-key-not-a-secret")
hooks.install(exec=True)
with wire.run("r"):
    records.record_grant({"basis": "declared", "tools": {"allow": [{"rule": "x"}]}})
    records.record_control("policy", decision="deny", gated_tool_call_id="call_1")
    records.control_check(control="acl")(lambda: True)()
    records.record_extension("skill", "s")
handle.flush(5.0)
print(json.dumps(sorted(m for m in sys.modules if m.startswith("fabric.reconstruct"))))
"""
    done = subprocess.run([sys.executable, "-c", code, str(tmp_path)], cwd=SDK,  # noqa: S603
                          capture_output=True, text=True, timeout=120, check=False)  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == []


# ============================================================================ B3
class _BlockingQueue(queue.Queue[Any]):
    """A capture queue whose blocking ``put`` would wait 5 s."""

    def put(self, item: Any, block: bool = True, timeout: float | None = None) -> None:
        if block:
            time.sleep(5)
        super().put(item, block=False)


def _boom(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("recorder fault")


def _inject(fault: str, handle: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    if fault == "raise":  # every records module's emit entry raises
        for module in (rec_controls, rec_grant, rec_extension, rec_run):
            monkeypatch.setattr(module, "emit", _boom)
        monkeypatch.setattr(rec_controls, "emit_control", _boom)
        monkeypatch.setattr(rec_grant, "emit_grant", _boom)
        monkeypatch.setattr(rec_run, "emit_grant", _boom)
        monkeypatch.setattr(rec_extension, "emit_extension", _boom)
        monkeypatch.setattr(rec_check, "emit_control", _boom)
    elif fault == "block":
        monkeypatch.setattr(handle.pipeline, "_queue", _BlockingQueue())
    elif fault == "full":

        def full(job: Any) -> None:
            raise queue.Full

        monkeypatch.setattr(handle.pipeline._queue, "put_nowait", full)


@pytest.mark.parametrize("fault", ["raise", "block", "full"])
def test_b3_capture_failure_never_reaches_the_caller(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    value, error = _Value(), PermissionError("refused")

    def refuse() -> None:
        raise error

    with capture(monkeypatch) as handle:
        _inject(fault, handle, monkeypatch)
        started = time.perf_counter()
        handles = _handles()
        assert records.control_check(control="acl")(lambda: value)() is value
        with pytest.raises(PermissionError) as raised:
            records.control_check(control="acl")(refuse)()
        assert raised.value is error
        assert time.perf_counter() - started < 2.0  # never waited on the recorder
    for api, ref in handles:
        assert ref is None or ref.recorded in (True, False), api
    if fault == "raise":
        assert COUNTERS.internal_errors >= 5


# ============================================================================ B5
def test_b5_invariants_are_constants_never_parameters() -> None:
    assert records.ENFORCED_BY_FABRIC is False
    assert records.AUTHENTICATION == "unverified_caller_report"
    for fn in (records.record_control, records.control_check, rec_controls.emit_control):
        params = set(inspect.signature(fn).parameters)
        assert not params & {"enforced_by_fabric", "authentication"}, fn
    assert not rec_check.KEYWORDS & {"enforced_by_fabric", "authentication"}


def test_b5_every_control_path_records_both_invariants(monkeypatch: pytest.MonkeyPatch) -> None:
    with capture(monkeypatch) as handle:
        records.record_control("policy", decision="deny")
        records.record_control("approval", "request", "escalate", control_id="a-1")
        records.record_control("approval", "resolution", "approve", resolves="a-1")
        records.control_check(control="acl")(lambda: False)()
        with records.control_check(control="acl", exit_means="allow"):
            pass
        config = FabricConfig(tenant_id="t", agent_id="a", profile="permissive")
        client = Fabric(config, tracer=fabric_tracer())
        with client.decision(session_id="s", request_id="r") as decision:
            decision.record_control("guardrail", decision="deny")
        rows = spans(handle, "control")
    assert len(rows) == 6
    for row in rows:
        assert row["fabric.control.enforced_by_fabric"] is False
        assert row["fabric.control.authentication"] == "unverified_caller_report"


# ============================================================================ B6
#: Every reader module: any of them can put a string into the report, the projection, the
#: view or a diagnostic, so the scan never depends on a hand-kept list of the printing ones.
_READER = tuple(sorted(p.relative_to(SRC).as_posix() for p in (SRC / "reconstruct").rglob("*.py")))
#: Literals that contain a scanned word but are never output: a cloud SDK exception class
#: name the object reader matches a store error against (``reconstruct/_objects.py``).
_NOT_OUTPUT = frozenset({"UnauthorizedSSOTokenError"})


def _printable_literals(tree: ast.Module) -> list[str]:
    """String constants that can reach output: every one except docstrings."""
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in docstrings]  # fmt: skip


def test_b6_the_scan_covers_every_reader_module() -> None:
    assert len(_READER) >= 15
    for relative in ("reconstruct/__main__.py", "reconstruct/_security.py",
                     "reconstruct/_controls.py", "reconstruct/_explain.py",
                     "reconstruct/_verify.py", "reconstruct/_project.py",
                     "reconstruct/_derive.py", "reconstruct/dialects/safety_map.py",
                     "reconstruct/dialects/tool_result.py"):  # fmt: skip
        assert relative in _READER, relative


@pytest.mark.parametrize("relative", _READER)
def test_b6_reader_can_print_no_evaluation_word(relative: str) -> None:
    for literal in _printable_literals(_tree(relative)):
        if literal in _NOT_OUTPUT:
            continue
        assert not FORBIDDEN_WORDS.search(literal), (relative, literal)


def test_b6_no_reader_golden_contains_an_evaluation_word() -> None:
    goldens = [*(TESTS / "goldens" / "security_reader").glob("*"),
               *(TESTS / "goldens" / "security_acceptance").glob("*")]  # fmt: skip
    assert len(goldens) > 30
    for path in goldens:
        assert not FORBIDDEN_WORDS.search(path.read_text(encoding="utf-8")), path.name


def test_b6_the_word_scan_finds_each_word() -> None:
    for word in ("violation", "Unauthorized", "non-compliant", "breach", "policy failure"):
        assert FORBIDDEN_WORDS.search(f"x {word} y"), word


# ============================================================================ B8
def test_b8_no_057_capture_point_is_active_by_default() -> None:
    """The records points are explicit-API points (active only through the application's
    own call) and stay off the published runtime manifest, so an agent that records none
    produces byte-identical capture output (§9.1); hook channels default to disabled."""
    for point in ("records.control", "records.grant", "records.extension"):
        assert POINTS[point].opt_in is False and POINTS[point].kind == "R"
        assert point not in RUNTIME_POINTS
        assert point not in DEFAULT_STATES
    for point in ("exec.subprocess", "http.nonmodel", "remote.sandbox"):
        assert DEFAULT_STATES[point] == ("disabled", "hook_disabled")
    registry = json.loads((ROOT / "contracts/coverage/v1/registry/capture-points-v1.json")
                          .read_text(encoding="utf-8"))  # fmt: skip
    rows = {row["id"]: row for row in registry["capture_points"]}
    for point in ("records.control", "records.grant", "records.extension"):
        assert rows[point]["activation"] == "explicit API"


def test_b8_no_classification_list_or_profile_is_built_in() -> None:
    """Classification lists come only from the customer's capture policy: the SDK has no
    built-in control host, hook program, watched path, marker or mapping profile."""
    from fabric import _security_policy  # noqa: PLC0415

    assert _security_policy.check_security_context({}) == {}
    for path in SRC.rglob("*"):
        if "__pycache__" in path.parts:
            continue
        if path.is_file() and path.suffix not in (".py", ".typed"):
            pytest.fail(f"non-code file in the package: {path.relative_to(SRC)}")
    for relative in NEW_MODULES:
        text = (SRC / relative).read_text(encoding="utf-8")
        assert "otlp-mapping-profile/v1" not in text or relative == "_security_policy.py"


# ============================================================================ B9
_THIRD_PARTY_ALLOWED = frozenset({"httpx", "aiohttp"})  # the qualified transport libraries


@pytest.mark.parametrize("relative", NEW_MODULES)
def test_b9_new_modules_import_only_stdlib_and_fabric(relative: str) -> None:
    for module in _imports(_tree(relative), relative):
        root = module.split(".")[0]
        allowed = root in ("fabric", "__future__") or root in sys.stdlib_module_names
        assert allowed or root in _THIRD_PARTY_ALLOWED, (relative, module)


def _squash(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _identifiers(tree: ast.Module) -> Iterator[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.alias)):
            yield node.name
        elif isinstance(node, ast.arg):
            yield node.arg


def _spec_057_tests() -> list[Path]:
    names = ("test_records_*.py", "test_reconstruct_security.py", "test_reconstruct_controls.py",
             "test_reconstruct_wire_derivation.py",
             "test_security_*.py", "_sc_*.py", "_security_capture.py", "_records_*.py",
             "_budget.py")  # fmt: skip
    return sorted({p for pattern in names for p in TESTS.glob(pattern)})


def test_b9_no_framework_name_in_a_057_module_identifier_or_test_name() -> None:
    files = [SRC / m for m in NEW_MODULES] + _spec_057_tests()
    assert len(files) > len(NEW_MODULES) + 10
    for path in files:
        assert not any(f in _squash(path.name) for f in FRAMEWORKS), path.name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name in _identifiers(tree):
            squashed = _squash(name)
            assert not any(f in squashed for f in FRAMEWORKS), (path.name, name)
    goldens = [*(TESTS / "goldens" / "security_records").glob("*"),
               *(TESTS / "goldens" / "security_reader").glob("*"),
               *(TESTS / "goldens" / "security_acceptance").glob("*")]  # fmt: skip
    for path in goldens:
        assert not any(f in _squash(path.name) for f in FRAMEWORKS), path.name


def test_b9_capture_point_names_follow_the_pattern() -> None:
    """Every capture point spec 057 adds (the registry rows that name spec 057) matches the
    §2.1 pattern; none is named after a product."""
    registry = json.loads((ROOT / "contracts/coverage/v1/registry/capture-points-v1.json")
                          .read_text(encoding="utf-8"))  # fmt: skip
    added = [row["id"] for row in registry["capture_points"] if "057" in row.get("state", "")]
    assert set(added) >= {"records.control", "records.grant", "records.extension"}
    for point in added:
        assert POINT_NAME.fullmatch(point), point
        assert not any(f in _squash(point) for f in FRAMEWORKS), point
    for point in ("records.control", "records.grant", "records.extension"):
        assert point in POINTS
    assert not POINT_NAME.fullmatch("langchain_callbacks") and POINT_NAME.fullmatch("exec.x")


# ===================================================================== no auto-wrapping
_FORBIDDEN_CALLS = frozenset({
    "sys.settrace", "sys.setprofile", "threading.settrace", "threading.setprofile",
    "threading.settrace_all_threads", "threading.setprofile_all_threads", "sys._getframe",
    "inspect.stack", "inspect.currentframe", "inspect.getmembers", "inspect.getouterframes",
    "gc.get_objects", "gc.get_referrers", "dir",
})  # fmt: skip
_FORBIDDEN_ATTRIBUTES = frozenset({
    "sys.meta_path", "sys.path_hooks", "sys.path_importer_cache", "sys.monitoring",
    "builtins.__import__", "importlib.abc", "MetaPathFinder", "PathEntryFinder",
})  # fmt: skip
_FORBIDDEN_IMPORTS = frozenset({"fnmatch", "importlib.abc", "sys.monitoring"})


def _auto_wrapping(tree: ast.Module) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted(node.func) in _FORBIDDEN_CALLS:
            found.append(f"{_dotted(node.func)}()@{node.lineno}")
        elif isinstance(node, ast.Attribute) and _dotted(node) in _FORBIDDEN_ATTRIBUTES:
            found.append(f"{_dotted(node)}@{node.lineno}")
        elif isinstance(node, ast.Name) and node.id in ("__import__", "MetaPathFinder"):
            found.append(f"{node.id}@{node.lineno}")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [
                node.module or "", *(f"{node.module}.{a.name}" for a in node.names)]  # fmt: skip
            found.extend(f"import {n}@{node.lineno}" for n in names if n in _FORBIDDEN_IMPORTS)
        elif isinstance(node, (ast.For, ast.comprehension)):
            iterated = _dotted(node.iter)
            if iterated.startswith("sys.modules"):
                found.append(f"iterates sys.modules@{getattr(node, 'lineno', 0)}")
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and _dotted(node.func.value) == "sys.modules"
                and node.func.attr in ("items", "values", "keys")):  # fmt: skip
            found.append(f"sys.modules.{node.func.attr}()@{node.lineno}")
    return found


def test_no_import_hook_tracer_or_name_matching_anywhere_in_the_sdk() -> None:
    """Fabric never finds checks by itself (§4.10.3): no module installs an import hook,
    a trace or profile function, inspects the stack, or enumerates objects or modules to
    match names. (``sys.modules.get`` of a fixed name and patches of the qualified
    transport libraries by literal attribute stay allowed.)"""
    problems = {}
    for path in sorted(SRC.rglob("*.py")):
        found = _auto_wrapping(ast.parse(path.read_text(encoding="utf-8")))
        if found:
            problems[path.relative_to(SRC).as_posix()] = found
    assert problems == {}


def test_the_auto_wrapping_scan_finds_each_form() -> None:
    code = ("import sys, inspect, fnmatch\nsys.settrace(f)\nsys.setprofile(f)\n"
            "sys.meta_path.insert(0, F)\ninspect.getmembers(m)\nimport builtins\n"
            "builtins.__import__ = f\nfor n in sys.modules: pass\ndir(m)\n")  # fmt: skip
    found = " ".join(_auto_wrapping(ast.parse(code)))
    for form in ("sys.settrace", "sys.setprofile", "sys.meta_path", "inspect.getmembers",
                 "fnmatch", "builtins.__import__", "iterates sys.modules", "dir()"):  # fmt: skip
        assert form in found, (form, found)


_FINGERPRINT = r"""
import hashlib, inspect, json, sys, threading
sys.path.insert(0, sys.argv[1])

def code_of(obj):
    fn = getattr(obj, "__func__", obj)
    code = getattr(fn, "__code__", None)
    if code is None:
        return None
    return hashlib.sha256(code.co_code + repr(code.co_consts).encode() +
                          repr(code.co_names).encode()).hexdigest()

def fingerprint(module):
    out = {}
    for name, obj in sorted(vars(module).items()):
        if name.startswith("__"):
            continue
        row = {"type": type(obj).__qualname__, "code": code_of(obj),
               "module": getattr(obj, "__module__", None),
               "wrapped": hasattr(obj, "__wrapped__")}
        if isinstance(obj, type):
            row["members"] = {k: [type(v).__qualname__, code_of(v), hasattr(v, "__wrapped__")]
                              for k, v in sorted(vars(obj).items()) if not k.startswith("__")}
        out[name] = row
    return out

def identities(module):
    return {name: id(obj) for name, obj in vars(module).items()}

def environment():
    import builtins
    monitoring = getattr(sys, "monitoring", None)
    tools = [monitoring.get_tool(i) for i in range(6)] if monitoring else []
    return {"trace": sys.gettrace() is None, "profile": sys.getprofile() is None,
            "thread_trace": threading.gettrace() is None,
            "thread_profile": threading.getprofile() is None,
            "meta_path": [type(m).__qualname__ for m in sys.meta_path],
            "path_hooks": len(sys.path_hooks),
            "import": type(builtins.__import__).__name__ == "builtin_function_or_method"
                      and builtins.__import__.__self__ is builtins,
            "monitoring": all(t is None for t in tools)}

from tests import _sc_application as app
before = identities(app)
first = fingerprint(app)
if sys.argv[2] == "use":  # Fabric imported, installed and used after the application
    import os, tempfile
    os.environ.setdefault("FABRIC_IDENTITY_MODE", "pseudonymous")
    from opentelemetry.sdk.trace import TracerProvider
    from fabric import LocalFilesystemContentStore, hooks, records, wire
    import fabric.records, fabric.decision
    store = LocalFilesystemContentStore(root=tempfile.mkdtemp(), tenant_id="t")
    handle = wire.install(store=store, tracer_provider=TracerProvider(), patch_aiohttp=False,
                          id_key=b"fabric-test-id-key-not-a-secret")
    hooks.install(exec=True)
    with wire.run("r"):
        records.record_control("permission_check", decision="deny")
        records.record_grant({"basis": "declared", "tools": {"allow": [{"rule": "x"}]}})
        records.control_check(control="own")(lambda: True)()
    handle.flush(5.0)
same = identities(app) == before
print(json.dumps({"fingerprint": first, "after": fingerprint(app), "same_objects": same,
                  "environment": environment(),
                  "fabric_loaded": sorted(m for m in sys.modules if m == "fabric")}))
"""


def _fingerprint(mode: str, *, autoload: bool, tmp: Path) -> dict[str, Any]:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("FABRIC_", "COV_", "COVERAGE_", "OTEL_"))}  # fmt: skip
    if autoload:
        argv = [sys.executable, "-m", "fabric.wire", "--print-autoload-path"]
        path = subprocess.run(argv, capture_output=True, text=True,  # noqa: S603
                              check=True).stdout.strip()  # fmt: skip
        env.update({
            "PYTHONPATH": os.pathsep.join(filter(None, [path, env.get("PYTHONPATH")])),
            "FABRIC_WIRE_AUTOLOAD": "1", "FABRIC_TENANT_ID": "t",
            "FABRIC_WIRE_STORE": f"file://{tmp}/store", "FABRIC_WIRE_EXEC": "1",
            "FABRIC_WIRE_ID_KEY": "fabric-test-id-key-not-a-secret",
        })  # fmt: skip
    done = subprocess.run([sys.executable, "-c", _FINGERPRINT, str(SDK), mode],  # noqa: S603
                          cwd=tmp, env=env, capture_output=True, text=True, timeout=120,
                          check=False)  # fmt: skip
    assert done.returncode == 0, done.stderr[-3000:]
    found: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    return found


def test_importing_and_autoloading_fabric_leaves_application_functions_untouched() -> None:
    """The fixture application module is identical (same objects, same code, nothing
    wrapped) whether Fabric is absent, imported, installed and used after it, or autoloaded
    before it with the exec hook on; and no trace, profile or monitoring hook, import hook
    or ``__import__`` replacement is installed in any of those interpreters."""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        plain = _fingerprint("none", autoload=False, tmp=tmp)
        used = _fingerprint("use", autoload=False, tmp=tmp)
        autoloaded = _fingerprint("use", autoload=True, tmp=tmp)
    assert plain["fabric_loaded"] == [] and autoloaded["fabric_loaded"] == ["fabric"]
    reference = plain["fingerprint"]
    assert reference["can_use"]["code"] is not None and not reference["can_use"]["wrapped"]
    for run in (used, autoloaded):
        assert run["fingerprint"] == reference
        assert run["after"] == reference
        assert run["same_objects"] is True
        assert run["environment"] == plain["environment"]
    assert all(v is True for k, v in plain["environment"].items()
               if k not in ("meta_path", "path_hooks"))  # fmt: skip


# ===================================================================== helpers' controls
def test_the_framework_list_catches_a_framework_name() -> None:
    assert any(f in _squash("LangGraphAdapter") for f in FRAMEWORKS)
    assert any(f in _squash("nemo_guardrails_hook") for f in FRAMEWORKS)
    assert not any(f in _squash("permission_check") for f in FRAMEWORKS)
