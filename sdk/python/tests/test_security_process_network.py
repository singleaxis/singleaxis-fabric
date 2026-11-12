# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 P2a end to end (§10.3 WP7-10 and WP7-13, field finding F2).

The plain tool loop of ``tests/_sc_agent.py`` on a fixture model, under real capture
(``tests/_sc_capture.py``: the httpx patch, the ``exec.subprocess`` hook, the
``http.nonmodel`` hook, a sink-JSONL export) and read by ``python -m fabric.reconstruct``
as an operator reads it. Before each tool the agent's own code asks a fixture policy
service on a listed host and runs a hook script (exit 0 to continue, exit 2 to skip).
Nothing in the loop imports Fabric: classification comes only from the capture policy's
``security_context`` lists.

- **Hook programs** (WP7-10): one hook row per hook run with ``basis=process``, the
  customer's label, the exit code or signal and the exit map's outcome; without a map the
  outcome is ``unknown``. The hook's path never appears on telemetry.
- **Control endpoints** (WP7-13): one contact row per request to the listed host with
  ``decision=unknown``; with the response retained and ``--capture-policy``, the decision
  a configured pointer extracts (``configured_extract``); bodies withheld under the
  default roles; an unlisted host gives no control row.
- **F2**: a tool whose action happens somewhere no enabled channel looks, with a local
  pre-tool hook. The hook process never counts as the tool's effect.
"""

from __future__ import annotations

import json
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric._roles import ROLES
from fabric.deployment_policy import DeploymentPolicy

from ._sc_agent import Call, FixtureModel, ToolLoop, Turn
from ._sc_capture import Read, capture_run, env, read_export

CANARY = "P2A-CANARY-c41d"
HOOK_LABEL = "pre-tool-check"
POLICY_LABEL = "policy-svc"
SKIPPED = "skipped by the pre-tool hook"
REFUSED = "refused by the policy service"
CONTROL_ROLES = ("control.exchange.request", "control.exchange.response")

# The hook: exit 0 to continue, exit 2 to skip the tool, and one run killed by a signal.
HOOK_BODY = """case "$1" in
  *two*) exit 2 ;;
  *three*) kill -TERM $$ ;;
  *) exit 0 ;;
esac"""
EXIT_MAP = {"0": "passed", "2": "blocked", "-15": "errored"}

SCRIPT: list[Turn] = [
    [Call("call_1", "run_command", {"cmd": "echo one"})],
    [Call("call_2", "run_command", {"cmd": "echo two"})],
    [Call("call_3", "run_command", {"cmd": "echo three"})],
    [Call("call_4", "run_command", {"cmd": "echo four"})],
    "Done.",
]  # fmt: skip


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()
    with env(monkeypatch):
        yield
    COUNTERS.reset()


class PolicyService:
    """A fixture policy service: ``POST /v1/check`` answers ``{"decision": ...}``: ``DENY``
    for a command naming ``four``, else ``ALLOW``. Its ledger is the harness's ground
    truth of every contact."""

    def __init__(self) -> None:
        self.ledger: list[tuple[str, str]] = []
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                command = json.loads(raw)["command"]
                decision = "DENY" if "four" in command else "ALLOW"
                service.ledger.append((command, decision))
                body = json.dumps({"result": {"decision": decision, "note": CANARY}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> PolicyService:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def _hook(root: Path) -> Path:
    path = root / "hooks" / "pre-tool.sh"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\n{HOOK_BODY}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _policy(section: dict[str, Any], *retained: str) -> dict[str, Any]:
    """A local-profile capture policy naming every default content role, the ``retained``
    roles and ``section`` as its ``security_context``."""
    privacy = {role: "retain_original" for role, row in ROLES.items()
               if row.default_policy == "content"}  # fmt: skip
    privacy.update(dict.fromkeys(retained, "retain_original"))
    return {
        "schema_version": "fabric.deployment-policy/v1", "policy_id": "p2a-capture",
        "policy_version": 1, "tenant_id": "tenant-sc", "workload_id": "agent-1",
        "privacy": privacy,
        "storage": {"backend": "local", "region": "local", "key_id": "kid-1"},
        "retention": {"days": 30}, "required_integrations": [],
        "deployment": {"profile": "local", "image_digest": "local", "tls_required": False,
                       "encrypted_store_required": False},
        "security_context": section,
    }  # fmt: skip


class Agent:
    """The agent's own code around each tool: ask the policy service (when it has one),
    then run the hook; either can skip the tool. No Fabric import."""

    def __init__(self, model_url: str, hook: Path | None, service: str | None,
                 remote: bool = False, hook_first: bool = False) -> None:  # fmt: skip
        self.hook, self.service, self.remote = hook, service, remote
        self.hook_first = hook_first  # run the hook before asking the policy service
        self.hook_exits: list[int] = []
        self.loop = ToolLoop(model_url, check=lambda user, tool, args: True, around=self.around)

    def around(self, call: Call, phase: str, outcome: object) -> str | None:
        if phase != "before":
            return None
        command = call.args["cmd"]
        steps = (self._hook, self._ask) if self.hook_first else (self._ask, self._hook)
        for step in steps:
            if (refused := step(command)) is not None:
                return refused
        if self.remote:  # the tool's action happens where no enabled channel looks
            return f"remote job finished: {command}"
        return None

    def _ask(self, command: str) -> str | None:
        if self.service is not None:
            answer = httpx.post(f"http://{self.service}/v1/check",
                                json={"command": command, "note": CANARY},
                                timeout=10.0)  # fmt: skip
            if answer.json()["result"]["decision"] == "DENY":
                return REFUSED
        return None

    def _hook(self, command: str) -> str | None:
        if self.hook is not None:
            done = subprocess.run([str(self.hook), command], check=False)  # noqa: S603
            self.hook_exits.append(done.returncode)
            if done.returncode == 2:
                return SKIPPED
        return None


def _run(
    root: Path, monkeypatch: pytest.MonkeyPatch, *, section: Any = None, retained: Any = (),
    reader_policy: bool = False, hook: bool = True, service: bool = True,
    listed: bool = True, pointer: bool = True, exit_map: bool = True, remote: bool = False,
    script: list[Turn] | None = None, hook_first: bool = False,
    reader_document: dict[str, Any] | None = None,
) -> tuple[Agent, Read, PolicyService, Path]:  # fmt: skip
    """One captured run and its read. ``listed``: the policy service is in
    ``control_hosts``; ``pointer``: its entry gives the offline extraction;
    ``reader_policy``: the reader is given ``--capture-policy`` (``reader_document``
    instead of the capture policy when given)."""
    root.mkdir(parents=True, exist_ok=True)
    hook_path = _hook(root)
    with PolicyService() as policy_service, FixtureModel(script or SCRIPT) as model:
        if section is None:
            section = {}
            if hook:
                entry: dict[str, Any] = {"path": str(hook_path), "label": HOOK_LABEL}
                if exit_map:
                    entry["exit_map"] = EXIT_MAP
                section["hook_programs"] = [entry]
            if service and listed:
                host: dict[str, Any] = {"host": policy_service.host, "label": POLICY_LABEL,
                                        "control_kind": "policy"}  # fmt: skip
                if pointer:
                    host["decision_pointer"] = "/result/decision"
                    host["decision_map"] = [{"value": "ALLOW", "decision": "allow"},
                                            {"value": "DENY", "decision": "deny"}]  # fmt: skip
                section["control_hosts"] = [host]
        document = _policy(section, *retained)
        agent = Agent(model.url, hook_path if hook else None,
                      policy_service.host if service else None, remote, hook_first)  # fmt: skip

        def body(provider: Any) -> None:
            agent.loop.run("Go.")

        export = capture_run(
            root / "capture", "p2a-run", model.port, body,
            monkeypatch=monkeypatch, capture_policy=DeploymentPolicy(document),
            http_hosts=(f"http://{policy_service.host}",) if service else (),
        )  # fmt: skip
        extra: tuple[str, ...] = ()
        if reader_policy:
            policy_file = root / "capture-policy.json"
            policy_file.write_text(json.dumps(reader_document or document), encoding="utf-8")
            extra = ("--capture-policy", str(policy_file))
        (root / "read").mkdir()
        read = read_export(export, root / "read", *extra)
    return agent, read, policy_service, export.spans.parent


def _rows(read: Read, kind: str) -> list[dict[str, Any]]:
    (view_run,) = read.actions["runs"]
    return [row for row in view_run["rows"] if row["kind"] == kind]


def _call_labels(read: Read) -> dict[str, str]:
    """The view's ``T`` label of each scripted call, in the order the model issued them."""
    named = [c["call"] for row in _rows(read, "model_call") for c in row.get("tool_calls", ())]
    return {f"call_{n + 1}": label for n, label in enumerate(named)}


def _everything(export_root: Path, read: Read) -> str:
    """Every byte a reader of the export can see: the span file, every stored object, the
    report, the projection and the view."""
    parts = [json.dumps(read.report), json.dumps(read.projection), json.dumps(read.actions),
             read.view]  # fmt: skip
    for path in export_root.rglob("*"):
        if path.is_file():
            parts.append(path.read_bytes().decode("utf-8", "replace"))
    return "\n".join(parts)


def _fact_codes(read: Read) -> set[str]:
    (report_run,) = read.report["runs"]
    return {fact["code"] for fact in report_run["security_context"]["facts"]}


def _chain(read: Read, name: str) -> dict[str, Any]:
    (report_run,) = read.report["runs"]
    return dict(report_run["chains"][name])


# ------------------------------------------------------------------ WP7-10: hook programs
def test_hook_runs_are_hook_rows_with_the_exit_map_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, read, _, export_root = _run(tmp_path, monkeypatch, service=False)
    assert agent.hook_exits == [0, 2, -15, 0]  # the hook's own exits, as the agent saw them
    labels = _call_labels(read)
    hooks = _rows(read, "hook")
    assert len(hooks) == len(agent.hook_exits)  # exactly one row per hook run
    assert [h["outcome"] for h in hooks] == ["passed", "blocked", "errored", "passed"]
    assert [h.get("exit_code") for h in hooks] == [0, 2, None, 0]
    assert [h.get("signal") for h in hooks] == [None, None, 15, None]
    for hook, call in zip(hooks, ("call_1", "call_2", "call_3", "call_4"), strict=True):
        assert hook["basis"] == "process" and hook["program_label"] == HOOK_LABEL
        assert hook["derivation"] == "configured_exit_map"
        assert hook["latency_ms"] >= 0
        link = hook["link"]
        assert (link["target"], link["method"], link["confidence"], link["state"]) == (
            labels[call], "sequence_bracket", "tentative", "resolved")  # fmt: skip
    # a hook run is never an effect row; the skipped call has none and says why
    effects = _rows(read, "effect")
    assert [e["caused_by"][0]["target"] for e in effects] == [
        labels[c] for c in ("call_1", "call_3", "call_4")
    ]
    (report_run,) = read.report["runs"]
    assert report_run["attribution"]["effects_not_observed"]["control_denied"] == 1
    context = report_run["security_context"]
    assert context["hooks"] == [
        {"basis": "process", "outcome": "blocked", "count": 1},
        {"basis": "process", "outcome": "errored", "count": 1},
        {"basis": "process", "outcome": "passed", "count": 2},
    ]
    assert "control_denied" in _fact_codes(read)
    # the blocked call was not dispatched: its missing effect does not lower the chain
    assert _chain(read, "effects") == {"verdict": "complete"}
    assert "program pre-tool-check" in read.view and "(configured_exit_map)" in read.view
    # §7.3: the hook program's path never reaches telemetry or the report
    spans = (export_root / "spans.jsonl").read_text(encoding="utf-8")
    assert "pre-tool.sh" not in spans
    assert "pre-tool.sh" not in json.dumps([read.report, read.projection])


def test_without_an_exit_map_every_hook_outcome_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, read, _, _ = _run(tmp_path, monkeypatch, service=False, exit_map=False)
    hooks = _rows(read, "hook")
    assert [h["outcome"] for h in hooks] == ["unknown"] * 4
    assert all("derivation" not in h for h in hooks)
    assert [h.get("exit_code") for h in hooks] == [0, 2, None, 0]  # still recorded
    (report_run,) = read.report["runs"]
    # nothing says the hook blocked call_2: it is a call with no effect, not a denied one
    assert report_run["attribution"]["effects_not_observed"].get("control_denied", 0) == 0
    assert "control_denied" not in _fact_codes(read)


# -------------------------------------------------------------- WP7-13: control endpoints
def test_contacts_with_a_listed_host_are_control_rows_with_decision_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default roles: one contact row per request, ``decision=unknown``, and neither the
    request nor the response of the control endpoint is stored anywhere."""
    _, read, service, export_root = _run(tmp_path, monkeypatch, hook=False, pointer=False)
    assert [d for _, d in service.ledger] == ["ALLOW", "ALLOW", "ALLOW", "DENY"]
    labels = _call_labels(read)
    controls = _rows(read, "control")
    assert len(controls) == len(service.ledger)  # exactly one row per contact
    for control, call in zip(controls, ("call_1", "call_2", "call_3", "call_4"), strict=True):
        assert control["control_kind"] == "policy" and control["phase"] == "observation"
        assert control["decision"] == "unknown" and control["derivation"] == "literal"
        assert control["engine"] == POLICY_LABEL and control["status"] == 200
        assert control["latency_ms"] >= 0
        link = control["link"]
        assert (link["target"], link["method"], link["confidence"]) == (
            labels[call], "sequence_bracket", "tentative")  # fmt: skip
    assert CANARY not in _everything(export_root, read)  # bodies withheld
    assert service.host not in json.dumps([read.report, read.projection, read.actions])
    (report_run,) = read.report["runs"]
    assert report_run["security_context"]["control_links"] == {"sequence_bracket": 4}
    assert report_run["security_context"]["controls"] == [
        {"kind": "policy", "decision": "unknown", "derivation": "literal", "count": 4}
    ]
    assert _chain(read, "controls")["verdict"] == "complete"
    # the denied call is not known to be denied: nothing was read from the response
    assert report_run["attribution"]["effects_not_observed"].get("control_denied", 0) == 0


def test_a_configured_pointer_extracts_the_decision_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, read, _, _ = _run(tmp_path, monkeypatch, hook=False, retained=CONTROL_ROLES,
                                   reader_policy=True)  # fmt: skip
    labels = _call_labels(read)
    controls = _rows(read, "control")
    assert [c["decision"] for c in controls] == ["allow", "allow", "allow", "deny"]
    assert {c["derivation"] for c in controls} == {"configured_extract"}
    assert controls[3]["link"]["target"] == labels["call_4"]
    (report_run,) = read.report["runs"]
    # the extracted deny gates call_4, which ran nothing: F5, by the reader's join only
    assert report_run["attribution"]["effects_not_observed"]["control_denied"] == 1
    assert "(configured_extract)" in read.view
    assert agent.loop.outcomes[3].result == REFUSED  # the agent's own code decided


def test_without_the_reader_policy_a_retained_response_is_not_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, read, _, _ = _run(tmp_path, monkeypatch, hook=False, retained=CONTROL_ROLES)
    assert {c["decision"] for c in _rows(read, "control")} == {"unknown"}


def test_a_listed_pointer_whose_body_was_not_retained_is_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, read, _, _ = _run(tmp_path, monkeypatch, hook=False, reader_policy=True)
    controls = _rows(read, "control")
    assert {c["decision"] for c in controls} == {"unknown"}
    assert all(c["body_not_retained"] for c in controls)
    chain = _chain(read, "controls")
    assert chain["verdict"] == "partial" and "body_not_retained" in chain["reasons"]
    assert "response body not retained" in read.view


def test_an_unlisted_host_gives_no_control_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, read, service, _ = _run(tmp_path, monkeypatch, hook=False, listed=False,
                               section={"hook_programs": []})  # fmt: skip
    assert len(service.ledger) == 4  # the agent still called it
    assert _rows(read, "control") == []
    assert len(_rows(read, "http")) == 4  # recorded as general HTTP


def test_hooks_and_contacts_together_each_have_exactly_one_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, read, service, _ = _run(tmp_path, monkeypatch, retained=CONTROL_ROLES,
                                   reader_policy=True)  # fmt: skip
    assert len(_rows(read, "control")) == len(service.ledger) == 4
    assert len(_rows(read, "hook")) == len(agent.hook_exits) == 3  # call_4: refused first
    (report_run,) = read.report["runs"]
    # call_2 (hook blocked) and call_4 (policy deny) are both F5
    assert report_run["attribution"]["effects_not_observed"]["control_denied"] == 2


# --------------------------------------------------------- field finding F2 (harness shape B)
REMOTE: list[Turn] = [
    [Call("call_1", "run_command", {"cmd": "make build"})],
    [Call("call_2", "run_command", {"cmd": "make test"})],
    "Done.",
]  # fmt: skip


def test_f2_a_declared_hook_program_never_satisfies_the_tool_call_had_an_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A remote-sandbox tool with a local pre-tool hook and no remote effect recorded: the
    hook is a hook row; both calls stay in ``tool_calls_without_effect`` and the effects
    chain is not ``complete``."""
    agent, read, _, _ = _run(tmp_path, monkeypatch, service=False, remote=True, script=REMOTE)
    assert agent.hook_exits == [0, 0]
    assert _rows(read, "effect") == []
    assert len(_rows(read, "hook")) == 2
    (view_run,) = read.actions["runs"]
    labels = _call_labels(read)
    without = view_run["tool_calls_without_effect"]
    assert sorted(item["call"] for item in without) == sorted(labels.values())
    assert {item["reason"] for item in without} == {"none_in_window"}
    chain = _chain(read, "effects")
    assert chain["verdict"] == "partial" and "none_in_window" in chain["reasons"]
    (report_run,) = read.report["runs"]
    assert report_run["attribution"]["effects_not_observed"]["none_in_window"] == 2
    assert report_run["attribution"]["links"] == {}  # the hook is linked to no call as an effect


def test_f2_an_undeclared_hook_program_is_linked_as_before_tentative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without a ``hook_programs`` entry nothing classifies the process: it is linked as
    today (``sequence_bracket``, tentative). Fabric never guesses a hook by its name."""
    _, read, _, _ = _run(tmp_path, monkeypatch, service=False, remote=True, script=REMOTE,
                         section={"hook_programs": [
                             {"basename": "another-hook.sh", "label": "other"}]})  # fmt: skip
    assert _rows(read, "hook") == []
    effects = _rows(read, "effect")
    assert len(effects) == 2
    for effect in effects:
        (link,) = effect["caused_by"]
        assert effect["rule"] == "A2" and link["link"] == "sequence_bracket · tentative"
    (view_run,) = read.actions["runs"]
    assert view_run["tool_calls_without_effect"] == []


def test_f2_a_passed_hook_then_a_deny_leaves_no_stray_none_in_window_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P2a review: the hook passes call_4, then the policy service denies it (extracted
    offline). F5 moves call_4 to ``control_denied``; no call is left ``none_in_window``, so
    the effects chain must not keep the ``none_in_window`` reason the hook run added."""
    agent, read, service, _ = _run(tmp_path, monkeypatch, retained=CONTROL_ROLES,
                                   reader_policy=True, hook_first=True)  # fmt: skip
    assert agent.hook_exits == [0, 2, -15, 0]  # call_4's hook passed; the service denied it
    assert [d for _, d in service.ledger] == ["ALLOW", "ALLOW", "DENY"]  # call_2: skipped
    (report_run,) = read.report["runs"]
    not_observed = report_run["attribution"]["effects_not_observed"]
    assert not_observed["none_in_window"] == 0
    assert not_observed["control_denied"] == 2  # call_2 (hook blocked), call_4 (deny)
    assert _chain(read, "effects") == {"verdict": "complete"}
    (view_run,) = read.actions["runs"]
    assert {item["reason"] for item in view_run["tool_calls_without_effect"]} == {"control_denied"}


# ---------------------------------------------------------------------- the reader option
def test_a_capture_policy_no_run_was_captured_under_is_a_warning_naming_the_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """P2a review: the lists apply only to runs whose manifest names the policy's digest.
    A policy changed after the run (here: the hook entry gains an ``exit_map``) used to
    apply to nothing, silently; the reader now says so on stderr, with the fix, and the
    output is as without the option."""
    edited = _policy({"hook_programs": [{"basename": "pre-tool", "label": HOOK_LABEL,
                                         "exit_map": EXIT_MAP}]})  # fmt: skip
    _, read, _, _ = _run(tmp_path, monkeypatch, retained=CONTROL_ROLES, reader_policy=True,
                         reader_document=edited)  # fmt: skip
    err = capsys.readouterr().err
    assert err.count("--capture-policy applied to no run") == 3  # report, --json, view
    assert "FABRIC_CAPTURE_POLICY" in err and "decision_pointer" in err
    assert str(tmp_path) not in err and CANARY not in err
    contacts = _rows(read, "control")
    assert contacts and {row["decision"] for row in contacts} == {"unknown"}  # nothing applied
    # the matching policy: no warning
    _run(tmp_path / "same", monkeypatch, retained=CONTROL_ROLES, reader_policy=True)
    assert "--capture-policy" not in capsys.readouterr().err


def test_capture_policy_option_errors_name_the_cause_and_the_fix(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from fabric.reconstruct.__main__ import main  # noqa: PLC0415

    spans = tmp_path / "spans.jsonl"
    spans.write_text("", encoding="utf-8")
    not_json = tmp_path / "bad.json"
    not_json.write_text(f"{{{CANARY}", encoding="utf-8")
    no_section = tmp_path / "plain.json"
    plain = _policy({})
    del plain["security_context"]
    no_section.write_text(json.dumps(plain), encoding="utf-8")
    for path, cause in ((tmp_path / "missing.json", "cannot be read"),
                        (not_json, "not a valid deployment-policy/v1 document"),
                        (no_section, "no security_context section")):  # fmt: skip
        code = main(["actions", str(spans), "--capture-policy", str(path)])
        assert code not in (0, None)
        message = capsys.readouterr().err
        assert cause in message and "--capture-policy" in message
        assert "FABRIC_CAPTURE_POLICY" in message or "security_context" in message  # the fix
        assert CANARY not in message
