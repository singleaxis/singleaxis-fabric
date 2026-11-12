# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric verify``, ``fabric show`` and ``fabric doctor`` (spec 058 §5.6-§5.8, WP8-5),
end to end without Docker: the local-dir sink on loopback stands in for the Node, so the
canary and an unchanged agent started by ``fabric run`` go through real wire capture,
real delivery and the real reader.

The silent failures of the friction audit each produce a catalogue reason with a fix
(G6): S1 (autoload with no destination, and a model host no endpoint matched), S2
(plaintext OTLP to a non-loopback Node), S6 (a policy that withholds roles under
autoload)."""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric.cli import _doctor, _read, _runstate, _show, _verify
from fabric.cli._report import Finding, Report, emit

from ._cli_run_support import (
    AGENT,
    FakeModel,
    Sink,
    base_env,
    make_project,
    secrets_dir,
    write,
)
from ._cli_support import parse, secret_values
from .test_security_boundary import FORBIDDEN_WORDS, _printable_literals, _tree


@pytest.fixture
def lab(tmp_path: Path) -> Iterator[dict[str, Any]]:
    """A project, the sink in its data directory, a fake model, and the environment of a
    shell whose FABRIC_OTLP_ENDPOINT (a variable already set wins, §6.2) is the sink."""
    with _lab(tmp_path) as made:
        yield made


@contextlib.contextmanager
def _lab(tmp_path: Path) -> Iterator[dict[str, Any]]:
    env = base_env(tmp_path)
    project = make_project(tmp_path, env)
    sink = Sink(project / "fabric-data")
    model = FakeModel()
    shell = {**env, "FABRIC_OTLP_ENDPOINT": sink.url}
    try:
        yield {
            "env": env,
            "shell": shell,
            "project": project,
            "model": model,
            "agent": write(tmp_path / "agent.py", AGENT),
        }
    finally:
        sink.close()
        model.close()


def _verify_now(
    lab: dict[str, Any], *args: str, node: bool = True
) -> tuple[int, list[str], dict[str, Any]]:
    report, lines = _verify.run(
        parse(["verify", "--wait", "20", *args]),
        lab["shell"],
        lab["project"],
        node_ok=lambda *_: node,
    )
    return report.exit_code, lines, report.to_json()


def _ids(report: dict[str, Any]) -> list[str]:
    return [finding["id"] for finding in report["findings"]]


def _start_agent(lab: dict[str, Any], *extra: str, label: str = "agent-1") -> dict[str, Any]:
    env = {**lab["shell"], "OPENAI_BASE_URL": lab["model"].url}
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "fabric.cli",
            "run",
            "--run",
            label,
            *extra,
            "--",
            sys.executable,
            str(lab["agent"]),
        ],
        cwd=lab["project"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0 and result.stderr == "", result.stdout + result.stderr
    answer: dict[str, Any] = json.loads(result.stdout)
    return answer


def test_verify_show_and_doctor_on_a_working_project(lab: dict[str, Any]) -> None:
    code, lines, report = _verify_now(lab)
    assert code == 0 and "FC-065" in _ids(report) and "FC-066" in _ids(report), lines
    assert _start_agent(lab)["answer"] == "It is noon in UTC."

    code, lines, report = _verify_now(lab)
    assert code == 0, (lines, report["findings"])
    assert {"FC-065", "FC-069"} <= set(_ids(report))
    run = report["data"]["run"]
    assert run["label"] == "agent-1" and run["capture"] == "on"
    (process,) = run["runs"]  # the canary's own run is never taken for the agent's
    assert process["exchanges"] == 2 and process["chains"]["decisions"] == "complete"
    rows = {row["row"]: (row["state"], row["note"]) for row in run["coverage"]}
    assert rows["model calls (requests and responses)"] == ("recorded", "2 exchange(s)")
    assert rows["commands the agent ran"] == ("fix", "fabric init --exec")
    assert rows["end user and session"][0] == "needs code"
    assert any(line.startswith("coverage (observed):") for line in lines)
    # --spans in each of the reader's input forms (13.4): the data directory `fabric up`
    # prints, its spans/ directory; a path that is none of them names the accepted forms.
    data = lab["project"] / "fabric-data"
    for spans in (data, data / "spans"):
        code, lines, report = _verify_now(lab, "--canary-only", "--spans", str(spans))
        code, lines, report = _verify_now(lab, "agent-1", "--spans", str(spans))
        assert code == 0 and "FC-069" in _ids(report), (spans, report["findings"])
    code, _, report = _verify_now(lab, "agent-1", "--spans", str(data / "nothing-here"))
    (unreadable,) = [f for f in report["findings"] if f["id"] == "FC-073"]
    assert code == 1 and "fabric up` data directory" in unreadable["detail"]

    # show: the conversation, the tool call with its arguments, the answer.
    report_, lines = _show.run(
        parse(["show", "--content"]), lab["shell"], lab["project"], is_tty=lambda: False
    )
    text = "\n".join(lines)
    assert report_.exit_code == 0 and "run agent-1" in text and "verdict: complete" in text
    assert 'user: "What time is it in UTC?"' in text
    assert 'tool_call T1 get_time  {"zone": "UTC"}' in text
    assert '↳ result T1  "{"time": "12:00"}"' in text
    assert 'answer: "It is noon in UTC."' in text
    # Not a terminal and no --content: no content, and a finding says how to get it.
    report_, lines = _show.run(parse(["show"]), lab["shell"], lab["project"], is_tty=lambda: False)
    assert "noon" not in "\n".join(lines) and "FC-082" in [f.id for f in report_.findings]
    report_, lines = _show.run(
        parse(["show", "--transcript", "--content"]),
        lab["shell"],
        lab["project"],
        is_tty=lambda: False,
    )
    assert "output match" not in "\n".join(lines) and "get_time" in "\n".join(lines)
    report_, lines = _show.run(parse(["show", "--actions"]), lab["shell"], lab["project"])
    assert any("decisions: complete" in line for line in lines)
    report_, lines = _show.run(parse(["show", "--list"]), lab["shell"], lab["project"])
    assert [(r["label"], r["verdict"]) for r in report_.data["runs"]] == [("agent-1", "complete")]

    # doctor: the same environment, no problem.
    report_, lines = _doctor.run(
        parse(["doctor"]),
        lab["shell"],
        lab["project"],
        node_ok=lambda *_: True,
        which=lambda name, path=None: sys.executable,
    )
    ids = [f.id for f in report_.findings]
    assert report_.exit_code == 0 and "FC-091" in ids, report_.findings
    # Nothing printed or written by these commands holds a secret value.
    secrets = secret_values(secrets_dir(lab["env"]))
    everything = json.dumps(report) + text + "\n".join(lines)
    for value in secrets:
        assert value.decode(errors="replace") not in everything


def test_a_project_path_with_a_space_reads_its_content_store(tmp_path: Path) -> None:
    """The compiled FABRIC_WIRE_STORE is a file URI (a space is %20); verify and show must
    read the store the SDK wrote, or every exchange reads back unverified."""
    root = tmp_path / "my projects"
    root.mkdir()
    with _lab(root) as lab:
        _start_agent(lab)
        code, lines, report = _verify_now(lab)
        assert code == 0 and {"FC-065", "FC-069"} <= set(_ids(report)), report["findings"]
        _, lines = _show.run(
            parse(["show", "--content"]), lab["shell"], lab["project"], is_tty=lambda: False
        )
        assert 'answer: "It is noon in UTC."' in "\n".join(lines)


def test_s1_a_model_host_no_endpoint_matches_is_named_with_the_fix(lab: dict[str, Any]) -> None:
    """F2/S1: the agent's model host matches nothing (base-URL derivation off): the run
    records no model call, and verify says which host and the one line that fixes it."""
    fabric_yaml = lab["project"] / "fabric.yaml"
    fabric_yaml.write_text(fabric_yaml.read_text() + "providers:\n  from_environment: false\n")
    _start_agent(lab, label="unmatched")
    code, _lines, report = _verify_now(lab)
    assert code == 1
    findings = {f["id"]: f for f in report["findings"]}
    port = lab["model"].url.split(":")[2].split("/")[0]
    assert f"fabric init --provider http://127.0.0.1:{port}/v1" in findings["FW-006"]["detail"]
    rows = {row["row"]: row for row in report["data"]["run"]["coverage"]}
    assert rows["model calls (requests and responses)"] == {
        "row": "model calls (requests and responses)",
        "state": "fix",
        "note": f"fix: fabric init --provider http://127.0.0.1:{port}/v1",
    }
    assert findings["FW-006"]["fix"]
    assert "no model call was recorded" in findings["FC-068"]["detail"]


def test_s1_autoload_with_no_destination_says_so(tmp_path: Path) -> None:
    """S1: a two-variable manual setup (no fabric.yaml) records nothing: doctor says the
    spans have no destination, with the fix."""
    env = {**base_env(tmp_path), "FABRIC_WIRE_AUTOLOAD": "1", "FABRIC_TENANT_ID": "t1"}
    (tmp_path / "manual").mkdir()
    report, _ = _doctor.run(
        parse(["doctor"]), env, tmp_path / "manual", which=lambda name, path=None: sys.executable
    )
    findings = {f.id: f for f in report.findings}
    assert "FC-090" in findings and "FW-002" in findings
    assert findings["FW-002"].entry["fix"].startswith("set FABRIC_OTLP_ENDPOINT")


def test_s2_plaintext_to_a_remote_node_is_named_with_the_fix(lab: dict[str, Any]) -> None:
    shell = {**lab["shell"], "FABRIC_OTLP_ENDPOINT": "http://fabric-node.example.com:4318"}
    report, _ = _doctor.run(
        parse(["doctor"]),
        shell,
        lab["project"],
        node_ok=lambda *_: True,
        which=lambda name, path=None: sys.executable,
    )
    (finding,) = [f for f in report.findings if f.id == "FW-012"]
    assert report.exit_code == 1 and "use https" in finding.entry["fix"]
    assert "FC-009" in [f.id for f in report.findings]  # the shell variable is named
    # verify's canary meets the same reason, with the same fix.
    report_, _ = _verify.run(
        parse(["verify", "--canary-only"]), shell, lab["project"], node_ok=lambda *_: True
    )
    (canary,) = [f for f in report_.findings if f.id == "FC-062"]
    assert report_.exit_code == 1 and canary.detail and canary.detail.startswith("FW-012")


def test_s6_a_policy_that_withholds_roles_is_named(lab: dict[str, Any]) -> None:
    policy = {
        "schema_version": "fabric.deployment-policy/v1",
        "policy_id": "policy",
        "policy_version": 1,
        "tenant_id": "default",
        "workload_id": "agent",
        "privacy": {"terminal.argv": "redact", "llm.request": "retain_original"},
        "storage": {"backend": "local", "region": "laptop", "key_id": "local"},
        "retention": {"days": 1},
        "required_integrations": [],
        "deployment": {
            "profile": "local",
            "image_digest": "local",
            "tls_required": False,
            "encrypted_store_required": False,
        },
    }
    (lab["project"] / "policy.json").write_text(json.dumps(policy))
    fabric_yaml = lab["project"] / "fabric.yaml"
    fabric_yaml.write_text(fabric_yaml.read_text() + "capture:\n  privacy: ./policy.json\n")
    report, _ = _doctor.run(
        parse(["doctor"]),
        lab["shell"],
        lab["project"],
        node_ok=lambda *_: True,
        which=lambda name, path=None: sys.executable,
    )
    (finding,) = [f for f in report.findings if f.id == "FW-004"]
    assert finding.detail == "roles: terminal.argv" and finding.entry["fix"]


def test_verify_failures_name_the_cause(lab: dict[str, Any]) -> None:
    code, _, report = _verify_now(lab, node=False)
    assert code == 1 and _ids(report)[-2:] == ["FC-061", "FC-066"]
    assert "canary" not in report["data"]
    # A run recorded with capture off is a failure that names why.
    record = _runstate.RunRecord(
        label="bare", started_ns=1, command="python", runtime="python", findings=[{"id": "FC-050"}]
    )
    _runstate.save(record, lab["project"] / ".fabric")
    code, _, report = _verify_now(lab, "bare", "--canary-only")
    assert code == 0 and "run" not in report["data"]
    code, _, report = _verify_now(lab, "bare")
    (finding,) = [f for f in report["findings"] if f["id"] == "FC-070"]
    assert code == 1 and "FC-050" in finding["detail"]
    code, _, report = _verify_now(lab, "no-such-run")
    assert code == 1 and "FC-067" in _ids(report)
    with pytest.raises(Exception, match="FC-011"):
        _verify.run(parse(["verify", "--production"]), lab["shell"], lab["project"])


def test_the_judgement_is_the_readers_verdict_and_the_decisions_chain() -> None:
    record = _runstate.RunRecord(label="r", started_ns=0, command="python", runtime="python")

    def run(
        verdict: str, decisions: str, gaps: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        return {
            "run_id": "source:s-1:1",
            "verdict": verdict,
            "gaps": gaps or [],
            "counts": {"exchanges": 1},
            "run_state": "terminated",
            "chains": {"decisions": {"verdict": decisions}},
        }

    (ok,) = _verify._judge([run("complete_for_observed_scopes", "complete")], record)
    assert ok == Finding("FC-069", "1 process(es), 1 exchange(s), decisions: complete")
    (partial,) = _verify._judge(
        [run("partial", "complete", [{"gap_type": "sequence_gap", "effect": "partial"}])], record
    )
    assert partial.id == "FC-068" and "sequence_gap: records are missing" in (partial.detail or "")
    assert "fix:" in (partial.detail or "")
    (none,) = _verify._judge([run("complete_for_observed_scopes", "not_observed")], record)
    assert none.id == "FC-068" and "no model call" in (none.detail or "")
    assert _read.words("not_a_known_reason").startswith("not_a_known_reason (see")


def test_reader_outputs_name_no_evaluation_word() -> None:
    """I1 / 057 B6: verify and show print the reader's facts, never an evaluation."""
    for module in (
        "cli/_verify.py",
        "cli/_show.py",
        "cli/_read.py",
        "cli/_transcript.py",
        "cli/_doctor.py",
        "cli/_run.py",
    ):
        for literal in _printable_literals(_tree(module)):
            assert not FORBIDDEN_WORDS.search(literal), (module, literal)


def test_human_output_never_drives_the_terminal(capsys: pytest.CaptureFixture[str]) -> None:
    """``show`` prints model answers and tool results, ``verify`` and ``doctor`` hosts and
    labels from status files: none of them may reach the terminal as an escape sequence."""
    hostile = "It is noon\x1b]0;owned\x07\x1b[2J \u202etxt.exe\x9b"
    report = Report("show", findings=[Finding("FW-006", f"{hostile}: 3 request(s)")])
    report.findings.append(Finding("FC-068", hostile))  # an error goes to stderr
    emit(report, [f'  1  model  fake  answer: "{hostile}"', "tab\tand\nnewline"],
         as_json=False, quiet=False)  # fmt: skip
    out, err = capsys.readouterr()
    for stream in (out, err):
        assert not any(ch in stream for ch in "\x1b\x07\u202e\x9b"), stream
    assert "\\x1b]0;owned\\x07" in out and "\\u202etxt.exe" in out and "\\x1b[2J" in err
    assert "tab\tand\nnewline" in out
    emit(report, [], as_json=True, quiet=False)
    assert "\x1b" not in capsys.readouterr().out
