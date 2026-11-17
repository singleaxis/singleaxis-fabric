# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric snapshot`` (spec 057 WP7-17, §4.10.2; spec 058 OQ-3), end to end without
Docker: the local-dir sink on loopback stands in for the Node, so the snapshot goes
through the project's real capture configuration, real delivery and the real reader.

The work package's tests: the snapshot is a ``declared`` grant with source boundary
``operator_snapshot`` and the file's keyed ``pth-`` id (the id a host sensor puts on the
agent's opens of that entry); the contents are kept only when the capture policy retains
``run.permissions``; the path, the file name and the contents never reach telemetry; a
changed file gives a new snapshot and F2; and an agent process with the same
configuration never opens the file (``test_security_operator_snapshot`` covers the
reader's join to a watched open).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric import cli
from fabric._sequence import pseudonym_v2
from fabric.cli import _config, _project, _read, _run, _snapshot
from fabric.cli._report import CliError
from fabric.reconstruct._attribute import ActionReader

from ._cli_run_support import Sink, base_env, make_project, secrets_dir
from ._cli_support import parse

RULES_V1 = '{"allow": ["read_file"], "deny": ["RULE-CANARY-7d1e"]}\n'
RULES_V2 = '{"allow": ["read_file", "write_file"], "deny": ["RULE-CANARY-7d1e"]}\n'
CANARY = "RULE-CANARY-7d1e"
FILE_NAME = "agent-permissions-3c9a.json"


def _policy(rule: Path, *, profile: str = "local", keep: bool = True,
            extra: list[dict[str, str]] | None = None) -> dict[str, Any]:  # fmt: skip
    privacy = {"llm.request": "retain_original"}
    if keep:
        privacy["run.permissions"] = "retain_original"
    return {
        "schema_version": "fabric.deployment-policy/v1",
        "policy_id": "policy",
        "policy_version": 1,
        "tenant_id": "default",
        "workload_id": "agent",
        "privacy": privacy,
        "storage": {"backend": "local", "region": "laptop", "key_id": "local"},
        "retention": {"days": 1},
        "required_integrations": [],
        "deployment": {
            "profile": profile,
            "image_digest": "local" if profile == "local" else "sha256:" + "5" * 64,
            "tls_required": profile != "local",
            "encrypted_store_required": profile != "local",
        },
        "security_context": {
            "watched_paths": [
                {"path": str(rule), "match": "exact", "label": "agent-acl",
                 "class": "permission_config"},
                {"path": "/opt/hooks", "match": "prefix", "label": "hooks",
                 "class": "hook_config"},
                *(extra or []),
            ]
        },
    }  # fmt: skip


@pytest.fixture
def lab(tmp_path: Path) -> Iterator[dict[str, Any]]:
    env = base_env(tmp_path)
    project = make_project(tmp_path, env)
    sink = Sink(project / "fabric-data")
    rule = tmp_path / "rules" / FILE_NAME
    rule.parent.mkdir()
    rule.write_text(RULES_V1)
    try:
        yield {"shell": {**env, "FABRIC_OTLP_ENDPOINT": sink.url}, "env": env,
               "project": project, "rule": rule, "tmp": tmp_path}  # fmt: skip
    finally:
        sink.close()


def _use_policy(lab: dict[str, Any], policy: dict[str, Any]) -> None:
    (lab["project"] / "policy.json").write_text(json.dumps(policy))
    fabric_yaml = lab["project"] / "fabric.yaml"
    if "privacy:" not in fabric_yaml.read_text():
        fabric_yaml.write_text(fabric_yaml.read_text() + "capture:\n  privacy: ./policy.json\n")


def _snap(lab: dict[str, Any], *args: str, **kwargs: Any) -> tuple[int, list[str], dict[str, Any]]:
    report, lines = _snapshot.run(parse(["snapshot", *args]), lab["shell"], lab["project"],
                                  **kwargs)  # fmt: skip
    return report.exit_code, lines, report.to_json()


def _ids(report: dict[str, Any]) -> list[str]:
    return [finding["id"] for finding in report["findings"]]


def _id_key(lab: dict[str, Any]) -> bytes:
    located = _config.discover(None, lab["shell"], lab["project"])
    project = _project.load(located, {}, lab["shell"])
    dest = _read.destination(project, lab["shell"])
    assert dest.id_key is not None
    return dest.id_key


def _telemetry(lab: dict[str, Any]) -> bytes:
    spans = lab["project"] / "fabric-data" / "spans"
    return b"".join(path.read_bytes() for path in sorted(spans.iterdir()) if path.is_file())


def _stored(lab: dict[str, Any]) -> bytes:
    store = lab["project"] / "fabric-data" / "store"
    return b"".join(p.read_bytes() for p in sorted(store.rglob("*"))
                    if p.is_file() and ".fabric-wire-spool" not in p.parts)  # fmt: skip


def _grants(lab: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Every grant the reader finds in the project's records, with its run's facts."""
    located = _config.discover(None, lab["shell"], lab["project"])
    project = _project.load(located, {}, lab["shell"])
    dest = _read.destination(project, lab["shell"])
    assert dest.spans_dir is not None
    reader = ActionReader(every_run=True, keep_runs=True, id_key=dest.id_key)
    _read.read(dest, _read.span_files(dest.spans_dir), actions=reader)
    found = []
    for run in reader.runs:
        assert run.security is not None
        facts = {fact["code"]: fact for fact in run.security.context["facts"]}
        found += [(grant, facts) for grant in run.security.grants]
    return sorted(found, key=lambda item: item[0]["start_ns"])


def test_a_snapshot_is_a_declared_grant_with_the_files_keyed_id(lab: dict[str, Any]) -> None:
    _use_policy(lab, _policy(lab["rule"]))
    code, lines, report = _snap(lab)
    assert code == 0 and _ids(report) == ["FC-106"], (lines, report["findings"])
    (item,) = report["data"]["files"]  # only the permission_config entry is read
    expected = pseudonym_v2("pth", str(lab["rule"]), _id_key(lab))
    assert expected is not None
    assert item["label"] == "agent-acl" and item["path_ref"] == expected
    assert item["recorded"] and item["files"] == 1 and item["bytes"] == len(RULES_V1)
    assert report["data"]["contents"] == "kept" and report["data"]["delivered"] is True

    ((grant, facts),) = _grants(lab)
    assert grant["basis"] == "declared" and grant["source_boundary"] == "operator_snapshot"
    assert grant["path_ref"] == expected and grant["id"] == item["grant_id"]
    assert grant["trigger"] == "requested" and "grant_changed" not in facts
    # Telemetry holds keyed ids only: never the path, the file's name or what it says.
    telemetry = _telemetry(lab)
    assert expected.encode() in telemetry and item["grant_id"].encode() in telemetry
    for secret in (str(lab["rule"]), FILE_NAME, CANARY, "read_file", "/opt/hooks"):
        assert secret.encode() not in telemetry, secret
    # The policy names run.permissions: the contents are kept verbatim, as content.
    stored = _stored(lab)
    assert json.dumps(RULES_V1)[1:-1].encode() in stored
    assert FILE_NAME.encode() not in stored and str(lab["rule"]).encode() not in stored


def test_contents_are_absent_under_the_default_production_profile(lab: dict[str, Any]) -> None:
    _use_policy(lab, _policy(lab["rule"], profile="production", keep=False))
    code, lines, report = _snap(lab)
    assert code == 0, (lines, report["findings"])
    assert _ids(report) == ["FC-107", "FC-106"] and report["data"]["contents"] == "not_kept"
    (item,) = report["data"]["files"]
    assert item["recorded"] and item["path_ref"].startswith("pth-")
    ((grant, _),) = _grants(lab)
    assert grant["path_ref"] == item["path_ref"] and grant["id"] == item["grant_id"]
    everything = _telemetry(lab) + _stored(lab)
    for secret in (CANARY, "read_file", FILE_NAME, str(lab["rule"])):
        assert secret.encode() not in everything, secret


def test_a_changed_file_gives_a_new_snapshot_and_f2(lab: dict[str, Any]) -> None:
    _use_policy(lab, _policy(lab["rule"]))
    _, _, first = _snap(lab)
    code, _, same = _snap(lab)
    assert code == 0 and "FC-109" not in _ids(same)  # an unchanged file is the same grant
    assert same["data"]["files"][0]["grant_id"] == first["data"]["files"][0]["grant_id"]
    lab["rule"].write_text(RULES_V2)
    code, lines, changed = _snap(lab)
    assert code == 0 and _ids(changed) == ["FC-109", "FC-106"], changed["findings"]
    assert any("changed since the last snapshot" in line for line in lines)
    old, new = first["data"]["files"][0], changed["data"]["files"][0]
    assert new["path_ref"] == old["path_ref"] and new["grant_id"] != old["grant_id"]

    grants = _grants(lab)
    assert [g["id"] for g, _ in grants] == [old["grant_id"], old["grant_id"], new["grant_id"]]
    latest, facts = grants[-1]
    assert latest["trigger"] == "change" and latest["previous_id"] == old["grant_id"]
    assert latest["changed"] is True and facts["grant_changed"]["count"] == 1
    assert all("grant_changed" not in f for _, f in grants[:2])
    # the state keeps keyed ids only
    state = (lab["project"] / ".fabric" / "state" / "snapshots.json").read_text()
    assert json.loads(state)["files"] == {new["path_ref"]: new["grant_id"]}
    assert FILE_NAME not in state


def test_a_directory_entry_is_one_snapshot_of_its_files(lab: dict[str, Any]) -> None:
    rules = lab["tmp"] / "rules.d"
    (rules / "nested").mkdir(parents=True)
    (rules / "a.json").write_text('{"a": 1}')
    (rules / "nested" / "b.bin").write_bytes(b"\xff\xfe\x00rules")
    (rules / "big.json").write_bytes(b"x" * (_snapshot.FILE_LIMIT + 1))
    os.symlink(lab["rule"], rules / "link.json")
    entry = {"path": str(rules), "match": "prefix", "label": "rules-dir",
             "class": "permission_config"}  # fmt: skip
    _use_policy(lab, _policy(lab["rule"], extra=[entry]))
    code, _, report = _snap(lab)
    assert code == 0 and "FC-108" in _ids(report), report["findings"]
    by_label = {item["label"]: item for item in report["data"]["files"]}
    found = by_label["rules-dir"]
    assert found["files"] == 3 and found["incomplete"] == ["size_limit"]  # never the link
    assert found["path_ref"] == pseudonym_v2("pth", str(rules), _id_key(lab))
    stored = _stored(lab)
    assert b"base64" in stored and b"content_omitted" in stored
    for name in ("a.json", "b.bin", "big.json", "rules.d"):
        assert name.encode() not in stored + _telemetry(lab), name


def test_an_unreadable_file_is_named_and_the_others_are_recorded(lab: dict[str, Any]) -> None:
    missing = {"path": str(lab["tmp"] / "gone.json"), "match": "exact", "label": "gone",
               "class": "permission_config"}  # fmt: skip
    _use_policy(lab, _policy(lab["rule"], extra=[missing]))
    code, _, report = _snap(lab)
    assert code == 1 and "FC-103" in _ids(report) and "FC-106" not in _ids(report)
    (finding,) = [f for f in report["findings"] if f["id"] == "FC-103"]
    assert "gone" in finding["detail"] and "FileNotFoundError" in finding["detail"]
    assert finding["fix"]
    recorded = {item["label"]: item["recorded"] for item in report["data"]["files"]}
    assert recorded == {"agent-acl": True, "gone": False}
    assert len(_grants(lab)) == 1


def test_dry_run_reads_and_records_nothing(lab: dict[str, Any]) -> None:
    _use_policy(lab, _policy(lab["rule"]))

    def never(*_: Any, **__: Any) -> dict[str, Any]:
        raise AssertionError("--dry-run started the worker")

    code, lines, report = _snap(lab, "--dry-run", worker=never)
    assert code == 0 and report["findings"] == []
    assert any("would read agent-acl" in line for line in lines)
    assert not (lab["project"] / "fabric-data" / "spans").exists()


def test_the_list_may_be_given_as_a_file(lab: dict[str, Any]) -> None:
    listing = lab["tmp"] / "watched.json"
    listing.write_text(json.dumps(_policy(lab["rule"])["security_context"]["watched_paths"]))
    code, _, report = _snap(lab, "--watched-paths", str(listing))
    assert code == 0 and report["data"]["files"][0]["label"] == "agent-acl"


def test_nothing_listed_names_where_to_list_it(lab: dict[str, Any]) -> None:
    with pytest.raises(CliError) as caught:  # no capture policy at all
        _snap(lab)
    (finding,) = caught.value.findings
    assert finding.id == "FC-100" and "watched_paths" in finding.entry["fix"]
    policy = _policy(lab["rule"])
    policy["security_context"]["watched_paths"] = policy["security_context"]["watched_paths"][1:]
    _use_policy(lab, policy)
    with pytest.raises(CliError) as caught:  # a list with no permission_config entry
        _snap(lab)
    assert caught.value.findings[0].id == "FC-100"


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ("not json", "is not JSON"),
        ('"text"', "must be a list"),
        ("[3]", "watched_paths[0] must be an object"),
        ('[{"path": "/a", "match": "exact", "label": "x", "class": "permission_config", '
         '"mode": 1}]', "unknown field 'mode'"),
        ('[{"path": "/a", "match": "exact", "class": "permission_config"}]', "label is missing"),
        ('[{"path": "rel/a", "match": "exact", "label": "x", "class": "permission_config"}]',
         "absolute path"),
        ('[{"path": "/a", "match": "glob", "label": "x", "class": "permission_config"}]',
         "exact or prefix"),
        ('[{"path": "/a", "match": "exact", "label": "bad label", "class": '
         '"permission_config"}]', "label must start"),
        ('[{"path": "/a", "match": "exact", "label": "x", "class": "rules"}]', "class must be"),
    ],
)  # fmt: skip
def test_an_invalid_list_names_the_entry_and_the_rule(
    lab: dict[str, Any], text: str, said: str
) -> None:
    listing = lab["tmp"] / "watched.json"
    listing.write_text(text)
    with pytest.raises(CliError) as caught:
        _snap(lab, "--watched-paths", str(listing))
    (finding,) = caught.value.findings
    assert finding.id == "FC-101" and said in (finding.detail or ""), finding.detail
    with pytest.raises(CliError) as caught:
        _snap(lab, "--watched-paths", str(lab["tmp"] / "no-such-list.json"))
    assert caught.value.findings[0].id == "FC-101"


@pytest.mark.parametrize(
    ("answer", "finding", "said"),
    [
        ({"installed": True, "error": "no_id_key", "entries": []}, "FC-102", None),
        ({"installed": False, "status": {"reason_id": "FW-003", "reason": "no destination",
                                         "fix": "set node.endpoint"}}, "FC-104",
         "FW-003: no destination; fix: set node.endpoint"),
        ({"installed": False, "error": "no answer in 90 s"}, "FC-104", "no answer in 90 s"),
    ],
)  # fmt: skip
def test_a_snapshot_that_cannot_be_recorded_names_the_cause(
    lab: dict[str, Any], answer: dict[str, Any], finding: str, said: str | None
) -> None:
    _use_policy(lab, _policy(lab["rule"]))
    code, lines, report = _snap(lab, worker=lambda *_: answer)
    assert code == 1 and _ids(report) == [finding]
    assert said is None or report["findings"][0]["detail"] == said
    assert report["findings"][0]["fix"] and "nothing was recorded" in lines[-1]
    assert not (lab["project"] / ".fabric" / "state" / "snapshots.json").exists()


def test_a_policy_capture_refuses_is_reported_with_the_sdks_reason(lab: dict[str, Any]) -> None:
    policy = _policy(lab["rule"])
    policy["deployment"]["profile"] = "production"  # with no pinned image, TLS or encryption
    _use_policy(lab, policy)
    code, _, report = _snap(lab)  # the real worker: its status file names the reason
    assert code == 1 and _ids(report) == ["FC-104"]
    assert report["findings"][0]["detail"].startswith("FW-001: FABRIC_CAPTURE_POLICY is not")


def test_a_snapshot_the_node_did_not_take_is_an_error(lab: dict[str, Any]) -> None:
    _use_policy(lab, _policy(lab["rule"]))
    row = {"index": 0, "label": "agent-acl", "path_ref": "pth-" + "a" * 32, "recorded": True,
           "grant_id": "grt-" + "b" * 32, "changed": False, "files": 1, "bytes": 3}  # fmt: skip
    answer = {"installed": True, "delivered": False, "contents": "kept", "entries": [row]}
    code, _, report = _snap(lab, worker=lambda *_: answer)
    assert code == 1 and _ids(report) == ["FC-105"]


def test_the_command_line_runs_it_and_help_lists_it(
    lab: dict[str, Any], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_policy(lab, _policy(lab["rule"]))
    monkeypatch.chdir(lab["project"])
    for name, value in lab["shell"].items():
        monkeypatch.setenv(name, value)
    assert cli.main(["snapshot", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["command"] == "snapshot" and report["data"]["files"][0]["recorded"]
    assert cli.main(["help", "snapshot"]) == 0
    assert "--watched-paths" in capsys.readouterr().out


AGENT_PROCESS = """
import json, os, sys
opened = []
def audit(event, args):
    if event in ("open", "os.scandir", "os.listdir") and args and isinstance(args[0], (str, bytes)):
        opened.append(os.fsdecode(args[0]))
sys.addaudithook(audit)
for name in ("stat", "lstat"):
    def traced(path, *a, _real=getattr(os, name), **k):
        if isinstance(path, (str, bytes)):
            opened.append(os.fsdecode(path))
        return _real(path, *a, **k)
    setattr(os, name, traced)
from fabric import records, wire
handle = wire.install_from_env()
assert handle is not None and handle.capturing
with wire.run("agent-with-the-policy"):
    records.record_grant({"permission_mode": "default"})
handle.close(20)
print(json.dumps(sorted(set(opened))))
"""


def test_the_agent_process_never_opens_the_file_on_fabrics_behalf(lab: dict[str, Any]) -> None:
    """An agent with the same capture configuration (the policy that lists the file) and
    capture installed touches neither the file nor its directory: the snapshot is the
    operator's process alone (§4.3, OD-8)."""
    _use_policy(lab, _policy(lab["rule"]))
    located = _config.discover(None, lab["shell"], lab["project"])
    project = _project.load(located, {}, lab["shell"])
    plan = _run.Plan(added=dict(_project.compile_environment(project)))
    env, _ = _run.child_environment(lab["shell"], plan)
    env.pop("FABRIC_WIRE_AUTOLOAD", None)
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", AGENT_PROCESS], env=env, capture_output=True, text=True,
        timeout=120, check=False, cwd=lab["project"],
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    touched = json.loads(result.stdout.strip().splitlines()[-1])
    assert any(path.endswith("policy.json") for path in touched)  # the trace sees file opens
    rules_dir = str(lab["rule"].parent)
    assert [path for path in touched if path.startswith(rules_dir)] == []
    # and the capture path never loads the snapshot command
    loaded = (
        "import sys, fabric, fabric.wire, fabric.records\n"
        "print('fabric.cli._snapshot' in sys.modules or 'fabric.cli' in sys.modules)"
    )
    probe = subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-c", loaded], capture_output=True, text=True, timeout=60, check=True
    )
    assert probe.stdout.strip() == "False"
    assert secrets_dir(lab["env"]).is_dir()


# ---------------------------------------------------------------- review fixes


def test_an_entry_over_the_body_limit_keeps_what_fits_and_says_so(lab: dict[str, Any]) -> None:
    """The ``run.permissions`` walker counts every character as up to 6 bytes against the
    role's 1 MiB limit: four 128 KiB text files do not fit. Before the fix the whole body
    was dropped (``payload_too_large``) while the command said the contents were kept."""
    rules = lab["tmp"] / "big.d"
    rules.mkdir()
    texts = {f"f{i}.txt": (chr(ord("a") + i) * _snapshot.FILE_LIMIT) for i in range(4)}
    for name, text in texts.items():
        (rules / name).write_text(text)
    small = lab["tmp"] / "small.bin"
    small.write_bytes(b"\xff" * _snapshot.FILE_LIMIT)  # base64 alone is over the limit
    entries = [{"path": str(rules), "match": "prefix", "label": "big",
                "class": "permission_config"},
               {"path": str(small), "match": "exact", "label": "bin",
                "class": "permission_config"}]  # fmt: skip
    _use_policy(lab, _policy(lab["rule"], extra=entries))
    code, _, report = _snap(lab)
    assert code == 0 and report["data"]["contents"] == "kept", report["findings"]
    detail = [f["detail"] for f in report["findings"] if f["id"] == "FC-108"]
    assert sorted(d.split(":")[0] for d in detail) == ["big", "bin"]
    stored = _stored(lab)
    kept = [name for name, text in texts.items() if text.encode() in stored]
    assert kept, "no file's contents reached the store"  # a body was stored, not a descriptor
    assert len(kept) < len(texts) and stored.count(b"content_omitted") >= 2
    assert RULES_V1.strip().encode() in stored.replace(b'\\"', b'"')  # the other entry too


def test_a_document_that_fits_is_left_unchanged() -> None:
    files = [{"path_ref": "pth-" + "a" * 32, "sha256": "0" * 64, "bytes": 2,
              "content": "{}", "encoding": "utf-8"}]  # fmt: skip
    document = {"basis": "declared", _snapshot.EXTENSION: {"match": "exact", "files": files}}
    assert _snapshot.fit(json.loads(json.dumps(document)), 1 << 20) == document
    fitted = _snapshot.fit(json.loads(json.dumps(document)), 64)
    (row,) = fitted[_snapshot.EXTENSION]["files"]
    assert "content" not in row and row["content_omitted"] == "size_limit"
    assert fitted[_snapshot.EXTENSION]["incomplete"] == ["size_limit"]


@pytest.mark.parametrize(
    ("mode", "said"),
    [("retain_original", "kept"), ("original_plus_masked", "kept"), ("omit", "not_kept"),
     ("metadata_only", "not_kept"), ("redact", "masked"), ("tokenize", "masked"),
     ("masked_only", "masked")],
)  # fmt: skip
def test_what_becomes_of_the_contents_follows_the_roles_mode(mode: str, said: str) -> None:
    assert _snapshot.contents_of(mode) == said


def test_metadata_only_keeps_no_contents_and_says_so(lab: dict[str, Any]) -> None:
    """``metadata_only`` stores a descriptor without bytes: before the fix the command
    reported the contents kept."""
    policy = _policy(lab["rule"], keep=False)
    policy["privacy"]["run.permissions"] = "metadata_only"
    _use_policy(lab, policy)
    code, _, report = _snap(lab)
    assert code == 0 and report["data"]["contents"] == "not_kept", report["findings"]
    assert _ids(report) == ["FC-107", "FC-106"]
    assert CANARY.encode() not in _telemetry(lab) + _stored(lab)


def test_an_entry_the_worker_never_reached_is_named(lab: dict[str, Any]) -> None:
    other = {"path": "/etc/other.json", "match": "exact", "label": "other",
             "class": "permission_config"}  # fmt: skip
    _use_policy(lab, _policy(lab["rule"], extra=[other]))
    row = {"index": 0, "label": "agent-acl", "path_ref": "pth-" + "a" * 32, "recorded": True,
           "grant_id": "grt-" + "b" * 32, "changed": False, "files": 1, "bytes": 3}  # fmt: skip
    answer = {"installed": True, "delivered": True, "contents": "kept", "entries": [row],
              "error": "MemoryError"}  # fmt: skip
    code, lines, report = _snap(lab, worker=lambda *_: answer)
    assert code == 1 and _ids(report) == ["FC-103"], report["findings"]
    assert report["findings"][0]["detail"] == "other: /etc/other.json: not reached (MemoryError)"
    assert any("other: not snapshotted" in line for line in lines)
    assert {f["label"]: f["recorded"] for f in report["data"]["files"]} == {
        "agent-acl": True,
        "other": False,
    }


FAULT = """
import fabric._rec_grant as grants
_real = grants.check_document
def check_document(value):
    if value.get("source", {}).get("name") == "boom":
        raise RuntimeError("injected")
    return _real(value)
grants.check_document = check_document
"""


def test_one_entrys_fault_never_hides_the_others(lab: dict[str, Any]) -> None:
    """A fault while recording one entry is that entry's finding; the worker goes on."""
    boom = lab["tmp"] / "boom.json"
    boom.write_text("{}")
    entries = [{"path": str(boom), "match": "exact", "label": "boom",
                "class": "permission_config"}]  # fmt: skip
    _use_policy(lab, _policy(lab["rule"], extra=entries))
    hook = lab["tmp"] / "hook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(FAULT)
    lab["shell"]["PYTHONPATH"] = str(hook)
    code, _, report = _snap(lab)
    assert code == 1 and _ids(report) == ["FC-103"], report["findings"]
    assert report["findings"][0]["detail"].endswith("the snapshot failed (RuntimeError)")
    recorded = {item["label"]: item["recorded"] for item in report["data"]["files"]}
    assert recorded == {"agent-acl": True, "boom": False}
    assert len(_grants(lab)) == 1
