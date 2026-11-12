# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 P1b end to end (§10.2 WP7-7 and WP7-8): MCP on the wire as security context.

The MCP Python library's own client (``tests/_mcp_client.py``, no Fabric code in it)
talks to the fixture MCP server (``tests/mcp_fixture_server.py``) over Streamable HTTP and
over stdio, under real capture (``tests/_sc_capture.py``: the ``http.nonmodel`` hook for
the server's host, the ``mcp.client`` transport hook, the exec hook, a sink-JSONL export),
and ``python -m fabric.reconstruct --derive mcp.jsonrpc`` reads the export as an operator
would. The fixture's ledger is the ground truth.

- **WP7-7, Streamable HTTP**: the server's identity and version (``mcp_initialize``), its
  three listed tools with annotation counts (one destructive) and inventory digest
  (``mcp_tools_list``), a ``listed`` grant, the inventory change mid-run (F11), the roots
  the client exposed (pseudonymised: never in clear in telemetry), ``tools/call`` rows with
  ``isError`` (F14) and protocol errors (N25), elicitation accept, decline and cancel as
  control rows joined by JSON-RPC id. Bodies not retained -> ``body_not_retained`` and no
  rows. With the MCP owner marker set nothing is recorded twice.
- **WP7-8, stdio**: the same message set derived from the transport hook's records; the
  server process's launch, lifetime and exit (exec hook), the ``process_launch`` extension
  joined to it; an unpinned library version leaves the hook off; a non-Python MCP client
  gives launch evidence only.
"""

from __future__ import annotations

import json
import shlex
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric._roles import ROLES
from fabric._sequence import pseudonym_v2
from fabric.deployment_policy import DeploymentPolicy
from fabric.hooks import _mcp
from fabric.wire import _routes

from ._mcp_client import ACTIONS, ELICITATION_MARKER, SECRET_ROOT, SERVER, run_http, run_stdio
from ._sc_capture import ID_KEY, Read, capture_run, env, read_export
from .mcp_fixture_server import HttpServer

NETWORK = ("network.request", "network.response")
MCP = ("mcp.request", "mcp.response", "mcp.notification")
CANARIES = (SECRET_ROOT, "secret-root-canary", ELICITATION_MARKER, "elicit-canary")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()
    with env(monkeypatch):
        yield
    COUNTERS.reset()


def _policy(*retained: str) -> dict[str, Any]:
    privacy = {role: "retain_original" for role, row in ROLES.items()
               if row.default_policy == "content"}  # fmt: skip
    privacy.update(dict.fromkeys(retained, "retain_original"))
    return {
        "schema_version": "fabric.deployment-policy/v1", "policy_id": "p1b-capture",
        "policy_version": 1, "tenant_id": "tenant-sc", "workload_id": "agent-1",
        "privacy": privacy,
        "storage": {"backend": "local", "region": "local", "key_id": "kid-1"},
        "retention": {"days": 30}, "required_integrations": [],
        "deployment": {"profile": "local", "image_digest": "local", "tls_required": False,
                       "encrypted_store_required": False},
    }  # fmt: skip


def _run(root: Path, monkeypatch: pytest.MonkeyPatch, *, http: bool = True, stdio: bool = False,
         retained: tuple[str, ...] = (*NETWORK, *MCP), mcp_hook: bool = True,
         listed: bool = True, owned: bool = False,
         body: Any = None) -> tuple[Read, dict[str, Any], Path]:  # fmt: skip
    """One captured run of the scripted client and its read with ``--derive mcp.jsonrpc``
    (``--mcp-host`` the fixture's host when ``listed``). ``owned`` runs the HTTP session
    inside the MCP owner marker."""
    seen: dict[str, Any] = {}
    with HttpServer() as server:
        host = f"http://127.0.0.1:{server.port}"

        def run(provider: Any) -> None:
            if body is not None:
                body(seen)
            if stdio:
                seen["stdio"] = run_stdio()
            if http:
                if owned:
                    with _routes.owner_marker():
                        seen["http"] = run_http(server.url)
                else:
                    seen["http"] = run_http(server.url)

        export = capture_run(root / "capture", "mcp-run", 9, run, monkeypatch=monkeypatch,
                             capture_policy=DeploymentPolicy(_policy(*retained)),
                             http_hosts=(host,), mcp=mcp_hook)  # fmt: skip
        seen["ledger"] = list(server.ledger)
        options = ["--derive", "mcp.jsonrpc"] + (["--mcp-host", host] if listed else [])
        (root / "read").mkdir()
        read = read_export(export, root / "read", *options)
    return read, seen, export.spans.parent


def _run_report(read: Read) -> dict[str, Any]:
    (run,) = read.report["runs"]
    return run  # type: ignore[no-any-return]


def _rows(read: Read, kind: str) -> list[dict[str, Any]]:
    (view,) = read.actions["runs"]
    return [row for row in view["rows"] if row["kind"] == kind]


def _facts(read: Read) -> dict[str, int]:
    return {f["code"]: f["count"] for f in _run_report(read)["security_context"]["facts"]}


def _shape(read: Read) -> dict[str, Any]:
    """What one session gives, independent of transport and run: the derived rows as
    counts and sequences of their literal values."""
    controls = [r for r in _rows(read, "control") if r.get("control_kind") == "elicitation"]
    exts = _rows(read, "extension")
    return {
        "controls": [(r["phase"], r["decision"], r.get("reason_code"), r["method"])
                     for r in controls],
        "extensions": [(r["observed_via"], r.get("name"), r.get("version"), r.get("tools"),
                        json.dumps(r.get("annotations"), sort_keys=True))
                       for r in exts if r["observed_via"] != "process_launch"],
        "grants": [(r["basis"], r.get("counts"), bool(r.get("changed")))
                   for r in _rows(read, "grant")],
        "calls": [(r["method"], r.get("tool"), r["outcome"]) for r in _rows(read, "mcp_call")],
        # the stdio launch row is one more extension of unknown signature (F9)
        "facts": {k: v for k, v in _facts(read).items() if k != "extension_signature"},
    }  # fmt: skip


# ------------------------------------------------------------------- WP7-7: Streamable HTTP
def test_http_session_yields_server_tools_grants_calls_and_elicitations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read, seen, _ = _run(tmp_path, monkeypatch)
    shape = _shape(read)
    initialize, *listings = shape["extensions"]
    assert initialize[:3] == ("mcp_initialize", "repo-tools", "1.4.0")
    # four tools listed first (one destructive, one read-only, one idempotent, one
    # open-world: the server's assertions), five after the change
    assert [e[3] for e in listings] == [4, 5]
    assert json.loads(listings[0][4]) == {"destructive": 1, "idempotent": 1, "open_world": 1,
                                          "read_only": 1}  # fmt: skip
    assert json.loads(listings[1][4])["destructive"] == 2
    # F11: the tools/list digest changed within the run, once
    assert shape["facts"]["inventory_changed"] == 1
    assert _rows(read, "extension")[-1].get("changed") is True
    # listed grants: tools, then tools and the client's roots, then the changed tools
    assert shape["grants"] == [("listed", {"tools_listed": 4}, False),
                               ("listed", {"tools_listed": 4, "fs_rules": 1}, True),
                               ("listed", {"tools_listed": 5, "fs_rules": 1}, True)]  # fmt: skip
    assert shape["calls"] == [
        ("tools/call", "read_file", "ok"), ("tools/call", "fail", "tool_error"),
        ("tools/call", "delete_branch", "ok"), ("tools/call", "delete_branch", "tool_error"),
        ("tools/call", "delete_branch", "tool_error"), ("tools/call", "change_tools", "ok"),
        ("notifications/tools/list_changed", None, "notification"),
        ("tools/call", "missing", "protocol_error"),
    ]  # fmt: skip
    # F14: an MCP isError result is a structured error flag; a protocol error is not one
    assert shape["facts"]["tool_result_error"] == 3
    assert seen["http"][-2:] == [("missing", "MCPError"), ("resources/read", "MCPError")]


def test_elicitation_accept_decline_and_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read, seen, _ = _run(tmp_path, monkeypatch)
    rows = [r for r in _rows(read, "control") if r.get("control_kind") == "elicitation"]
    requests = [r for r in rows if r["phase"] == "request"]
    answers = [r for r in rows if r["phase"] == "resolution"]
    assert [r["decision"] for r in requests] == ["escalate"] * len(ACTIONS)
    assert all(r["method"] == "mcp_session" and r["link"]["confidence"] == "certain"
               for r in requests)  # fmt: skip
    assert [(r["decision"], r["reason_code"]) for r in answers] == [
        ("allow", "elicitation.accept"),
        ("deny", "elicitation.decline"),
        ("cancelled", "elicitation.cancel"),
    ]  # the client's answers, in the order the ground truth gave them
    assert all(r["method"] == "rpc_id" and r["decided_by"] == "human" for r in answers)
    numbers = {r["attempt_uid"]: r["n"] for r in rows}
    for request, answer in zip(requests, answers, strict=True):
        assert answer["resolves_attempt"] == request["attempt_uid"]
        assert numbers[answer["resolves_attempt"]] < answer["n"]
    asked = [m["message"] for m in seen["ledger"] if m["message"].get("method") ==
             "elicitation/create"]  # fmt: skip
    assert len(asked) == len(requests)
    run = _run_report(read)
    assert run["chains"]["controls"]["verdict"] == "complete"
    counts = Counter((c["kind"], c["decision"]) for c in run["security_context"]["controls"]
                     for _ in range(c["count"]))  # fmt: skip
    assert counts[("elicitation", "escalate")] == 3
    for control in rows:  # B5 on derived rows
        assert "invariant" not in control
    assert "pending_at_end" not in json.dumps(rows)
    text = read.view
    assert "elicitation · resolution · deny" in text and "(human)" in text


def test_bodies_not_retained_give_body_not_retained_and_no_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read, seen, root = _run(tmp_path, monkeypatch, retained=())
    run = _run_report(read)
    assert run["chains"]["controls"] == {"verdict": "partial", "reasons": ["body_not_retained"]}
    assert _rows(read, "mcp_call") == [] and _rows(read, "extension") == []
    assert not [r for r in _rows(read, "control") if r.get("control_kind") == "elicitation"]
    assert seen["http"] == run_http_expected()
    everything = "\n".join(p.read_bytes().decode("utf-8", "replace")
                           for p in root.rglob("*") if p.is_file())  # fmt: skip
    for canary in CANARIES:
        assert canary not in everything


def run_http_expected() -> list[Any]:
    """What the scripted client sees over HTTP with no capture at all."""
    with HttpServer() as server:
        return run_http(server.url)


def test_unlisted_host_without_bodies_states_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read, _, _ = _run(tmp_path, monkeypatch, retained=(), listed=False)
    assert "body_not_retained" not in json.dumps(_run_report(read)["chains"])


def test_no_double_record_when_the_owner_marker_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """053 §4.3: traffic inside the MCP owner marker never reaches ``http.nonmodel``; the
    stdio session is recorded by the transport hook alone. Each message is derived once."""
    read, seen, _ = _run(tmp_path, monkeypatch, stdio=True, owned=True)
    assert seen["http"] == seen["stdio"]
    (view,) = read.actions["runs"]
    assert not [r for r in view["rows"] if r["kind"] == "http"]  # owned: not recorded
    shape = _shape(read)
    assert len([c for c in shape["controls"] if c[0] == "request"]) == len(ACTIONS)
    both, _, _ = _run(tmp_path / "both", monkeypatch, stdio=True)
    assert len([c for c in _shape(both)["controls"] if c[0] == "request"]) == 2 * len(ACTIONS)


def test_canaries_never_in_clear_in_telemetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read, _, root = _run(tmp_path, monkeypatch, stdio=True)
    spans = (root / "spans.jsonl").read_text(encoding="utf-8")
    report = json.dumps([read.report, read.projection, read.actions]) + read.view
    for canary in CANARIES:
        assert canary not in spans, canary
        assert canary not in report, canary


# --------------------------------------------------------------------------- WP7-8: stdio
def test_stdio_gives_the_same_rows_as_http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    over_http, http_seen, _ = _run(tmp_path / "http", monkeypatch)
    over_stdio, stdio_seen, _ = _run(tmp_path / "stdio", monkeypatch, http=False, stdio=True)
    assert stdio_seen["stdio"] == http_seen["http"]  # what the agent saw
    assert _shape(over_stdio) == _shape(over_http)


def test_stdio_launch_lifetime_and_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    read, _, _ = _run(tmp_path, monkeypatch, http=False, stdio=True)
    (launch,) = [r for r in _rows(read, "extension") if r["observed_via"] == "process_launch"]
    assert launch["source_kind"] == "process" and launch["provenance"] == "observed"
    expected = pseudonym_v2("src", shlex.join([sys.executable, str(SERVER)]), ID_KEY)
    assert launch["source_ref"] == expected
    (effect,) = _rows(read, "effect")
    assert effect["exit_code"] == 0  # the exec hook's record: launch to exit
    assert "running" not in json.dumps(effect.get("status", ""))
    run = _run_report(read)
    (ext,) = [e for e in run["security_context"]["extensions"]
              if e["observed_via"] == "process_launch"]  # fmt: skip
    assert ext["count"] == 1


def test_stdio_bodies_not_retained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    read, _, _ = _run(tmp_path, monkeypatch, http=False, stdio=True, retained=())
    run = _run_report(read)
    assert run["chains"]["controls"] == {"verdict": "partial", "reasons": ["body_not_retained"]}
    assert _rows(read, "mcp_call") == []
    # the launch is still known: it needs no body
    assert [r["observed_via"] for r in _rows(read, "extension")] == ["process_launch"]


def test_an_unpinned_library_version_records_launch_evidence_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = _mcp._version
    monkeypatch.setattr(_mcp, "_version", lambda name: "2.4.0" if name == "mcp" else real(name))
    read, seen, root = _run(tmp_path, monkeypatch, http=False, stdio=True)
    assert seen["stdio"] == run_stdio()
    spans = [json.loads(line) for line in (root / "spans.jsonl").read_text().splitlines()]
    rows = [row for s in spans
            for row in s["attributes"].get("fabric.manifest.capture_points", ())
            if isinstance(row, str) and row.startswith("mcp.client@")]  # fmt: skip
    # the manifest's compact row form: point@version:kind:state:...:reason
    assert rows and ":unsupported:" in rows[-1] and rows[-1].endswith("unsupported_version")
    assert not any(str(s["attributes"].get("fabric.capture.point", "")).startswith("mcp.client")
                   for s in spans)  # fmt: skip
    assert _rows(read, "mcp_call") == [] and _rows(read, "extension") == []
    assert len(_rows(read, "effect")) == 1  # the launch, by the exec hook


def test_a_non_python_client_gives_launch_evidence_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A shell script is the MCP client: it launches the server and speaks to it over its
    pipes. The Python hooks see only the launch of the client (exec hook)."""
    script = tmp_path / "client.sh"
    script.write_text(
        'printf \'%s\\n\' \'{"jsonrpc":"2.0","id":1,"method":"initialize",'
        '"params":{"protocolVersion":"2025-06-18"}}\' | '
        f"{shlex.quote(sys.executable)} {shlex.quote(str(SERVER))}\n",
        encoding="utf-8",
    )

    def client(seen: dict[str, Any]) -> None:
        import subprocess  # noqa: PLC0415

        done = subprocess.run(["/bin/sh", str(script)], capture_output=True, check=False)  # noqa: S603
        seen["client"] = done.returncode, b"repo-tools" in done.stdout

    read, seen, _ = _run(tmp_path, monkeypatch, http=False, body=client)
    assert seen["client"] == (0, True)
    assert _rows(read, "mcp_call") == [] and _rows(read, "extension") == []
    assert len(_rows(read, "effect")) == 1  # the client's launch, nothing of its messages
