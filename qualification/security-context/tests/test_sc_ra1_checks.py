# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-1 checks are not vacuous: on a real replayed run they pass, and each one fails
when a record is missing, extra or carries the wrong value.

One module-scoped run of two sessions (``mcp-stdio``: both MCP transports, the tool-list
change, an elicitation and a tool error; ``safety-openai``: a provider safety signal), with
capture off and on, through the real autoload, hooks, sealed spool, sink and reader.
Each negative test edits a copy of the reader's output (or the delivered bytes) and asserts
the named check now fails.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sc_ra1 import check, model
from sc_ra1.harness import Canaries, Harness, Options, Result


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Harness, dict[str, Any]]]:
    out = tmp_path_factory.mktemp("sc-ra1")
    harness = Harness(Options(mode="replay", out=out))
    found: dict[str, Any] = {}
    for name in ("mcp-stdio", "safety-openai"):
        session = harness.session(name)
        found[name] = {
            "on": harness.run(session, capture=True),
            "off": harness.run(session, capture=False),
        }
    yield harness, found


def _safety(name: str) -> list[dict[str, Any]]:
    doc = json.loads(model.CASSETTE.read_text())
    rows = []
    for entry in doc["sessions"][name]["responses"]:
        if "contract_fixture" in entry:
            fixture = json.loads((model.REPO / entry["contract_fixture"]).read_text())
            rows += fixture["cases"][entry["case"]]["rows"]
    return rows


def _checks(harness: Harness, result: Result) -> dict[str, check.Check]:
    found = check.check_session(result, harness.canaries, _safety(result.session.name))
    return {c.name: c for c in found.checks}


def _edited(result: Result, edit: Callable[[list[dict[str, Any]]], None]) -> Result:
    actions = copy.deepcopy(result.actions)
    (run,) = [r for r in actions["runs"] if any(x["kind"] == "model_call" for x in r["rows"])]
    edit(run["rows"])
    return replace(result, actions=actions)


@pytest.mark.parametrize("name", ["mcp-stdio", "safety-openai"])
def test_every_check_passes_on_the_real_run(
    runs: tuple[Harness, dict[str, Any]], name: str
) -> None:
    harness, found = runs
    on, off = found[name]["on"], found[name]["off"]
    failed = [c for c in _checks(harness, on).values() if not c.ok]
    assert not failed, failed
    assert check.check_identity(on, off).ok
    assert all(c.ok for c in check.check_canaries(on, harness.canaries))


def _drop(kind: str, **match: Any) -> Callable[[list[dict[str, Any]]], None]:
    def edit(rows: list[dict[str, Any]]) -> None:
        index = next(
            i
            for i, r in enumerate(rows)
            if r["kind"] == kind and all(r.get(k) == v for k, v in match.items())
        )
        del rows[index]

    return edit


def _change(
    kind: str, field: str, value: Any, **match: Any
) -> Callable[[list[dict[str, Any]]], None]:
    def edit(rows: list[dict[str, Any]]) -> None:
        row = next(
            r for r in rows if r["kind"] == kind and all(r.get(k) == v for k, v in match.items())
        )
        row[field] = value

    return edit


def _add_control(rows: list[dict[str, Any]]) -> None:
    rows.append(
        {
            "kind": "control",
            "control_kind": "permission_check",
            "phase": "observation",
            "decision": "deny",
            "attempt_uid": "x",
            "n": 999,
        }
    )


@pytest.mark.parametrize(
    ("session", "edit", "failing"),
    [
        ("mcp-stdio", _drop("control", phase="resolution"), "events.elicitation"),
        (
            "mcp-stdio",
            _change("control", "decision", "allow", phase="resolution"),
            "events.elicitation",
        ),
        ("mcp-stdio", _add_control, "events.no_other_control"),
        ("mcp-stdio", _drop("grant", basis="listed"), "events.listed_grants"),
        (
            "mcp-stdio",
            _change("grant", "id", "grt-" + "0" * 32, basis="listed"),
            "grant_ids.listed",
        ),
        (
            "mcp-stdio",
            _change("grant", "id", "grt-" + "0" * 32, basis="offered"),
            "grant_ids.offered",
        ),
        (
            "mcp-stdio",
            _change("grant", "tool_choice", "auto", basis="offered", tool_choice="required"),
            "events.offered_grants",
        ),
        ("mcp-stdio", _drop("extension", observed_via="process_launch"), "events.extensions"),
        (
            "mcp-stdio",
            _change("extension", "annotations", {}, observed_via="mcp_tools_list"),
            "events.extensions",
        ),
        (
            "mcp-stdio",
            _change("mcp_call", "outcome", "ok", outcome="tool_error"),
            "events.mcp_calls",
        ),
        (
            "mcp-stdio",
            _change("model_call", "offered_grant_id", None),
            "grant_ids.model_call_offered_grant_id",
        ),
        (
            "safety-openai",
            _drop("control", control_kind="provider_safety"),
            "events.provider_safety",
        ),
        (
            "safety-openai",
            _change("control", "stage", "input", control_kind="provider_safety"),
            "events.provider_safety",
        ),
    ],
)
def test_a_wrong_record_fails_its_check(
    runs: tuple[Harness, dict[str, Any]],
    session: str,
    edit: Callable[[list[dict[str, Any]]], None],
    failing: str,
) -> None:
    harness, found = runs
    checks = _checks(harness, _edited(found[session]["on"], edit))
    assert not checks[failing].ok, failing


def test_a_changed_output_fails_identity(runs: tuple[Harness, dict[str, Any]]) -> None:
    _, found = runs
    on, off = found["mcp-stdio"]["on"], found["mcp-stdio"]["off"]
    outputs = copy.deepcopy(off.outputs)
    outputs["mcp-stdio"]["tools"][0]["stdout"] = "changed"
    assert not check.check_identity(on, replace(off, outputs=outputs)).ok


def test_a_canary_in_the_spool_or_the_export_fails(
    runs: tuple[Harness, dict[str, Any]], tmp_path: Path
) -> None:
    harness, found = runs
    on = found["mcp-stdio"]["on"]
    leaked = replace(on, spool_bytes=on.spool_bytes + harness.canaries.elicitation.encode())
    failed = {c.name for c in check.check_canaries(leaked, harness.canaries) if not c.ok}
    assert failed == {"canaries.elicitation"}
    leaked = replace(on, view=on.view + harness.canaries.system)
    failed = {c.name for c in check.check_canaries(leaked, harness.canaries) if not c.ok}
    assert failed == {"canaries.system_prompt"}


def test_the_root_canary_is_the_secret_directory_not_a_generic_segment() -> None:
    """CI regression: the root needle was ``root.split("/")[3]``, which is ``home``; every
    Linux path (``/home/runner``) then matched it and the secret itself was never searched."""
    canaries = Canaries.fresh()
    needle = canaries.needles()["mcp_root"]
    assert needle.startswith("scra1-secret-") and len(needle) > len("scra1-secret-")
    assert needle in canaries.root and needle not in "/home/runner/work/_temp/sc-ra1"
