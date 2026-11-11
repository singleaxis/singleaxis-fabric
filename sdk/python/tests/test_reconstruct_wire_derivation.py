# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 P1, WP7-4 to WP7-6: the reader's wire derivation rules on real exports, and the
``grant_in_force`` join.

The fixture runs are exports built by the verifier tests' capture helper (it plays the
capture worker: model exchanges with their stored bytes, records-input records shaped as
the SDK emits them). Each goes through ``fabric.reconstruct`` with the derivation rules
asked for; the run report and the ``actions`` view are compared with
``tests/goldens/security_reader/<fixture>.report.json`` and ``.view.txt``
(``FABRIC_UPDATE_GOLDENS=1`` rewrites them). Each fixture also states its expectations
in code. The dialect rules themselves are tested on documents below.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from fabric._rec_grant import grant_digest, grant_id, normalise_grant
from fabric.reconstruct import _security, reconstruct
from fabric.reconstruct.__main__ import _view, format_actions, main
from fabric.reconstruct._attribute import ActionReader
from fabric.reconstruct._derive import Derivation
from fabric.reconstruct._graph import RunGraph
from fabric.reconstruct._project import ProjectionCollector, build_projection
from fabric.reconstruct.dialects import offered_grant, safety_map, tool_result
from fabric.reconstruct.dialects.tool_result import MarkerTable
from tests.test_reconstruct_project import validate_projection
from tests.test_reconstruct_security import (
    FORBIDDEN,
    ID_KEY,
    Loop,
    SecurityCapture,
    begin,
    check_golden,
    end,
    pid,
)
from tests.test_reconstruct_verifier import (
    GENERATED_AT,
    RUN,
    SYSTEM,
    USER,
    chat_request,
    chat_response,
    validate,
)
from tests.test_reconstruct_verifier import (
    tool_result as chat_tool_result,
)

ROOT = Path(__file__).resolve().parents[3]
COVERAGE = ROOT / "contracts" / "coverage" / "v1"
SAFETY_MAP = COVERAGE / "registry" / "provider-safety-map-v1.json"
REFUSAL = "permission denied: /etc"
WIRE = ("wire",)


# ============================================================================ WP7-4 rules
def _chat_tools(*names: str) -> list[dict[str, Any]]:
    return [{"type": "function", "function": {"name": n, "parameters": {"type": "object"}}}
            for n in names]  # fmt: skip


CHAT_REQUEST: dict[str, Any] = {
    "model": "gpt-4o", "messages": [SYSTEM, USER], "tools": _chat_tools("read_file", "shell"),
    "tool_choice": "auto", "parallel_tool_calls": False,
}  # fmt: skip
RESPONSES_REQUEST: dict[str, Any] = {
    "model": "gpt-4.1", "instructions": "You operate a workspace.", "input": "List /work.",
    "tools": [
        {"type": "function", "name": "read_file", "parameters": {"type": "object"}},
        {"type": "web_search_preview"},
        {"type": "mcp", "server_label": "repo-tools", "server_url": "https://mcp.example"},
    ],
    "tool_choice": {"type": "allowed_tools", "mode": "auto",
                    "tools": [{"type": "function", "name": "read_file"}]},
}  # fmt: skip
ANTHROPIC_REQUEST: dict[str, Any] = {
    "model": "claude-x", "max_tokens": 64, "system": "You operate a workspace.",
    "messages": [{"role": "user", "content": "List /work."}],
    "tools": [
        {"name": "read_file", "input_schema": {"type": "object"}},
        {"type": "web_search_20250305", "name": "web_search"},
    ],
    "tool_choice": {"type": "tool", "name": "read_file", "disable_parallel_tool_use": True},
}  # fmt: skip


def _offer(api: str, request: Mapping[str, Any], exchange: str = "ex-1") -> Any:
    found = offered_grant.offered(api, dict(request), exchange_id=exchange,
                                  endpoint_id="ep", key=ID_KEY)  # fmt: skip
    assert found is not None
    return found


@pytest.mark.parametrize(
    ("api", "request_doc", "tools", "choice"),
    [
        ("openai.chat_completions", CHAT_REQUEST,
         [("read_file", "function"), ("shell", "function")],
         {"mode": "auto", "allowed_count": None, "parallel": False}),
        ("openai.responses", RESPONSES_REQUEST,
         [("read_file", "function"), ("web_search_preview", "provider_hosted"),
          ("repo-tools", "mcp")],
         {"mode": "allowed_subset", "allowed_count": 1, "parallel": None}),
        ("anthropic.messages", ANTHROPIC_REQUEST,
         [("read_file", "function"), ("web_search", "provider_hosted")],
         {"mode": "specific", "allowed_count": 1, "parallel": False}),
    ],
)  # fmt: skip
def test_offered_grant_per_supported_dialect(
    api: str, request_doc: dict[str, Any], tools: list[tuple[str, str]], choice: dict[str, Any]
) -> None:
    found = _offer(api, request_doc)
    document = found.document
    assert document["basis"] == "offered"
    assert document["source"] == {"boundary": "llm_wire", "endpoint_id": "ep"}
    assert [(t["name"], t["type"]) for t in document["tools_offered"]] == tools
    for tool, raw in zip(document["tools_offered"], request_doc["tools"], strict=True):
        assert re.fullmatch(r"[0-9a-f]{64}", tool["definition_sha256"])
        assert "parameters" not in tool and "input_schema" not in tool and raw  # names only
    assert document["tool_choice"] == choice
    assert document["instructions_digest"].startswith("sha256:")  # C20, never the text
    assert "workspace" not in json.dumps(document) and "weather" not in json.dumps(document)
    assert document["request_ref"] == {"exchange_id": "ex-1", "locator": "/tools"}
    # G01: the id the SDK's record_grant gives the same document under the same key
    assert found.digest == grant_digest(document)
    assert found.grant_id == grant_id(found.digest, ID_KEY)


def test_offered_digest_is_stable_across_requests_with_the_same_set() -> None:
    """A different request (other messages, other id, tools reordered and repeated) that
    offers the same set gives the same digest and id; one tool less gives another."""
    first = _offer("openai.chat_completions", CHAT_REQUEST, "ex-1")
    later = dict(
        CHAT_REQUEST,
        messages=[SYSTEM, USER, {"role": "user", "content": "more"}],
        tools=list(reversed(CHAT_REQUEST["tools"])) + CHAT_REQUEST["tools"][:1],
    )
    second = _offer("openai.chat_completions", later, "ex-9")
    assert (second.digest, second.grant_id) == (first.digest, first.grant_id)
    assert normalise_grant(second.document) == normalise_grant(first.document)
    fewer = dict(CHAT_REQUEST, tools=CHAT_REQUEST["tools"][:1])
    assert _offer("openai.chat_completions", fewer).grant_id != first.grant_id
    other_system = dict(CHAT_REQUEST, messages=[{"role": "system", "content": "x"}, USER])
    assert _offer("openai.chat_completions", other_system).grant_id != first.grant_id


@pytest.mark.parametrize(
    ("api", "fields", "expected"),
    [
        ("openai.chat_completions", {}, ("auto", None, None)),
        ("openai.chat_completions", {"tools": []}, ("none", None, None)),
        ("openai.chat_completions", {"tool_choice": "none"}, ("none", None, None)),
        ("openai.chat_completions", {"tool_choice": "required", "parallel_tool_calls": True},
         ("required", None, True)),
        ("openai.chat_completions",
         {"tool_choice": {"type": "function", "function": {"name": "shell"}}},
         ("specific", 1, None)),
        ("openai.chat_completions",
         {"tool_choice": {"type": "allowed_tools", "allowed_tools": {
             "mode": "required", "tools": [{"type": "function", "function": {"name": "a"}},
                                           {"type": "function", "function": {"name": "b"}}]}}},
         ("allowed_subset", 2, None)),
        ("openai.chat_completions", {"tool_choice": "sometimes"}, ("unknown", None, None)),
        ("openai.chat_completions", {"tool_choice": 7}, ("unknown", None, None)),
        ("openai.responses", {"tool_choice": {"type": "file_search"}}, ("specific", 1, None)),
        ("anthropic.messages", {"tool_choice": {"type": "any"}}, ("required", None, None)),
        ("anthropic.messages", {"tool_choice": {"type": "auto",
                                                "disable_parallel_tool_use": False}},
         ("auto", None, True)),
        ("anthropic.messages", {"tool_choice": {"type": "none"}}, ("none", None, None)),
        ("anthropic.messages", {"tool_choice": {"type": "mystery"}}, ("unknown", None, None)),
    ],
)  # fmt: skip
def test_tool_choice_is_normalised_from_the_literal(
    api: str, fields: dict[str, Any], expected: tuple[Any, ...]
) -> None:
    base = {"openai.chat_completions": CHAT_REQUEST, "openai.responses": RESPONSES_REQUEST,
            "anthropic.messages": ANTHROPIC_REQUEST}[api]  # fmt: skip
    request = {k: v for k, v in base.items() if k not in ("tool_choice", "parallel_tool_calls")}
    request.update(fields)
    choice = _offer(api, request).tool_choice
    assert (choice["mode"], choice["allowed_count"], choice["parallel"]) == expected


def test_no_offered_grant_outside_the_tool_dialects_or_for_malformed_tools() -> None:
    for api in ("openai.embeddings", "openai.completions", "gemini.generate"):
        assert offered_grant.offered(api, {"tools": []}, exchange_id="x", endpoint_id=None,
                                     key=ID_KEY) is None  # fmt: skip
    bad = dict(CHAT_REQUEST, tools={"name": "x"})
    assert offered_grant.offered("openai.chat_completions", bad, exchange_id="x",
                                 endpoint_id=None, key=ID_KEY) is None  # fmt: skip
    keyless = offered_grant.offered("openai.chat_completions", CHAT_REQUEST, exchange_id="x",
                                    endpoint_id=None, key=None)  # fmt: skip
    assert keyless is not None and keyless.grant_id is None  # G01: omitted without a key


# ============================================================================ WP7-5 rules
def _safety_map() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(SAFETY_MAP.read_text(encoding="utf-8"))
    return document


def test_the_shipped_rows_are_the_confirmed_rows_of_the_contract_map() -> None:
    rows = {row["id"]: row for row in _safety_map()["rows"]}
    confirmed = {i for i, row in rows.items() if row["status"] == "confirmed"}
    assert confirmed == set(safety_map.ROWS)
    for row_id, row in safety_map.ROWS.items():
        contract = rows[row_id]
        assert (
            contract["dialect"],
            contract["signal"],
            contract["stage"],
            contract["decision"],
        ) == (row.dialect, row.signal, row.stage, row.decision)
    # Dialects the wire parser does not read stay pending and project nothing.
    pending = {row["dialect"] for i, row in rows.items() if i not in confirmed}
    assert {"bedrock_converse", "gemini_generate"} <= pending


def _fixture(row_id: str) -> dict[str, Any]:
    row = next(r for r in _safety_map()["rows"] if r["id"] == row_id)
    document: dict[str, Any] = json.loads(
        (COVERAGE / row["fixture_id"]).read_text(encoding="utf-8")
    )
    return document


def _map_rows(api: str, response: Any, stream: bool = False) -> list[dict[str, Any]]:
    return [{"row": r.row_id, "signal": r.signal, "stage": r.stage, "decision": r.decision,
             **({"reason_code": r.reason_code} if r.reason_code else {})}
            for r in safety_map.safety_rows(api, response, stream=stream)]  # fmt: skip


@pytest.mark.parametrize("row_id", sorted(safety_map.ROWS))
def test_every_map_row_against_its_response_fixture(row_id: str) -> None:
    """Each fixture holds the response cases of its row (``with``: the field present;
    ``without``: the same response with the field absent or benign) and the rows each
    gives; every case of every fixture is read by the dialect rule."""
    fixture = _fixture(row_id)
    assert fixture["row_id"] == row_id
    api = safety_map.ROWS[row_id].api
    assert fixture["api"] == api
    for case in fixture["cases"]:
        got = _map_rows(api, case["response"], stream=case.get("stream", False))
        assert got == case["rows"], (row_id, case["name"])
    assert any(row_id in [r["row"] for r in c["rows"]] for c in fixture["cases"])
    assert any(c["rows"] == [] for c in fixture["cases"])  # no row when the field is absent


def test_no_text_heuristics_a_refusal_like_sentence_without_the_field_gives_nothing() -> None:
    sentence = "I'm sorry, but I can't help with that. This request was blocked by a filter."
    chat = chat_response({"role": "assistant", "content": sentence}, "chatcmpl-x")
    assert safety_map.safety_rows("openai.chat_completions", chat, stream=False) == []
    responses = {"id": "resp_1", "status": "completed", "output": [{
        "type": "message", "role": "assistant",
        "content": [{"type": "output_text", "text": sentence}]}]}  # fmt: skip
    assert safety_map.safety_rows("openai.responses", responses, stream=False) == []
    anthropic = {"id": "msg_1", "type": "message", "role": "assistant", "stop_reason": "end_turn",
                 "content": [{"type": "text", "text": sentence}]}  # fmt: skip
    assert safety_map.safety_rows("anthropic.messages", anthropic, stream=False) == []
    assert (
        safety_map.safety_rows(
            "gemini.generate", {"promptFeedback": {"blockReason": "X"}}, stream=False
        )
        == []
    )  # a dialect the parser does not read


def test_a_filtered_category_that_fails_the_reason_pattern_is_left_out() -> None:
    response = chat_response({"role": "assistant", "content": None}, "c", "content_filter")
    response["choices"][0]["content_filter_results"] = {"Hate Speech!": {"filtered": True}}
    (row,) = safety_map.safety_rows("openai.chat_completions", response, stream=False)
    assert (row.row_id, row.reason_code) == ("azure.choice_filter_results.filtered", None)


# ============================================================================ WP7-6 rules
def test_tool_results_carry_the_dialects_structured_flag() -> None:
    anthropic = {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu_1", "content": "ok"},
        {"type": "tool_result", "tool_use_id": "tu_2", "is_error": True,
         "content": [{"type": "text", "text": "exit 1"}]},
        {"type": "tool_result", "tool_use_id": "tu_3", "is_error": False, "content": "fine"},
    ]}]}  # fmt: skip
    found = tool_result.tool_results("anthropic.messages", anthropic)
    assert [(r.call_id, r.is_error, r.text) for r in found] == [
        ("tu_1", None, "ok"), ("tu_2", True, "exit 1"), ("tu_3", False, "fine")]  # fmt: skip
    chat = {"messages": [chat_tool_result("call_1", "boom")]}
    assert [(r.call_id, r.is_error) for r in tool_result.tool_results(
        "openai.chat_completions", chat)] == [("call_1", None)]  # fmt: skip
    responses = {"input": [{"type": "function_call_output", "call_id": "fc_1", "output": "x"}]}
    assert [(r.call_id, r.is_error) for r in tool_result.tool_results(
        "openai.responses", responses)] == [("fc_1", None)]  # fmt: skip


MARKERS: list[dict[str, Any]] = [
    {"label": "fs-acl", "equals": REFUSAL, "reason_code": "path.outside_root"},
    {"label": "shell-gate", "prefix": "blocked by policy", "decision": "escalate",
     "kind": "policy"},
    {"label": "api-acl", "json": {"pointer": "/error/code", "values": ["forbidden", 403]}},
]  # fmt: skip


@pytest.mark.parametrize(
    ("text", "label"),
    [
        (REFUSAL, "fs-acl"),
        ("blocked by policy: rm -rf", "shell-gate"),
        ("blocked by policy", "shell-gate"),
        ('{"error": {"code": "forbidden", "detail": "no"}}', "api-acl"),
        ('{"error": {"code": 403}}', "api-acl"),
    ],
)
def test_one_fixture_per_matching_rule(text: str, label: str) -> None:
    marker = MarkerTable.load(MARKERS).match(text)
    assert marker is not None and marker.label == label


@pytest.mark.parametrize(
    "text",
    [
        "permission denied: /etd",  # one byte
        "Permission denied: /etc",  # case
        " permission denied: /etc",  # leading space
        "permission denied: /etc\n",  # a trailing byte: equals is whole-text
        "error: permission denied: /etc",  # inside the text: no search
        "Blocked by policy: rm",  # case on a prefix
        " blocked by policy",  # leading space on a prefix
        '{"error": {"code": "Forbidden"}}',  # case in a JSON value
        '{"error": {"code": "403"}}',  # 403 the string, not the number
        '{"error": {"code": true}}',  # a bool is not a listed literal
        '{"err": {"code": "forbidden"}}',  # the pointer resolves nowhere
        '{"error": {"code": "forbidden"}',  # not JSON
        "",
    ],
)
def test_a_near_miss_produces_nothing(text: str) -> None:
    assert MarkerTable.load(MARKERS).match(text) is None


def test_a_marker_declaring_allow_is_refused_at_load_with_a_status() -> None:
    entries = [*MARKERS, {"label": "ok-gate", "equals": "ok", "decision": "allow"},
               {"label": "bad", "equals": "marker-x", "prefix": "marker-y"}]  # fmt: skip
    table = MarkerTable.load(entries)
    assert table.status == "active" and len(table.markers) == 3
    assert table.refused == ((3, "decision_allow"), (4, "invalid"))
    assert table.match("ok") is None  # never an allow row
    summary = table.summary()
    assert summary["refused"] == [{"index": 3, "reason": "decision_allow"},
                                  {"index": 4, "reason": "invalid"}]  # fmt: skip
    assert summary["count"] == 5 and summary["loaded"] == 3
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", summary["sha256"])
    only_allow = MarkerTable.load([{"label": "ok-gate", "equals": "ok", "decision": "allow"}])
    assert only_allow.status == "refused" and only_allow.markers == ()
    assert MarkerTable.load("not a list").status == "refused"
    assert MarkerTable.load([{"label": "x", "equals": "y"}] * 257).refused == ((0, "over_limit"),)
    # The table's report form never holds a marker string.
    text = json.dumps(table.summary())
    for entry in entries:
        for value in (entry.get("equals"), entry.get("prefix"), entry["label"]):
            assert value is None or json.dumps(value)[1:-1] not in text


# ============================================================================ exports
def read(paths: list[Path], store: Any, derivation: Derivation
         ) -> tuple[dict[str, Any], dict[str, Any], str, list[Any]]:  # fmt: skip
    """The report, the step projection, the ``actions`` view text and its rows, with the
    derivation rules applied."""
    reader = ActionReader(every_run=True, keep_runs=True, derivation=derivation)
    collector = ProjectionCollector()
    graphs: list[RunGraph] = []
    report = reconstruct(paths, store=store, generated_at=GENERATED_AT, id_key=ID_KEY,
                         actions=reader, projection_sink=collector, graphs_out=graphs)  # fmt: skip
    validate(report)
    projection = build_projection(
        report, graphs=graphs, reconstruction_sha256="sha256:" + "0" * 64,
        evaluated_at=GENERATED_AT, collector=collector,
    )  # fmt: skip
    assert projection is not None
    validate_projection(projection)
    views = [_view(run, report) for run in reader.runs]
    text = "\n".join(format_actions(view) for view in views)
    return report, projection, text, views


Built = tuple[dict[str, Any], dict[str, Any], str, list[Any]]
FIXTURES: dict[str, Callable[[Path], Built]] = {}


def fixture(name: str) -> Callable[[Callable[[Path], Built]], Callable[[Path], Built]]:
    def register(fn: Callable[[Path], Built]) -> Callable[[Path], Built]:
        FIXTURES[name] = fn
        return fn

    return register


def _only(report: Mapping[str, Any]) -> dict[str, Any]:
    (run,) = report["runs"]
    return dict(run)


def _facts(run: Mapping[str, Any]) -> dict[str, int]:
    return {f["code"]: f["count"] for f in run["security_context"]["facts"]}


def _call_message(*calls: tuple[str, str]) -> dict[str, Any]:
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": c, "type": "function", "function": {"name": n, "arguments": "{}"}}
        for c, n in calls]}  # fmt: skip


class OfferLoop(Loop):
    """The plain tool loop, offering the model the tools it goes on to call."""

    OFFER = ("write_file", "shell", "fetch", "read_file")

    def turn(self, *calls: tuple[str, str], results: tuple[tuple[str, str], ...] = ()) -> None:
        self.messages += [chat_tool_result(call, text) for call, text in results]
        message = _call_message(*calls) if calls else {"role": "assistant", "content": "Done."}
        response = chat_response(message, f"chatcmpl-{self.turns}",
                                 "tool_calls" if calls else "stop")  # fmt: skip
        self.capture.exchange(chat_request(list(self.messages), tools=_chat_tools(*self.OFFER)),
                              response)  # fmt: skip
        self.turns += 1
        if calls:
            self.messages.append(message)


@fixture("sc-wire-offered-grants")
def sc_wire_offered_grants(root: Path) -> Built:
    """A tool loop whose offered set changes mid-run (a tool is dropped, then the agent
    restricts tool choice), and a replayed response naming a tool it was not offered."""
    cap = SecurityCapture(root)
    segment = begin(cap)
    tools = _chat_tools("read_file", "shell", "fetch_url")
    messages: list[dict[str, Any]] = [SYSTEM, USER]
    first = _call_message(("call_1", "read_file"))
    cap.exchange(
        {"model": "gpt-4o", "messages": messages, "tools": tools},
        chat_response(first, "chatcmpl-0", "tool_calls"),
        endpoint_id="openai",
    )
    messages = [*messages, first, chat_tool_result("call_1", "notes.txt")]
    second = _call_message(("call_2", "shell"))
    cap.exchange(
        {"model": "gpt-4o", "messages": messages, "tools": list(reversed(tools))},
        chat_response(second, "chatcmpl-1", "tool_calls"),
        endpoint_id="openai",
    )
    messages = [*messages, second, chat_tool_result("call_2", "done")]
    third = _call_message(("call_3", "fetch_url"))  # replayed: fetch_url is no longer offered
    cap.exchange(
        {
            "model": "gpt-4o",
            "messages": messages,
            "tools": tools[:2],
            "tool_choice": "required",
            "parallel_tool_calls": False,
        },
        chat_response(third, "chatcmpl-2", "tool_calls"),
        endpoint_id="openai",
    )
    messages = [*messages, third, chat_tool_result("call_3", "<html>")]
    cap.exchange({"model": "gpt-4o", "messages": messages, "tools": tools[:2],
                  "tool_choice": "none"},
                 chat_response({"role": "assistant", "content": "Done."}, "chatcmpl-3"),
                 endpoint_id="openai")  # fmt: skip
    end(cap, segment)
    return read([cap.write()], cap.store, Derivation.build(WIRE))


@fixture("sc-wire-safety-signals")
def sc_wire_safety_signals(root: Path) -> Built:
    """Provider safety signals of each supported dialect, replayed through the fixture
    model (one exchange per map row), and a refusal-like sentence without the field."""
    cap = SecurityCapture(root)
    segment = begin(cap)
    for row_id in sorted(safety_map.ROWS):
        case = next(c for c in _fixture(row_id)["cases"] if c["rows"])
        api = safety_map.ROWS[row_id].api
        request = _fixture(row_id)["request"]
        response: Any = case["response"]
        if case.get("stream"):
            response = "".join(f"data: {json.dumps(event)}\n\n" for event in response)
            response = (response + ("data: [DONE]\n\n" if api.startswith("openai.c") else "")
                        ).encode()  # fmt: skip
        cap.exchange(request, response, api=api, endpoint_id=row_id.split(".", 1)[0])
    sentence = "I'm sorry, but I can't help with that. This request was blocked."
    cap.exchange(chat_request([SYSTEM, USER]),
                 chat_response({"role": "assistant", "content": sentence}, "chatcmpl-z"),
                 endpoint_id="openai")  # fmt: skip
    end(cap, segment)
    return read([cap.write()], cap.store, Derivation.build(["wire.safety_map"]))


@fixture("sc-wire-tool-results")
def sc_wire_tool_results(root: Path) -> Built:
    """Anthropic tool results with and without ``is_error``, fed back and then repeated in
    the history; and chat tool results whose text a configured denial marker matches by
    each rule, with near misses beside them."""
    cap = SecurityCapture(root)
    segment = begin(cap)
    tools = [{"name": "shell", "input_schema": {"type": "object"}}]
    history: list[dict[str, Any]] = [{"role": "user", "content": "Build it."}]

    def turn(calls: list[str], results: list[dict[str, Any]], rid: str) -> None:
        nonlocal history
        if results:
            history = [*history, {"role": "user", "content": results}]
        content = [{"type": "tool_use", "id": c, "name": "shell", "input": {}} for c in calls]
        stop = "tool_use" if calls else "end_turn"
        if not calls:
            content = [{"type": "text", "text": "Done."}]
        response = {"id": rid, "type": "message", "role": "assistant", "model": "claude-x",
                    "content": content, "stop_reason": stop,
                    "usage": {"input_tokens": 10, "output_tokens": 5}}  # fmt: skip
        cap.exchange({"model": "claude-x", "max_tokens": 64, "messages": history,
                      "tools": tools}, response, api="anthropic.messages",
                     endpoint_id="anthropic")  # fmt: skip
        if calls:
            history = [*history, {"role": "assistant", "content": content}]

    turn(["tu_1", "tu_2"], [], "msg_0")
    turn(["tu_3"], [
        {"type": "tool_result", "tool_use_id": "tu_1", "content": "built"},
        {"type": "tool_result", "tool_use_id": "tu_2", "is_error": True,
         "content": [{"type": "text", "text": "exit 2: missing target"}]},
    ], "msg_1")  # fmt: skip
    turn([], [{"type": "tool_result", "tool_use_id": "tu_3", "is_error": False,
               "content": "ok"}], "msg_2")  # fmt: skip
    loop = OfferLoop(cap)
    loop.turn(("call_1", "write_file"), ("call_2", "shell"), ("call_3", "fetch"))
    loop.turn(("call_4", "write_file"), ("call_5", "shell"), results=(
        ("call_1", REFUSAL), ("call_2", "blocked by policy: rm -rf /"),
        ("call_3", '{"error": {"code": "forbidden"}}'),
    ))  # fmt: skip
    loop.turn(results=(("call_4", "Permission denied: /etc"),
                       ("call_5", " blocked by policy")))  # fmt: skip
    end(cap, segment)
    return read([cap.write()], cap.store, Derivation.build(WIRE, MARKERS))


def _grant_attrs(basis: str, grant: str, trigger: str = "run_start") -> dict[str, Any]:
    return {"fabric.grant.basis": basis, "fabric.grant.id": grant,
            "fabric.grant.trigger": trigger, "fabric.grant.source_boundary": "api"}  # fmt: skip


@fixture("sc-grant-in-force")
def sc_grant_in_force(root: Path) -> Built:
    """Reported grants and offered grants derived from the wire, with controls and tool
    calls before, between and after them."""
    cap = SecurityCapture(root)
    segment = begin(cap)
    loop = OfferLoop(cap)
    cap.control("permission_check", decision="allow", gated_kind="run", engine="startup")
    cap.grant("declared", "grt-" + "1" * 32, tools_allow=2)
    loop.turn(("call_1", "read_file"))
    cap.control("permission_check", decision="allow", engine="fs-read")
    cap.grant("declared", "grt-" + "2" * 32, trigger="change", previous="grt-" + "1" * 32,
              tools_allow=1)  # fmt: skip
    cap.control("permission_check", decision="deny", engine="fs-read", call="call_1")
    loop.turn(("call_2", "shell"), results=(("call_1", "permission denied"),))
    loop.turn(results=(("call_2", "ok"),))
    end(cap, segment)
    return read([cap.write()], cap.store, Derivation.build(["wire.offered_grant"]))


@fixture("sc-grant-in-force-ambiguous")
def sc_grant_in_force_ambiguous(root: Path) -> Built:
    """Grant snapshots from two processes of one run: a control after both cannot say
    which is latest (their order is a wall-clock order across processes)."""
    agent = SecurityCapture(root)
    segment = begin(agent, exec_channel=False)
    agent.grant("declared", "grt-" + "a" * 32)
    worker = SecurityCapture(root, source_id="s-" + "b" * 32, epoch=9, id_prefix="w")
    worker.manifest()
    other = worker.new_segment()
    worker.run_start(RUN, segment_id=other)
    worker._sdk("run", _grant_attrs("declared", "grt-" + "b" * 32))
    worker.run_end(RUN)
    worker.segment_seal(RUN, segment_id=other)
    worker.heartbeat()
    for _ in range(3):  # the agent's next records start after the worker's
        agent.heartbeat()
    agent.control("permission_check", decision="deny", gated_kind="run", engine="startup")
    end(agent, segment)
    return read([agent.write(), worker.write("worker.jsonl")], agent.store, Derivation())


EXPECTED: dict[str, dict[str, Any]] = {
    "sc-wire-offered-grants": {
        "controls": {"verdict": "complete"},
        "grants": {"offered": 3, "listed": 0, "declared": 0},
        "facts": {"no_declared_grant": 1, "grant_changed": 2, "tool_called_not_offered": 1},
    },
    "sc-wire-safety-signals": {
        "controls": {"verdict": "complete"},
        "control_links": {"exchange_id": 9},
        "facts": {"no_declared_grant": 1},
    },
    "sc-wire-tool-results": {
        "controls": {"verdict": "complete"},
        "control_links": {"provider_id": 3},
        "facts": {"no_declared_grant": 1, "grant_changed": 1, "control_denied": 2,
                  "tool_result_error": 1},
    },
    "sc-grant-in-force": {
        "controls": {"verdict": "complete"},
        "grants": {"offered": 1, "listed": 0, "declared": 2},
        "facts": {"grant_changed": 1, "control_denied": 1},
    },
    "sc-grant-in-force-ambiguous": {
        "controls": {"verdict": "complete"},
        "grants": {"offered": 0, "listed": 0, "declared": 2},
        "facts": {"grant_changed": 1},
    },
}  # fmt: skip


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_fixture_run_matches_its_golden_report_and_view(name: str, tmp_path: Path) -> None:
    report, _projection, text, _views = FIXTURES[name](tmp_path)
    runs = {"runs": report["runs"], "inputs": {"derivation": report["inputs"].get("derivation")}}
    check_golden(name, runs, text)
    assert not FORBIDDEN.search(text) and not FORBIDDEN.search(json.dumps(report))  # B6
    run = report["runs"][0] if name.endswith("ambiguous") else _only(report)
    expected = EXPECTED[name]
    assert run["chains"]["controls"] == expected["controls"], name
    if "grants" in expected:
        assert run["security_context"]["grants"] == expected["grants"], name
    if "control_links" in expected:
        assert run["security_context"]["control_links"] == expected["control_links"], name
    assert _facts(run) == expected["facts"], name


def _rows(views: list[Any], kind: str) -> list[dict[str, Any]]:
    return [row for view in views for row in view["rows"] if row["kind"] == kind]


def test_offered_grants_are_snapshots_per_change_and_every_call_names_its_grant(
    tmp_path: Path,
) -> None:
    report, projection, text, views = FIXTURES["sc-wire-offered-grants"](tmp_path)
    grants = [r for v in views for r in [*v.get("preamble", ()), *v["rows"]]
              if r["kind"] == "grant"]  # fmt: skip
    # the first call, then each change; the second request (same set, reordered) is none
    assert [g["counts"]["tools_offered"] for g in grants] == [3, 2, 2]
    assert [g["tool_choice"] for g in grants] == ["auto", "required", "none"]
    assert all(g["provenance"] == "observed" and g["trigger"] == "derived" for g in grants)
    assert (
        grants[1]["previous_id"] == grants[0]["id"] and grants[2]["previous_id"] == grants[1]["id"]
    )
    calls = _rows(views, "model_call")
    assert [c["offered_grant_id"] for c in calls] == [
        grants[0]["id"], grants[0]["id"], grants[1]["id"], grants[2]["id"]]  # fmt: skip
    # G16 on every model-call step of the projection
    steps = [s for s in projection["steps"] if s["step_kind"] == "model_call"]
    values = [s["layers"]["context"]["model_call.offered_grant_id"]["value"] for s in steps]
    assert sorted(values) == sorted(c["offered_grant_id"] for c in calls)
    # F12: the replayed response named fetch_url, which its own request no longer offered
    (flagged,) = [c for row in calls for c in row.get("tool_calls", ()) if c.get("not_offered")]
    assert flagged["name"] == "fetch_url"
    assert "(F12: T3 not in offered" in text
    assert report["inputs"]["derivation"] == {
        "rules": ["wire.offered_grant", "wire.safety_map", "wire.tool_result_flag"]}  # fmt: skip
    # the plain digest is never shown, only the keyed id
    for g in grants:
        assert g["id"].startswith("grt-")
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", g["instructions_digest"])  # G15 = C20
    digests = {s["layers"]["context"]["instructions.digest"]["value"] for s in steps}
    assert {g["instructions_digest"] for g in grants} == digests
    assert "instr sha256:" in text


def test_hosted_tool_calls_are_not_f12(tmp_path: Path) -> None:
    """A Responses hosted call (``web_search_call``) and an Anthropic ``server_tool_use``
    are provider-hosted by their literal type: never an un-offered tool call."""
    cap = SecurityCapture(tmp_path)
    segment = begin(cap)
    cap.exchange({"model": "gpt-4.1", "input": "Search.", "tools": [{"type": "function",
                  "name": "read_file", "parameters": {}}]},
                 {"id": "resp_1", "object": "response", "status": "completed", "model": "gpt-4.1",
                  "output": [{"type": "web_search_call", "id": "ws_1", "status": "completed"},
                             {"type": "function_call", "call_id": "fc_1", "name": "read_file",
                              "arguments": "{}"}]},
                 api="openai.responses")  # fmt: skip
    cap.exchange({"model": "claude-x", "max_tokens": 64, "messages": [
                     {"role": "user", "content": "Search."}],
                  "tools": [{"name": "read_file", "input_schema": {}}]},
                 {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
                  "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1},
                  "content": [{"type": "server_tool_use", "id": "srv_1", "name": "web_search",
                               "input": {}},
                              {"type": "tool_use", "id": "tu_1", "name": "read_file",
                               "input": {}}]},
                 api="anthropic.messages")  # fmt: skip
    end(cap, segment)
    report, _, _, _ = read([cap.write()], cap.store, Derivation.build(WIRE))
    assert "tool_called_not_offered" not in _facts(_only(report))


def test_safety_rows_name_their_model_call_and_evidence(tmp_path: Path) -> None:
    report, _, text, views = FIXTURES["sc-wire-safety-signals"](tmp_path)
    controls = _rows(views, "control")
    calls = {row["exchange_id"]: row["n"] for row in _rows(views, "model_call")}
    assert len(controls) == len(safety_map.ROWS) + 1  # the Azure fixture filters two categories
    for row in controls:
        assert (row["control_kind"], row["derivation"], row["phase"]) == (
            "provider_safety", "literal", "observation")  # fmt: skip
        assert row["signal"] in ("content_filter", "refusal") and row["decision"] != "allow"
        link = row["link"]
        assert (link["method"], link["confidence"], link["namespace"]) == (
            "exchange_id", "certain", "exchange")  # fmt: skip
        assert row["evidence"] == [link["target"]] and link["target_n"] == calls[link["target"]]
        assert row["n"] == link["target_n"] + 1 or row["n"] == link["target_n"] + 2
    # the refusal-like sentence without a field gave nothing: its model call has no row
    assert len({r["link"]["target"] for r in controls}) == len(calls) - 1
    run = _only(report)
    kinds = {(c["kind"], c["derivation"]) for c in run["security_context"]["controls"]}
    assert kinds == {("provider_safety", "literal")}
    assert "← model_call #" in text


def test_tool_result_flags_count_once_per_call_and_markers_link_by_provider_id(
    tmp_path: Path,
) -> None:
    report, _, text, views = FIXTURES["sc-wire-tool-results"](tmp_path)
    controls = _rows(views, "control")
    assert [(c["engine"], c["decision"], c["control_kind"], c["derivation"]) for c in controls] == [
        ("fs-acl", "deny", "permission_check", "configured_marker"),
        ("shell-gate", "escalate", "policy", "configured_marker"),
        ("api-acl", "deny", "permission_check", "configured_marker"),
    ]  # fmt: skip
    labels = [c["link"]["target"] for c in controls]
    assert labels == ["T4", "T5", "T6"]  # call_1..3 after the Anthropic loop's tu_1..3
    for row in controls:
        assert (row["link"]["method"], row["link"]["confidence"]) == ("provider_id", "certain")
    assert controls[0]["reason_code"] == "path.outside_root"
    # each marker row sits under the call it gates; the near misses (call_4, call_5) give none
    run = _only(report)
    assert _facts(run)["tool_result_error"] == 1  # tu_2 once, though the history repeats it
    assert "(is_error: T2)" in text
    without = {r["call"]: r["reason"] for v in views for r in v["tool_calls_without_effect"]}
    assert without["T4"] == without["T6"] == "control_denied"
    for value in (REFUSAL, "blocked by policy", "forbidden"):  # marker strings: never shown
        assert value not in text and value not in json.dumps(report)


def test_grant_in_force_on_every_control_and_tool_call(tmp_path: Path) -> None:
    _, projection, text, views = FIXTURES["sc-grant-in-force"](tmp_path)
    controls = _rows(views, "control")
    assert controls[0]["grant_in_force"] == {"grant_basis": "none"}
    assert controls[1]["grant_in_force"]["grant_basis"] == "observed"  # the offered grant of call 1
    assert controls[2]["grant_in_force"] == {"grant_basis": "reported", "certainty": "certain",
                                             "id": "grt-" + "2" * 32}  # fmt: skip
    calls = [c for row in _rows(views, "model_call") for c in row.get("tool_calls", ())]
    # call_2 comes after the second declared snapshot; its request offered the same set
    assert [c["grant_in_force"]["grant_basis"] for c in calls] == ["observed", "reported"]
    assert "in force none" in text and "in force grt-2222" in text
    links = [lk for s in projection["steps"] if s["step_kind"] == "control"
             for lk in s.get("links", ()) if lk.get("method") == "grant_in_force"]  # fmt: skip
    assert len(links) == 2 and links[1]["target"] == {"namespace": "external",
                                                      "id": "grt-" + "2" * 32}  # fmt: skip


def test_grant_in_force_across_processes_is_ambiguous(tmp_path: Path) -> None:
    _, _, text, views = FIXTURES["sc-grant-in-force-ambiguous"](tmp_path)
    (control,) = _rows(views, "control")
    in_force = control["grant_in_force"]
    assert in_force["certainty"] == "ambiguous"
    assert sorted(in_force["candidates"]) == ["grt-" + "a" * 32, "grt-" + "b" * 32]
    assert "in force ambiguous: " in text


def test_a_run_without_grants_carries_no_grant_in_force(tmp_path: Path) -> None:
    cap = SecurityCapture(tmp_path)
    segment = begin(cap)
    loop = OfferLoop(cap)
    loop.turn(("call_1", "write_file"))
    cap.control("permission_check", decision="deny", engine="fs-write")
    loop.turn(results=(("call_1", "no"),))
    end(cap, segment)
    _, projection, text, views = read([cap.write()], cap.store, Derivation())
    assert "grant_in_force" not in json.dumps(views) and "in force" not in text
    assert "grant_in_force" not in json.dumps(projection)


def test_without_derivation_a_wire_run_reports_exactly_as_before(tmp_path: Path) -> None:
    """§9.1: the rules are opt-in. The same export read with ``Derivation()`` and with no
    derivation argument gives the same report; with the rules it gains them."""
    cap = SecurityCapture(tmp_path)
    segment = begin(cap)
    OfferLoop(cap).turn(("call_1", "shell"))
    end(cap, segment)
    path = cap.write()
    plain = reconstruct([path], store=cap.store, generated_at=GENERATED_AT, id_key=ID_KEY,
                        actions=ActionReader())  # fmt: skip
    empty = reconstruct([path], store=cap.store, generated_at=GENERATED_AT, id_key=ID_KEY,
                        actions=ActionReader(derivation=Derivation()))  # fmt: skip
    assert plain == empty
    assert "derivation" not in plain["inputs"]
    assert plain["runs"][0]["security_context"] == _security.zero_context()
    derived, _, _, _ = read([path], cap.store, Derivation.build(WIRE))
    assert _only(derived)["security_context"]["grants"]["offered"] == 1


def test_cli_options_apply_the_rules_and_report_marker_refusals(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = SecurityCapture(tmp_path)
    segment = begin(cap)
    loop = OfferLoop(cap)
    loop.turn(("call_1", "write_file"))
    loop.turn(results=(("call_1", REFUSAL),))
    end(cap, segment)
    path = cap.write()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"security_context": {"tool_result_markers": [
        {"label": "fs-acl", "equals": REFUSAL},
        {"label": "ok", "equals": "ok", "decision": "allow"}]}}))  # fmt: skip
    out = tmp_path / "report.json"
    monkeypatch.setenv("F057_ID_KEY", ID_KEY.decode())
    common = ["--store-root", str(tmp_path / "store"), "--tenant", "tenant-a",
              "--id-key-env", "F057_ID_KEY"]  # fmt: skip
    main(["--spans", str(path), *common, "--out", str(out), "--derive", "wire.offered_grant",
          "--tool-result-markers", str(policy)])  # fmt: skip
    report = json.loads(out.read_text())
    assert report["inputs"]["derivation"]["rules"] == ["wire.offered_grant",
                                                       "wire.tool_result_marker"]  # fmt: skip
    markers = report["inputs"]["derivation"]["tool_result_markers"]
    assert (markers["status"], markers["count"], markers["loaded"]) == ("active", 2, 1)
    assert markers["refused"] == [{"index": 1, "reason": "decision_allow"}]
    assert REFUSAL not in out.read_text()
    controls = _only(report)["security_context"]["controls"]
    assert controls == [{"kind": "permission_check", "decision": "deny",
                         "derivation": "configured_marker", "count": 1}]  # fmt: skip
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    capsys.readouterr()
    assert main(["--spans", str(path), *common, "--tool-result-markers", str(bad)]) != 0
    assert "no tool_result_markers list" in capsys.readouterr().err


def test_marker_derivation_ignores_a_result_that_matches_nothing(tmp_path: Path) -> None:
    cap = SecurityCapture(tmp_path)
    segment = begin(cap)
    loop = OfferLoop(cap)
    loop.turn(("call_1", "write_file"))
    loop.turn(results=(("call_1", "written"),))
    end(cap, segment)
    report, _, _, views = read([cap.write()], cap.store, Derivation.build((), MARKERS))
    assert _rows(views, "control") == []
    assert _only(report)["security_context"]["controls"] == []
    assert pid("call_1").startswith("p-")
