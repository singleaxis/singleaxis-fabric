# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact annotation membership must be complete, bound, and privacy-minimal."""

import copy
import io
import json
from urllib.error import HTTPError

import pytest

from scripts.qualification import report_codeql_pr_annotations as report

SHA = "a" * 40
PREFIX = "/repos/example/repo/"


def check(count=1):
    return {
        "id": 17,
        "name": "CodeQL",
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "failure",
        "app": {"slug": "github-advanced-security"},
        "pull_requests": [{"number": 165, "head": {"sha": SHA}}],
        "output": {"annotations_count": count},
    }


def annotation(line=1):
    return {
        "path": "sdk/python/example.py",
        "start_line": line,
        "end_line": line,
        "annotation_level": "warning",
        "title": "py/file-not-closed",
        "message": "PRIVATE_CONTENT_MUST_NOT_APPEAR",
        "raw_details": "SECRET",
    }


def getter(current, items, *, final=None, other=()):
    def get(route):
        if "/commits/" in route:
            runs = [*other, current]
            return {"total_count": len(runs), "check_runs": runs}
        if "/annotations?" in route:
            page = int(route.rsplit("=", 1)[1])
            return items[(page - 1) * 100 : page * 100]
        return current if final is None else final

    return get


def test_complete_paginated_exact_head_membership_omits_messages():
    current = check(101)
    result = report.collect(
        getter(current, [annotation(i + 1) for i in range(101)]),
        "example/repo",
        SHA,
        165,
        0,
    )
    assert result["membership_verified"] is True
    assert result["check_conclusion"] == "failure"
    assert result["annotations_count"] == len(result["annotations"]) == 101
    assert result["security_acceptance"] == "not_determined_by_diagnostic"
    assert "PRIVATE_CONTENT" not in json.dumps(result)
    assert "SECRET" not in json.dumps(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "b" * 40),
        ("name", "other"),
        ("app", {"slug": "github-actions"}),
        ("pull_requests", [{"number": 164, "head": {"sha": SHA}}]),
        ("status", "in_progress"),
    ],
)
def test_wrong_or_pending_check_never_claims_membership(field, value):
    current = check()
    current[field] = value
    with pytest.raises(
        report.DiagnosticError, match="completed_codeql_check_unavailable"
    ):
        report.collect(getter(current, [annotation()]), "example/repo", SHA, 165, 0)


def test_newer_pending_run_wins_over_old_completed():
    older = check()
    current = dict(older, id=18, status="in_progress")
    with pytest.raises(report.DiagnosticError):
        report.collect(
            getter(current, [annotation()], other=[older]), "example/repo", SHA, 165, 0
        )


@pytest.mark.parametrize(
    "count,items", [(2, [annotation()]), (0, [annotation()]), (1001, [])]
)
def test_partial_or_oversized_membership_fails(count, items):
    with pytest.raises(report.DiagnosticError):
        report.collect(getter(check(count), items), "example/repo", SHA, 165, 0)


def test_check_update_during_read_fails():
    current = check()
    changed = copy.deepcopy(current)
    changed["output"]["annotations_count"] = 2
    with pytest.raises(report.DiagnosticError, match="changed_during_read"):
        report.collect(
            getter(current, [annotation()], final=changed), "example/repo", SHA, 165, 0
        )


@pytest.mark.parametrize(
    "path",
    ["../secret", "/etc/passwd", "a/../secret", "a\nsecret", "https://other/secret"],
)
def test_annotation_paths_are_not_freeform_output(path):
    item = annotation()
    item["path"] = path
    with pytest.raises(report.DiagnosticError):
        report.annotation_metadata(item)


def test_unknown_rule_title_not_inferred_from_prose():
    item = annotation()
    item["title"] = "Sensitive freeform title"
    assert report.annotation_metadata(item)["rule_id_if_reported"] is None


@pytest.mark.parametrize(
    "route",
    [
        "https://other/secret",
        PREFIX + "issues/1",
        PREFIX + "check-runs/17/annotations?per_page=100&page=1&redirect=other",
        "/repos/other/repo/check-runs/17",
    ],
)
def test_transport_never_requests_unapproved_route(route):
    reader = report.ChecksReader("example/repo", "PRIVATE_TOKEN", float("inf"))

    class NoNetwork:
        def open(self, *args, **kwargs):
            pytest.fail("must not make request")

    reader.opener = NoNetwork()
    with pytest.raises(report.DiagnosticError, match="invalid_api_route"):
        reader(route)


def test_denied_api_output_never_contains_token_or_remote_body(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/repo")
    monkeypatch.setenv("CODEQL_PR_HEAD_SHA", SHA)
    monkeypatch.setenv("CODEQL_PR_NUMBER", "165")
    monkeypatch.setenv("GITHUB_TOKEN", "PRIVATE_TOKEN")

    class Denied:
        def open(self, request, **kwargs):
            assert request.get_method() == "GET"
            assert request.full_url.startswith(
                "https://api.github.com/repos/example/repo/"
            )
            assert request.get_header("Authorization") == "Bearer PRIVATE_TOKEN"
            raise HTTPError(
                request.full_url, 403, "PRIVATE_TOKEN", {}, io.BytesIO(b"SECRET")
            )

    monkeypatch.setattr(report, "build_opener", lambda *args: Denied())
    assert report.main() == 1
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "membership_verified": False,
        "diagnostic_error": "github_http_403",
    }
    assert "PRIVATE_TOKEN" not in output and "SECRET" not in output


def test_redirect_handler_never_forwards_request():
    assert (
        report.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other/")
        is None
    )


def test_check_list_is_paginated_and_deduplicated():
    target = check()
    target["id"] = 201
    first = [dict(check(), id=i, name="unrelated") for i in range(1, 101)]
    routes = []

    def get(route):
        routes.append(route)
        return {
            "total_count": 101,
            "check_runs": first if route.endswith("page=1") else [target],
        }

    assert report.select_check(get, PREFIX, SHA, 165) == target
    assert len(routes) == 2
    with pytest.raises(report.DiagnosticError, match="duplicate_check_identity"):
        report.select_check(
            lambda _: {"total_count": 2, "check_runs": [check(), check()]},
            PREFIX,
            SHA,
            165,
        )


def test_deadline_never_starts_http_request():
    reader = report.ChecksReader("example/repo", "PRIVATE_TOKEN", 0)
    with pytest.raises(report.DiagnosticError, match="deadline"):
        reader(PREFIX + "check-runs/17")
