#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Read exact completed CodeQL PR-check membership; never decide acceptance.

Requires only checks:read. No source excerpts, freeform finding messages, token,
remote error bodies, or links from API responses are emitted or followed.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_PAGES = 10
MAX_BYTES = 4 * 1024 * 1024


class DiagnosticError(Exception):
    """A closed, non-sensitive diagnostic reason."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ChecksReader:
    def __init__(self, repository: str, token: str, deadline: float):
        self.prefix = f"/repos/{repository}/"
        self.token = token
        self.deadline = deadline
        self.opener = build_opener(NoRedirect())

    def __call__(self, route: str) -> Any:
        suffix = route.removeprefix(self.prefix)
        if not route.startswith(self.prefix) or not re.fullmatch(
            r"(?:commits/[a-f0-9]{40}/check-runs\?per_page=100&page=[1-9][0-9]*"
            r"|check-runs/[1-9][0-9]*(?:/annotations\?per_page=100&page=[1-9][0-9]*)?)",
            suffix,
        ):
            raise DiagnosticError("invalid_api_route")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise DiagnosticError("poll_deadline_reached")
        request = Request(
            "https://api.github.com" + route,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self.token,
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=min(10, remaining)) as response:
                body = response.read(MAX_BYTES + 1)
        except HTTPError as error:
            code = error.code
            error.close()
            raise DiagnosticError(f"github_http_{code}") from None
        except (URLError, TimeoutError, OSError):
            raise DiagnosticError("github_transport_failure") from None
        if len(body) > MAX_BYTES:
            raise DiagnosticError("response_size_limit")
        try:
            return json.loads(body)
        except (ValueError, UnicodeError):
            raise DiagnosticError("invalid_github_json") from None


def positive(value: Any) -> bool:
    return type(value) is int and value > 0


def select_check(get: Any, prefix: str, sha: str, pr: int) -> dict[str, Any] | None:
    runs = []
    for page in range(1, MAX_PAGES + 1):
        result = get(f"{prefix}commits/{sha}/check-runs?per_page=100&page={page}")
        if not isinstance(result, dict) or not isinstance(
            result.get("check_runs"), list
        ):
            raise DiagnosticError("invalid_check_list")
        total = result.get("total_count")
        batch = result["check_runs"]
        if (
            type(total) is not int
            or not 0 <= total <= MAX_PAGES * 100
            or len(batch) > 100
        ):
            raise DiagnosticError("check_list_limit_or_shape")
        runs.extend(batch)
        if len(runs) >= total:
            if len(runs) != total:
                raise DiagnosticError("check_list_changed")
            break
    else:
        raise DiagnosticError("check_list_page_limit")
    if any(not isinstance(run, dict) or not positive(run.get("id")) for run in runs):
        raise DiagnosticError("invalid_check_identity")
    if len({run["id"] for run in runs}) != len(runs):
        raise DiagnosticError("duplicate_check_identity")
    matches = [
        run
        for run in runs
        if run.get("name") == "CodeQL"
        and run.get("head_sha") == sha
        and run.get("app", {}).get("slug") == "github-advanced-security"
        and any(
            item.get("number") == pr and item.get("head", {}).get("sha") == sha
            for item in run.get("pull_requests", [])
        )
    ]
    return max(matches, key=lambda run: run["id"]) if matches else None


def annotation_metadata(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise DiagnosticError("invalid_annotation")
    path = item.get("path")
    if (
        not isinstance(path, str)
        or len(path) > 1024
        or re.fullmatch(r"[A-Za-z0-9_.@+/-]+", path) is None
        or path.startswith("/")
        or any(p in {"", ".", ".."} for p in path.split("/"))
    ):
        raise DiagnosticError("unsafe_annotation_path")
    start, end = item.get("start_line"), item.get("end_line")
    level = item.get("annotation_level")
    if (
        not positive(start)
        or not positive(end)
        or end < start
        or level not in {"notice", "warning", "failure"}
    ):
        raise DiagnosticError("invalid_annotation_location")
    # Rule IDs may be absent from Checks annotations; do not infer them from prose.
    rule = None
    title = item.get("title")
    if isinstance(title, str) and re.fullmatch(r"(?:py|js|go)/[a-z0-9-]+", title):
        rule = title
    return {
        "path": path,
        "start_line": start,
        "end_line": end,
        "annotation_level": level,
        "rule_id_if_reported": rule,
    }


def collect(
    get: Any, repository: str, sha: str, pr: int, deadline: float
) -> dict[str, Any]:
    prefix = f"/repos/{repository}/"
    while True:
        check = select_check(get, prefix, sha, pr)
        if check is not None and check.get("status") == "completed":
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DiagnosticError("completed_codeql_check_unavailable")
        time.sleep(min(5, remaining))
    count = check.get("output", {}).get("annotations_count")
    if type(count) is not int or not 0 <= count <= MAX_PAGES * 100:
        raise DiagnosticError("invalid_annotation_count")
    records = []
    for page in range(1, MAX_PAGES + 1):
        items = get(
            f"{prefix}check-runs/{check['id']}/annotations?per_page=100&page={page}"
        )
        if not isinstance(items, list) or len(items) > 100:
            raise DiagnosticError("invalid_annotation_page")
        records.extend(annotation_metadata(item) for item in items)
        if len(records) >= count or len(items) < 100:
            break
    if len(records) != count:
        raise DiagnosticError("annotation_count_mismatch")
    # Re-read the same check, so a concurrent update cannot silently change scope.
    current = get(f"{prefix}check-runs/{check['id']}")
    fields = (
        "id",
        "head_sha",
        "name",
        "status",
        "conclusion",
        "output",
        "app",
        "pull_requests",
    )
    if not isinstance(current, dict) or any(
        current.get(k) != check.get(k) for k in fields
    ):
        raise DiagnosticError("check_changed_during_read")
    return {
        "schema_version": "fabric.codeql-pr-annotations/v1",
        "membership_verified": True,
        "repository": repository,
        "head_sha": sha,
        "pr": pr,
        "check_id": check["id"],
        "check_conclusion": check.get("conclusion"),
        "annotations_count": count,
        "annotations": records,
        "security_acceptance": "not_determined_by_diagnostic",
    }


def main() -> int:
    try:
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        sha = os.environ.get("CODEQL_PR_HEAD_SHA", "")
        raw_pr = os.environ.get("CODEQL_PR_NUMBER", "")
        token = os.environ.get("GITHUB_TOKEN", "")
        if (
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
            or any(part in {".", ".."} for part in repository.split("/"))
            or re.fullmatch(r"[a-f0-9]{40}", sha) is None
            or re.fullmatch(r"[1-9][0-9]*", raw_pr) is None
            or not token
        ):
            raise DiagnosticError("invalid_or_missing_ci_identity")
        deadline = time.monotonic() + 60
        result = collect(
            ChecksReader(repository, token, deadline),
            repository,
            sha,
            int(raw_pr),
            deadline,
        )
    except DiagnosticError as error:
        print(
            json.dumps({"membership_verified": False, "diagnostic_error": str(error)})
        )
        return 1
    except Exception:
        print(
            json.dumps(
                {
                    "membership_verified": False,
                    "diagnostic_error": "unexpected_diagnostic_failure",
                }
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
