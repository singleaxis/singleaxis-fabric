# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The documentation structure (spec 058 §14.1, §14.2):

- every relative link in the repository's Markdown resolves to a file, and every link
  into ``docs/`` with an anchor resolves to a heading of that page (old page paths keep
  a stub, so no inbound link breaks);
- the four parts exist: Get started, Choose your deployment shape, Go to production and
  Reference, with the pages §14.1 lists;
- every old page path is a stub that links to its new home;
- every page in ``get-started/``, ``shapes/`` and ``production/`` passes the docs-as-tests
  lint (marked command blocks, budgets, no hand-made items, no internal ids) and each of
  its paths is executed by a CI job;
- no page in those directories names a spec, work-package or milestone id.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
_spec = importlib.util.spec_from_file_location(
    "docs_runner", ROOT / "scripts/docs_as_tests/run.py"
)
assert _spec and _spec.loader
runner = importlib.util.module_from_spec(_spec)
sys.modules["docs_runner"] = runner
_spec.loader.exec_module(runner)

PAGES = {
    "get-started": ("python.md", "node.md", "other-languages.md", "kubernetes.md"),
    "shapes": ("choose.md", "laptop.md", "linux-host.md", "containers.md", "kubernetes.md",
               "serverless-and-sandboxes.md", "macos-and-windows.md"),
    "production": ("index.md", "linux-host.md", "kubernetes.md", "destinations.md",
                   "secrets-and-rotation.md", "sizing.md", "upgrade.md"),
    "reference": ("cli.md", "fabric-yaml.md", "env-vars.md", "reconstruct.md",
                  "explicit-apis.md", "action-reconstruction.md", "run-record.md",
                  "host-sensors.md", "privacy-and-security.md", "glossary.md",
                  "api-stability.md", "qualified-run-mode.md", "diagnostics.md",
                  "manual-setup/quickstart.md", "manual-setup/production-setup.md",
                  "manual-setup/deployment.md"),
}  # fmt: skip
#: Old page paths and their new homes (§14.1: each keeps a stub).
MOVED = {
    **{f"{n}.md": f"reference/{n}.md" for n in (
        "reconstruct", "explicit-apis", "action-reconstruction", "run-record", "host-sensors",
        "privacy-and-security", "glossary", "api-stability", "qualified-run-mode",
        "diagnostics")},
    **{f"{n}.md": f"reference/manual-setup/{n}.md"
       for n in ("quickstart", "production-setup", "deployment")},
}  # fmt: skip
#: Where each docs-as-tests path is executed in CI (a workflow file and the text naming it).
EXECUTED_BY = {
    "laptop-python": ".github/workflows/recorder-ci.yml",
    "laptop-python-provider": ".github/workflows/recorder-ci.yml",
    "laptop-node": ".github/workflows/recorder-ci.yml",
    "kubernetes": ".github/workflows/e2e.yml",
}
#: The harness each Get started path runs in.
SCRIPTS = {"laptop-node": "scripts/ttfr/ttfr_node.py",
           "kubernetes": "scripts/ttfr/kubernetes/ttfr_kubernetes.py"}  # fmt: skip
LINK = re.compile(r"\]\(([^)\s]+)\)|^\[[^\]]+\]:\s*(\S+)", re.MULTILINE)


def _markdown() -> list[Path]:
    listed = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True,
                            text=True, check=True).stdout.split()  # fmt: skip
    return [ROOT / p for p in listed if (ROOT / p).exists()]


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"`|\*|_(?=\w)|(?<=\w)_", "", heading.strip().lower())
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(page: Path) -> set[str]:
    found: set[str] = set()
    seen: dict[str, int] = {}
    inside = False
    for line in page.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            inside = not inside
        if inside:
            continue
        heading = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if heading:
            slug = _slug(heading.group(1))
            count = seen.get(slug, 0)
            seen[slug] = count + 1
            found.add(slug if count == 0 else f"{slug}-{count}")
        for name in re.findall(r'<a (?:name|id)="([^"]+)"', line):
            found.add(name)
    return found


def _links(page: Path) -> list[str]:
    links, inside = [], False
    for line in page.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            inside = not inside
            continue
        if inside:
            continue
        line = re.sub(r"`[^`]*`", "", line)
        for match in LINK.finditer(line):
            links.append(match.group(1) or match.group(2))
    return links


def test_every_relative_link_resolves() -> None:
    broken = []
    for page in _markdown():
        for target in _links(page):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith(
                ("<", "/")
            ):
                continue
            path, _, anchor = target.partition("#")
            resolved = (page.parent / path).resolve() if path else page
            where = f"{page.relative_to(ROOT)} -> {target}"
            if not resolved.exists():
                broken.append(where)
            elif (anchor and resolved.suffix == ".md" and DOCS in resolved.parents
                  and anchor not in _anchors(resolved)):  # fmt: skip
                broken.append(f"{where} (no such heading)")
    assert not broken, "broken links:\n" + "\n".join(broken)


def test_the_four_parts_have_their_pages() -> None:
    missing = [f"{part}/{name}" for part, names in PAGES.items() for name in names
               if not (DOCS / part / name).is_file()]  # fmt: skip
    assert not missing, missing


@pytest.mark.parametrize("old", sorted(MOVED))
def test_old_paths_are_stubs_linking_to_the_new_home(old: str) -> None:
    text = (DOCS / old).read_text(encoding="utf-8")
    assert len(text.splitlines()) <= 5, f"docs/{old} should be a stub"
    assert f"]({MOVED[old]})" in text


def _tested_pages() -> list[Path]:
    return sorted(p for part in runner.TESTED_DIRS for p in (DOCS / part).glob("*.md"))


@pytest.mark.parametrize(
    "page", _tested_pages(), ids=lambda p: str(p.relative_to(DOCS))
)
def test_tested_pages_pass_the_docs_lint(page: Path) -> None:
    counts = runner.lint(page, DOCS)
    ci = (ROOT / ".github/workflows/recorder-ci.yml").read_text(encoding="utf-8")
    for path in counts:
        if path in runner.SMOKE_PATHS:
            assert "scripts/docs_as_tests/smoke.py" in ci, path
            continue
        workflow = (ROOT / EXECUTED_BY[path]).read_text(encoding="utf-8")
        script = SCRIPTS.get(path, "scripts/ttfr/ttfr.py")
        assert script in workflow, (path, EXECUTED_BY[path])
    assert not runner.INTERNAL_IDS.search(page.read_text(encoding="utf-8"))


def test_coverage_tables_are_generated_from_the_committed_reports() -> None:
    """§12.5: no hand-written coverage claim; each table equals what the committed CI
    report renders to, and each page embeds it unchanged."""
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / "scripts/docs_coverage/render.py"), "--check"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    embedded = [
        p for p in DOCS.rglob("*.md") if "<!-- fabric-coverage:" in p.read_text("utf-8")
    ]
    assert {p.parent.name for p in embedded} >= {"shapes"}


def test_a_failed_or_local_report_is_not_a_source(tmp_path: Path) -> None:
    """§12.5: tables come from passing CI runs only. A plan-scenarios report made outside a
    network namespace or with a failed scenario, or a TTFR report that is not ok, is
    refused with the fix (regression: a report made in a container, with problems, was
    committed as the source of the shape pages' tables)."""
    import json

    sys.path.insert(0, str(ROOT / "scripts/docs_coverage"))
    try:
        import render
    finally:
        sys.path.pop(0)
    plan = {"network_namespace": False,
            "scenarios": [{"id": "s", "problems": ["shape 'container', expected 'linux-host'"],
                           "coverage": []}]}  # fmt: skip
    (tmp_path / "plan-scenarios.json").write_text(json.dumps(plan), encoding="utf-8")
    (tmp_path / "ttfr-laptop-python.json").write_text('{"ok": false}', encoding="utf-8")
    found = render.unfit(tmp_path)
    assert len(found) == 3, found
    assert all("commit the" in line for line in found)
    plan = {"network_namespace": True, "scenarios": [{"id": "s", "problems": []}]}
    (tmp_path / "plan-scenarios.json").write_text(json.dumps(plan), encoding="utf-8")
    (tmp_path / "ttfr-laptop-python.json").write_text('{"ok": true}', encoding="utf-8")
    assert render.unfit(tmp_path) == []
    assert render.unfit() == []
