# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §3.3 and §14.2: documentation executed as written.

The Get started page for Python holds G1's budgets (one install, three commands, no flag
on the default path and one on the provider path, at most 80 lines), every command block
on it is marked, and no block makes a hand-made item. The runner's rules are pinned on
synthetic pages. The page itself is executed by the ``ttfr-laptop-python`` CI job
(``scripts/ttfr/ttfr.py``)."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "docs_as_tests"))

import run as docs  # noqa: E402

PAGE = ROOT / "docs" / "get-started" / "python.md"


def test_the_python_page_meets_g1() -> None:
    counts = docs.lint(PAGE, ROOT / "docs")
    assert counts == {
        "laptop-python": {"install": 1, "commands": 3, "flags": 0, "lines": counts["laptop-python"]["lines"]},
        "laptop-python-provider": {"install": 1, "commands": 3, "flags": 1,
                                   "lines": counts["laptop-python"]["lines"]},
    }  # fmt: skip
    assert counts["laptop-python"]["lines"] <= 80


def test_the_python_page_runs_install_up_run_verify() -> None:
    blocks, unmarked = docs.parse(PAGE)
    assert unmarked == []
    default = [c for b in docs.blocks_for(blocks, "laptop-python") for c in b.commands]
    provider = [
        c for b in docs.blocks_for(blocks, "laptop-python-provider") for c in b.commands
    ]
    assert default == ['pip install "singleaxis-fabric[cli]"', "fabric up",
                       "fabric run -- python agent.py", "fabric verify"]  # fmt: skip
    assert provider == ['pip install "singleaxis-fabric[cli]"',
                        "fabric up --provider https://my-llm.example.com/v1",
                        "fabric run -- python agent.py", "fabric verify"]  # fmt: skip
    verify = docs.blocks_for(blocks, "laptop-python")[-1]
    assert verify.expects == ["FC-069"], (
        "verify must prove the agent's own run, not the canary"
    )


def _page(tmp_path: Path, body: str, name: str = "page.md") -> Path:
    directory = tmp_path / "docs" / "get-started"
    directory.mkdir(parents=True, exist_ok=True)
    page = directory / name
    page.write_text(body)
    return page


GOOD = textwrap.dedent("""\
    # A page

    <!-- fabric-docs-test: path=laptop-python step=1 kind=install -->
    ```bash
    echo installing
    ```

    <!-- fabric-docs-test: path=laptop-python step=2 -->
    ```bash
    echo up
    # expect: up
    ```
""")


def test_a_good_page_lints_and_runs(tmp_path: Path) -> None:
    page = _page(tmp_path, GOOD)
    assert docs.lint(page, tmp_path / "docs")["laptop-python"]["commands"] == 1
    results = docs.run(page, "laptop-python", tmp_path)
    assert [r["ok"] for r in results] == [True, True]


def test_an_unmet_expectation_fails_the_run(tmp_path: Path) -> None:
    page = _page(tmp_path, GOOD.replace("# expect: up", "# expect: down"))
    results = docs.run(page, "laptop-python", tmp_path)
    assert results[-1]["ok"] is False and results[-1]["missing_expectations"] == [
        "down"
    ]


def test_a_failing_command_stops_the_run(tmp_path: Path) -> None:
    page = _page(tmp_path, GOOD.replace("echo installing", "false"))
    results = docs.run(page, "laptop-python", tmp_path)
    assert len(results) == 1 and results[0]["exit_code"] == 1


@pytest.mark.parametrize(
    ("command", "why"),
    [
        ("export OPENAI_BASE_URL=x", "exports a variable"),
        ("FABRIC_TENANT_ID=a fabric up", "sets a variable"),
        ("cat > fabric.yaml", "creates a file"),
        ("echo key | tee id.key", "creates a file"),
        ("echo x > id.key", "writes a file"),
        ("openssl rand -hex 32", "openssl"),
    ],
)
def test_hand_made_items_are_refused(tmp_path: Path, command: str, why: str) -> None:
    page = _page(tmp_path, GOOD.replace("echo up", command))
    with pytest.raises(docs.DocsTestError, match=why):
        docs.lint(page, tmp_path / "docs")


def test_a_heredoc_is_refused(tmp_path: Path) -> None:
    page = _page(tmp_path, GOOD.replace("echo up", "python - <<'EOF'"))
    with pytest.raises(docs.DocsTestError, match="heredoc"):
        docs.lint(page, tmp_path / "docs")


def test_an_unmarked_command_block_is_refused(tmp_path: Path) -> None:
    page = _page(tmp_path, GOOD + "\n```bash\nfabric show\n```\n")
    with pytest.raises(docs.DocsTestError, match="without a marker"):
        docs.lint(page, tmp_path / "docs")


def test_more_commands_or_flags_than_the_target_are_refused(tmp_path: Path) -> None:
    extra = "".join(
        f"\n<!-- fabric-docs-test: path=laptop-python step={n} -->\n```bash\necho {n}\n```\n"
        for n in (3, 4, 5)
    )
    with pytest.raises(docs.DocsTestError, match="4 commands"):
        docs.lint(_page(tmp_path, GOOD + extra, "many.md"), tmp_path / "docs")
    with pytest.raises(docs.DocsTestError, match="1 flags, target 0"):
        docs.lint(_page(tmp_path, GOOD.replace("echo up", "fabric up --wait 60"), "flag.md"),
                  tmp_path / "docs")  # fmt: skip


def test_the_agent_command_after_the_separator_is_not_a_flag() -> None:
    assert docs._flags("fabric run -- python agent.py --verbose -x") == 0
    assert docs._flags("fabric up --provider https://h/v1") == 1


def test_a_page_too_long_is_refused(tmp_path: Path) -> None:
    page = _page(tmp_path, GOOD + "\nline\n" * 80)
    with pytest.raises(docs.DocsTestError, match="lines, target 80"):
        docs.lint(page, tmp_path / "docs")


@pytest.mark.parametrize(
    "text", ["see WP8-10", "built in spec 058", "phase P1-A", "M2 work"]
)
def test_get_started_pages_name_no_internal_id(tmp_path: Path, text: str) -> None:
    page = _page(tmp_path, GOOD + f"\n{text}\n")
    with pytest.raises(docs.DocsTestError, match="internal id"):
        docs.lint(page, tmp_path / "docs")
