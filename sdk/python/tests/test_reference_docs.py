# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The generated reference pages (spec 058 §14.1, §14.2) have drift tests: each page
equals what its generator renders from the CLI's parser, the ``fabric.config/v1`` schema
and settings table, and the variable table, and the variable table names exactly the
``FABRIC_*`` variables the SDK and the CLI read."""

from __future__ import annotations

import pytest

from fabric import cli
from tests import _reference_docs as reference


@pytest.mark.parametrize("name", sorted(reference.PAGES))
def test_the_page_is_generated(name: str) -> None:
    page = reference.REFERENCE / name
    assert page.read_text("utf-8") == reference.PAGES[name](), (
        f"docs/reference/{name} is stale: run `python -m tests._reference_docs` from sdk/python"
    )


def test_every_variable_the_sdk_reads_is_documented_and_no_other() -> None:
    documented = {name for _, name, _ in reference.VARIABLES}
    typescript_only = {name for _, name, text in reference.VARIABLES if text.startswith("TS:")}
    assert reference.source_variables() == documented - typescript_only
    typescript = "".join(
        p.read_text("utf-8") for p in (reference.ROOT / "sdk/typescript/src").rglob("*.ts")
    )
    for name in typescript_only:
        assert f'"{name}"' in typescript, name


def test_every_cli_command_has_a_section() -> None:
    text = (reference.REFERENCE / "cli.md").read_text("utf-8")
    for name in cli.COMMANDS:
        assert f"## fabric {name}\n" in text
