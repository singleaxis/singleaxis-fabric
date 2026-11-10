# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Renders docs/diagnostics.md from the catalogue (spec 058 §13.1). The page is generated:
`python -m tests._diagnostics_doc > ../../docs/diagnostics.md` from sdk/python."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

CATALOGUE = Path(__file__).resolve().parents[3] / "contracts/diagnostics/v1/messages-v1.json"
_PREFIXES = (
    ("FC", "The fabric CLI"),
    ("FW", "The SDKs (wire capture, status, autoload)"),
    ("FE", "The host emitter"),
    ("FR", "The reader"),
    ("FN", "The Fabric Node"),
)


def _wrap(text: str) -> list[str]:
    return textwrap.wrap(text, width=100, break_long_words=False, break_on_hyphens=False)


def render() -> str:
    entries = json.loads(CATALOGUE.read_text("utf-8"))["messages"]
    lines = [
        "# Diagnostics",
        "",
        "<!-- Generated from contracts/diagnostics/v1/messages-v1.json by",
        "     sdk/python/tests/_diagnostics_doc.py; a test keeps them equal. -->",
        "",
        "Every message Fabric prints or writes has a stable id. Search for the id you saw;",
        "each entry says what it means and how to fix it. Messages never carry a secret, a",
        "header, a URL credential or content; a host name or path appears only in local",
        "output (the CLI, the status file), never on telemetry.",
        "",
    ]
    for prefix, title in _PREFIXES:
        group = [e for e in entries if e["id"].startswith(prefix + "-")]
        if not group:
            continue
        lines += [f"## {title}", ""]
        for entry in group:
            retired = " (retired)" if entry.get("retired") else ""
            lines += [
                f"### {entry['id']}",
                "",
                *_wrap(f"`{entry['name']}`, {entry['severity']}{retired}: {entry['text']}."),
                "",
                *_wrap(f"Fix: {entry['fix']}."),
                "",
            ]
    return "\n".join(lines).rstrip("\n") + "\n"


if __name__ == "__main__":
    print(render(), end="")
