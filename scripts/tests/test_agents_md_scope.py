# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``AGENTS.md`` carries the security-context wording approved in spec 057 section 11.

OD-20: the owner approved the wording on 2026-11-09 and WP7-3 applies it with the first
057 records. The test reads the four quoted blocks of section 11 and checks that
``AGENTS.md`` holds each one, verbatim, where section 11 places it: the in-scope bullet
right after the OTLP-identity bullet, the two clarified "Outside the OSS core" items in
place of the short ones, and the Control Runtime paragraph right after the Control
Runtime bullet.

It then undoes exactly those four changes and compares the result with the file as it was
before WP7-3 (its SHA-256, pinned below), so the change set is section 11 and nothing
else. A later, deliberate edit of ``AGENTS.md`` elsewhere updates the pin.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "specs/057-security-context-recording.md"
AGENTS = ROOT / "AGENTS.md"

# AGENTS.md as it stood before WP7-3 applied section 11.
PRE_057_SHA256 = "36228eeca97bfba805b004db38e5f33a18f7ec26416ec9e1c040ec42018263f4"
OTLP_BULLET = "- preservation of OTLP identity and causal correlation supplied by the source;\n"
CONTROL_RUNTIME_BULLET = (
    "- **Optional future customer-side Control Runtime:** Enforce customer-approved\n"
    "  decisions. It is separate from the default recorder and is never enabled by\n"
    "  installing Fabric OSS.\n"
)
# The two "Outside the OSS core" items section 11 clarifies, as they read before.
OLD_EVALUATION = "- continuous evaluation services, judges or finding generation;\n"
OLD_ENFORCEMENT = "- advisory recommendations or enforcement orchestration;\n"


def _section_11() -> str:
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("\n## 11. `AGENTS.md` change")
    end = text.index("\n## 12. ", start)
    return text[start:end]


def _quoted_blocks() -> list[str]:
    """Each run of ``>`` lines in section 11, with the quote marks removed."""
    blocks: list[list[str]] = []
    previous_quoted = False
    for line in _section_11().splitlines():
        quoted = line.startswith(">")
        if quoted:
            if not previous_quoted:
                blocks.append([])
            blocks[-1].append(re.sub(r"^> ?", "", line))
        previous_quoted = quoted
    return ["\n".join(block) + "\n" for block in blocks]


def test_section_11_has_the_four_approved_blocks() -> None:
    blocks = _quoted_blocks()
    assert len(blocks) == 4, blocks
    scope, evaluation, enforcement, runtime = blocks
    assert scope.startswith("- recording, as observed or reported evidence, the security")
    assert "`enforced_by_fabric=false`" in scope
    assert evaluation.startswith("- continuous evaluation services, judges or finding")
    assert enforcement.startswith("- advisory recommendations or enforcement orchestration,")
    assert runtime.startswith("A separately installed Control Runtime")
    assert "OD-20" in _section_11()


def test_agents_md_places_each_block_where_section_11_says() -> None:
    text = AGENTS.read_text(encoding="utf-8")
    scope, evaluation, enforcement, runtime = _quoted_blocks()
    in_scope = text[text.index("## In scope for the OSS core"):text.index("## Outside the OSS")]
    outside = text[text.index("## Outside the OSS core"):text.index("## Product and repository")]
    boundary = text[text.index("## Product and repository boundary"):]
    assert OTLP_BULLET + scope in in_scope
    assert evaluation in outside and enforcement in outside
    assert OLD_EVALUATION not in text and OLD_ENFORCEMENT not in text
    assert CONTROL_RUNTIME_BULLET + "\n" + runtime in boundary


def test_the_agents_md_change_is_exactly_section_11() -> None:
    text = AGENTS.read_text(encoding="utf-8")
    scope, evaluation, enforcement, runtime = _quoted_blocks()
    reverted = (
        text.replace(OTLP_BULLET + scope, OTLP_BULLET, 1)
        .replace(evaluation, OLD_EVALUATION, 1)
        .replace(enforcement, OLD_ENFORCEMENT, 1)
        .replace(CONTROL_RUNTIME_BULLET + "\n" + runtime, CONTROL_RUNTIME_BULLET, 1)
    )
    digest = hashlib.sha256(reverted.encode("utf-8")).hexdigest()
    assert digest == PRE_057_SHA256, (
        "AGENTS.md differs from its pre-057 text by more than the section 11 wording"
    )


def test_the_recorder_scope_statement_keeps_record_only_language() -> None:
    """The added scope bullet records decisions; it never makes Fabric the decider."""
    scope = _quoted_blocks()[0]
    assert "never computes,\n  applies, waits for or returns any of these decisions" in scope
    assert "never depends on a particular agent framework" in scope
