# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Guard customer-facing recorder documentation against product-plane drift."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

PRIMARY_DOCS = (
    "README.md",
    "SECURITY.md",
    "GOVERNANCE.md",
    "CONTRIBUTING.md",
    "SUPPORT.md",
    "sdk/README.md",
    "specs/000-overview.md",
    "specs/010-development-standards.md",
    "specs/027-recorder-v1.md",
    "docs/README.md",
    "docs/architecture.md",
    "docs/run-variant-artifact-outcome-change-list.md",
    "docs/install.md",
    "docs/quickstart.md",
    "docs/deployment.md",
    "docs/integration-models.md",
    "docs/capturing-interactions.md",
    "docs/exporting-to-your-observability-backend.md",
    "docs/enterprise-readiness.md",
    "docs/auditor-checklist.md",
    "docs/loom-walkthrough.md",
    "docs/how-fabric-fits-in-your-agent-stack.md",
    "docs/regulatory-profiles.md",
    "docs/operations/dr.md",
    "docs/api-stability.md",
    "docs/building-fabric.md",
    "docs/typescript-parity-backlog.md",
    "docs/verify-release.md",
    "docs/recorder-v1-qualification-status.md",
)

# Secondary documentation surfaces scanned with the same stale-claim
# list: example READMEs and deployment READMEs must not quietly
# advertise removed capabilities either.
EXTENDED_DOC_GLOBS = (
    "examples/**/*.md",
    "deploy/**/README.md",
    ".github/**/*.md",
    ".github/**/*.yml",
)

# Directory components that never contain maintained documentation
# (tool caches, virtualenvs, vendored deps).
_EXCLUDED_DIR_PREFIXES = (".",)
_EXCLUDED_DIR_NAMES = frozenset({"node_modules", "__pycache__"})

# A document that prominently declares itself a historical note may
# describe removed capabilities without the scan treating them as live
# product claims. The marker must appear within this many leading
# characters so it cannot be buried at the bottom of a file.
LEGACY_DOC_MARKER = "not part of recorder v1"
LEGACY_MARKER_WINDOW = 1000

STALE_POSITIVE_CLAIMS = (
    "eu-ai-act-high-risk",
    "permissive-dev",
    "fabricredactprocessor",
    "fabricsamplerprocessor",
    "ToolAuthorizer",
    "record_eval",
    "queue_judge",
    "757 tests",
    "Inline PII redaction",
    "Fail-closed guardrails",
)


def _iter_extended_docs() -> Iterator[Path]:
    """Yield repo-relative markdown paths under the extended globs."""
    seen: set[Path] = set()
    for pattern in EXTENDED_DOC_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            relative = path.relative_to(ROOT)
            parts = relative.parts
            if any(
                part.startswith(_EXCLUDED_DIR_PREFIXES) or part in _EXCLUDED_DIR_NAMES
                for part in parts
            ):
                continue
            if relative not in seen:
                seen.add(relative)
                yield relative


def _is_marked_legacy(text: str) -> bool:
    """True when the file prominently declares itself historical."""
    return LEGACY_DOC_MARKER in text[:LEGACY_MARKER_WINDOW].lower()


def test_primary_recorder_docs_do_not_restore_legacy_product_claims() -> None:
    for relative in PRIMARY_DOCS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        if _is_marked_legacy(text):
            continue
        for stale in STALE_POSITIVE_CLAIMS:
            assert stale not in text, (
                f"{relative} contains stale recorder claim {stale!r}"
            )


def test_extended_recorder_docs_do_not_restore_legacy_product_claims() -> None:
    scanned = list(_iter_extended_docs())
    assert scanned, "extended documentation scan matched no files"
    for relative in scanned:
        text = (ROOT / relative).read_text(encoding="utf-8")
        if _is_marked_legacy(text):
            continue
        for stale in STALE_POSITIVE_CLAIMS:
            assert stale not in text, (
                f"{relative} contains stale recorder claim {stale!r}; a "
                f"clearly-marked historical note must declare "
                f"{LEGACY_DOC_MARKER!r} within the first "
                f"{LEGACY_MARKER_WINDOW} characters"
            )


def test_downstream_design_docs_are_prominently_scoped() -> None:
    superseded = (ROOT / "specs/025-product-planes-and-packaging.md").read_text(
        encoding="utf-8"
    )
    assert "Superseded. Do not implement recorder v1" in superseded[:700]


def test_readme_describes_the_actual_recorder_cli() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert (
        "Local recorder initialization, configuration validation, digest, help, and version"
        in readme
    )
    assert "deployment receipts" not in readme
