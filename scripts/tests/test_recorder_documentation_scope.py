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
    "sdk/python/README.md",
    "sdk/typescript/README.md",
    "components/otel-collector-fabric/README.md",
    "specs/000-overview.md",
    "specs/010-development-standards.md",
    "specs/027-recorder-v1.md",
    "docs/README.md",
    "docs/quickstart.md",
    "docs/architecture.md",
    "docs/deployment.md",
    "docs/privacy-and-security.md",
    "docs/operations/README.md",
    "docs/operations/dr.md",
    "docs/reconstruct.md",
    "docs/explicit-apis.md",
    "docs/qualified-run-mode.md",
    "docs/host-sensors.md",
    "docs/limitations-and-roadmap.md",
    "docs/genai-semantic-conventions.md",
    "docs/api-stability.md",
    "docs/building-fabric.md",
    "docs/verify-release.md",
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
    # Removed reference-taxonomy API and its bundled attack-taxonomy data.
    "load_bundled_taxonomies",
    "bundled_taxonomy_names",
    "fabric.taxonomy",
    "mitre-atlas",
    "owasp-llm",
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


def test_readme_describes_the_actual_recorder_cli() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert (
        "Writes and validates a reviewable recorder declaration (`contracts/recorder/v1`); "
        "in v0.8 neither the SDK nor the Node reads it"
    ) in readme
    assert "deployment receipts" not in readme


# Spec 057 (WP7-3): the security-context modules and their documentation describe
# recording, never Fabric deciding. Positive claims only: "Fabric decides nothing" passes.
SPEC_057_SOURCES = (
    "sdk/python/src/fabric/_rec_check.py",
    "sdk/python/src/fabric/_rec_controls.py",
    "sdk/python/src/fabric/_rec_extension.py",
    "sdk/python/src/fabric/_rec_grant.py",
    "sdk/python/src/fabric/_rec_run.py",
    "sdk/python/src/fabric/_records_api.py",
    "sdk/python/src/fabric/_security_policy.py",
    "sdk/python/src/fabric/records/__init__.py",
    "sdk/python/src/fabric/reconstruct/_controls.py",
    "sdk/python/src/fabric/reconstruct/_security.py",
    "sdk/python/src/fabric/reconstruct/_derive.py",
    "sdk/python/src/fabric/reconstruct/dialects/__init__.py",
    "sdk/python/src/fabric/reconstruct/dialects/offered_grant.py",
    "sdk/python/src/fabric/reconstruct/dialects/safety_map.py",
    "sdk/python/src/fabric/reconstruct/dialects/tool_result.py",
    "sdk/python/src/fabric/reconstruct/dialects/jsonrpc2.py",
    "sdk/python/src/fabric/reconstruct/dialects/mcp.py",
    "sdk/python/src/fabric/reconstruct/_mcp_read.py",
    "sdk/python/src/fabric/hooks/_mcp.py",
    "docs/action-reconstruction.md",
    "docs/explicit-apis.md",
    "docs/reconstruct.md",
)
DECIDER_CLAIMS = (
    "Fabric blocks",
    "Fabric enforces",
    "Fabric approves",
    "Fabric denies",
    "Fabric evaluates",
    "Fabric judges",
    "enforced_by_fabric=true",
    "enforced_by_fabric: true",
    "fabric.blocked=true",
    "guardrail sidecar",
)


def _module_docstring_and_comments(text: str) -> str:
    import ast

    tree = ast.parse(text)
    docs = [ast.get_docstring(node) or "" for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef))]  # fmt: skip
    comments = [line.split("#", 1)[1] for line in text.splitlines() if "#" in line]
    return "\n".join(docs + comments)


def test_spec_057_sources_and_docs_never_claim_fabric_decides() -> None:
    for relative in SPEC_057_SOURCES:
        text = (ROOT / relative).read_text(encoding="utf-8")
        prose = (
            _module_docstring_and_comments(text) if relative.endswith(".py") else text
        )
        assert prose.strip(), relative
        for claim in (*STALE_POSITIVE_CLAIMS, *DECIDER_CLAIMS):
            assert claim.lower() not in prose.lower(), f"{relative} contains {claim!r}"
