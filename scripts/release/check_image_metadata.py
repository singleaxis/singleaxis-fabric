#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Check a release image's title, description and every other label and annotation.

AGENTS.md: no recorder release artifact may advertise a capability outside
Capture -> Protect -> Deliver. ``docker/metadata-action`` fills
``org.opencontainers.image.description`` from the GitHub repository's description,
which overrides the Dockerfile's label, so the release workflow sets the title and
description from ``release-policy.json`` (``image_metadata``) and this script refuses
anything else:

- ``--print-github-output`` prints ``title=`` and ``description=`` for ``$GITHUB_OUTPUT``;
- ``--labels`` / ``--annotations``: the metadata-action outputs, before the build
  (``key=value`` lines; an annotation may carry a ``level:`` prefix);
- ``--inspect``: JSON from ``docker buildx imagetools inspect`` of the pushed image
  (``--raw`` index or manifest, or ``--format '{{json .Image}}'`` configs), before signing;
- ``--dockerfile``: the image's Dockerfile ``LABEL`` instructions.

Every label and annotation value is matched against ``forbidden_capability_terms``;
the title and description, wherever they appear, must equal the policy's.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

TITLE = "org.opencontainers.image.title"
DESCRIPTION = "org.opencontainers.image.description"


class MetadataError(ValueError):
    """An image's metadata is not the policy's or advertises a forbidden capability."""


def load_policy(path: Path) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if policy.get("schema_version") != "fabric.release-policy/v1":
        raise MetadataError("unsupported or missing release policy schema_version")
    return dict(policy)


def forbidden_terms(policy: Mapping[str, Any]) -> re.Pattern[str]:
    """The policy's capability deny-list as one case-insensitive pattern."""
    patterns = policy["forbidden_capability_terms"]["patterns"]
    return re.compile("(?i)(" + "|".join(f"(?:{p})" for p in patterns) + ")")


def expected(policy: Mapping[str, Any], image: str) -> dict[str, str]:
    try:
        entry = policy["image_metadata"][image]
    except KeyError:
        raise MetadataError(f"{image}: no image_metadata entry in the policy") from None
    if image not in policy["images"]:
        raise MetadataError(f"{image}: not a release image of the policy")
    return {TITLE: str(entry["title"]), DESCRIPTION: str(entry["description"])}


def check_pairs(
    pairs: Sequence[tuple[str, str]],
    want: Mapping[str, str],
    deny: re.Pattern[str],
    where: str,
    *,
    require: bool,
) -> None:
    """No value names a forbidden capability; a title or description equals the policy's
    (and, with ``require``, both are present)."""
    seen: set[str] = set()
    for key, value in pairs:
        found = deny.search(value) or deny.search(key)
        if found:
            raise MetadataError(
                f"{where}: {key} advertises a capability outside the recorder "
                f"({found.group(0)!r})"
            )
        if key in want:
            seen.add(key)
            if value != want[key]:
                raise MetadataError(
                    f"{where}: {key} is {value!r}, expected {want[key]!r}"
                )
    missing = sorted(set(want) - seen)
    if require and missing:
        raise MetadataError(f"{where}: missing {', '.join(missing)}")


def key_values(text: str, *, levels: bool = False) -> list[tuple[str, str]]:
    """``key=value`` lines (metadata-action output); ``levels`` strips an annotation's
    ``manifest:`` / ``index,manifest:`` prefix."""
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise MetadataError(f"not a key=value line: {line!r}")
        if levels and ":" in key:
            key = key.split(":", 1)[1]
        out.append((key.strip(), value))
    return out


def _walk(node: Any) -> Iterator[tuple[str, str]]:
    """Every label and annotation of an inspect document, wherever it is nested."""
    if isinstance(node, Mapping):
        for name, value in node.items():
            if name in ("Labels", "labels", "annotations") and isinstance(
                value, Mapping
            ):
                for key, text in value.items():
                    yield str(key), str(text)
            else:
                yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def inspect_pairs(text: str) -> list[tuple[str, str]]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MetadataError(f"inspect output is not JSON: {exc}") from None
    return list(_walk(document))


def dockerfile_labels(text: str) -> list[tuple[str, str]]:
    """The ``LABEL key="value" ...`` pairs of a Dockerfile (continuations joined)."""
    joined = re.sub(r"\\\n", " ", text)
    out: list[tuple[str, str]] = []
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("LABEL "):
            continue
        for token in shlex.split(stripped[6:]):
            key, sep, value = token.partition("=")
            if sep:
                out.append((key, value))
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--image", required=True, help="release image name (policy `images`)"
    )
    parser.add_argument("--print-github-output", action="store_true")
    parser.add_argument("--labels", type=Path, help="metadata-action `labels` output")
    parser.add_argument(
        "--annotations", type=Path, help="metadata-action `annotations` output"
    )
    parser.add_argument(
        "--inspect", type=Path, action="append", default=[],
        help="docker buildx imagetools inspect JSON of the pushed image (repeatable)",
    )  # fmt: skip
    parser.add_argument("--dockerfile", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
        want = expected(policy, args.image)
        deny = forbidden_terms(policy)
        for key, value in want.items():
            check_pairs([(key, value)], want, deny, "policy", require=False)
        if args.print_github_output:
            for value in want.values():
                if "\n" in value:
                    raise MetadataError("policy: a title or description is one line")
            print(f"title={want[TITLE]}")
            print(f"description={want[DESCRIPTION]}")
        if args.labels is not None:
            pairs = key_values(args.labels.read_text(encoding="utf-8"))
            check_pairs(pairs, want, deny, "labels", require=True)
        if args.annotations is not None:
            pairs = key_values(
                args.annotations.read_text(encoding="utf-8"), levels=True
            )
            check_pairs(pairs, want, deny, "annotations", require=True)
        for path in args.inspect:
            pairs = inspect_pairs(path.read_text(encoding="utf-8"))
            check_pairs(pairs, want, deny, f"inspect {path.name}", require=False)
        if args.dockerfile is not None:
            pairs = dockerfile_labels(args.dockerfile.read_text(encoding="utf-8"))
            check_pairs(pairs, want, deny, str(args.dockerfile), require=True)
    except (MetadataError, OSError, KeyError) as exc:
        print(f"image metadata check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
