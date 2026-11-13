#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Check the contents of a built ``fabric-cli`` image (spec 058 §4.1 I1, §11.1).

AGENTS.md: recorder release artifacts never compile, bundle, expose, install or
advertise a capability outside Capture -> Protect -> Deliver, enforced by artifact-content
tests. For the CLI image this script runs the image (it must be loaded locally) and
refuses it unless:

- ``fabric version`` answers with the release version, and ``fabric help`` lists exactly
  the commands of ``cli_image.commands`` (the I1 allowlist);
- the installed ``singleaxis-fabric`` distribution has the policy's console scripts and
  extras, and none of ``python_distribution``'s forbidden wheel paths or prefixes;
- no installed distribution's name or summary, and no label, names a forbidden capability
  (``forbidden_capability_terms``); the title and description are the policy's;
- the clients of ``cli_image.clients`` (Docker, the Compose plugin, Helm) answer;
- the image runs as a non-root user and its entry point is ``fabric``.

    python scripts/release/check_cli_image.py --policy scripts/release/release-policy.json \\
        --image fabric-cli:pr [--version 0.12.1]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_image_metadata import (  # noqa: E402
    MetadataError,
    check_pairs,
    expected,
    forbidden_terms,
    load_policy,
)

# Runs inside the image with the CLI's interpreter: what is installed, as JSON.
_INVENTORY = r"""
import importlib.metadata as m, json
from fabric import cli
dist = m.distribution("singleaxis-fabric")
print(json.dumps({
    "version": dist.version,
    "files": sorted(str(f) for f in (dist.files or ())),
    "console_scripts": {e.name: e.value for e in dist.entry_points if e.group == "console_scripts"},
    "extras": sorted(dist.metadata.get_all("Provides-Extra") or []),
    "commands": list(cli.COMMANDS),
    "distributions": sorted(
        [d.metadata["Name"], d.metadata.get("Summary") or ""] for d in m.distributions()
    ),
}))
"""


class ImageError(ValueError):
    """The image holds or advertises something the release policy does not allow."""


def _docker(*args: str, timeout: float = 120) -> str:
    result = subprocess.run(  # noqa: S603 - the operator's docker, fixed arguments
        ["docker", *args],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise ImageError(f"docker {' '.join(args[:4])}: {result.stderr.strip()[-400:]}")
    return result.stdout


def check_inventory(policy: Mapping[str, Any], inventory: Mapping[str, Any]) -> None:
    """The installed files, scripts, extras, commands and distributions (pure: tested)."""
    image = policy["cli_image"]
    wheel = policy["python_distribution"]
    if list(inventory["commands"]) != list(image["commands"]):
        raise ImageError(
            f"fabric commands {inventory['commands']} are not the I1 allowlist {image['commands']}"
        )
    scripts = dict(inventory["console_scripts"])
    if scripts != dict(wheel["required_console_scripts"]):
        raise ImageError(
            f"console scripts {scripts} are not {wheel['required_console_scripts']}"
        )
    missing = sorted(set(image["extras"]) - set(inventory["extras"]))
    if missing:
        raise ImageError(f"the distribution lacks the extras {missing}")
    files = [f for f in inventory["files"] if f.startswith("fabric/")]
    if not files:
        raise ImageError("the singleaxis-fabric distribution lists no fabric/ files")
    forbidden = set(wheel["forbidden_wheel_paths"])
    prefixes = tuple(wheel["forbidden_wheel_prefixes"])
    for path in files:
        if path in forbidden or path.startswith(prefixes):
            raise ImageError(
                f"the image installs {path}, which the release policy forbids"
            )
    for path in wheel["required_wheel_paths"]:
        if path not in inventory["files"]:
            raise ImageError(f"the image lacks {path}")
    deny = forbidden_terms(policy)
    for name, summary in inventory["distributions"]:
        found = deny.search(name) or deny.search(summary)
        if found:
            raise ImageError(
                f"installed distribution {name} names a capability outside the recorder "
                f"({found.group(0)!r})"
            )


def check_config(policy: Mapping[str, Any], config: Mapping[str, Any]) -> None:
    """The image config of ``docker image inspect``: user, entry point and labels."""
    user = str(config.get("User") or "")
    if user in ("", "0", "root") or user.startswith(("0:", "root:")):
        raise ImageError(
            f"the image runs as {user or 'root'}; it must run as a non-root user"
        )
    if list(config.get("Entrypoint") or []) != ["fabric"]:
        raise ImageError(
            f"the entry point is {config.get('Entrypoint')}, not ['fabric']"
        )
    labels = dict(config.get("Labels") or {})
    name = policy["cli_image"]["image"]
    try:
        check_pairs(list(labels.items()), expected(policy, name), forbidden_terms(policy),
                    "image config", require=True)  # fmt: skip
    except MetadataError as exc:
        raise ImageError(str(exc)) from None


def check(policy: Mapping[str, Any], image: str, version: str | None) -> list[str]:
    """Run every check against the loaded ``image``; returns what was checked."""
    done: list[str] = []
    shown = _docker("run", "--rm", image, "version")
    match = re.match(r"^fabric (\S+) ", shown)
    if not match or (version is not None and match.group(1) != version):
        raise ImageError(
            f"fabric version printed {shown.strip()!r}, expected {version}"
        )
    done.append(f"fabric version {match.group(1)}")
    helped = _docker("run", "--rm", image, "help")
    listed = re.findall(r"^  ([a-z]+)\s", helped, flags=re.MULTILINE)
    if listed != list(policy["cli_image"]["commands"]):
        raise ImageError(f"fabric help lists {listed}")
    done.append("fabric help lists the I1 commands")
    raw = _docker("run", "--rm", "--entrypoint", "/opt/fabric/bin/python", image, "-I", "-c",
                  _INVENTORY)  # fmt: skip
    check_inventory(policy, json.loads(raw.strip().splitlines()[-1]))
    done.append("installed files, scripts, extras and distributions")
    for label, argv in policy["cli_image"]["clients"].items():
        answer = _docker(
            "run", "--rm", "--entrypoint", argv[0], image, *argv[1:]
        ).strip()
        done.append(f"{label}: {answer.splitlines()[0] if answer else '?'}")
    inspected = json.loads(_docker("image", "inspect", image))
    check_config(policy, inspected[0]["Config"])
    done.append("non-root user, entry point and labels")
    return done


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--image", required=True, help="a locally loaded image reference"
    )
    parser.add_argument("--version", help="the release version the CLI must report")
    options = parser.parse_args(argv)
    try:
        for line in check(load_policy(options.policy), options.image, options.version):
            print(f"ok: {line}")
    except (ImageError, MetadataError, KeyError, ValueError) as exc:
        print(f"fabric-cli image check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
