#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Check that the workflows publish exactly the GHCR packages the release policy allows.

Legacy images (``fabric-redteam-runner``, ``fabric-presidio-sidecar``, ...) stayed on
GHCR after their sources were removed: nothing said which packages a release publishes.
``release-policy.json`` now names them (``ghcr_packages``), and this static check reads
every workflow under ``.github/workflows`` and fails closed:

- a ``docker/build-push-action`` step that pushes publishes the job's ``IMAGE_NAME``
  (``${{ github.repository_owner }}/<name>``), expanded over the job's matrix;
- a ``helm push`` to ``oci://ghcr.io/${{ github.repository_owner }}/charts`` publishes
  ``charts/<name>``, the ``name`` of the job's ``CHART_DIR``'s ``Chart.yaml``;
- any other push command (``docker push``, ``oras``, ``crane``, ``skopeo``, ``ko``,
  ``imagetools create``), a push this script cannot name, and a job with
  ``packages: write`` that publishes nothing it recognizes are refused.

Every published name must be in the allowlist and every allowlisted name published,
so anything else on GHCR is known to be stale (docs/verify-release.md).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

OWNER = "${{ github.repository_owner }}/"
CHART_REF = "oci://ghcr.io/${{ github.repository_owner }}/charts"
_MATRIX = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
_OTHER_PUSH = re.compile(
    r"\b(docker\s+push|docker\s+buildx\s+imagetools\s+create|oras\s+(push|cp|copy)|"
    r"crane\s+(push|copy|cp|append|mutate)|skopeo\s+copy|ko\s+(publish|build|resolve|apply)|"
    r"podman\s+push|buildah\s+push|regctl\s+image\s+copy)\b"
)


class PackageError(ValueError):
    """A workflow publishes a package the policy does not allow, or one it cannot name."""


def allowlist(policy: Mapping[str, Any]) -> frozenset[str]:
    """The policy's ``ghcr_packages``; every release image (``images``) must be in it."""
    names = policy.get("ghcr_packages")
    if not isinstance(names, list) or not all(isinstance(n, str) and n for n in names):
        raise PackageError(
            "release policy: ghcr_packages must be a list of package names"
        )
    if len(set(names)) != len(names):
        raise PackageError("release policy: ghcr_packages lists a package twice")
    missing = sorted(set(policy.get("images", ())) - set(names))
    if missing:
        raise PackageError(f"release policy: images not in ghcr_packages: {missing}")
    return frozenset(names)


def _matrix_values(job: Mapping[str, Any], key: str) -> list[str]:
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    if not isinstance(matrix, Mapping):
        raise PackageError(f"matrix.{key}: the matrix is an expression, not a list")
    values = [str(entry[key]) for entry in matrix.get("include", ()) if key in entry]
    plain = matrix.get(key)
    if isinstance(plain, list):
        values += [str(value) for value in plain]
    elif plain is not None:
        raise PackageError(f"matrix.{key}: not a list of names")
    if not values:
        raise PackageError(f"matrix.{key}: no value to name the package by")
    return values


def _expand(template: str, job: Mapping[str, Any]) -> list[str]:
    """``template`` over the job's matrix (one ``matrix.<key>`` at most)."""
    keys = set(_MATRIX.findall(template))
    if len(keys) > 1:
        raise PackageError(f"{template!r}: more than one matrix key")
    if not keys:
        return [template]
    (key,) = keys
    return [_MATRIX.sub(value, template) for value in _matrix_values(job, key)]


def _env(job: Mapping[str, Any], workflow: Mapping[str, Any], name: str) -> str | None:
    for scope in (job.get("env") or {}, workflow.get("env") or {}):
        if name in scope:
            return str(scope[name])
    return None


def _pushes(step: Mapping[str, Any]) -> bool:
    push = (step.get("with") or {}).get("push")
    return push not in (None, False, "false")


def _image_names(
    job_id: str, job: Mapping[str, Any], workflow: Mapping[str, Any]
) -> list[str]:
    registry = _env(job, workflow, "REGISTRY")
    image = _env(job, workflow, "IMAGE_NAME")
    if registry != "ghcr.io" or image is None or not image.startswith(OWNER):
        raise PackageError(
            f"job {job_id}: a pushing build must name REGISTRY ghcr.io and IMAGE_NAME "
            f"{OWNER}<name>"
        )
    return _expand(image[len(OWNER) :], job)


def _chart_names(
    job_id: str, job: Mapping[str, Any], workflow: Mapping[str, Any], root: Path
) -> list[str]:
    ref = _env(job, workflow, "OCI_REF")
    chart_dir = _env(job, workflow, "CHART_DIR")
    if ref != CHART_REF or chart_dir is None:
        raise PackageError(
            f"job {job_id}: helm push must use OCI_REF {CHART_REF} and CHART_DIR"
        )
    chart = yaml.safe_load(
        (root / chart_dir / "Chart.yaml").read_text(encoding="utf-8")
    )
    name = chart.get("name") if isinstance(chart, Mapping) else None
    if not isinstance(name, str) or not name:
        raise PackageError(f"job {job_id}: {chart_dir}/Chart.yaml has no name")
    for step in job.get("steps") or ():
        signed = (step.get("env") or {}).get("CHART_NAME")
        if signed is not None and signed != name:
            raise PackageError(
                f"job {job_id}: signs charts/{signed}, pushes charts/{name}"
            )
    return [f"charts/{name}"]


def _packages_write(job: Mapping[str, Any], workflow: Mapping[str, Any]) -> bool:
    for scope in (job.get("permissions"), workflow.get("permissions")):
        if scope == "write-all" or (
            isinstance(scope, Mapping) and scope.get("packages") == "write"
        ):
            return True
    return False


def published(root: Path) -> dict[str, list[str]]:
    """Every GHCR package the workflows under ``root`` publish, with the jobs that do."""
    out: dict[str, list[str]] = {}
    for path in sorted((root / ".github/workflows").glob("*.y*ml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_id, job in (workflow.get("jobs") or {}).items():
            where = f"{path.name}:{job_id}"
            names: list[str] = []
            for step in job.get("steps") or ():
                uses = str(step.get("uses", ""))
                run = str(step.get("run", ""))
                if uses.startswith("docker/build-push-action") and _pushes(step):
                    names += _image_names(where, job, workflow)
                if re.search(r"\bhelm\s+push\b", run):
                    names += _chart_names(where, job, workflow, root)
                if _OTHER_PUSH.search(run):
                    raise PackageError(f"{where}: a push this check cannot name")
            if _packages_write(job, workflow) and not names:
                raise PackageError(
                    f"{where}: packages: write but no recognized publication"
                )
            for name in dict.fromkeys(names):
                out.setdefault(name, []).append(where)
    return out


def check(root: Path, policy: Mapping[str, Any]) -> list[str]:
    """The allowlisted packages, after checking the workflows publish exactly them."""
    allowed = allowlist(policy)
    found = published(root)
    extra = sorted(set(found) - allowed)
    if extra:
        detail = "; ".join(f"{name} ({', '.join(found[name])})" for name in extra)
        raise PackageError(f"publishes packages outside ghcr_packages: {detail}")
    unpublished = sorted(allowed - set(found))
    if unpublished:
        raise PackageError(
            f"ghcr_packages lists packages no workflow publishes: {unpublished}"
        )
    return sorted(found)


def _lines(names: Sequence[str]) -> Iterator[str]:
    for name in names:
        yield f"ghcr.io/<owner>/{name}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    try:
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        names = check(args.repo_root, policy)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"check_ghcr_packages: {exc}", file=sys.stderr)
        return 1
    print("\n".join(_lines(names)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
