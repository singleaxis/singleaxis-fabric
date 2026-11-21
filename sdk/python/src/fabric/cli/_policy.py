# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The production capture policy preset (spec 058 §6.3).

``fabric init --production`` writes it into the project as a ``fabric.deployment-policy/v1``
file, so it is reviewable and versioned; the customer edits it, never the CLI (an existing
file is never overwritten). It is the production setup page's example: the model exchanges
are kept (the decisions chain needs them), and no command argument, command output or
non-model HTTP body is kept in clear. One difference: the command roles are
``metadata_only`` where the example says ``redact``. Under zero-code capture (what
``fabric run`` turns on) a ``redact`` role has no transformation and is withheld, and the
SDK's status warns about it on every run (``FW-004``); ``metadata_only`` keeps the same
nothing-in-clear outcome and says so. The privacy choices are the customer's; this is a
starting point, not a recommendation for their data.

A production policy must name a pinned image digest (the SDK refuses ``local``). The CLI
does not know the agent's image, so without ``--image-digest`` the file carries the
all-zero digest, and ``FC-168`` says to set it."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from ..deployment_policy import DeploymentPolicy
from ._report import Finding

#: The file `init --production` writes beside fabric.yaml and names in capture.privacy.
PRESET_FILE = "fabric-capture-policy.json"
PRESET_SETTING = "./" + PRESET_FILE
PLACEHOLDER_DIGEST = "sha256:" + "0" * 64
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"[^A-Za-z0-9._-]+")
#: The preset's roles (spec 049 role table): kept, masked or metadata only. Roles left out
#: are ``omit``.
PRESET_PRIVACY: dict[str, str] = {
    "model.exchange.request": "retain_original",
    "model.exchange.response": "retain_original",
    "model.exchange.part": "retain_original",
    "record.evidence": "retain_original",
    "terminal.argv": "metadata_only",
    "terminal.context": "metadata_only",
    "terminal.stdout": "metadata_only",
    "terminal.stderr": "metadata_only",
    "network.request": "metadata_only",
    "network.response": "metadata_only",
}


def _identifier(text: str, fallback: str) -> str:
    """A deployment-policy identifier (letters, digits and ._-, at most 128)."""
    cleaned = _ID_RE.sub("-", text).strip("-._")[:128]
    return cleaned or fallback


def preset(tenant: str, agent: str, *, image_digest: str | None = None) -> dict[str, Any]:
    """The production preset for one agent of one tenant."""
    workload = _identifier(agent, "agent")
    return {
        "schema_version": "fabric.deployment-policy/v1",
        "policy_id": _identifier(f"{workload}-capture", "agent-capture"),
        "policy_version": 1,
        "tenant_id": _identifier(tenant, "default"),
        "workload_id": workload,
        "privacy": dict(PRESET_PRIVACY),
        "storage": {"backend": "local", "region": "local", "key_id": f"{workload}-key"[:128]},
        "retention": {"days": 30},
        "required_integrations": [],
        "deployment": {
            "profile": "production",
            "image_digest": image_digest or PLACEHOLDER_DIGEST,
            "tls_required": True,
            "encrypted_store_required": True,
        },
    }


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2) + "\n"


def write_preset(path: Path, tenant: str, agent: str, *, image_digest: str | None) -> bool:
    """Write the preset at ``path`` unless a file is there (the customer's to edit, never
    overwritten). Returns whether it was written."""
    document = preset(tenant, agent, image_digest=image_digest)
    DeploymentPolicy(document)  # the preset is always one the SDK accepts
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(render(document))
    except FileExistsError:
        return False
    return True


def check(path: Path, tenant: str, *, setting: str = "capture.privacy") -> list[Finding]:
    """Findings for the production capture policy at ``path``: ``FC-166`` when it is not
    there, ``FC-167`` when the SDK would refuse it (not a valid document, another tenant,
    not a production policy), ``FC-168`` while it names the placeholder image digest."""
    if not path.is_file():
        return [Finding("FC-166", f"{setting}: {path} does not exist")]
    try:
        raw = path.read_bytes()
        policy = DeploymentPolicy(json.loads(raw))
    except (OSError, ValueError, TypeError):
        # The SDK's own words are fixed text; the reason is never the file's content.
        return [Finding("FC-167", f"{path}: not a valid fabric.deployment-policy/v1 document")]
    findings: list[Finding] = []
    if policy.tenant_id != tenant:
        findings.append(Finding("FC-167", f"{path}: tenant_id is not this project's tenant "
                                          f"({tenant})"))  # fmt: skip
    if policy.deployment["profile"] != "production":
        findings.append(Finding("FC-167", f"{path}: deployment.profile is not production"))
    elif policy.deployment["image_digest"] == PLACEHOLDER_DIGEST:
        findings.append(Finding("FC-168", str(path)))
    return findings


def image_digest_argument(text: str) -> str:
    """``--image-digest``: ``sha256:`` and 64 lowercase hex digits (an argparse type)."""
    value = text.strip()
    if not DIGEST_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "must be sha256: and 64 lowercase hex digits, as "
            "docker image inspect --format '{{.Id}}' IMAGE prints it"
        )
    return value
