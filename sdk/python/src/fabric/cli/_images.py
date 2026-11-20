# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The container images ``fabric up`` runs, pinned by digest (spec 058 §5.4, §11.2).

``fabric up`` never pulls a floating tag: every reference below names a digest, and a test
refuses anything else. The Fabric images are the signed images of the release named by
:data:`RELEASE` (verify them with cosign as docs/verify-release.md describes).

An operator testing a locally built image can set ``FABRIC_NODE_IMAGE``,
``FABRIC_SENSOR_IMAGE``, ``FABRIC_SINK_IMAGE`` or ``FABRIC_TRIAL_S3_IMAGE``; ``fabric up``
then says so (``FC-028``)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

#: The published release whose images are pinned here.
RELEASE = "0.12.1"
#: The Fabric Node (ghcr.io/singleaxis/fabric-otelcol:<RELEASE>, multi-arch index digest).
NODE = (
    "ghcr.io/singleaxis/fabric-otelcol"
    "@sha256:4c84162b9e1eb4c282b53bd95cd62f422cfb25740fe2c60648b4f0dba940ffdf"
)
#: The eBPF host sensor (ghcr.io/singleaxis/fabric-host-emitter:<RELEASE>).
SENSOR = (
    "ghcr.io/singleaxis/fabric-host-emitter"
    "@sha256:2fcf304b4ae3cc59b9a2459319c23a088a8d33dd767e2d5d732d29f941600073"
)
#: The interpreter that runs the bundled local-dir sink (python:3.12-alpine).
SINK = "python@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a"
#: The trial destination's S3-compatible test store (spec 058 §9.1, F20): the SeaweedFS of
#: the Compose TLS overlay (deploy/compose/docker-compose.content-s3-local-tls.yml).
TRIAL_S3 = (  # chrislusf/seaweedfs:4.50
    "chrislusf/seaweedfs@sha256:c2658820e763294a9e9de7b36c81e59b879e3459148351aee4e31a126ca64860"
)

PINNED: Mapping[str, str] = {"node": NODE, "sensor": SENSOR, "sink": SINK, "trial_s3": TRIAL_S3}
OVERRIDES: Mapping[str, str] = {
    "node": "FABRIC_NODE_IMAGE", "sensor": "FABRIC_SENSOR_IMAGE", "sink": "FABRIC_SINK_IMAGE",
    "trial_s3": "FABRIC_TRIAL_S3_IMAGE",
}  # fmt: skip
DIGEST_REF = re.compile(r"^[a-z0-9][a-z0-9./-]*@sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class Images:
    node: str
    sensor: str
    sink: str
    overridden: tuple[str, ...] = ()  # the variables that replaced a pinned image
    trial_s3: str = TRIAL_S3

    def to_json(self) -> dict[str, str]:
        return {"node": self.node, "sensor": self.sensor, "sink": self.sink,
                "trial_s3": self.trial_s3, "release": RELEASE}  # fmt: skip


def resolve(environ: Mapping[str, str]) -> Images:
    """The pinned images, or an operator's override per image (named, never silent)."""
    chosen: dict[str, str] = {}
    overridden: list[str] = []
    for name, pinned in PINNED.items():
        value = (environ.get(OVERRIDES[name]) or "").strip()
        chosen[name] = value or pinned
        if value and value != pinned:
            overridden.append(OVERRIDES[name])
    return Images(
        chosen["node"], chosen["sensor"], chosen["sink"], tuple(overridden), chosen["trial_s3"]
    )
