# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A model-calling application for the spec 049 P0-A exit gate (``test_p0a_gate_e2e.py``).

Unlike ``_wire_capture_agent.py`` it installs wire capture explicitly, because the
transformations of ``masked_only``, ``original_plus_masked`` and ``redact`` (§7.7) are
named per role in code: ``fabric.wire.install()`` with the node-mode configuration from
``FABRIC_*`` (the customer redaction service from ``FABRIC_REDACTION_ENDPOINT``) plus,
with ``--transform``, one transformation for the request, response and part roles. The
redaction service performs it (``contracts/redaction/v1``); Fabric runs no customer
code. It then makes one OpenAI-compatible chat call
over httpx and prints one JSON line: the HTTP status, whether capture was installed and
the install's content status (``WireHandle.status()``, values only).

``--body``:

- ``plain``: one user message holding ``E2E_GATE_CANARY``;
- ``split``: the canary text plus two inline base64 images, each above
  ``FABRIC_WIRE_PART_MIN_BYTES`` (the side is split when it exceeds
  ``FABRIC_WIRE_MAX_BODY_BYTES``, §7.4);
- ``big``: a ``--size`` byte text message plus one inline image, so that the
  skeleton is just below ``--size`` (the 63 MiB request-cap case).

``--transform``: ``none``; ``mask`` is ``gate-mask``, which the gate's service maps to
replacing the canary with ``[masked]`` (the JSON stays valid); ``fail`` is
``gate-fail``, which the service does not implement (a failed call: withheld).
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import os
import sys

import httpx

ROLES = ("model.exchange.request", "model.exchange.response", "model.exchange.part")


def _image(size: int, seed: int) -> str:
    raw = bytes((seed + i) % 256 for i in range(size))
    return "data:image/png;base64," + base64.b64encode(raw).decode()


def _body(kind: str, canary: str, size: int) -> dict[str, object]:
    text = {"type": "text", "text": f"{canary} describe these"}
    if kind == "plain":
        content: object = f"{canary} What is the temperature in Paris?"
    elif kind == "split":
        content = [text] + [{"type": "image_url", "image_url": {"url": _image(4096, seed)}}
                            for seed in (1, 2)]  # fmt: skip
    else:  # big: the text fills the skeleton; one image is extracted
        filler = "x" * (size - 4096)
        content = [{"type": "text", "text": f"{canary} {filler}"},
                   {"type": "image_url", "image_url": {"url": _image(256 * 1024, 3)}}]  # fmt: skip
    return {
        "model": "e2e-model-2026",
        "messages": [{"role": "user", "content": content}],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-url", required=True)
    parser.add_argument("--body", choices=("plain", "split", "big"), default="plain")
    parser.add_argument("--transform", choices=("none", "mask", "fail"), default="none")
    parser.add_argument("--size", type=int, default=63 * 1024 * 1024 - 64 * 1024)
    args = parser.parse_args()
    canary = os.environ["E2E_GATE_CANARY"]

    from fabric import wire
    from fabric.wire import Transformation
    from fabric.wire._config import config_from_env

    config, _ = config_from_env(os.environ)
    if args.transform != "none":
        # performed by the customer redaction service (FABRIC_REDACTION_ENDPOINT)
        transform = Transformation(f"gate-{args.transform}", "1")
        config = dataclasses.replace(
            config, transformations=dict.fromkeys(ROLES, transform)
        )
    handle = wire.install(config)
    with httpx.Client(timeout=300) as client:
        response = client.post(
            args.model_url,  # the chat-completions URL
            json=_body(args.body, canary, args.size),
            headers={"Authorization": f"Bearer {os.environ['E2E_MODEL_API_KEY']}"},
        )
    flushed = wire.flush(120.0)
    print(json.dumps({
        "status_code": response.status_code, "capture_active": True,
        "flushed": flushed, "status": handle.status(),
    }))  # fmt: skip
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
