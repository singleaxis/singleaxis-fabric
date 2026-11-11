# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A node-mode records capture for the spec 057 WP7-1 suites.

``capture()`` installs the records harness's real pipeline and spool sender
(``tests/_records_harness.Handle``) as the current capture handle, so the public
``fabric.records`` APIs record onto it. ``spans`` reads the records-input spans back from
the spool in sequence order, ``bodies`` the spooled content (descriptor and bytes) and
``normalise`` turns records into stable golden rows (volatile ids and times replaced).
Goldens live in ``tests/goldens/security_records``; ``FABRIC_UPDATE_GOLDENS=1`` rewrites
them.
"""

from __future__ import annotations

import json
import os
import re
import types
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from fabric import _records_api as api

from ._records_harness import Handle

ID_KEY = b"fabric-test-id-key-not-a-secret"  # the coverage vectors' test key
GOLDENS = Path(__file__).resolve().parent / "goldens" / "security_records"
UPDATE_ENV = "FABRIC_UPDATE_GOLDENS"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
VOLATILE = frozenset({
    "fabric.source_id", "fabric.source.epoch", "fabric.source.sequence", "fabric.event_id",
    "fabric.run.id", "fabric.run.scope_id", "fabric.run.segment_id",
})  # fmt: skip
MEASURED = frozenset({"fabric.control.latency_ms"})


@contextmanager
def capture(
    monkeypatch: pytest.MonkeyPatch, *, key: bytes | None = ID_KEY, **handle_options: Any
) -> Iterator[Handle]:
    """A node-mode handle (real pipeline, real spool) as the current capture handle."""
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    handle = Handle(id_key=key, **handle_options)
    if "gate" in handle_options:  # the records input reads the gate's policy (§7.2 switches)
        handle.gate = handle_options["gate"]
        handle.records = type(handle.input)(handle)  # type: ignore[arg-type]
    monkeypatch.setattr(api, "_WIRE", types.SimpleNamespace(current_handle=lambda: handle))
    try:
        yield handle
    finally:
        handle.close()


def spans(handle: Handle, kind: str | None = None) -> list[dict[str, Any]]:
    """Attributes of every spooled records-input span (of step ``kind``), in order."""
    handle.flush()
    assert handle.sender is not None
    found = [dict(span["attributes"]) for *_, span, _ in handle.sender.items]
    found = [a for a in found if a.get("fabric.capture.input") == "records"]
    found.sort(key=lambda a: int(a["fabric.source.sequence"]))
    return [a for a in found if kind is None or a.get("fabric.step.kind") == kind]


def bodies(handle: Handle) -> list[tuple[dict[str, Any], bytes]]:
    """Every spooled body as ``(descriptor, bytes)``, in spool order."""
    handle.flush()
    assert handle.sender is not None
    return [body for *_, staged in handle.sender.items for body in staged]


def spooled_bytes(handle: Handle) -> bytes:
    """The raw spool files: every span and body as written to disk."""
    handle.flush()
    sender = handle.sender
    assert sender is not None
    return b"".join(sender.spool.read(name) for name in sender.spool.names())


def node_export(handle: Handle) -> bytes:
    """What reaches the Node once the spool drains: OTLP spans and content bodies."""
    sender = handle.sender
    assert sender is not None
    assert sender.deliver()
    span_text = json.dumps(
        [dict(s.attributes or {}) for s in sender.exported.get_finished_spans()], default=str
    ).encode()
    return span_text + b"".join(data for _, data in sender.content_log.bodies)


def normalise(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Golden rows: volatile keys dropped, uuid4 values numbered by first appearance, the
    capture point's version and measured latencies replaced."""
    names: dict[str, str] = {}

    def stable(value: Any) -> Any:
        if isinstance(value, str):
            if value.startswith("sdk.records@"):
                return "sdk.records@<version>"
            return _UUID.sub(lambda m: names.setdefault(m.group(0), f"<uuid-{len(names) + 1}>"),
                             value)  # fmt: skip
        if isinstance(value, (list, tuple)):
            return [stable(v) for v in value]
        return value

    out = []
    for attrs in records:
        row: dict[str, Any] = {}
        for key in sorted(attrs):
            if key in VOLATILE:
                continue
            value = attrs[key]
            if key in MEASURED:
                assert isinstance(value, float) and value >= 0, (key, value)
                row[key] = "<measured>"
            else:
                row[key] = stable(value)
        out.append(row)
    return out


def check_golden(name: str, document: Any) -> None:
    """Compare ``document`` with ``goldens/security_records/<name>.json`` (rewrite it under
    ``FABRIC_UPDATE_GOLDENS=1``)."""
    path = GOLDENS / f"{name}.json"
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if os.environ.get(UPDATE_ENV) == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert path.exists(), f"missing golden {path.name}; run with {UPDATE_ENV}=1"
    assert json.loads(path.read_text(encoding="utf-8")) == json.loads(text), name


__all__ = [
    "GOLDENS", "ID_KEY", "bodies", "capture", "check_golden", "node_export", "normalise",
    "spans", "spooled_bytes",
]  # fmt: skip
