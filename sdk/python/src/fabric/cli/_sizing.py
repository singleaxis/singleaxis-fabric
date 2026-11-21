# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``node.queue_size`` (spec 058 §6.1, F22): one setting for the Node's durable queue, and
advice that checks it against the free disk.

The Node's queue is a number of items, each up to the largest request it accepts: a
telemetry batch of up to 8 MiB and, with a content store, a content record of up to
64 MiB (the production collector configuration). Its worst case is items times that
size. ``node.queue_size`` is a disk budget in bytes instead, which is what a person can
check against a disk: the CLI turns it into item counts. ``auto`` budgets half of the free
space of the disk the queue is on, never more items than the shipped configuration holds.

Advice (never a failure; real batches are far smaller than the worst case): ``FC-170``
when a budget is more than the disk has free, with a value that fits; ``FC-171`` when the
disk is so full that the Node's queue holds fewer than :data:`MIN_TELEMETRY_ITEMS`
batches. Reading the free space is local (``statvfs``); nothing else is touched."""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import _config
from ._report import Finding

MIB = 1 << 20
TELEMETRY_ITEM_BYTES = 8 * MIB  # the OTLP receivers' max_request_body_size
CONTENT_ITEM_BYTES = 64 * MIB  # the content receiver's limit
PRODUCTION_TELEMETRY_ITEMS = 10000  # collector-production*.yaml sending_queue.queue_size
PRODUCTION_CONTENT_ITEMS = 64  # the content overlay's fabriccontent queue_size
LOCAL_TELEMETRY_ITEMS = 1000  # the local Node's queue (fabric up, local profile)
AUTO_SHARE = 0.5  # auto: at most half of the free disk
CONTENT_SHARE = 0.25  # the part of a budget given to content records
MIN_TELEMETRY_ITEMS = 100


@dataclass
class QueuePlan:
    """What the Node's queue holds under one setting, and the advice about it."""

    setting: Any  # "auto" or the fabric.yaml value
    telemetry_items: int
    content_items: int
    free_bytes: int | None
    where: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst_case_bytes(self) -> int:
        return (self.telemetry_items * TELEMETRY_ITEM_BYTES
                + self.content_items * CONTENT_ITEM_BYTES)  # fmt: skip

    def to_json(self) -> dict[str, Any]:
        return {
            "setting": self.setting, "telemetry_items": self.telemetry_items,
            "content_items": self.content_items, "worst_case_bytes": self.worst_case_bytes,
            "free_bytes": self.free_bytes, "disk": self.where,
        }  # fmt: skip


def human(size: float) -> str:
    """Bytes in the binary units ``node.queue_size`` accepts back (``29GiB``)."""
    for unit, scale in (("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", MIB), ("KiB", 1 << 10)):
        if size >= scale:
            value = size / scale
            return f"{value:.0f}{unit}" if value >= 10 else f"{value:.1f}{unit}"  # noqa: PLR2004
    return f"{int(size)}B"


def _existing(path: Path) -> Path:
    """The path, or its nearest ancestor that exists (the queue directory may not yet)."""
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return path


def _items(budget: int, *, telemetry_max: int, content: bool) -> tuple[int, int]:
    content_items = 0
    if content:
        content_items = min(PRODUCTION_CONTENT_ITEMS,
                            max(1, int(budget * CONTENT_SHARE) // CONTENT_ITEM_BYTES))  # fmt: skip
    rest = budget - content_items * CONTENT_ITEM_BYTES
    telemetry_items = min(telemetry_max, max(1, rest // TELEMETRY_ITEM_BYTES))
    return int(telemetry_items), content_items


def plan(setting: Any, queue_dir: Path, *, production: bool, content: bool,
         disk_usage: Callable[[Path], Any] | None = None) -> QueuePlan:  # fmt: skip
    """The item counts ``setting`` (``node.queue_size``) gives a Node whose queue is in
    ``queue_dir``, and the advice for the disk it is on."""
    telemetry_max = PRODUCTION_TELEMETRY_ITEMS if production else LOCAL_TELEMETRY_ITEMS
    content = content and production  # the local Node has no content pipeline
    where = _existing(queue_dir)
    try:
        free: int | None = int((disk_usage or shutil.disk_usage)(where).free)
    except OSError:
        free = None
    findings: list[Finding] = []
    if setting == "auto":
        if free is None:
            return QueuePlan(setting, telemetry_max, PRODUCTION_CONTENT_ITEMS if content else 0,
                             None, str(where))  # fmt: skip
        telemetry, content_items = _items(int(free * AUTO_SHARE), telemetry_max=telemetry_max,
                                          content=content)  # fmt: skip
        if telemetry < MIN_TELEMETRY_ITEMS:
            findings.append(Finding("FC-171", f"{human(free)} free on {where}: the Node's queue "
                                              f"holds {telemetry} batches"))  # fmt: skip
        return QueuePlan(setting, telemetry, content_items, free, str(where), findings)
    budget = _config.parse_size(setting) or 1
    telemetry, content_items = _items(budget, telemetry_max=telemetry_max, content=content)
    if free is not None and budget > free:
        findings.append(Finding("FC-170", f"node.queue_size {human(budget)} is more than the "
                                          f"{human(free)} free on {where}; set node.queue_size: "
                                          f"{human(free * AUTO_SHARE)} or auto"))  # fmt: skip
    return QueuePlan(setting, telemetry, content_items, free, str(where), findings)
