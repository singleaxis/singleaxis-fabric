# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared harness for the spec 050 WP-11a suites: the WP-00 reference implementations
(loaded from ``scripts/contracts``), the vectors, and a records input on a real capture
pipeline, allocator and loss emitter behind the WP-01 spool stub (a sender that takes every
item: WP-11b's spool is not merged yet)."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

from fabric._capture_types import Allocation, NullRunTable
from fabric._loss import LossEmitter
from fabric._records import RecordsInput
from fabric._sequence import SourceAllocator
from fabric.wire._pipeline import CapturePipeline
from fabric.wire._stream import Budget

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "contracts/coverage/v1/fixtures/vectors"
SOURCE = "s-" + "b" * 32
SEG_A, SEG_B = "seg-" + "a" * 32, "seg-" + "b" * 32


def _load(name: str, path: Path) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def reference() -> ModuleType:
    """``scripts/contracts/p1_reference.py``: the executable definition of the P1 rules."""
    return _load("_p1_reference", REPO / "scripts/contracts/p1_reference.py")


def coverage_validator() -> ModuleType:
    return _load("_coverage_validator", REPO / "scripts/contracts/validate_coverage_contracts.py")


def vector(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((VECTORS / name).read_text(encoding="utf-8"))
    return loaded


class StubSender:
    """The WP-01 spool stub: every item is taken (or given ``outcome``) and kept here."""

    def __init__(self, outcome: str = "spooled") -> None:
        self.items: list[tuple[str, int, dict[str, Any], list[tuple[dict[str, Any], bytes]]]] = []
        self.outcome = outcome

    def spool_exchanges(self, items: Any) -> list[str]:
        self.items.extend(items)
        return [self.outcome] * len(items)

    def wake(self) -> None:
        return None


class SegmentTable(NullRunTable):
    """Every allocation in the segment ``choose`` names (``None``: segment-less)."""

    def __init__(self, choose: Callable[[Allocation], str | None]) -> None:
        self.choose = choose

    def on_allocate(self, allocation: Allocation) -> str | None:
        return self.choose(allocation)


def alternating(*segments: str) -> Callable[[Allocation], str | None]:
    cycle: Iterator[str] = iter(segments * 10_000)
    return lambda allocation: next(cycle)


class Handle:
    """A minimal installed handle around a real pipeline (spool stub or provider path)."""

    def __init__(
        self, *, node: bool = True, provider: Any = None, budget: int = 1 << 30,
        queue_max_items: int = 1024, protector: Any = None, gate: Any = None,
        labels: str = "pseudonymous", id_key: bytes | None = None,
        segments: Callable[[Allocation], str | None] | None = None,
        sender: StubSender | None = None,
    ) -> None:  # fmt: skip
        self.loss = LossEmitter()
        self.markers: list[Any] = []
        self.allocator = SourceAllocator(SOURCE, "wire")
        self.sender = (sender or StubSender()) if node else None
        self.pipeline = CapturePipeline(
            store=None, tracer_provider=provider, loss=self.loss, sender=self.sender,  # type: ignore[arg-type]
            node_tenant_id="tenant-a" if node else None, queue_max_items=queue_max_items,
            protector=protector, gate=gate,
        )  # fmt: skip
        self.pipeline.seals.set_sink(self.markers.append)  # type: ignore[attr-defined]
        self.budget = Budget(budget)
        table = SegmentTable(segments) if segments is not None else None
        self.allocator.attach(segments=table, seals=self.pipeline.seals)
        self.pipeline.set_settle(self.allocator.settle)
        self.loss.set_settle(self.allocator.settle)
        self.config = SimpleNamespace(labels=labels, id_key=id_key)
        self._tee_or_none = SimpleNamespace(
            pipeline=self.pipeline, allocator=self.allocator, loss=self.loss, budget=self.budget
        )
        self.capturing = True
        self.records: RecordsInput | None = None
        self.records = RecordsInput(self)  # type: ignore[arg-type]

    @property
    def input(self) -> RecordsInput:
        assert self.records is not None
        return self.records

    def flush(self) -> None:
        assert self.pipeline.flush(5.0)

    def close(self) -> None:
        self.pipeline.close(2.0)
        self.loss.close(1.0)
