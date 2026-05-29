# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The soak workload: drive many decisions and sample memory.

Self-contained — no Presidio / NeMo / network. A stub guardrail checker
gives the guard-input path a real rail (otherwise it raises
``GuardrailNotConfiguredError``). A real ``TracerProvider`` +
``InMemorySpanExporter`` is used so the span machinery is genuinely
exercised; the exporter is drained periodically so retained spans do not
masquerade as a leak.
"""

from __future__ import annotations

import sys
import threading
import tracemalloc
from dataclasses import dataclass, field

try:
    import resource
except ImportError:  # pragma: no cover - non-unix (resource is unix-only)
    resource = None  # type: ignore[assignment]

from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric.client import Fabric, FabricConfig
from fabric.decision import Decision
from fabric.guardrails import CheckerVerdict

_SAMPLE_TEXT = "the quick brown fox jumps over the lazy dog " * 4
# One decision span + one llm_call child span per driven turn.
_SPANS_PER_DECISION = 2
_BYTES_PER_MIB = 1024.0 * 1024.0
# Coarse tracemalloc live-growth budget across the concurrent phase
# (after drains). Above this we flag a possible per-decision retention.
_TRACED_GROWTH_BUDGET_MB = 8.0


class _CountingSpanProcessor(SpanProcessor):
    """Atomically counts every ended span.

    Counting via the ``InMemorySpanExporter`` length would race the
    periodic drain (``len()`` then ``clear()`` is not atomic against a
    concurrent worker's ``on_end`` append, so spans could be cleared
    unaccounted). This processor increments a lock-guarded counter in
    ``on_end``, giving an exact total independent of when the exporter is
    drained for memory.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.count = 0

    def on_start(self, span: object, parent_context: object = None) -> None:
        return None

    def on_end(self, span: ReadableSpan) -> None:
        with self._lock:
            self.count += 1

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return True


class _AllowChecker:
    """Guardrail checker that always allows, with no rewrite.

    Structurally satisfies :class:`fabric.guardrails.GuardrailChecker`.
    Stateless and returns a cached verdict, so it is safe to share across
    the concurrent workers (each drives its OWN ``Decision``).
    """

    name = "soak-allow"
    _VERDICT = CheckerVerdict(action="allow")

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        return self._VERDICT

    def close(self) -> None:
        return None


@dataclass(frozen=True)
class SoakConfig:
    """Soak run parameters."""

    sequential_decisions: int = 50_000
    threads: int = 8
    per_thread_decisions: int = 5_000
    drain_every: int = 2_000
    # Coarse RSS backstop. ru_maxrss is a peak high-water mark and the
    # allocator (pymalloc/glibc arenas) holds freed pages, so RSS over a
    # 90k-decision run legitimately grows tens-to-low-hundreds of MiB
    # without any leak. tracemalloc live growth is the real gate; this is
    # a generous backstop so the default run does not false-fail.
    max_rss_growth_mb: float = 256.0


@dataclass
class SoakReport:
    """Outcome of a soak run."""

    sequential_decisions: int
    threads: int
    per_thread_decisions: int
    spans_expected: int
    spans_observed: int
    rss_start_mb: float
    rss_mid_mb: float
    rss_end_mb: float
    memory_verdict: str
    errors: list[str] = field(default_factory=list)

    @property
    def concurrent_decisions(self) -> int:
        return self.threads * self.per_thread_decisions

    @property
    def total_decisions(self) -> int:
        return self.sequential_decisions + self.concurrent_decisions

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def rss_growth_mb(self) -> float:
        return self.rss_end_mb - self.rss_start_mb

    @property
    def ok(self) -> bool:
        return not self.errors and self.spans_observed == self.spans_expected


def _rss_mb() -> float:
    """Current process RSS in MiB; 0.0 if ``resource`` is unavailable.

    ``ru_maxrss`` is in bytes on macOS and kilobytes on Linux — normalize
    to MiB. This is a coarse, reporting-only figure (peak, not live), so
    the memory-stability verdict leans on ``tracemalloc`` instead.
    """
    if resource is None:  # pragma: no cover - non-unix
        return 0.0
    maxrss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    divisor = _BYTES_PER_MIB if sys.platform == "darwin" else 1024.0
    return maxrss / divisor


def _build_fixture() -> tuple[Fabric, InMemorySpanExporter, _CountingSpanProcessor]:
    exporter = InMemorySpanExporter()
    counter = _CountingSpanProcessor()
    provider = TracerProvider()
    # Counter first so every ended span is tallied exactly; the exporter
    # is kept only so the periodic drain has something to clear (memory
    # bound) — the count never reads its length.
    provider.add_span_processor(counter)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("fabric.soak")
    fabric = Fabric(
        FabricConfig(tenant_id="soak-tenant", agent_id="soak-agent"),
        tracer=tracer,
        guardrail_checkers=[_AllowChecker()],
    )
    return fabric, exporter, counter


def _drive_one(fabric: Fabric, session: str, request: str) -> None:
    """One realistic turn: decision + guard + records + child span."""
    decision: Decision = fabric.decision(session_id=session, request_id=request)
    with decision as d:
        d.guard_input(_SAMPLE_TEXT)
        d.record_retrieval("rag", query=_SAMPLE_TEXT, result_count=3)
        d.remember(kind="semantic", content=_SAMPLE_TEXT, key="k")
        with d.llm_call(system="anthropic", model="claude") as call:
            call.set_usage(input_tokens=100, output_tokens=50, finish_reason="stop")


def run_soak(config: SoakConfig) -> SoakReport:
    """Run the sequential + concurrent phases and return a report."""
    fabric, exporter, counter = _build_fixture()
    errors: list[str] = []

    def drain() -> None:
        # Bound memory only — the exact span tally comes from the counting
        # processor, so clearing here never loses an accounted span.
        exporter.clear()

    tracemalloc.start()
    _baseline, _ = tracemalloc.get_traced_memory()
    rss_start = _rss_mb()

    # -- sequential phase --------------------------------------------
    for i in range(config.sequential_decisions):
        try:
            _drive_one(fabric, "soak-seq", f"seq-{i}")
        except Exception as exc:  # aggregate every failure into the report
            errors.append(f"sequential[{i}]: {type(exc).__name__}: {exc}")
        if config.drain_every > 0 and (i + 1) % config.drain_every == 0:
            drain()

    mid_traced, _ = tracemalloc.get_traced_memory()
    rss_mid = _rss_mb()

    # -- concurrent phase: one decision per worker per turn ----------
    def worker(worker_id: int) -> None:
        for j in range(config.per_thread_decisions):
            try:
                _drive_one(fabric, f"soak-w{worker_id}", f"w{worker_id}-{j}")
            except Exception as exc:  # aggregate every failure into the report
                errors.append(f"worker[{worker_id}][{j}]: {type(exc).__name__}: {exc}")
            if config.drain_every > 0 and (j + 1) % config.drain_every == 0:
                drain()

    workers = [threading.Thread(target=worker, args=(w,)) for w in range(config.threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    drain()
    end_traced, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_end = _rss_mb()

    spans_expected = (
        config.sequential_decisions + config.threads * config.per_thread_decisions
    ) * _SPANS_PER_DECISION

    # Memory-stability verdict. tracemalloc is the deterministic signal:
    # after periodic drains, live tracked Python memory should not grow
    # roughly in proportion to the number of decisions (which would
    # indicate retained per-decision objects). RSS growth is reported but
    # only fails the run if it blows past the coarse threshold.
    traced_growth_mb = (end_traced - mid_traced) / _BYTES_PER_MIB
    rss_growth_mb = rss_end - rss_start
    verdict_parts: list[str] = []
    if traced_growth_mb <= _TRACED_GROWTH_BUDGET_MB:
        verdict_parts.append(f"tracemalloc stable (+{traced_growth_mb:.2f} MiB live)")
    else:
        verdict_parts.append(f"tracemalloc GROWTH +{traced_growth_mb:.2f} MiB live")
        errors.append(
            f"tracemalloc live memory grew {traced_growth_mb:.2f} MiB across the "
            "concurrent phase after drains — possible per-decision retention"
        )
    if rss_growth_mb > config.max_rss_growth_mb:
        verdict_parts.append(f"RSS GROWTH +{rss_growth_mb:.1f} MiB")
        errors.append(
            f"RSS grew {rss_growth_mb:.1f} MiB (> {config.max_rss_growth_mb:.1f} MiB threshold)"
        )
    else:
        verdict_parts.append(f"RSS +{rss_growth_mb:.1f} MiB within threshold")

    return SoakReport(
        sequential_decisions=config.sequential_decisions,
        threads=config.threads,
        per_thread_decisions=config.per_thread_decisions,
        spans_expected=spans_expected,
        spans_observed=counter.count,
        rss_start_mb=rss_start,
        rss_mid_mb=rss_mid,
        rss_end_mb=rss_end,
        memory_verdict="; ".join(verdict_parts),
        errors=errors,
    )
