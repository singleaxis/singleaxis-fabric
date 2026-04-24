# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Suite orchestrator.

Given a :class:`~.config.RunConfig`, pick one driver per suite and run
all of its probes against the configured target. Failures inside one
suite don't short-circuit sibling suites — redteam runs are about
getting maximum coverage, not bisecting a bug."""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from .config import RunConfig, SuiteConfig, TargetConfig
from .results import Finding, ProbeResult, RunResult, Severity, Verdict

_LOG = logging.getLogger(__name__)


@runtime_checkable
class Suite(Protocol):
    """Contract every suite driver implements.

    A driver takes a target + per-suite config, yields one
    :class:`ProbeResult` per probe it ran. The runner is responsible
    for timing, aggregation, and emission."""

    name: str

    def run(
        self,
        target: TargetConfig,
        suite_config: SuiteConfig,
    ) -> Iterable[ProbeResult]: ...


class Runner:
    """Executes a :class:`RunConfig` against registered suite drivers.

    Drivers are registered by name (``garak``, ``pyrit``, …) so the
    config can reference them symbolically. Unknown suite names become
    a single ``Verdict.ERROR`` probe result so a typo in a ConfigMap
    does not silently skip testing."""

    def __init__(self, suites: Sequence[Suite]) -> None:
        self._suites: dict[str, Suite] = {s.name: s for s in suites}

    def run(self, config: RunConfig) -> RunResult:
        started = datetime.now(UTC)
        probes: list[ProbeResult] = []
        for suite_cfg in config.suites:
            driver = self._suites.get(suite_cfg.name)
            if driver is None:
                probes.append(
                    ProbeResult(
                        suite=suite_cfg.name,
                        probe="<unknown-suite>",
                        verdict=Verdict.ERROR,
                        attempts=0,
                        findings=[
                            Finding(
                                attempt_id="n/a",
                                prompt_hash="",
                                response_hash="",
                                severity=Severity.INFO,
                                notes=f"no driver registered for suite {suite_cfg.name!r}",
                            )
                        ],
                    )
                )
                continue
            probes.extend(self._run_suite(driver, config.target, suite_cfg))
        finished = datetime.now(UTC)
        return RunResult(
            run_id="run-" + uuid.uuid4().hex[:12],
            tenant_id=config.tenant_id,
            agent_id=config.agent_id,
            profile=config.profile,
            started_at=started,
            finished_at=finished,
            probes=probes,
        )

    def _run_suite(
        self,
        driver: Suite,
        target: TargetConfig,
        suite_cfg: SuiteConfig,
    ) -> list[ProbeResult]:
        out: list[ProbeResult] = []
        for result in driver.run(target, suite_cfg):
            out.append(result)
            _LOG.info(
                "suite=%s probe=%s verdict=%s duration_ms=%d findings=%d",
                result.suite,
                result.probe,
                result.verdict.value,
                result.duration_ms,
                len(result.findings),
            )
        return out


def load_suite(name: str) -> Suite:
    """Import and instantiate the built-in driver for ``name``.

    Falls back to a stub that errors with a clear message if the
    upstream library isn't installed."""

    if name == "garak":
        from .garak import GarakSuite  # noqa: PLC0415

        return GarakSuite()
    if name == "pyrit":
        from .pyrit import PyritSuite  # noqa: PLC0415

        return PyritSuite()
    raise ValueError(f"unknown suite: {name!r}")


def hash_text(text: str) -> str:
    """Deterministic short hash for prompt/response bodies. We never
    ship raw probe bodies into telemetry — the hash is enough to
    dedupe and correlate across runs."""

    return hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest()
