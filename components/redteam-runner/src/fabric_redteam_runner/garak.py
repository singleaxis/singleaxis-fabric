# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Garak driver.

Garak is a CLI. Rather than spawn a subprocess per probe, we invoke
its Python API directly when the library is installed; when it isn't
(tests, unit envs), the driver short-circuits to a stub that marks
every requested probe as ``Verdict.ERROR`` with a clear note. This
keeps the happy path fast and unit tests hermetic."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Iterator
from typing import Any

from .config import SuiteConfig, TargetConfig
from .results import Finding, ProbeResult, Severity, Verdict
from .runner import hash_text

_LOG = logging.getLogger(__name__)


class GarakSuite:
    """Driver for https://github.com/leondz/garak."""

    name = "garak"

    def run(self, target: TargetConfig, suite_config: SuiteConfig) -> Iterable[ProbeResult]:
        if not suite_config.probes:
            return []
        try:
            harness = _load_harness()
        except _HarnessUnavailableError as e:
            return [_error_result(p, str(e)) for p in suite_config.probes]
        return list(self._run_probes(target, suite_config, harness))

    def _run_probes(
        self,
        target: TargetConfig,
        suite_config: SuiteConfig,
        harness: _GarakHarness,
    ) -> Iterator[ProbeResult]:
        for probe_name in suite_config.probes:
            started = time.monotonic()
            try:
                attempts = harness.run_probe(
                    probe_name=probe_name,
                    target_url=target.url,
                    headers=target.headers,
                    timeout_seconds=target.timeout_seconds,
                    attempts=suite_config.attempts_per_probe,
                )
            except _HarnessUnavailableError as e:
                yield ProbeResult(
                    suite=self.name,
                    probe=probe_name,
                    verdict=Verdict.ERROR,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    attempts=0,
                    findings=[
                        Finding(
                            attempt_id="n/a",
                            prompt_hash="",
                            response_hash="",
                            severity=Severity.INFO,
                            notes=str(e),
                        )
                    ],
                )
                continue
            duration_ms = int((time.monotonic() - started) * 1000)
            findings = [
                Finding(
                    attempt_id=a.attempt_id,
                    prompt_hash=hash_text(a.prompt),
                    response_hash=hash_text(a.response),
                    severity=Severity(a.severity.lower()),
                    notes=a.detector or "",
                )
                for a in attempts
                if a.hit
            ]
            yield ProbeResult(
                suite=self.name,
                probe=probe_name,
                verdict=Verdict.FAIL if findings else Verdict.PASS,
                duration_ms=duration_ms,
                attempts=len(attempts),
                findings=findings,
            )


# --- Harness abstraction ------------------------------------------------


def _error_result(probe: str, note: str) -> ProbeResult:
    return ProbeResult(
        suite="garak",
        probe=probe,
        verdict=Verdict.ERROR,
        attempts=0,
        findings=[
            Finding(
                attempt_id="n/a",
                prompt_hash="",
                response_hash="",
                severity=Severity.INFO,
                notes=note,
            )
        ],
    )


class _HarnessUnavailableError(RuntimeError):
    pass


class _GarakAttempt:
    """Typed view of one Garak probe attempt."""

    def __init__(
        self,
        *,
        attempt_id: str,
        prompt: str,
        response: str,
        hit: bool,
        severity: str,
        detector: str | None,
    ) -> None:
        self.attempt_id = attempt_id
        self.prompt = prompt
        self.response = response
        self.hit = hit
        self.severity = severity
        self.detector = detector


class _GarakHarness:
    """Thin wrapper around Garak's Python API. Instantiated once per
    process; reuses Garak's global state."""

    def __init__(self) -> None:
        try:
            import garak  # noqa: PLC0415  (optional import)

            self._garak = garak
        except ImportError as e:
            raise _HarnessUnavailableError(
                "garak is not installed in this image; "
                "install with `pip install .[suites]` or pass a different suite name"
            ) from e

    def run_probe(
        self,
        *,
        probe_name: str,
        target_url: str,
        headers: dict[str, str],
        timeout_seconds: float,
        attempts: int,
    ) -> list[_GarakAttempt]:
        # Garak's API is unstable across minor versions (as of 0.9.x
        # the public entry is still marked experimental). We keep the
        # adapter small enough to swap in lock-step with upstream.
        from garak import _config  # noqa: PLC0415
        from garak.generators.rest import RestGenerator  # noqa: PLC0415

        _config.transient.run_id = "fabric-redteam"
        generator = RestGenerator(
            uri=target_url,
            headers=headers,
            timeout=timeout_seconds,
        )
        probe = self._load_probe(probe_name)
        raw_attempts = probe.probe(generator, generations=attempts)
        out: list[_GarakAttempt] = []
        for att in raw_attempts:
            for i, resp in enumerate(att.outputs):
                hit = any(det.detect(att) for det in probe.detectors)
                out.append(
                    _GarakAttempt(
                        attempt_id=f"{att.uuid}-{i}",
                        prompt=str(att.prompt),
                        response=str(resp),
                        hit=bool(hit),
                        severity=str(getattr(probe, "severity", "low")),
                        detector=getattr(probe, "primary_detector", None),
                    )
                )
        return out

    def _load_probe(self, probe_name: str) -> Any:
        from garak import _plugins  # noqa: PLC0415

        return _plugins.load_plugin(f"probes.{probe_name}")


def _load_harness() -> _GarakHarness:
    return _GarakHarness()
