# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Garak driver.

Garak is a CLI. Rather than spawn a subprocess per probe, we invoke
its Python API directly when the library is installed; when it isn't
(tests, unit envs), the driver short-circuits to a stub that marks
every requested probe as ``Verdict.ERROR`` with a clear note. This
keeps the happy path fast and unit tests hermetic."""

from __future__ import annotations

import json
import logging
import subprocess
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .config import SuiteConfig, TargetConfig
from .results import Finding, ProbeResult, Severity, Verdict
from .runner import hash_text, resolve_venv_python

# Timeout for the build-time smoke probe of the garak venv. The
# runner itself sets its own per-probe timeout via ``target.timeout_seconds``
# during actual execution; this is just for the import-check.
_VENV_PROBE_TIMEOUT_S = 30.0

_LOG = logging.getLogger(__name__)


class GarakSuite:
    """Driver for https://github.com/leondz/garak."""

    name = "garak"

    def __init__(self, *, venv: Path | None = None) -> None:
        # When ``venv`` is provided, the driver shells out to that
        # virtualenv's python so garak's dep graph stays isolated
        # from pyrit's (SPEC 014 §4.1). When unset, falls back to
        # importing garak in the current process — used by tests and
        # ad-hoc dev runs.
        self._venv = venv

    def run(self, target: TargetConfig, suite_config: SuiteConfig) -> Iterable[ProbeResult]:
        if not suite_config.probes:
            return []
        try:
            harness = _load_harness(venv=self._venv)
        except _HarnessUnavailableError as e:
            return [_error_result(p, str(e)) for p in suite_config.probes]
        return list(self._run_probes(target, suite_config, harness))

    def _run_probes(
        self,
        target: TargetConfig,
        suite_config: SuiteConfig,
        harness: _GarakHarness | _VenvGarakHarness,
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


def _load_harness(*, venv: Path | None = None) -> _GarakHarness | _VenvGarakHarness:
    if venv is not None:
        return _VenvGarakHarness(venv=venv)
    return _GarakHarness()


class _VenvGarakHarness:
    """Subprocess-backed harness. Spawns ``{venv}/bin/python`` with
    an inline adapter script per probe; reads JSON attempts from
    stdout. Used by the published image so garak's deps stay isolated
    from pyrit's."""

    def __init__(self, *, venv: Path) -> None:
        self._python = resolve_venv_python(venv)
        if self._python is None or not Path(self._python).exists():
            raise _HarnessUnavailableError(
                f"garak venv python not found at {self._python}; "
                "is the image's /opt/venv/garak intact?"
            )
        # Smoke-check: confirm `import garak` works in the venv.
        # A broken venv at runtime is a clearer error than a cryptic
        # ImportError emerging from probe execution.
        try:
            subprocess.run(  # noqa: S603 (path is venv-relative, fixed by caller)
                [str(self._python), "-c", "import garak"],
                check=True,
                capture_output=True,
                timeout=_VENV_PROBE_TIMEOUT_S,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            raise _HarnessUnavailableError(
                f"garak smoke-import failed in venv {self._python}: {e}"
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
        # The probe execution itself still uses garak's Python API,
        # but inside the venv subprocess. The adapter script writes
        # JSON-serialized attempts to stdout; we parse and reconstruct.
        # Probe selection / chaining logic stays out of this row — see
        # SPEC 014 row #2.
        payload = json.dumps(
            {
                "probe_name": probe_name,
                "target_url": target_url,
                "headers": headers,
                "timeout_seconds": timeout_seconds,
                "attempts": attempts,
            }
        )
        try:
            result = subprocess.run(  # noqa: S603
                [str(self._python), "-c", _GARAK_ADAPTER_SCRIPT],
                input=payload,
                capture_output=True,
                text=True,
                check=True,
                timeout=max(_VENV_PROBE_TIMEOUT_S, timeout_seconds * max(attempts, 1) + 30),
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            raise _HarnessUnavailableError(
                f"garak subprocess failed for probe {probe_name}: {e}"
            ) from e
        try:
            raw = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as e:
            raise _HarnessUnavailableError(
                f"garak adapter returned non-JSON output for {probe_name}"
            ) from e
        return [
            _GarakAttempt(
                attempt_id=str(r.get("attempt_id", "")),
                prompt=str(r.get("prompt", "")),
                response=str(r.get("response", "")),
                hit=bool(r.get("hit", False)),
                severity=str(r.get("severity", "low")),
                detector=r.get("detector"),
            )
            for r in raw
        ]


# Inline adapter script the garak venv subprocess executes. Kept as a
# string literal (not a separate file) so the runner package doesn't
# need to be installed into the garak venv. Reads JSON request from
# stdin, prints JSON-serialized attempts to stdout. Mirrors the body
# of ``_GarakHarness.run_probe`` above.
_GARAK_ADAPTER_SCRIPT = """\
import json, sys
req = json.loads(sys.stdin.read() or '{}')
from garak import _config
from garak.generators.rest import RestGenerator
from garak import _plugins
_config.transient.run_id = 'fabric-redteam'
generator = RestGenerator(
    uri=req['target_url'],
    headers=req.get('headers') or {},
    timeout=req.get('timeout_seconds', 30.0),
)
probe = _plugins.load_plugin('probes.' + req['probe_name'])
raw = probe.probe(generator, generations=req.get('attempts', 1))
out = []
for att in raw:
    for i, resp in enumerate(att.outputs):
        hit = any(det.detect(att) for det in probe.detectors)
        out.append({
            'attempt_id': f"{att.uuid}-{i}",
            'prompt': str(att.prompt),
            'response': str(resp),
            'hit': bool(hit),
            'severity': str(getattr(probe, 'severity', 'low')),
            'detector': getattr(probe, 'primary_detector', None),
        })
json.dump(out, sys.stdout)
"""
