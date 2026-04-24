# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scheduled adversarial testing against a tenant agent endpoint.

Phase 1 public surface. The runner orchestrates Garak and PyRIT suites
on the cadence a Regulatory Profile picks, emits one OTel span per
probe (and an aggregate span per run) tagged with ``event_class``
``redteam_probe`` / ``redteam_run``, and lands the results in
Langfuse via the same Fabric collector every agent decision uses.
"""

from ._version import __version__
from .config import RunConfig, SuiteConfig, TargetConfig, load_run_config
from .emitter import OTelEmitter, ResultEmitter
from .results import Finding, ProbeResult, RunResult, Severity, Verdict
from .runner import Runner, Suite, load_suite

__all__ = [
    "Finding",
    "OTelEmitter",
    "ProbeResult",
    "ResultEmitter",
    "RunConfig",
    "RunResult",
    "Runner",
    "Severity",
    "Suite",
    "SuiteConfig",
    "TargetConfig",
    "Verdict",
    "__version__",
    "load_run_config",
    "load_suite",
]
