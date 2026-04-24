# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run configuration loaded from disk.

The CronJob mounts a ConfigMap at a known path; this module parses it
into typed records. One ``RunConfig`` drives one Runner invocation.

Example YAML:

```yaml
tenant_id: acme-prod
agent_id: support-bot
profile: eu-ai-act-high-risk
target:
  url: https://support-bot.acme.example.com/respond
  headers:
    Authorization: Bearer ${env:AGENT_BEARER}
  timeout_seconds: 30
suites:
  - name: garak
    probes: [continuation.ContinueSlursReclaimedSlurs80, promptinject.PromptInject]
    attempts_per_probe: 1
  - name: pyrit
    scenarios: [jailbreak_fuzzer, prompt_injection]
```
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TargetConfig(_Base):
    """HTTP target the probes attack."""

    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = 30.0


class SuiteConfig(_Base):
    """Per-suite knobs. Exactly one of ``probes`` (Garak) or
    ``scenarios`` (PyRIT) applies; the runner picks the right field
    based on ``name``."""

    name: str
    probes: list[str] = Field(default_factory=list)
    scenarios: list[str] = Field(default_factory=list)
    attempts_per_probe: int = 1


class RunConfig(_Base):
    tenant_id: str
    agent_id: str
    profile: str = "permissive-dev"
    target: TargetConfig
    suites: list[SuiteConfig] = Field(default_factory=list)


def load_run_config(path: Path) -> RunConfig:
    """Load a run config from YAML. ``${env:NAME}`` placeholders in
    string values are resolved from the process environment — a small
    ergonomic win that lets operators keep bearer tokens out of the
    ConfigMap.
    """

    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")
    resolved = _resolve_env(raw)
    return RunConfig.model_validate(resolved)


def _resolve_env(value: Any) -> Any:
    if isinstance(value, str):
        return _expand_env_refs(value)
    if isinstance(value, list):
        return [_resolve_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _resolve_env(v) for k, v in value.items()}
    return value


def _expand_env_refs(raw: str) -> str:
    """Expand ``${env:NAME}`` occurrences. Unknown names become empty."""

    out: list[str] = []
    i = 0
    while i < len(raw):
        start = raw.find("${env:", i)
        if start == -1:
            out.append(raw[i:])
            break
        end = raw.find("}", start)
        if end == -1:
            out.append(raw[i:])
            break
        out.append(raw[i:start])
        name = raw[start + len("${env:") : end]
        out.append(os.environ.get(name, ""))
        i = end + 1
    return "".join(out)
