---
title: Agent Surface Logging
status: draft
revision: 1
last_updated: 2026-06-10
owner: project-lead
---

# Spec 022 — Agent Surface Logging

**Status:** proposed (v0.7 target)
**Depends on:** spec 002 (architecture), the existing hash-on-span privacy contract.

## Goal

Extend the OSS SDK so it logs **every way an agent touches the outside world**,
not just decisions/LLM/tool/retrieval/memory/side-effects. Add five touch
points: **MCP server inventory · skills · sub-agent delegation · hooks · file
access.** Logging only (OSS); threat analysis on top is Commercial.

## The one invariant (applies to all five)

> Every touch point is a **span event** under the `fabric.*` namespace, carrying
> **metadata + SHA-256 hashes** — **never raw data** on the span. Hashing uses
> the existing `_sha256_hex` helper (UTF-8 `surrogatepass`). This is the same
> contract `record_retrieval`/`remember`/`record_side_effect` already follow.

All additions are **additive**: no existing `fabric.*` attribute changes, so the
**31 frozen conformance goldens stay byte-identical**. New goldens MAY be added
for the new events but existing ones MUST NOT change.

## 1. MCP server inventory (extend `integrations/mcp.py`)

Today `traced_call_tool`/`InstrumentedMCPSession` log tool *calls*. Add inventory
capture so you can detect a server's tools changing underneath the agent
(shadow/poison attack).

- New method `InstrumentedMCPSession.snapshot_inventory()` (and an
  auto-capture wrapper around `list_tools()` if present) that records what the
  server exposes.
- New module helper `record_mcp_inventory(decision, *, server, transport, tools, resources=None, prompts=None)`.
- Each tool's **definition** (name + description + input schema) is hashed →
  `def_hash`. The raw description/schema is NOT placed on the span.
- Event `fabric.mcp.inventory` with attributes:
  - `fabric.mcp.server` (str), `fabric.mcp.transport` (str)
  - `fabric.mcp.tool_count` (int)
  - `fabric.mcp.tools` (tuple[str]) — each `"<tool_name>:<def_hash[:12]>"`
  - `fabric.mcp.tools_hash` (str) — hash over the canonical full tool list
  - `fabric.mcp.resource_count`, `fabric.mcp.prompt_count` (int, optional)

## 2. Skills / plugins (new `Decision.record_skill`)

```python
d.record_skill(name, version, *, source=None, manifest_hash=None, signed=None)
```

- Event `fabric.skill` with: `fabric.skill.name`, `.version`, `.source`
  (optional), `.manifest_hash` (optional; hash of the prompt+tools bundle),
  `.signed` (bool, optional — was the manifest signature valid?).
- Rolling decision-span attribute `fabric.skill_count`.

## 3. Sub-agent delegation (new `Decision.delegate`)

First-class "agent A invoked agent B", reusing the existing tracestate
propagation.

```python
with d.delegate(to_agent, *, protocol="custom") as sub_ctx:
    ...  # sub_ctx exposes the carrier/context to pass downstream
```

- Context manager. On enter, emits `fabric.delegation` event:
  `fabric.delegation.to_agent`, `.protocol` (e.g. `"a2a"`, `"mcp"`, `"custom"`),
  `.depth` (int — delegation depth).
- Propagation gains `parent_agent_id` + `parent_decision_id` so the child
  agent's spans link back. Add `parent_agent_id` to `FabricContext`
  (optional, backward-compatible).
- Rolling attribute `fabric.delegation_count`.

## 4. Hooks / middleware (new `Decision.record_hook`)

```python
d.record_hook(name, phase, *, modified=False, input_hash=None, output_hash=None)
```

- `phase` is a closed vocab: `pre_model | post_model | pre_tool | post_tool | pre_decision | post_decision`.
- Event `fabric.hook` with: `fabric.hook.name`, `.phase`, `.modified` (bool),
  `.input_hash`, `.output_hash` (optional). A differing in/out hash with
  `modified=True` is the "something tampered with context" signal.
- Rolling attribute `fabric.hook_count`.

## 5. File access (new `Decision.record_file_access`)

```python
d.record_file_access(path, operation, *, content_hash=None, size_bytes=None, redact_path=False)
```

- `operation`: `read | write | delete | append`.
- **Names + hash, never data.** Captures: `fabric.file.path` (or
  `fabric.file.path_hash` when `redact_path=True`), `fabric.file.operation`,
  `fabric.file.content_hash` (optional — hash of contents), `fabric.file.size_bytes`,
  `fabric.file.path_redacted` (bool).
- **Privacy:** the file's *contents* are never on the span — only a hash. The
  *path* is captured readable by default but `redact_path=True` hashes it (for
  sensitive paths like `/patients/jane/record.pdf`). Profiles MAY default
  `redact_path=True`.
- Rolling attribute `fabric.file_access_count`.

## Implementation notes

- Follow `record_retrieval` / `remember` / `record_side_effect` (in
  `sdk/python/src/fabric/decision.py`) as the template: `with self._exclusive()`,
  emit a span event, update a rolling count attribute, use `_sha256_hex` for
  hashing.
- Add new `ATTR_*` constants in `sdk/python/src/fabric/_attributes.py`.
- Async variants where natural (delegation), matching the existing
  `aguard_*`/`aevaluate_policy` pattern.
- `mypy --strict`, `ruff` clean, full pytest suite green, coverage ≥85%.

## Conformance

- Run the conformance suite and confirm the **31 existing goldens are
  byte-identical** (these features emit only when explicitly called).
- Add at least one new conformance golden per touch point exercising the new
  events deterministically.

## Out of scope (Commercial / later)

- Threat detection (poisoned tool, malicious skill, tampering hook) — Commercial
  Surface Audit.
- Raw content to a ContentStore for these events (hash-only for v1).
- TypeScript SDK mirror (tracked separately, #70).
