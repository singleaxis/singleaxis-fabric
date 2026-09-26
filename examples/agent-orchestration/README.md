# Agent orchestration demo — capture, protect, deliver, reconstruct

An end-to-end UAT of Fabric's governed recording plane against a real
agentic workload. Not a mock — every layer below is exercised for real:

```text
agent.py  (Fabric SDK, governed capture, spooled durability)
   |  OTLP spans: refs only, no raw content
   v
otelcol-fabric  (otlp receiver + audit receiver + fabricguard)
   |  allowlisted attrs; argv hashed at collection
   v
sink.py   (durable destination: decoded span/log records -> records.jsonl)
   |
   +-- governed store (out/store/)  <- content bytes never left this
   +-- audit stream   (out/audit/)  <- host observation layer
   v
reconstruct.py  ->  out/journal.json  ->  viewer/index.html
```

## The workload

A scripted deterministic "model" (`orchestrator-v1`) runs an incident
investigation — deterministic so the demo is reproducible offline with
no API keys; everything *around* the model is real:

| Step | What really happens |
|---|---|
| `llm_call` ×2 | instructions + task in; tool requests → report directive out |
| `read_file` | real read of `data/deploy.log` (audit `openat`) |
| `run_shell` ×3 | real `grep`, `ls`, and `sh -c …` subprocesses (audit `execve`) |
| `fetch_metrics` | real localhost HTTP GET (audit `connect` + peer addr) |
| `record_context` | `runbook.md` captured as `context.file` |
| `record_retrieval` | runbook search → governed `retrieval.results` |
| `write_report` | real `incident-report.md` write + `side_effect` record |
| `run_shell` (secret) | exec whose argv carries a secret-shaped token — proves the collector hashes argv (`process.command_args_sha256`) and never exports it |

## Run it

```bash
bash examples/agent-orchestration/run.sh
open examples/agent-orchestration/viewer/index.html
```

Prereqs: Docker (for `fabric-otelcol:local` — rebuild with
`docker build -t fabric-otelcol:local components/otel-collector-fabric`
if the image predates your checkout), repo Python venv.

`reconstruct.py` doubles as the UAT gate — it exits non-zero unless all
of these hold:

- decision, both model calls, and every tool span reached the sink with
  refs (`fabric.content.request_ref`/`result_ref`/`manifest_ref`);
- every manifest item resolved **available** — descriptor, byte length,
  and SHA-256 digest verified (21 items on a clean run);
- audit exec/connect/openat events exist for the commands/connections
  the agent actually made, correlated to spans as `inferred` provenance;
- the secret argv token never appears in exported telemetry — only its
  sha256 does;
- the stamped `manifest_ref` equals the resolved manifest URI.

## Host layer honesty

- **macOS** (this demo): the kernel has no Linux audit subsystem and
  Docker Desktop's VM masks `CAP_AUDIT_*` — `audit_shim.py` therefore
  emits auditd-format records for syscalls the agent *really* performed
  (real pid/ppid/exit/argv/cwd measured at exec). The collector parses,
  assembles, dedupes, allowlists and forwards them through the identical
  production code path (`audit` receiver → `fabricguard` → export).
- **Linux**: `collect-audit-linux.sh start` loads
  `deploy/auditd/fabric.rules` into real auditd; bind-mount
  `/var/log/audit` over `out/audit/` (or use the receiver's netlink
  source with `CAP_AUDIT_READ`). Zero demo code changes — kernel truth
  replaces the shim.
- Audit events are **inferred provenance** (time+pid joins), never
  claimed causal edges — per spec 030.

## What this is not

Demo artifacts only: no evaluation, no judging, no governance UI. The
viewer is a read-only local renderer for the journal — policy,
enforcement and fleet features stay out of scope per `AGENTS.md`.
