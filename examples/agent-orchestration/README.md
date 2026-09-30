# Agent orchestration demo — inspect a bounded synthetic run

An offline demonstration of Fabric's governed recording path. The model is a
scripted deterministic stand-in; local subprocess, HTTP, and file operations
are real. The audit-format shim is emitted by the agent, not an independent
kernel witness. This is not a production-completeness or enterprise GO test.

```text
agent.py  (Fabric SDK, governed capture, spooled durability)
   |  OTLP spans: refs only, no raw content
   v
otelcol-fabric  (otlp receiver + audit receiver + fabricguard)
   |  allowlisted attrs; argv hashed at collection
   v
sink.py   (demo destination: decoded span/log records -> records.jsonl;
           no fsync or durable-receipt claim)
   |
   +-- governed store (out/store/)  <- content bytes never left this
   +-- audit stream   (run/audit/)  <- agent-emitted shim, not host proof
   v
reconstruct.py  ->  run/journal.json  ->  run/viewer/index.html
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

## Run it locally

```bash
FABRIC_DEMO_ISOLATED=1 bash examples/agent-orchestration/run.sh
```

Run only with synthetic, non-sensitive data in an isolated local environment.
The demo sink listens on all local interfaces without authentication and does
not fsync or issue a durable persistence receipt. The explicit environment
flag is an acknowledgement of that limited test posture, not a security
control or production qualification.

The command prints a unique `out/runs/<run-id>/viewer/index.html` path to
open. Each run retains its own journal, collector log and viewer; the script
does not delete previous output or an existing Docker container. It stops and
removes only the container ID it created. The demo requires free local ports
and does not run privileged host capture.

Prereqs: Docker (for `fabric-otelcol:local` — rebuild with
`docker build -t fabric-otelcol:local components/otel-collector-fabric`
if the image predates your checkout), repo Python venv.

`reconstruct.py` is a demo self-check — it exits non-zero unless all
of these hold:

- decision, both model calls, and every tool span reached the sink with
  refs (`fabric.content.request_ref`/`result_ref`/`manifest_ref`);
- every manifest item resolved **available** — descriptor, byte length,
  and SHA-256 digest verified (21 items on a clean run);
- agent-emitted audit-format exec/connect/openat records exist for the
  commands/connections the agent made, correlated to spans as `inferred`
  provenance; these are not independent system records;
- the secret argv token never appears in exported telemetry — only its
  sha256 does;
- the stamped `manifest_ref` equals the resolved manifest URI.

## Host layer honesty

- **macOS and Linux, default demo:** `audit_shim.py` emits auditd-format
  records for operations this agent performs. The collector parses and
  protects those records, but the agent could omit or fabricate them.
- **Independent Linux host evidence:** not installed by this demo.
  `collect-audit-linux.sh` deliberately refuses to change audit rules.
  Broad `deploy/auditd/fabric.rules` covers all host processes and must not
  be loaded on a shared or customer host for this demonstration. A separately
  approved isolated disposable host and scoped rule plan are required;
  see `deploy/auditd/README.md`.
- Audit events are **inferred provenance** (time+pid joins), never
  claimed causal edges — per spec 030.

## What this is not

Demo artifacts only: no evaluation, judging, governance UI, independent
system audit or full-run verdict. The viewer is a read-only local renderer
for one synthetic run; policy, enforcement and fleet features stay out of
scope per `AGENTS.md`.
