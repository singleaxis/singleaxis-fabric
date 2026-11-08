<div align="center">

# SingleAxis Fabric

**The open-source recorder for AI agents.**
Capture what an agent does, protect it inside your boundary, and deliver a
verifiable record to storage you own.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Recorder CI](https://github.com/singleaxis/singleaxis-fabric/actions/workflows/recorder-ci.yml/badge.svg)](https://github.com/singleaxis/singleaxis-fabric/actions/workflows/recorder-ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/singleaxis/singleaxis-fabric/badge)](https://securityscorecards.dev/viewer/?uri=github.com/singleaxis/singleaxis-fabric)
[![PyPI](https://img.shields.io/pypi/v/singleaxis-fabric.svg)](https://pypi.org/project/singleaxis-fabric/)

[Quickstart](docs/quickstart.md) ·
[Architecture](docs/architecture.md) ·
[Deployment](docs/deployment.md) ·
[Production setup](docs/production-setup.md) ·
[Privacy and security](docs/privacy-and-security.md) ·
[Specs](specs/README.md) ·
[All docs](docs/README.md)

</div>

```text
CAPTURE  ->  PROTECT  ->  DELIVER
```

Fabric gives you a complete, tamper-evident record of what your AI agents
did. With no code changes, it records the exact request and response bytes
of every model call a Python agent sends through `httpx`, `httpx2` or
`aiohttp` to a matched model endpoint, and reports calls through other
detected clients as losses. It protects each record in the agent process
before it touches disk, and delivers it through the Fabric Node to a file directory,
an S3-compatible store and an OTLP destination that you control. An offline
verifier proves whether each run's record is complete and unaltered.

Fabric is passive. It never blocks, delays or changes the agent it records:
results and exceptions are unchanged, and all protection and export work
runs off the call path (about 0.2 ms per call in our benchmarks). It needs
no SingleAxis service.

## What Fabric records

For each agent run, Fabric builds a record that answers four questions:

| Chain | Question | Available |
|---|---|---|
| **Decisions** | What did the model see, and what did it return? | v0.8 |
| **Actions** | Which tools did the model call, with which arguments, and what result came back? | v0.8 |
| **Effects** | What did the agent's process actually run, and what did it return? | v0.10, for subprocesses (opt-in hook); v0.11 adds containers, E2B remote sandboxes and non-model HTTP |
| **Corroboration** | What does the operating system independently record? | Host sensors since v0.8; linked to actions since v0.10 (local profile) and v0.11 (production profile) |

Every link in the record says how it was established and how certain it
is. Fabric never guesses a link: anything it cannot attribute is reported
as unexplained, which is exactly what an auditor needs to see. The design
is [spec 056](specs/056-agent-action-reconstruction.md).

## Features

- **Zero-code capture.** Model calls through `httpx`, `httpx2` and
  `aiohttp`, which covers the official OpenAI and Anthropic SDKs, LiteLLM,
  DSPy and the frameworks built on them. Chat completions, Responses,
  completions, embeddings and Anthropic Messages, including streaming.
- **Protection before disk.** Seven privacy modes per content role,
  redaction by a redaction service you run, keyed pseudonyms for every
  caller identifier, and encryption at rest.
- **Durable delivery.** An encrypted agent spool with at-least-once
  delivery, restart replay and an explicit record of every loss.
- **Offline verification.** `python -m fabric.reconstruct` rebuilds each
  run, stitches tool calls to their results, and returns a verdict:
  complete, partial with the reason, or unverified.
- **Agent action reconstruction.** An opt-in subprocess hook records what
  the agent ran; `python -m fabric.reconstruct actions` links each command
  to the tool call that caused it and to host-sensor events, with a verdict
  per chain ([action reconstruction](docs/action-reconstruction.md)).
  Since v0.11, host sensors report to a production Node as authenticated
  sources of their own, so a command can be tied to its exec event with
  certainty in production, and opt-in hooks also record containers the
  agent starts, E2B remote-sandbox commands and non-model HTTP calls
  ([host sensors](docs/host-sensors.md); agent, Node and emitter end to end
  in [production setup](docs/production-setup.md)).
- **Fabric Node.** An OpenTelemetry Collector distribution with a
  default-deny export allowlist, source authentication, a configuration gate
  that refuses unsafe setups, and delivery to a file directory or S3 with
  server-side encryption.
- **Explicit APIs.** `decision()`, `record_*`, `CallRecorder` and
  byte-boundary adapters for anything the wire does not see, in Python and
  TypeScript, with governed content capture: content objects, transcript
  manifests, authorized resolution and transcript export.
- **Host sensors.** An eBPF emitter and an auditd receiver that record
  process starts and network connections on Linux, as metadata only.
- **Deployment.** A Helm chart with development and production profiles,
  and Docker Compose for local and production use.

## Install

```bash
pip install "singleaxis-fabric[otlp]"
```

```bash
npm install @singleaxis/fabric
```

The TypeScript SDK requires Node.js 22.18 or later.

The Fabric Node installs with the Helm chart
`oci://ghcr.io/singleaxis/charts/fabric` and a `shadow-dev` or
`shadow-production` profile ([deployment](docs/deployment.md)), or with
Docker Compose (`deploy/compose`).

The images and the chart are signed with cosign, the images carry SBOM and
provenance attestations, and `fabricctl` archives carry provenance
attestations. See [verify a release](docs/verify-release.md).

## Quickstart (5 minutes, offline)

Requires Python 3.11+. The model is a fake, so nothing leaves your machine.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install "singleaxis-fabric[otlp]" httpx
git clone https://github.com/singleaxis/singleaxis-fabric.git
cd singleaxis-fabric
python examples/wire-capture/react_agent.py --out-dir /tmp/fabric-demo
```

A small ReAct agent makes three model calls. Fabric stores each request and
response in `/tmp/fabric-demo/store`, writes one metadata-only span per
call to `spans.jsonl`, and verifies the run:

```text
run r-73312ae07246b3a81a3c4f7073ae3a4f: verdict=complete_for_observed_scopes
reconstruct exit code: 0
```

Now tamper with the record. Delete one `"fabric.model_call"` line from
`/tmp/fabric-demo/spans.jsonl` and verify again:

```bash
python -m fabric.reconstruct --spans /tmp/fabric-demo/spans.jsonl \
  --store-root /tmp/fabric-demo/store --tenant demo-tenant --run react-demo-1
# -> partial (sequence_gap), exit code 1
```

To record your own application, enable autoload. No code change is needed:

```bash
export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)${PYTHONPATH:+:$PYTHONPATH}"
export FABRIC_WIRE_AUTOLOAD=1
```

The [quickstart](docs/quickstart.md) runs an unmodified OpenAI SDK program
through a local Fabric Node. [Deployment](docs/deployment.md) covers the
production profile.

## How it works

```text
agent process                                   Fabric Node                         you choose
wire tee ─► PROTECT ─► encrypted spool ─────────► otlp/content ─► fabriccontent ─► file dir / S3 (SSE)
explicit APIs ───────────────────────────────────► otlp ─► fabricguard ─► queue ─► OTLP destination
                                                  (fabric-gate, source binding, sealed queues)
offline: python -m fabric.reconstruct  ─► complete_for_declared_scope | complete_for_observed_scopes | partial | unverified
```

- **Capture** copies bytes on the HTTP client and hands them to a
  background worker. Nothing on the call path parses or waits.
- **Protect** applies the capture policy per content role before the spool.
  A failure withholds the content; it never falls back to raw bytes.
- **Deliver** drains the spool to the Node, which writes the store and
  forwards allowlisted metadata, both through durable queues.
- **Verify** runs offline. Sequence numbers, loss records, heartbeats and
  digests let the verifier state exactly what is missing.

More: [architecture](docs/architecture.md).

## What ships

| Artifact | Purpose |
|---|---|
| Python SDK `singleaxis-fabric` | Wire capture, explicit APIs, `fabric.reconstruct`, qualified-run verifier |
| TypeScript SDK `@singleaxis/fabric` | Explicit APIs |
| Fabric Node image `ghcr.io/singleaxis/fabric-otelcol` | Protect, buffer and deliver; `fabric-gate` entrypoint |
| Host emitter image `ghcr.io/singleaxis/fabric-host-emitter` | Optional eBPF host sensor |
| Helm chart `fabric` | Installs the Fabric Node |
| `fabricctl` | Writes and validates a reviewable recorder declaration (`contracts/recorder/v1`); in v0.8 neither the SDK nor the Node reads it |
| Public contracts | Activity, connect, content, delivery, privacy and recorder interchange formats |

## Known limits

- Wire capture is Python only. TypeScript agents use the explicit APIs;
  TypeScript wire capture is specified ([spec 055](specs/055-typescript-wire-capture.md)).
- Model calls through `requests`/`urllib3` are reported as losses, and
  `boto3`, gRPC and model endpoints beyond the five above are not captured.
- Host sensors run with a local-profile Node; production ingress is
  specified ([spec 053](specs/053-execution-channels-p4.md) §6).
- A production Node serves one agent source.

The full list, with measurements: [limitations](docs/limitations-and-roadmap.md).

## Roadmap

| Release | Focus | Design |
|---|---|---|
| v0.8 | Model-call capture, protection, delivery and verification | [047](specs/047-llm-wire-capture-and-reconstruction.md), [048](specs/048-node-content-delivery-and-agent-spool.md), [049](specs/049-four-layer-capture-coverage.md) |
| v0.9 | Recorder-only scope: out-of-scope leftovers removed; documentation and design specs for the agent record | [056](specs/056-agent-action-reconstruction.md) |
| v0.10 | One run record across every input, and agent action reconstruction: effects linked to the tool calls that caused them, corroborated by host sensors. Released in v0.10.0: most of the run record (050 P1; WP-15, WP-21 and P1-A are not built) and reconstruction of subprocess effects on a local-profile Node (056 M1) | [050](specs/050-run-structure-and-records-p1.md), [053](specs/053-execution-channels-p4.md), [056](specs/056-agent-action-reconstruction.md) |
| v0.11 | Agent action reconstruction in production: host sensors as authenticated sources of a production Node, certain process anchors, container and E2B remote-sandbox effects, non-model HTTP. Released in v0.11.0 (056 M2) | [053](specs/053-execution-channels-p4.md), [056](specs/056-agent-action-reconstruction.md) |
| Later | Run context and lifecycle, decision and effect records, more execution channels, TypeScript wire capture | [051](specs/051-context-and-lifecycle-p2.md), [052](specs/052-decisions-and-effects-p3.md), [054](specs/054-specialised-runtimes-p5.md), [055](specs/055-typescript-wire-capture.md) |

## Scope

Fabric records. It does not evaluate, score, approve or control agents;
evaluation and guardrails consume Fabric's record downstream. Release
artifact tests keep such code out of every package and image
([AGENTS.md](AGENTS.md)).

## Status and support

v0.12.1 is the current stable release. It is tested in CI, including the
production profile through a real Node. Before v0.8.0 it was also run
against 18 agent frameworks and patterns (OpenAI Agents SDK, LangGraph,
LlamaIndex, PydanticAI, smolagents, AutoGen, AG2, CrewAI, DSPy and others)
with a fake model on a developer machine; that harness is not part of this
repository or CI. Before relying on a verdict in your environment, run the
checks in [deployment](docs/deployment.md).

Security reports: [SECURITY.md](SECURITY.md). Support: [SUPPORT.md](SUPPORT.md).
Apache-2.0. Contributions require DCO sign-off ([CONTRIBUTING.md](CONTRIBUTING.md)).
