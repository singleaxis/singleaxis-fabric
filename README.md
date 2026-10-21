<div align="center">

# SingleAxis Fabric

**A passive, customer-controlled recorder for AI agents.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Recorder CI](https://github.com/singleaxis/singleaxis-fabric/actions/workflows/recorder-ci.yml/badge.svg)](https://github.com/singleaxis/singleaxis-fabric/actions/workflows/recorder-ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/singleaxis/singleaxis-fabric/badge)](https://securityscorecards.dev/viewer/?uri=github.com/singleaxis/singleaxis-fabric)

[Quickstart](docs/quickstart.md) ·
[Architecture](docs/architecture.md) ·
[Deployment](docs/deployment.md) ·
[Privacy and security](docs/privacy-and-security.md) ·
[Limitations](docs/limitations-and-roadmap.md) ·
[All docs](docs/README.md)

</div>

Fabric records the exact bytes of every model call a Python agent makes
through `httpx`, `httpx2` or `aiohttp` (the official OpenAI and Anthropic
SDKs, LiteLLM, DSPy and the frameworks built on them) without code changes,
plus whatever the application reports through its SDK. It protects each
record in the agent process before it reaches disk (privacy mode per
content role, customer redaction by a redaction service you run, keyed
pseudonyms, encryption), spools it
durably, and delivers it through the Fabric Node to a file directory or
S3-compatible store and an OTLP destination that you own. An offline
verifier, `python -m fabric.reconstruct`, proves whether each run's record
is complete and unaltered. Fabric never blocks, alters or delays the agent,
never requires a SingleAxis service, and does not evaluate or control what
the agent does.

```text
CAPTURE  ->  PROTECT  ->  DELIVER
```

## Capabilities in v0.8

**Available**

| Capability | Where |
|---|---|
| Zero-code wire capture of model calls in Python (httpx, httpx2 and aiohttp; chat completions, responses, completions, embeddings, messages), enabled by autoload or `fabric.wire.install()`; model calls through `requests`/`urllib3` reported as `uninstrumented_client` losses | `sdk/python/src/fabric/wire` |
| Durable, encrypted agent spool (batched writes, loss ledger for a full disk) with at-least-once delivery and restart replay; on by default in node mode and in local file mode | `fabric/wire/_spool.py`, `fabric/wire/_ledger.py` |
| Multiprocessing worker pools ended with `close()`/`join()`: every call delivered | `fabric/wire/_forks.py` |
| PROTECT before disk: 7 privacy modes, customer redaction by a customer-run redaction service (`contracts/redaction/v1`, Unix socket or loopback; reference service in `examples/redaction-service`), typed extraction for large multimodal requests | `fabric/wire/_protect.py`, `fabric/redaction.py` |
| Production profile gate: no content without a capture policy, id key and spool key | `fabric/wire/_policy.py` |
| Keyed pseudonyms: run, source and service labels, and (pseudonym v2, per-type keys) session, user and other caller ids; caller-supplied ids always pseudonymised, emitted ids recognised by type (`EmittedId`) | `fabric/_sequence.py` |
| Fabric Node: allowlist, source authentication (one bound source per production Node), encrypted content queue and hash-sharded file store, delivery to a file directory or S3 with SSE | `components/otel-collector-fabric` |
| `fabric-gate`: refuses unsafe Node configurations at start | `components/otel-collector-fabric/gate` |
| Offline verifier `python -m fabric.reconstruct` and its verdicts | `fabric/reconstruct` |
| Explicit app-reported APIs: `decision()`/`record_*`, `ByteEvidenceRecorder` (Python and TypeScript); `CallRecorder` and byte-boundary adapters (Python) | `sdk/python`, `sdk/typescript` |
| Opt-in qualified-run mode: witness- and receipt-backed `verified_complete_for_declared_scope` (Python) | `fabric/qualified_run.py` |
| Helm chart (`shadow-dev`, `shadow-production`) and Docker Compose (local and production) | `charts/fabric`, `deploy/compose` |
| Linux host sensors (metadata only, corroboration; local profile only): auditd receiver, eBPF host emitter | `components/host-emitter`, `deploy/auditd` |

**Not yet available**

| Gap | Status |
|---|---|
| TypeScript wire capture | Not built (spec 049 TS-1) |
| Calls through `requests`/`urllib3` (reported as losses), `boto3`, gRPC and other clients | Not captured |
| Model endpoints other than the five above (images, audio, realtime, batch, files, ...) | Not captured (P5) |
| `with Pool()` worker pools (SIGTERM) | Can lose calls a worker had not written; accounted, never `complete` |
| Heavy CPU contention (16+ CPU-bound threads in one process) | GIL-bound capture sheds load; every loss is recorded and reported |
| Host sensors on a production Node | Local profile only (planned for P4) |
| Several agent sources on one production Node | One source per production Node |
| Four-layer record: run structure, context, decisions and effects | Phases P1–P5, not built |

Details and the other known defects: [limitations and roadmap](docs/limitations-and-roadmap.md).

## Quickstart (5 minutes, offline)

Requires Python 3.11+. The model is a fake, so nothing leaves your machine.

```bash
git clone https://github.com/singleaxis/singleaxis-fabric.git
cd singleaxis-fabric
python3 -m venv .venv && . .venv/bin/activate
pip install "./sdk/python[otlp]" httpx      # PyPI: singleaxis-fabric, once v0.8.0 is published

python examples/wire-capture/react_agent.py --out-dir /tmp/fabric-demo
```

A small ReAct agent makes three model calls; Fabric stores each request and
response in `/tmp/fabric-demo/store` and one metadata-only span per call in
`spans.jsonl`, then verifies the run:

```text
run r-73312ae07246b3a81a3c4f7073ae3a4f: verdict=complete_for_observed_scopes
reconstruct exit code: 0
```

Now break the record. Delete one `"fabric.model_call"` line from
`/tmp/fabric-demo/spans.jsonl` and re-run the verifier:

```bash
python -m fabric.reconstruct --spans /tmp/fabric-demo/spans.jsonl \
  --store-root /tmp/fabric-demo/store --tenant demo-tenant --run react-demo-1
# -> partial (sequence_gap), exit code 1
```

In your own application, capture needs no code change:

```bash
export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)${PYTHONPATH:+:$PYTHONPATH}"
export FABRIC_WIRE_AUTOLOAD=1
```

plus a store and an OTLP endpoint. The [quickstart](docs/quickstart.md)
runs an unmodified OpenAI SDK program through a local Fabric Node, and
[deployment](docs/deployment.md) covers the production profile.

## Architecture in brief

```text
agent process                                   Fabric Node                         you choose
wire tee ─► PROTECT ─► encrypted spool ─────────► otlp/content ─► fabriccontent ─► file dir / S3 (SSE)
explicit APIs ───────────────────────────────────► otlp ─► fabricguard ─► queue ─► OTLP destination
                                                  (fabric-gate, source binding, sealed queues)
offline: python -m fabric.reconstruct  ─► complete_for_declared_scope | complete_for_observed_scopes | partial | unverified
```

- **Capture** copies bytes on the HTTP client (httpx, httpx2, aiohttp)
  and hands them to a background worker; nothing is parsed and nothing on
  the call path waits.
- **Protect** applies the capture policy per role before the spool; failure
  withholds content, never falls back to raw bytes.
- **Deliver** drains the spool to the Node, which writes the store and
  forwards allowlisted metadata, both through durable queues.
- **Verify** is offline: sequence numbers, loss records, heartbeats and
  digests let the verifier say what is missing.

More: [architecture](docs/architecture.md).

## What ships

| Artifact | Purpose |
|---|---|
| Python SDK `singleaxis-fabric` | Wire capture, explicit APIs, `fabric.reconstruct`, qualified-run verifier |
| TypeScript SDK `@singleaxis/fabric` | Explicit APIs only |
| Fabric Node image `ghcr.io/singleaxis/fabric-otelcol` | Protect, buffer and deliver; `fabric-gate` entrypoint |
| Host emitter image `ghcr.io/singleaxis/fabric-host-emitter` | Optional eBPF host sensor |
| Helm chart `fabric` | Installs the Fabric Node |
| `fabricctl` | Local recorder initialization, configuration validation, digest, help, and version |
| Public contracts | Activity, connect, content, delivery, privacy and recorder interoperability |

See [verify a release](docs/verify-release.md).

Fabric OSS only records. Evaluating, scoring or controlling agents is
outside its scope ([AGENTS.md](AGENTS.md)), and release artifact tests keep
such code out of every package and image.

## Project status

v0.8 is tested in CI and on developer machines, including a matrix of 18
agent framework and pattern rows (OpenAI Agents SDK, LangGraph, LlamaIndex,
PydanticAI, smolagents, AutoGen, AG2, CrewAI, DSPy and others) against a fake
model, and the production profile through a real Node. No customer production deployment has been qualified.
Read [limitations](docs/limitations-and-roadmap.md) before relying on a
verdict.

Specifications: [specs/](specs/README.md). Security reports:
[SECURITY.md](SECURITY.md). Apache-2.0; contributions require DCO sign-off
([CONTRIBUTING.md](CONTRIBUTING.md)).
