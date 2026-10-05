# GPT-6 Sol subscription-backed local agent stage

Status: **experimental laptop rehearsal; production NO-GO**. This stage uses
the local Codex CLI signed in with a ChatGPT subscription. It is not an OpenAI
API-key integration, a customer agent, or an enterprise release artifact.
Fabric OSS remains CAPTURE → PROTECT → DELIVER; the offline comparison below
is a test harness, not a recorder judge or evaluation service.

## Frozen experimental boundary (revision 1)

| Item | Declared value |
| --- | --- |
| Agent | `codex-cli 0.156.1`, noninteractive `codex exec --json`, model `gpt-6-sol`, `--ignore-user-config --ephemeral` |
| Identity | Locally observed parent PID, CLI thread ID and fixture run ID; **not authenticated source→tenant binding** |
| Workspace | Fresh mode-0700 directory beneath the OS private temporary directory; `workspace-write` tool sandbox; synthetic files only |
| Model | Subscription-backed Codex service. The CLI's final visible provider-bound request/response, hidden instructions/tool definitions, transport attempts and provider-side records are unavailable to this harness |
| Tool routes | CLI-reported terminal commands; a fixture HTTP service; synthetic SQLite queries/mutations; Git state; allowlisted file artifacts. Each route is separately witnessed where feasible |
| Excluded | Real SSH, cloud accounts, browser state, customer DBs, privileged host sensors, Kubernetes administration, direct host secrets, and all uninstrumented routes |
| Data | Generated non-sensitive incident scenario with a fake canary; content stays in protected local fixture/evidence paths, never in OTLP or a public PR |
| Limits | One run, at most 16 completed model turns and 64 CLI events, 64 KiB per CLI JSONL event, 1 MiB per artifact, 120 s default agent deadline. Limit breaches lower the verdict; these are test bounds, not throughput measurements |

The command sandbox's network path is enabled only with Codex's network proxy
active and the exact `127.0.0.1`/`localhost` allowlist. The initial network-off
run correctly failed all three service operations. No open internet rule is
used. The subscription transport itself is outside the fixture's command
network policy and is not an independently witnessed provider boundary.

The task simulates a safety-critical infrastructure incident investigation.
The agent must inspect a policy file and immutable fixture inputs, query
SQLite, call a local HTTP telemetry/ticket endpoint, perform a bounded
subprocess calculation, inspect Git state, and create a JSON report plus a
binary evidence artifact. The scenario is deliberately synthetic; it does
not make a clinical, financial, operational-safety, or regulatory decision.
The agent may choose the order of its actions. Each requested action has an
independent expected witness, and any unexpected direct route is a coverage
discrepancy rather than silently added to scope.

## Capture and independent truth

| Boundary | Observable record | Independent comparison | Limit / verdict effect |
| --- | --- | --- | --- |
| Model input/output | Parent-supplied prompt bytes and CLI `agent_message` JSONL events | Parent prompt digest and CLI byte stream | **Not** provider-bound bytes or hidden context; always `unverified` for full model reconstruction |
| CLI terminal | `command_execution` command string, aggregated output, exit status, CLI order | Fixture command journal and resulting file/DB/service state | No ordered raw stdin/stdout/stderr separation, shell expansion or unreported descendants; cannot assert byte-exact terminal capture |
| HTTP service | Fixture server fsynced method/path/body/status/response witness | Service journal outside the CLI event stream | A direct call omitted from CLI JSONL is a known discrepancy |
| SQLite | Explicit fixture query/mutation journal plus pre/post DB snapshot | SQLite file and test-table inventory | SQLite has no independently authenticated server audit; this is a local test, not qualified DB capture |
| Git/files | Git HEAD/status/diff and before/after artifact inventory | Fixture repository and byte hashes outside the recorder's event stream | Reads not mediated by a fixture remain unknown; only allowlisted writes are checked |
| Fabric delivery | Optional metadata-only AEEP projection to the existing local kind Node/sink | Sink readback by record ID/digest | Node acceptance is not source authentication or destination durable receipt |

The first run records raw CLI JSONL and external witnesses in a private
evidence directory. A second, direct-bypass fixture changes the service/DB
or artifact outside the observed CLI session; reconciliation must show a
missing operation. The report uses `partial` for known misses and
`unverified` for missing provider/stream/identity/durable-receipt proof.
It must **never** emit `verified_complete_for_declared_scope` for this
subscription-backed Codex route.

## Offline Fabric projection (separate from the agent path)

After the Codex process exits, an optional test-only projection puts the
parent prompt, CLI JSONL, CLI-visible model messages/command strings and
aggregated outputs, independently witnessed HTTP request/response bodies,
and final artifact bytes into a tenant-scoped Fabric local content store.
The projection labels only the boundary it actually observed: the prompt and
CLI messages are caller-side, command strings are tool-call arguments rather
than true terminal `argv`, and aggregated output is a tool result rather than
raw ordered stdout/stderr. It creates explicit `unsupported` events for the
provider-bound request/response and raw terminal streams. The authorized
offline resolver must read back each stored object and verify exact length
and SHA-256 against the independent local witness. This establishes local
post-run Fabric byte storage, **not** passive real-time capture, authenticated
source identity, Node acceptance, or destination durability.

For the disposable laptop kind simulation only, the projected metadata may be
sent through the already-staged mTLS Node to the fsynced test sink. A separate
verifier parses copied sink OTLP files and matches every projected record ID,
event name and allowed attribute; it also rejects duplicate IDs and content
canaries. This is a stage-specific destination readback, not a customer-store
receipt or a proof about the unexposed agent boundaries.

## Acceptance before any broader claim

1. Pin the CLI binary version, prompt, fixture source digest, workspace
   inventory, model name and emitted event schema. Record exact hashes of
   protected JSONL, service journal, DB and artifact bytes.
2. Verify each expected operation by identity and object digest, not just
   aggregate counts. Include retries, failure, direct bypass and an
   unexpected tool route. Mark unavailable provider context and raw terminal
   streams explicitly unsupported/unverified.
3. Prove the fake canary remains out of Node OTLP, telemetry queue, logs,
   receipts and any published summary. Private raw CLI logs and fixture
   content may contain it and must remain in a mode-0700 test directory.
4. Compare agent outcome and side effects with and without the observer.
   Any observer backpressure or modified tool outcome fails passive capture.
5. Keep the final decision **NO-GO** until an approved target agent exposes
   an observable provider boundary, every reachable tool route is covered or
   closed, source and destination identities/receipts are qualified, storage
   policy is tested, and the independent owners sign the exact scope.

The initial two Sol smoke calls established only subscription routing and
CLI JSONL shape. One returned `SOL_READY`; one emitted a terminal command,
its aggregated output and exit code. The same event stream did not expose
provider-bound request bytes, native stdin/stdout/stderr chunks or hidden
context. No broader coverage is claimed from those calls.
