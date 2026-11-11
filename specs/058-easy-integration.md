---
title: Easy integration — near one-click setup, a launcher for zero-code capture, and checked paths to production (install, configuration and verification tooling only)
status: accepted
qualification: NO_COVERAGE_CLAIM
revision: 2.2
last_updated: 2026-11-11
owner: recorder-engineering
depends_on: ["047", "048", "049", "053", "055", "056", "057"]
related: ["027", "030", "031", "050", "051", "052", "054"]
---

# 058 — Easy integration

## Revision log

| Rev | Date | Change |
|---|---|---|
| 1 | 2026-11-09 | First draft, from the owner's direction of 2026-11-09 ("the ease of integration ... make it an easy one click set up (not literally but let us get as close to that as possible)"), the lead engineer's proposed plan, and the friction audit of the same day. Answers the owner's question on integration touch points (section 1). |
| 2 | 2026-11-10 | Accepted. The owner accepted every section 17 recommendation as written (OQ-1 to OQ-14). OQ-11 is applied to `AGENTS.md`. New section 16.8 marks the parts of E1-E3 that PRs merged on 2026-11-09/10 already did (#286, #287, #288), so the build does not redo them; OQ-10 is closed by spec 056 revision 11 (#287). No target, rule or work package changes otherwise. |
| 2.1 | 2026-11-10 | Build notes from unit E1a (WP8-1, WP8-6, WP8-7); no target or rule changes. (a) The built-in rows keep today's matcher ids (`openai`, `anthropic`, `azure-openai`); the emitted C35 label of a built-in row is `<id>.default`, the form 8.1 names, so nothing a reader or an operator's `--endpoint-id` already uses changes (I8). (b) Only those three rows ship in table version 1; the other candidate rows stay in the table's `candidates` list until a response recorded from that provider qualifies them (8.1: an unqualified row is not shipped). The qualification fixtures were recorded from an OpenAI- and Anthropic-compatible server; they qualify each row's dialect, not provider-specific behaviour. (c) The manifest property `endpoint_table_version` (15) is deferred to its own unit: the Node checks manifest keys against an allowlist, so the Python, schema and Go change must land together with a version-skew test; until then `status()`, the status file and `fabric version` report the table version. (d) `no_store` and `endpoint_set` (13.2) are notices, not warnings, so `python -m fabric.wire status` keeps its exit code for metadata-only users. (e) The unmatched-host fix names `FABRIC_WIRE_ENDPOINTS` until `fabric init --provider` ships (WP8-2). (f) The `FABRIC_OTLP_*` route is http/protobuf. (g) The catalogue's docs page is `docs/diagnostics.md` until the 14.1 restructure moves it. (h) The commands not built yet in a release report `FC-010` and exit 2. |
| 2.2 | 2026-11-11 | Build notes from unit E1b (WP8-2, WP8-3, local profile); no target or rule changes. (a) The `[cli]` extra also installs the OTLP/HTTP exporter (11.1 named PyYAML and cryptography only): `init` compiles an https Node endpoint, so without it the one install of G1 stops at `FW-011`. (b) The Node and the sink run as the operator's own uid (container root under rootless Docker; the image user with the Node key shared `root:65532 0440` when the operator is root), so the 0600 files of 7.2 stay private and no group is created. (c) The Compose templates and the sink ship as code (`fabric/cli/_templates.py`, `_localsink.py`), because the wheel carries no data file (057 B8). (d) The Compose project is always `fabric-<project>` (5.1 says the project name names it), so it can never be the customer's own Compose project in the same directory (I5). (e) `down --purge` never deletes recorded data (`./fabric-data`), only volumes and `.fabric/state`. (f) The emitter's local mode filters on one exact cgroup, so on Docker Desktop the sensor loads but sees only a process placed in `fabric.slice/agent-<project>` inside the VM; `FC-042` says a process on the Mac is invisible. Scoping a container is WP8-4's cgroup join. (g) `up` reissues a Node certificate within 14 days of expiry from the existing CA (7.3 leaves the trigger open). (h) `--rotate all` leaves the id key alone (7.3: never automatic). Tokens and the overlap rule of 7.3 are production (E4). (i) Not built in this unit and answered with `FC-011`: `up --verify-images` (cosign reaches the registry and the transparency log, which I4 has to name first), `init --from-env-file` and `--from-values` (E4, E2), the auditd sensor start (`FC-046` points at the manual page). (j) `secrets.id_key_file` and `secrets.ca_file` are added to `fabric.config/v1` for 11.3's "referenced by their existing paths". (k) Review of E1b: `secrets.ca_file` applies to an external Node only (a local Node's certificate is issued from the generated CA, so the pair `node.mode: docker` with `secrets.ca_file` is refused and `--from-env` does not import a CA without a Node endpoint); `down --purge` takes neither a helper image nor a cgroup path from `.fabric/state` on trust; a sensor that does not stay up is removed from the Compose project. |

**Status: accepted (revision 2, owner decisions of 2026-11-10); E1a
and E1b built (WP8-1 to WP8-3, WP8-6, WP8-7; build notes in revisions
2.1 and 2.2), the rest not built.** This spec changes no code and no
contract by itself. Contract additions are listed in section 15 and are applied only by the work
packages of section 16. The owner accepted every recommendation of
section 17 as written; section 16.8 lists work already done on main.

**Evidence.** Every target and every fix below cites the integration
friction audit of 2026-11-09 (an engineer with no prior Fabric context,
following only the public docs at `origin/main` `38bac8ce`, v0.12.1, on
five paths). Its findings are cited as **F1–F25** (ranked friction),
**N1–N8** (plan items it proposed), **S1–S7** (silent failures) and
**D1–D21** (documentation defects). Section 2 summarises the evidence;
section 16.7 maps every finding to the section that addresses or defers it.

---

## 0. Summary

**The problem.** A machine that already knows Docker and Kubernetes
reached a verified record of its own Python agent in 4 m 40 s on a laptop.
A person needs 20–40 minutes for the same path, 2–4 hours for a single
production host and 4–8 hours for Kubernetes. A Node.js agent never
reached a verified record. The production paths need about 34 (Compose)
and 45 (Kubernetes) hand-made certificates, keys, tokens, env lines and
YAML files, three undocumented workarounds, and seven failure modes that
say nothing or say the wrong thing.

**The fix.** One operator CLI, `fabric`, that sits outside the agent and
does the setup work a person does by hand today; small diagnostic and
packaging fixes in the SDK, Node, emitter, reader and chart; and
documentation that is executed in CI exactly as written.

| Command | One line |
|---|---|
| `fabric plan [-- CMD]` | Read-only. Detects how and where the agent runs, prints which capture layers to turn on, what each will record, what stays invisible, and the one command that closes each gap. |
| `fabric init` | Writes one `fabric.yaml` and generates every secret (pseudonym key, tokens, content and spool keys, local CA, certificates) into a private directory or Kubernetes Secrets. |
| `fabric up` / `fabric down` | Starts or stops the Fabric Node and a destination with Docker, or installs the Helm release; starts the host sensor where it can load and reports why where it cannot. |
| `fabric run -- CMD` | Turns on zero-code capture for one agent command and replaces itself with it (`exec`). Fail-open: if anything is wrong the agent runs exactly as it would without Fabric. |
| `fabric verify [--production]` | Sends a canary through the whole path, reads the user's last run back, prints the coverage report (recorded / invisible / fix) and, with `--production`, every hardening check. |
| `fabric doctor` | Diagnoses a broken install. Every message names the fix. |
| `fabric show [RUN]` | Shows what the agent did: the conversation, tool calls with arguments and results, effects and host evidence. |

**Targets** (section 3): own Python agent on a laptop in at most 5
minutes with one install command and three Fabric commands, and zero
hand-made files, secrets or env vars; a production single host in at
most 15 minutes and Kubernetes in at most 15 minutes with zero hand-made
secrets; `fabric plan` answers the "which layers" question in one
command; zero silent failures. CI measures each target with a
fresh-environment time-to-first-record (TTFR) test and with
documentation that is executed as written.

**Phases** (section 16): E0 audit (done) → E1 local CLI → E2 Kubernetes
and E3 plan, coverage and docs (in parallel) → E4 production path.

**Boundary** (section 4): install, configuration and verification tooling
for the recorder only. Fail-open and passive, no phone-home, no fleet
management or rollout, no framework dependency.

---

## 1. Integration touch points

The owner asked on 2026-11-09: *"What are the touch points for
integrations? Is it code? And what else, and how do we integrate within
the CLI and the SDK, or both?"*

### 1.1 Principle: code is the last resort

The default integration is **zero code: a launcher and configuration**.
A customer changes code only to report facts that exist nowhere except
inside the agent's own code:

1. **In-code permission decisions.** An `if` in the agent's dispatcher
   that refuses a tool call. Fabric observes the tool call, the refusal
   text and the missing effect with zero code (spec 057 §4.10.1, and a
   configured denial marker). It cannot know which rule decided. One
   decorator, `control_check`, records that (057 §4.10.3).
2. **Business identity.** End user, session or conversation in a
   multi-tenant service. Fabric does not capture the agent's inbound
   requests, so no zero-code path sees them. One line,
   `with fabric.wire.run(session_id=..., user_id=...)`, scopes each
   request (050 §3.6). A per-request tenant in one process is not
   supported by any input today (section 17, OQ-13).
3. **Steps with no observable boundary.** A workflow step, a memory write
   or a delegation that crosses no model call, process, network or OTLP
   boundary: the records APIs (051, 052).
4. **Model calls through clients Fabric does not hook** (`requests`,
   `urllib3`, gRPC, `boto3`): today a declared `uninstrumented_client`
   loss. The fix is `llm_call()` or a hooked client. `fabric plan` names
   which.

Everything else (model calls, tool calls and results, commands, network
contacts, MCP traffic, host evidence, the security context 057 derives
from the wire and the OS) is configuration.

### 1.2 Every place a customer touches

"CLI owns" and "SDK owns" say which of the two delivers the touch point.
The CLI and SDK are defined in 1.3.

| # | Touch point | Who | Code change? | Default zero-code path | CLI owns | SDK owns |
|---|---|---|---|---|---|---|
| T1 | **Agent launcher and environment.** How the agent process is started: a shell, `uv run`, a Dockerfile `CMD`, a systemd unit, a Compose service, a Pod spec. | Developer (laptop); platform (production) | No | `fabric run -- CMD`, or `fabric run --print-env --format sh/dotenv/docker/systemd/k8s` pasted into the existing launcher; on Kubernetes, opt-in pod injection by annotation (10.4). | Compiling configuration into the environment; launching by `exec`; the injector. | The autoload entry point that reads that environment. |
| T2 | **Agent dependencies** (virtualenv, image, `package.json`). | Developer | No (one dependency line) | `pip install singleaxis-fabric` in the agent's environment or image; `npm i @singleaxis/fabric` when TypeScript wire capture ships (055). `fabric run` and `fabric doctor` detect a missing SDK and print the exact line for that interpreter (5.4). | Detection and the install hint. | Everything that runs in the agent process. |
| T3 | **Agent code.** | Developer | **Only for the four code-only facts of 1.1** | None needed for levels 0, 1 and 3 of the ladder (1.5). | Nothing. `fabric plan` and `verify` name the API that would close a gap. | Explicit APIs: `fabric.wire.run(...)`, `control_check`, `record_*`, `llm_call()`, per language. |
| T4 | **Host or node.** Kernel sensor (eBPF or auditd) for process and network evidence that does not rely on the agent. | Platform; security | No | `fabric up` starts the sensor where it can load (Linux, kernel and BTF present, permitted); on Kubernetes the chart's `hostSensor` preset (10.5). Where it cannot load (macOS-native, gVisor, serverless) the reason is reported. | Loadability detection, start, scoping (5.4), reporting. | Nothing (the sensor is a separate component, 030/031). |
| T5 | **Collector and destination infrastructure.** The Fabric Node, its durable queue, and where records go. | Platform | No | `fabric up` with a destination preset (section 9); `helm install` with a preset on Kubernetes. | Rendering and starting; preset validation; readback for `verify`. | Spool and delivery to the Node (048). |
| T6 | **Configuration and secrets.** Tenant, agent id, capture policy (privacy), endpoints, keys, tokens, certificates. | Platform; security | No | `fabric init` writes `fabric.yaml` and generates every secret (sections 6, 7). Privacy defaults come from the profile. | All of it. | Reading the compiled environment and capture policy, as today. |
| T7 | **Existing telemetry.** The agent may already emit OpenTelemetry to its own collector. | Developer; platform | No | Fabric never takes over the agent's telemetry: `fabric run` sets only `FABRIC_*` variables, never `OTEL_*` (rule I2, 6.4). To also send records to the existing stack, choose the `otlp` destination preset. Third-party OTLP emitters reach Fabric through 057 P3 mapping profiles. | Detecting `OTEL_*` and leaving it alone; the `otlp` preset. | The private tracer provider (wire capture already uses one when a global provider exists). |
| T8 | **MCP and tool servers.** | Developer; platform | No | The model's MCP tool calls are in the model bodies (wire). HTTP MCP servers: one `capture.http_hosts` line. Stdio servers: the exec hook or the sensor sees them as processes; message content through the 053 transport hook (057 P1, OD-4) by configuration. | `plan` detects the MCP protocol library and prints the line. | The hooks. |
| T9 | **The read side.** Who reads the record and how. | Security; reviewer; developer | No | `fabric show`, `fabric verify`; the reader library and `python -m fabric.reconstruct` stay. | The user-facing commands and the coverage report. | The reader library (Python). |

### 1.3 CLI and SDK: the split

- **The SDK is the in-process library**, one per language: the capture
  hooks, the autoload entry point, the explicit APIs, the spool and the
  sender. It runs inside the agent and is the only Fabric code that does.
  The Python distribution also carries the reader library, as today.
- **The CLI is the operator tool outside the agent**: `plan`, `init`,
  `up`, `down`, `run`, `verify`, `doctor`, `show`. It is also the
  **launcher** that turns on the SDK's zero-code capture: `fabric run`
  compiles configuration into environment variables and `exec`s the agent
  command. After that the CLI is gone; the SDK does the capture.
- **The CLI is never imported by the agent.** It lives in its own module
  (`fabric.cli`) that autoload never imports, and its extra dependencies
  are never loaded into an agent process (test: the autoload import graph
  excludes `fabric.cli` and every `[cli]`-only dependency).
- **"Both" is the answer for most users**: the CLI configures and
  launches; the SDK captures. Developers who prefer to configure by hand
  keep doing so: the SDK reads exactly the same environment it reads
  today (section 11.3).

### 1.4 Getting the CLI without Python

| User | Gets the CLI from | Commands available |
|---|---|---|
| Python agent | PyPI: `pip install "singleaxis-fabric[cli]"` in the agent's own environment (one install gives SDK and CLI), or `pipx`/`uv tool install` for a global CLI. | All |
| Node.js-only | npm: `@singleaxis/fabric` ships a thin `fabric` bin with `run` and `doctor` only; the container image for the rest. No Python install. | `run`, `doctor` (npm); all (image) |
| Compiled binary (Go, Rust, JVM) | Container image `ghcr.io/singleaxis/fabric-cli:<version>`. `fabric run --print-env` output goes into the existing launcher. | All except `run` exec'ing a host binary from inside the container (use `--print-env`) |
| Kubernetes | The chart's secrets Job and injector use the same image; `fabric verify --kubernetes` from any of the above. | All |

The npm launcher reads the compiled environment file that `fabric init`
writes beside `fabric.yaml` (`.fabric/compiled.env`, 6.5), so it needs no
YAML parser and adds no dependency to the SDK. Its environment
compilation is tested against the Python CLI's with shared goldens. Why
not a static binary: section 11.1 and OQ-2.

### 1.5 The integration ladder

Each level adds to the one before. "Recorded" uses the 049 layers and the
056 chains.

| Level | What the customer does | Added coverage | Code? |
|---|---|---|---|
| **0 — Zero code, local** | `pip install "singleaxis-fabric[cli]"`, `fabric up`, `fabric run -- CMD`, `fabric verify`. | Every matched model call, request and response bytes; the tool calls the model asked for and the results fed back (parsed from the bodies); run structure per process; a verified record and `fabric show`. Layers: content and structure of model calls; the 056 `decisions` and `actions` chains. | No |
| **1 — Zero code, more capture points** | Configuration only (`fabric.yaml` lines or `fabric init` flags, each printed by `plan`): exec hook, non-model HTTP hosts, MCP transport, host sensor, retained content roles, 057 denial markers and classification lists. | Commands the agent ran and their output (as returned), non-model HTTP and MCP traffic, process and network evidence independent of the agent, the zero-code security context of 057 §4.8 (offered grants, OS refusals, denial markers, hook programs). Chains: `effects`, `corroboration`, and `controls` where configured. | No |
| **2 — Code for code-only facts** | The four cases of 1.1: `fabric.wire.run(session_id=..., user_id=...)`, `control_check`, `record_*`, `llm_call()`. | Business identity per run, control decisions with the rule that decided, internal steps, unhooked model clients. | A few lines |
| **3 — Production** | `fabric init --production`, a destination preset, `fabric up`, `fabric verify --production` with no FAIL. | Not more fields: the same record **authenticated, protected, durable and encrypted** (TLS, tokens, production capture policy, encrypted spool, ingress groups for sensors), so `corroboration` is production-qualified (049 §7.9, 053 §6). | No |

Level 3 is independent of level 2: a production deployment with zero code
is normal.

---

## 2. Background and evidence

### 2.1 Owner direction

"This is the most important part of using any open source tool!! the ease
of integration. ... make it an easy one click set up (not literally but
let us get as close to that as possible)." The lead engineer's plan
proposed the CLI, zero-config defaults, a Kubernetes path and a docs
restructure. This spec refines it with the audit's evidence and adds what
the audit found the plan lacked (N1–N8).

### 2.2 Baseline (audit section 1)

| Path | Measured | Human estimate | Manual steps | Hand-made files, secrets, env vars | Concepts | Doc lines | Workarounds |
|---|---|---|---|---|---|---|---|
| P1 Laptop, own Python agent | 4 m 40 s (6 m 15 s cold Node build) | 20–40 min; 60+ if the agent is not on loopback | 9 | 6 env vars incl. a JSON blob (+3 and a key file for the action view) | 10 | 868 | 1 |
| P2 Laptop, own Node.js agent | never verified (spans delivered at 3 m 05 s) | 30–60 min to delivered spans | 9 | 3 env vars, 26 changed lines of agent code, 5 packages | 8 | 623 | 1 |
| P3 Single Linux host, production | 6 m 00 s | 2–4 h | 22 | ≈34 | ≈22 | 1,476+ | 1 |
| P4 Kubernetes (kind), production | 17 m 06 s | 4–8 h | 24 | ≈45 | ≈26 | 729+ | 3 |
| P5 "Which layers do I need?" | ≈12 min reading | 1–2 h | — | — | — | ≈1,500 | docs answer 1 of 5 scenarios |

### 2.3 What already works (keep it)

The audit's section 5 is binding on this spec: nothing here may regress
it.

- The offline example (0.8 s) and its tamper exercise.
- Zero-code Python capture of a plain tool loop, unchanged agent output.
- `python -m fabric.wire status`: one JSON line and an exit code. It is
  the model for `fabric doctor`; it needs reasons (F2, F3).
- `preflight-prod.sh`: 30+ specific checks with fixes. It is the model for
  `verify --production` (13.4).
- Fail-closed gates and chart render errors that name the field and the
  fix.
- eBPF on Docker Desktop, loaded first try in production mode.
- Published artifacts complete and in version lockstep (PyPI, npm, GHCR
  images, OCI chart).
- `host-bindings.py`, `FABRIC_ENV_FILE` with `COMPOSE_PROJECT_NAME`.
- The verdict vocabulary. Users need it explained (F10), not removed.

### 2.4 Existing tooling this spec builds on

- **`fabricctl`** (Go, `tools/fabricctl`) writes and validates the
  `contracts/recorder/v1` declaration, which neither the SDK nor the Node
  reads. Its release binary is limited to `init`, `recorder validate`,
  `recorder digest` and `version` by a binary allowlist test. This spec
  does not change it. Its future is OQ-3.
- **Retired spec 026** ("fabricctl lifecycle") was deleted as outside the
  OSS scope. This spec is not a revival of it: section 4.2 states the
  difference, and OQ-11 asks the owner to confirm the boundary wording.
- **Make targets** in `deploy/compose`, the three chart profiles,
  `deploy/kubernetes/host-bindings.py` and the DaemonSet template. All
  stay; the CLI drives the same artifacts (sections 9, 10, 11.3).

---

## 3. Goal and measurable targets

**Goal.** A new user goes from nothing to a verified record of *their own*
agent, not only the examples, with the fewest commands and no hand-made
secrets or configuration on the default path. Production hardening is a
guided, checked path, not a reading exercise.

### 3.1 Definitions

- **TTFR (time to first record).** Wall clock from a clean environment
  that has only the stated prerequisites (Python 3.11+ or Node.js, Docker;
  for Kubernetes, `kubectl`, `helm` and an existing cluster) to the first
  `fabric verify` that exits 0 on a run of the user's own agent. Exit 0
  requires the reader verdict `complete_for_declared_scope` on the run's
  wire scope and `decisions: complete` (056). Cluster creation is
  excluded; image pulls are included (cold cache).
- **Command.** A line the user types or pastes, counted per path in the
  Get started page. The install command is counted separately.
- **Hand-made item.** A file the user writes, an environment variable
  the user sets, or a secret, key, token or certificate the user creates.
  A flag on a CLI command is not a hand-made item, but flags are counted
  where a target limits them.
- **Default path.** The Get started route for the path, with a model
  provider in the built-in endpoint table (section 8) or named by a
  standard base-URL variable in the agent's environment (8.3).

### 3.2 Targets

| ID | Path | Baseline (audit) | Target | Measured by |
|---|---|---|---|---|
| G1 | Laptop, own Python agent (local profile) | 4 m 40 s measured, 20–40 min human, 9 steps, 6 env vars, 868 doc lines, 1 workaround (F2, F3, F12, F16, F21, F25) | CI TTFR ≤ 300 s cold; 1 install + ≤ 3 commands (`up`, `run`, `verify`); 0 hand-made items; ≤ 1 flag when the model host is in neither the table nor a base-URL variable; Get started page ≤ 80 lines; 0 workarounds | `ttfr-laptop-python` (3.3) |
| G2 | Laptop, own Node.js agent | Never verified; 26 lines of agent code; 4 npm retries (F1, F7, F23) | **Before 055 TS-1U:** the documented install works first time; `plan` and `verify` state that model decisions are `unsupported(unsupported_runtime)`, never a false pass; `fabric show` displays explicit-API records labelled *reported*. **After TS-1U:** G1's targets with `node` in place of `python`. | `ttfr-laptop-node` |
| G3 | Single Linux host, production profile | 6 m 00 s measured, 2–4 h human, 22 steps, ≈34 hand-made items (F8, F9, F14, F20, F22) | CI TTFR ≤ 420 s; 1 install + ≤ 4 commands (`init --production`, `up`, `run`, `verify --production`); 0 hand-made secrets, keys, tokens or certificates; the only customer inputs are identifiers they already own (bucket and region, or an OTLP URL), given as flags; `verify --production` reports no FAIL; production page ≤ 200 lines to the first verified record | `ttfr-host-production` |
| G4 | Kubernetes, production profile | 17 m 06 s measured, 4–8 h human, 24 steps, ≈45 hand-made items, 3 workarounds (F4–F6, F15, F18, F19) | CI TTFR ≤ 600 s on kind; one `helm install` with a preset, one namespace label, one pod annotation (the SDK in the agent image is the only other change); 0 hand-made Secrets; 0 workarounds; human estimate ≤ 15 min | `ttfr-kubernetes` |
| G5 | "Which layers do I need?" | 12 min reading, 1–2 h human, 1 of 5 scenarios answered (D21) | `fabric plan` answers each of the audit's five scenarios with recorded / invisible / fix rows in one command, in ≤ 10 s, with no network access | `plan-scenarios` |
| G6 | Silent failures | 7 (S1–S7) | 0: each has a regression test that asserts a named reason and a fix in `status`, `doctor` or `verify` | diagnostics tests (13) |
| G7 | Error messages that name the fix | 2 of 9 (audit table) | Every message in the diagnostics catalogue (13.1) has a fix; Fabric-owned messages only | catalogue test |
| G8 | Passivity of the integration path | — | `fabric run` and the injector leave the agent's argv, stdin, stdout, stderr (non-TTY), exit code, PID and non-Fabric environment byte-identical to a bare run, with a valid, broken or missing configuration | passivity tests (4.1) |

Human-time targets cannot be measured by CI; the proxies are the counts
above (commands, hand-made items, doc lines, concepts named on the page)
and a repeat of the audit at the end of E3 and E4 by an engineer with no
Fabric context, using the same method and reported against the same
table.

### 3.3 How CI measures them

**Docs as tests.** Every command block in the Get started, Choose your
shape and Go to production pages carries a marker:

```markdown
<!-- fabric-docs-test: path=laptop-python step=2 -->
```

A runner (`scripts/docs_as_tests/run.py`) extracts the marked blocks in
order and executes them **verbatim** in the path's fresh environment.
`# expect:` comment lines in a block assert on output. A page fails CI
when:

- any marked block fails or its expectations do not match;
- the path has more commands than its target;
- a block creates a file (`cat >`, `tee`, heredoc), exports a variable,
  or runs `openssl` on a default path;
- an unmarked command block appears on a tested page.

**TTFR tests.** One CI job per path, each in a fresh environment:

| Job | Environment | Agent |
|---|---|---|
| `ttfr-laptop-python` | `ubuntu-latest` runner, empty Docker cache, `python:3.12` container for the agent | Fixture agents written once under `scripts/ttfr/agents/`, never imported from Fabric or `examples/`: a plain OpenAI-SDK tool loop and a plain `httpx` loop, against a fixture model server on a host that is **not** in the endpoint table, reached through `OPENAI_BASE_URL` |
| `ttfr-laptop-node` | `node:24` container, no Python | A plain `fetch` tool loop |
| `ttfr-host-production` | Linux runner with eBPF | The Python fixture agent in a container, production profile, `trial` destination (9.2) |
| `ttfr-kubernetes` | kind cluster created before the clock starts | The Python fixture agent image with the SDK installed |
| `plan-scenarios` | Five fixture environments, one per audit Path 5 scenario | — |

Each job writes `ttfr.json` (per-step wall clock, command count, exit
codes) as an artifact and fails when a budget in 3.2 is exceeded. The
jobs run on every pull request that touches the CLI, the chart, the
compose files or a tested page, and on every release candidate against
the **published** candidate artifacts (PyPI, npm, GHCR, chart), so a
packaging break fails the release. A nightly job may run the same agents
against one real provider with a repository secret; it is informative
and never gates a release.

---

## 4. Boundary rules

AGENTS.md is binding: Fabric OSS is CAPTURE → PROTECT → DELIVER, and
"Verify is a cross-cutting property provided by configuration checks,
integrity checks, canaries and delivery receipts". This spec adds
install, configuration and verification tooling for the recorder and
nothing else. Rules use the prefix **I** so they do not collide with
057's B1–B9.

### 4.1 Rules

| # | Rule | Enforced by |
|---|---|---|
| I1 | **Tooling only.** The CLI installs, configures, launches, checks and reads the recorder. It contains no capture logic of its own, no evaluation, no policy, no enforcement and no control path. | Release-boundary command allowlist for the CLI (as `fabricctl` has); the existing forbidden-term scans (`release-policy.json`) extended to `fabric/cli` and the CLI image; reader-output word scan (057 B6) applied to `verify` and `show` output. |
| I2 | **Passive launch.** `fabric run` never changes the agent's argv, stdin, working directory or exit code. On POSIX it replaces itself with the agent by `execvpe`, so the PID, signals and TTY are the agent's own. It adds only `FABRIC_*` variables, `PYTHONPATH` (Python autoload) and, after 055, a `NODE_OPTIONS` `--import` entry; **it never sets or changes an `OTEL_*` variable**, and never overrides a variable already set in its environment. It does no network I/O. Messages go to stderr only when stderr is a TTY, otherwise to the run's status file. | G8 passivity tests: byte-identical stdout, stderr (non-TTY), exit code and environment diff limited to the listed variables, for a valid, a broken and a missing configuration; a test that `fabric run` opens no socket. |
| I3 | **Fail-open.** Any error before `exec` (bad config, missing SDK, missing secrets, Node down) launches the agent with an unchanged environment. An error inside the agent is the SDK's existing fail-open (049 §7.1). The injector uses `failurePolicy: Ignore`. | Fault-injection matrix per failure of 5.4; webhook outage test (10.4). |
| I4 | **No phone-home.** The CLI contacts only what the user configured: their Node, their destination, their cluster's API server (current kube context, only for `--kubernetes`), and the image registry for pinned digests on `up`. No update check, no usage telemetry, no SingleAxis endpoint, no DNS lookups of anything else. `plan` makes no network connection at all. | A test runs every command in a network namespace whose only routes are the configured endpoints and asserts no other connection attempt (and none at all for `plan`). |
| I5 | **No fleet management.** No inventory of hosts or clusters, no remote push of configuration, no reconcile loop, no rollout, restart or approval flow, no UI. `up` acts once, when invoked, on the local Docker daemon or the current kube context. The injector affects a pod only when that pod is created by the customer's own rollout; Fabric never restarts or rolls out a workload. | Code review rule and tests: no command touches more than one target per invocation; no CLI code path calls a rollout, restart, scale or delete on a non-Fabric workload; the injector holds no state. |
| I6 | **Framework-agnostic (057 B9).** `plan` detects languages, interpreters, HTTP and protocol libraries, the OS, the kernel and the container runtime, never an agent framework. No preset, profile or table is named after an agent framework or agent SDK. Model-provider endpoints (section 8) are wire-boundary configuration, as `DEFAULT_ENDPOINTS` is today. | Name-pattern test on presets and tables; review rule; a test that `plan` output is unchanged when a fixture environment adds an agent framework package. |
| I7 | **Secrets stay local and private** (section 7). Generated on the customer's machine or cluster from the OS CSPRNG, stored with owner-only permissions, never written to `fabric.yaml`, never printed, never put on a command line, never in a Helm release record. | Section 7 tests. |
| I8 | **Nothing existing breaks.** Every environment variable, file, Make target, chart value and profile that works today keeps working with the same meaning (section 11.3). New SDK variables are additive. | Existing test suites unchanged; migration tests (11.3). |

### 4.2 Why `up` and the injector are in scope

AGENTS.md lists "local recorder initialization, configuration validation,
digesting and offline verification" in scope, and keeps "enterprise fleet
management, approvals, policy authoring or rollout UI" out of the
"default OSS runtime, installer or primary product story". Retired spec
026 described a deployment-bundle lifecycle. This spec keeps to the
first list:

- `up` drives **the customer's own** Docker Compose or Helm, once, with
  the same images and chart that ship today. Helm stays the Kubernetes
  deployment boundary (`fabricctl` README); the CLI renders values and
  calls `helm upgrade --install`, or writes the values for the customer's
  GitOps tool (`--render`).
- The injector is a stateless admission hook that adds environment
  variables and mounts to pods the customer annotated. It is an
  installation aid for the SDK, like `fabric run`, not a controller.

OQ-11 asks the owner to add one sentence naming this tooling to the
AGENTS.md in-scope list.

---

## 5. The CLI

### 5.1 Common behaviour

- **Name.** `fabric`, with an always-installed alias `singleaxis-fabric`
  (so `uvx --from "singleaxis-fabric[cli]" singleaxis-fabric plan` and
  `pipx run` work without naming a script). Name collisions: OQ-1.
- **Commands.** `plan`, `init`, `up`, `down`, `run`, `verify`, `doctor`,
  `show`, `version`, `help`. Nothing else ships (I1 allowlist). Additions
  need a spec change.
- **Project.** A project is a directory with a `fabric.yaml`. Its state
  lives in `.fabric/` beside it (written mode 0700, added to
  `.gitignore` by `init` when the directory is a git work tree), and its
  secrets in the secrets directory of 7.2. The project name defaults to
  the directory name and names the Compose project and the Helm release.
- **Flags on every command.** `--config PATH`, `--project NAME`,
  `--json` (stable schema `fabric.cli-report/v1`, 15), `--quiet`,
  `--no-color`.
- **Exit codes.** `0` success; `1` a check or verification did not pass
  (findings printed); `2` usage or configuration error; `3` a prerequisite
  is missing (Docker, Helm, kubectl, a kube context). `run` exits with the
  agent's exit code.
- **Output.** Human output is short: one line per finding, each with a
  fix. Every finding has a stable id from the diagnostics catalogue
  (13.1).

### 5.2 `fabric plan`

```text
fabric plan [--kubernetes] [--mcp-config PATH]... [--json] [-- CMD [ARGS...]]
```

Read-only. Writes nothing, starts nothing, runs no agent code, makes no
network connection (I4). With `--kubernetes` it reads the current kube
context's API (read-only) and still makes no other connection.

**Probes** (each result is shown with its evidence):

| Probe | How | Feeds |
|---|---|---|
| Agent runtime | Resolve `CMD`: `python`/`python3`/`uv run`/`poetry run` → Python and its interpreter path; `node`/`npx`/`tsx` → Node.js and version; `bun`/`deno` → unsupported JavaScript runtime; a script → its shebang; an ELF or Mach-O file → compiled (Go build info read when present); `java -jar` → JVM. Without `CMD`, the language of the project directory (manifest files). | Which SDK capture points can exist |
| Python environment | Run the target interpreter with `-I -c` to list installed distributions through `importlib.metadata`, without importing them | SDK presence and version; HTTP clients present (`httpx`, `aiohttp`, `requests`, `urllib3`, `grpcio`, `boto3`); the MCP protocol library |
| Node environment | Read `package.json` and the lockfile | `@singleaxis/fabric` presence; HTTP clients (`fetch` only, `undici`, `axios`); the MCP protocol SDK |
| Model endpoints | Names (never values) of standard base-URL and key variables in the environment (8.3) | Which endpoint-table rows apply; a custom endpoint line |
| OS and kernel | `uname`, `/sys/kernel/btf/vmlinux`, cgroup version and layout, capabilities, `/proc/version` | eBPF loadable; auditd present; sensor scoping method |
| Sandboxed or serverless runtime | gVisor (`/proc/version`, `dmesg` markers), Kata, Firecracker; serverless markers (`AWS_LAMBDA_FUNCTION_NAME`, `K_SERVICE`, `ECS_CONTAINER_METADATA_URI_V4` without host access) | Sensor impossible → stated as invisible, with the alternative |
| Containers | Docker or Podman present; running inside a container; Docker Desktop (the sensor sees only the VM) | Shape; Node reachability (TLS rule, 6.4) |
| Kubernetes (`--kubernetes`) | Server version, node OS and kernel, runtime classes and their handlers, NetworkPolicy support, existing Fabric release, kubelet cgroup layout (from node info) | E2 checks before install |
| MCP | The protocol library (above) and any file passed with `--mcp-config` (a JSON `mcpServers` object) | Which MCP transports and the lines to capture them |

**Output.** A shape (`laptop`, `linux-host`, `container`, `kubernetes`,
`serverless`, `remote-sandbox`), then the coverage report of section 12
in its *predicted* form, then the exact next command. Example (abridged):

```text
shape: laptop (macOS, Docker Desktop)   agent: python 3.12 (.venv/bin/python)   sdk: not installed

  model calls (requests and responses)   recorded      httpx; endpoint api.openai.com (built-in)
  tool calls and results                 recorded      parsed from model bodies
  commands the agent runs                fix           fabric init --exec
  network contacts (non-model HTTP)      fix           fabric init --http-host api.github.com
  MCP traffic (stdio server)             fix           fabric init --mcp
  host evidence (kernel sensor)          invisible     macOS: the sensor sees only the Docker VM; run the agent in a container or on Linux
  end user and session                   needs code    with fabric.wire.run(session_id=..., user_id=...)
  model calls through requests           invisible     requests is not hooked; switch the client or use llm_call()

next: .venv/bin/python -m pip install singleaxis-fabric   then   fabric up
```

### 5.3 `fabric init`

```text
fabric init [--profile local|production] [--shape SHAPE] [--tenant ID] [--agent ID]
            [--provider [DIALECT=]URL]... [--destination PRESET [PRESET-FLAGS]]
            [--exec] [--http-host HOST]... [--mcp] [--sensor auto|ebpf|auditd|off]
            [--kubernetes [--namespace NS] [--agent-namespace NS]...] [--render DIR]
            [--from-env] [--from-env-file FILE] [--from-values FILE]
            [--rotate NAME|all] [--force]
```

- Without `fabric.yaml`: runs the `plan` probes, writes `fabric.yaml`
  (section 6) with the detected shape and defaults, writes
  `.fabric/compiled.env` (6.5), and generates every secret the profile
  needs (section 7).
- With `fabric.yaml`: idempotent. Missing secrets are generated; existing
  ones are never overwritten; flags update the file (a diff is printed).
  `--force` rewrites the file and keeps a timestamped backup; it never
  regenerates secrets (that is `--rotate`).
- Non-interactive by default. It prompts only on a TTY and only for a
  choice it cannot default (a production destination with no preset
  flags). It never asks for a secret value.
- `--kubernetes` writes the secrets as Kubernetes Secrets in the current
  context (or as manifests into `--render DIR`), with the same generator
  as the chart's secrets Job (10.2).
- `--from-env`, `--from-env-file`, `--from-values` import an existing
  manual setup (11.3).
- Defaults: tenant `default`, agent id = project name, profile `local`,
  destination `local-dir`, sensor `auto`, content capture on with the
  implicit local policy (049 §2.7) in `local`, and the production capture
  policy preset in `production` (6.3).

### 5.4 `fabric up` and `fabric down`

```text
fabric up [--kubernetes] [--render DIR] [--no-sensor] [--wait SECONDS]
fabric down [--purge]
```

**Docker shapes** (`laptop`, `linux-host`, `container`):

1. Runs `init` with defaults when there is no `fabric.yaml`.
2. Renders a Compose project from templates **packaged with the CLI**
   (no repository clone, F12), with images pinned by digest to the CLI's
   own release (11.2). Optionally verifies image signatures when `cosign`
   is present (`--verify-images`).
3. Starts the Node and the destination (section 9) and waits for health
   (default 60 s).
4. **Host sensor** (`sensor: auto`): on Linux, when eBPF is loadable,
   starts the emitter in the profile's mode and creates an agent cgroup
   (`fabric.slice/agent-<project>`, no resource limits; needs root or a
   delegated cgroup, otherwise `FC-SENSOR-*` says so) as its scope; when
   eBPF is not loadable and auditd is present, offers the auditd sensor
   collector; otherwise prints the reason (`FC-SENSOR-*`) and continues.
   Docker Desktop: starts the emitter in the VM (the audit's working
   setup) and states that it observes containers only.
5. Prints the Node endpoint, the sensor state and the next command.

`up` is idempotent: a second run reconciles the rendered project to the
current `fabric.yaml` and the CLI's pinned images, prints the changes,
and applies them. `down` stops the project and keeps volumes; `--purge`
deletes volumes and `.fabric/state`, never the secrets directory.

**Kubernetes** (`--kubernetes`, or shape `kubernetes`): renders Helm values
from `fabric.yaml` and runs `helm upgrade --install` with the release's
chart version and a preset (10.1); `--render DIR` writes the values and
the Secrets manifests instead, for GitOps. It never restarts or rolls out
any workload (I5).

### 5.5 `fabric run`

```text
fabric run [--run NAME] [--exec|--no-exec] [--no-capture] [--print-env [--format FORMAT]] -- CMD [ARGS...]
```

**Behaviour, in order** (all before `exec`; any failure → step 6 with the
unchanged environment, I3):

1. Load `fabric.yaml` and `.fabric/compiled.env` (6.5). Variables
   already present in the environment win (6.2).
2. Detect the runtime of `CMD` (as `plan`).
3. Build the child environment:
   - **Python:** `FABRIC_WIRE_AUTOLOAD=1` and `PYTHONPATH` prefixed with
     the autoload directory **of the target interpreter's own SDK**
     (asked once with `python -I -m fabric.wire --print-autoload-path`,
     cached by interpreter path and modification time). If the SDK is not
     installed in that interpreter: message `FC-RUN-001` with the exact
     install line for that interpreter, and capture stays off.
   - **Node.js:** after 055 TS-1U ships, `NODE_OPTIONS` gains
     `--import=@singleaxis/fabric/register` when the package resolves
     from the agent's working directory. Before that, only the variables
     the explicit API reads.
   - **Other runtimes:** `FABRIC_RUN_ID` and the sensor scope only.
   - **All:** `FABRIC_TENANT_ID`, `FABRIC_AGENT_ID`, the Fabric OTLP
     variables (6.4), `FABRIC_WIRE_STORE` (local profile),
     `FABRIC_WIRE_ID_KEY_FILE`, `FABRIC_WIRE_SPOOL_KEY_FILE`,
     `FABRIC_WIRE_ENDPOINTS` for custom providers, the capture-point
     switches (`FABRIC_WIRE_EXEC`, `FABRIC_WIRE_HTTP_HOSTS`, …),
     `FABRIC_CAPTURE_POLICY` in production, `FABRIC_RUN_ID` (from
     `--run`, else a fresh label) and `FABRIC_WIRE_STATUS_FILE`
     (13.2). Keys are passed by file path, never by value: the spool
     and tokenization keys already have `*_FILE` variants; E1 adds
     `FABRIC_WIRE_ID_KEY_FILE` (the id key is read only by value today).
4. Record the run label, start time, command name (not arguments) and
   project in `.fabric/state/runs/` so `verify` and `show` default to the
   last run (F16).
5. On Linux with the sensor active, join the agent cgroup created by
   `up` (write own PID to its `cgroup.procs`). The cgroup has no limits,
   so this changes accounting only. If not permitted: `FC-RUN-010`, the
   run continues; `verify` reports `corroboration` not observed with the
   fix.
6. `execvpe(CMD, ARGS, env)`. On Windows (no `exec`): spawn, forward
   Ctrl-C, wait, and exit with the child's code.

Child processes inherit the environment, so Python programs the agent
starts are captured as their own sources (each its own epoch, 049 §2.4);
`plan` and `show` say so.

**`--print-env`** prints the environment of step 3 in a format for an
existing launcher: `sh` (default), `dotenv`, `docker` (`-e` and `-v`
flags, with the key and CA files mounted), `systemd` (`Environment=` and
`LoadCredential=`), `k8s` (an env and volume patch). It prints file paths,
never secret values. This is the zero-code route for launchers `fabric run`
cannot wrap (IDE debuggers, process managers, Dockerfiles).

**Budget.** `fabric run` adds at most 150 ms before `exec` with a warm
interpreter cache (measured in E1 acceptance).

### 5.6 `fabric verify`

```text
fabric verify [RUN] [--canary-only] [--production] [--kubernetes] [--spans PATH] [--strict] [--json]
```

**Steps** (each a finding with an id):

1. **Configuration.** `fabric.yaml` validates; secrets exist with the
   right permissions; the compiled environment matches the file.
2. **Node.** Reachable over the configured scheme and CA; healthy;
   version and image digest match the CLI's release (warn on skew).
3. **Canary.** In the CLI's own process, install wire capture with a
   dedicated canary source (its own ingress binding in production, 7.1),
   send one model exchange to a fake model server on loopback, close the
   run, and drain the spool. This exercises tee → spool → Node →
   destination → reader with the user's real configuration.
4. **Delivery.** Poll the destination (bounded, default 30 s) until the
   canary's spans and content objects are readable (9.3).
5. **Read.** Run the reader on the canary, then on `RUN` (default: the
   last `fabric run` run; canary runs are never selected). The input
   forms of N6 apply, so the user never names files.
6. **Coverage report.** Section 12, in its *observed* form, with every
   `partial` and `unverified` reason explained in plain words with a fix
   (F10).

`--canary-only` skips step 5's user run. `--spans PATH` reads a span
export the user supplies (for a destination Fabric cannot read back).
`--kubernetes` adds the in-cluster checks of 10.6.

**`--production`** adds the hardening checks of 13.4 (TLS on every
non-loopback hop, token and key strength and file modes, capture policy
present and not the local default, `redact` roles that withhold commands
under autoload (S6), spool encryption and key, spool and queue sizing
against free disk with advice (F22), destination durability and
retention where readable, certificate expiry, image digests, sensor
production mode and ingress-group binding (F14), clock uncertainty).

**Result.** Exit 0 when no finding is FAIL (WARN allowed unless
`--strict`). Verification is never a claim beyond the reader's own
verdict (`NO_COVERAGE_CLAIM` stands).

### 5.7 `fabric doctor`

```text
fabric doctor [--kubernetes] [--json]
```

Diagnoses a broken or unknown install, including one made by hand
without the CLI (it reads the same environment variables). It runs the
probes below in order, never changes anything, and prints each problem
with its catalogue id and fix:

- configuration: `fabric.yaml`, compiled environment, env overrides that
  disagree with the file (shown by name, never value);
- SDK: `python -m fabric.wire status` in the target interpreter with the
  compiled environment, including the reasons and warnings of 13.2;
- the last run's status file (13.2);
- Node: health, recent log lines matched against known error ids,
  exporter queue state;
- sensor: emitter health line (`pod_roots`, `agent_roots`, export
  errors with their gRPC code, N3, N4), loadability;
- network from the agent's side: the TLS rule (6.4), DNS of the Node
  name inside a container network;
- Kubernetes: NetworkPolicies selecting Fabric pods (F5), namespace and
  Secret presence, injector webhook state, runtime classes (10.5).

### 5.8 `fabric show`

```text
fabric show [RUN] [--list] [--actions|--transcript] [--content] [--json]
```

Default `RUN` is the last run; `--list` lists recent runs, newest first,
with their verdicts (F16). The default view is a readable timeline:

```text
run r-73f2…  python agent.py   2026-11-09 12:48:41  verdict: complete

 1  model  gpt-4o-mini   user: "What is the kernel version?"
 2   ↳ tool_call T1 run_shell   {"cmd": "uname -r; nproc"}
 3     effect exec uname -r; nproc     ← T1 output_match · certain
 4     host  exec pid 4121             ← #3 process_anchor · certain
 5   ↳ result T1  "6.12.76 …"
 6  model  answer: "The kernel is 6.12.76 with 8 CPUs."
```

- Arguments, results and answers come from the content store,
  decompressed, and only where the capture policy retained them and the
  reader holds the content key; otherwise the line says `redacted
  (privacy_policy)` or `not retained`. `--content` is required to print
  content when stdout is not a TTY.
- `--actions` is the 056 action view as today; `--transcript` is the
  conversation only.
- Repeated connects to the same peer are collapsed into one line with a
  count (F13).
- Explicit-API records from the TypeScript SDK are shown labelled
  *reported* (G2), never as verified wire records.

`show` is local: it reads the destination with the reader's credentials
and prints to the terminal. It sends nothing anywhere.

---

## 6. Configuration: `fabric.yaml`

### 6.1 Schema

`fabric.yaml` is a **source the CLI compiles** into the inputs the SDK,
the Node and the chart already read (environment variables, the
deployment-policy capture policy, the Node env file, Helm values). The
SDK and the Node never read `fabric.yaml` (OQ-7). Schema:
`contracts/cli-config/v1/fabric-config-v1.schema.json`, strict (unknown
keys refused with the nearest valid key suggested).

```yaml
schema: fabric.config/v1
project: support-agent          # default: directory name
profile: local                  # local | production
shape: laptop                   # laptop | linux-host | container | kubernetes (detected)
tenant: default
agent: support-agent

providers:
  builtin: true                 # the endpoint table of section 8
  from_environment: true        # derive endpoints from standard base-URL variables (8.3)
  custom:
    - url: https://my-llm.example.modal.run/v1      # one line per custom host
      dialect: openai                               # openai (default) | anthropic

capture:
  content: true                 # content capture; the capture policy decides each role
  privacy: profile-default      # profile-default | <path to a deployment-policy/v1 file>
  exec: false
  http_hosts: []                # non-model HTTP hosts to record (053 http.nonmodel)
  mcp: false                    # MCP transport hook (057 P1, OD-4), when built
  security_context: null        # path to the 057 security_context lists, passed through (16.6)

node:
  mode: docker                  # docker | helm | external
  endpoint: auto                # auto (from up) | https://host:port for an existing Node
  queue_size: auto              # one setting for the durable queue (F22); auto = sized to free disk

destination:
  preset: local-dir             # section 9
  path: ./fabric-data

sensor:
  kind: auto                    # auto | ebpf | auditd | off

secrets:
  dir: auto                     # section 7.2; references only, never values
```

### 6.2 Precedence

For every setting, the first source that sets it wins:

1. A CLI flag on the current command.
2. An environment variable already set in the environment of `fabric`
   (the existing `FABRIC_*` and `OTEL_*` names, unchanged meaning).
3. `fabric.yaml`.
4. Built-in defaults of the profile.

`fabric run --print-env` and `fabric doctor` show, by name, every
variable that overrides `fabric.yaml`, so an old shell export is never a
hidden cause.

**Discovery.** `--config PATH`, else `FABRIC_CONFIG`, else `./fabric.yaml`,
else the nearest parent directory's `fabric.yaml` up to the git work-tree
root or the home directory.

### 6.3 Profiles and privacy defaults

- `local`: the implicit `fabric.local-default` policy of 049 §2.7,
  loopback plaintext allowed, local destination.
- `production`: a production capture policy preset shipped with the CLI
  (the `docs/production-setup.md` example policy: no argument, output or
  HTTP body in clear), spool encryption on, TLS and tokens on every hop,
  ingress groups for sensors. `fabric init --production` writes the
  policy file into the project so it is reviewable and versioned; the
  customer edits it, never the CLI.

### 6.4 OTLP endpoint and the one TLS rule

- New SDK variables, read before the `OTEL_*` ones: `FABRIC_OTLP_ENDPOINT`,
  `FABRIC_OTLP_CERTIFICATE`, `FABRIC_OTLP_CLIENT_CERTIFICATE`,
  `FABRIC_OTLP_CLIENT_KEY`, `FABRIC_OTLP_HEADERS_FILE`. When none is set
  the SDK reads `OTEL_EXPORTER_OTLP_*` exactly as today (I8). `fabric run`
  sets only the `FABRIC_OTLP_*` names, so an agent's own OpenTelemetry
  export is never redirected (I2, T7).
- **One rule for both SDKs** (F3, F23): records leave the agent process
  over `https` with a verified CA, or over `http` to a loopback address.
  The TypeScript SDK adopts the Python rule (N2, E3). `fabric init`
  always generates a local CA and Node certificate, and `fabric run`
  always passes the CA, so a containerised agent reaching the Node by a
  service name works on the default path.

### 6.5 Compiled environment file

`fabric init` and `up` write `.fabric/compiled.env` (dotenv, mode 0600):
the environment of 5.5 step 3 with file paths for every secret. It is
regenerated whenever `fabric.yaml` changes and carries the digest of the
`fabric.yaml` it came from, so `doctor` can detect a stale file. The npm
launcher and `--print-env` read it; nothing else does.

---

## 7. Secrets

### 7.1 What is generated

| Secret | Profiles | Generated by | Use |
|---|---|---|---|
| Pseudonym id key (32 bytes) | all | `init` | `FABRIC_WIRE_ID_KEY_FILE`; the reader |
| Spool key | production (local: optional) | `init` | `FABRIC_WIRE_SPOOL_KEY_FILE` |
| Content key / KEK | production with an encrypted store | `init` | Node content exporter (049 §7.8); the reader |
| Ingest bearer token per source (agent, each sensor, canary) | production | `init` | Node ingress groups (049 §7.9, 053 §6) |
| Derived source ids (agent HMAC id, sensor source ids) | production | `init` (same derivation as `host-bindings.py` and the emitter) | Node bindings |
| Local CA, Node server certificate | all | `init` | TLS on every non-loopback hop |
| Client certificates per source | production when the profile requires mTLS | `init --source NAME` | Node client authentication |
| Trial destination credentials (S3-compatible test store, trial OTLP receiver certificate) | `trial` preset only | `init` | Section 9.2 |
| Webhook serving certificate | Kubernetes with the injector | the chart's secrets Job | Section 10.4 |

Never generated: a customer's cloud credentials. S3, GCS and OTLP
destinations use the ambient identity of the Node (instance role,
workload identity) or a credentials file the customer names by path.

### 7.2 Generation and storage

- Random material from the OS CSPRNG (`secrets.token_bytes`). Keys and
  certificates with the `cryptography` package (ECDSA P-256; local CA
  valid 2 years; leaf certificates 90 days; SANs from the shape:
  `localhost`, `127.0.0.1`, the Compose service name, the cluster service
  DNS names).
- **Files:** `$XDG_STATE_HOME/fabric/<project-id>/secrets/` (default
  `~/.local/state/...`; `%LOCALAPPDATA%` on Windows), directory 0700,
  files 0600, created exclusively (no clobber), fsynced, symlinks refused
  (the `fabricctl` file rules). The Node's container user (uid 65532)
  gets read access through a group the CLI creates or, on Docker Desktop,
  through the documented shared-directory mode (the same rules
  `preflight-prod.sh` checks).
- **Kubernetes:** Secrets in the release namespace and in each injected
  agent namespace (10.2), labelled `app.kubernetes.io/managed-by:
  fabric-cli`; never in a Helm release record, never in a ConfigMap.
- `fabric.yaml` holds no secret and refuses a value with a secret shape
  (reusing the `fabricctl` reference rules). Secrets are never printed;
  `--print-env` prints paths; `--json` reports names, fingerprints
  (SHA-256 of the public part or a keyed id) and expiry only.

### 7.3 Rotation

`fabric init --rotate NAME|all`:

| Secret | Rotation |
|---|---|
| Tokens, client certificates | New value written beside the old; the Node is given both where the ingress accepts a set, then the old one is removed after `--overlap` (default 24 h) by the next `up`; where it does not, `up` restarts the Node and the finding says so (16.6 asks the 049 §7.9 owner whether a token set is supported). |
| Node certificate, local CA | A new leaf is issued from the existing CA without agent changes; a new CA is distributed by `up`/`run` and needs agents restarted by the customer (the CLI says which). |
| Pseudonym id key | A new key id. Pseudonyms change from the next epoch; the capture manifest records the key id (049 §2.9); the old key is kept read-only for the reader. Never automatic. |
| Content key / KEK | Per 049 §7.8 (envelope re-wrap); the old key is retained for reads. |

`verify --production` warns 14 days before a certificate expires and
fails after expiry.

---

## 8. Built-in provider endpoint table

### 8.1 The table

Today `DEFAULT_ENDPOINTS` holds three matchers (`api.openai.com`,
`api.anthropic.com`, `*.openai.azure.com`) and every other host needs a
hand-written JSON matcher (F21). The table moves to a versioned data file,
`contracts/providers/v1/builtin-endpoints.json`, shipped in both SDKs and
read by the CLI, so all three agree. A row ships only when a recorded
response fixture from that provider passes wire parsing and
reconstruction for its dialect (E1 acceptance); an unqualified row is not
shipped.

Candidate rows (only the `openai` and `anthropic` dialects the wire parser
supports; endpoint ids follow 054 §4.1 C35, `<provider>.default`):

| Endpoint id | Host match | Path prefix | Dialect | Default |
|---|---|---|---|---|
| `openai.default` | `api.openai.com` | — | openai | on (today) |
| `anthropic.default` | `api.anthropic.com` | — | anthropic | on (today) |
| `azure-openai.default` | `*.openai.azure.com` | — | openai | on (today) |
| `gemini-openai.default` | `generativelanguage.googleapis.com` | `/v1beta/openai` | openai | on when qualified |
| `mistral.default` | `api.mistral.ai` | `/v1` | openai | on when qualified |
| `groq.default` | `api.groq.com` | `/openai/v1` | openai | on when qualified |
| `together.default` | `api.together.xyz` | `/v1` | openai | on when qualified |
| `fireworks.default` | `api.fireworks.ai` | `/inference/v1` | openai | on when qualified |
| `deepseek.default` | `api.deepseek.com` | — | openai | on when qualified |
| `openrouter.default` | `openrouter.ai` | `/api/v1` | openai | on when qualified |
| `xai.default` | `api.x.ai` | `/v1` | openai | on when qualified |
| `ollama.local` | `127.0.0.1`, `localhost` port 11434 | `/v1` | openai | only when listed or detected by `plan` |
| `vllm.local`, `lmstudio.local`, `llamacpp.local` | loopback ports 8000, 1234, 8080 | `/v1` | openai | only when listed or detected |

Loopback rows are never on by default: a port number does not identify a
model server. Matching still requires the dialect's path suffix (047 §2),
so a non-model request to a listed host is not captured as a model call.

**Privacy.** A new default row widens what autoload captures for an
existing user who calls that provider. The manifest already carries the
digest of the endpoint set; E1 adds the table version
(`fabric.manifest.endpoint_table_version`, a 049 delta, 15). Whether new
rows are on by default for plain autoload outside the CLI is OQ-4.

### 8.2 Custom endpoints in one line

`fabric init --provider https://my-llm.example.modal.run/v1` or one
`providers.custom` entry compiles to the existing matcher:

```json
{"endpoint_id": "my-llm", "dialect": "openai", "hosts": ["my-llm.example.modal.run"],
 "ports": [443], "schemes": ["https"], "path_prefix": "/v1"}
```

The endpoint name defaults to the first DNS label (the clear name is
emitted only under `FABRIC_WIRE_LABELS=clear`, 054 §4.1). `anthropic=URL`
selects the Anthropic dialect. The reader's `endpoint_id` arguments are
filled by `verify` and `show`, so the user never repeats the matcher.

### 8.3 Endpoints from the environment

With `providers.from_environment: true` (default), `plan` and `run` read
the **names and values** of the standard base-URL variables of the
provider clients (`OPENAI_BASE_URL`, `OPENAI_API_BASE`,
`ANTHROPIC_BASE_URL`, `AZURE_OPENAI_ENDPOINT`) from the environment and
add a matcher for a host the table does not cover. Key variables are read
by name only, to tell which providers are in use; their values are never
read. These are client-library conventions of the providers, not agent
frameworks (I6). The added matcher is shown by `plan` and `--print-env`.

The audit's agent used a custom Modal host: with this rule, or one
`--provider` flag, the 6-variable setup of P1 becomes zero hand-made
items (G1).

---

## 9. Destination presets

### 9.1 Presets

The Node's exporters today are `otlphttp` (spans) and the Fabric content
exporter (S3 API). Presets use only those; anything else is deferred.

| Preset | Profiles | Spans go to | Content goes to | Readback for `verify`/`show` | Customer inputs |
|---|---|---|---|---|---|
| `local-dir` (default) | local | The bundled sink, writing OTLP files directly into `./fabric-data/spans` (no export step, F16) | `file://./fabric-data/store` (SDK-written, as the quickstart) | Full | None |
| `trial` | production | A CLI-provisioned TLS OTLP receiver writing files into `./fabric-data/spans` | A bundled S3-compatible test store with TLS (SeaweedFS or Garage, never images that the audit found unpullable, F20) | Full | None. `verify --production` reports WARN `trial destination: not durable storage` |
| `s3` | production | (needs an OTLP target: combine with `otlp`, or with the canary tap) | AWS S3: `--bucket`, `--region`, `--sse-kms-key`; credentials from the Node's ambient identity | Content full; spans per the span target | Bucket, region, key id |
| `s3-compatible` | production | as `s3` | Any S3 API store with `--endpoint` and `--ca-file` (private CA, F6, F20), credentials file by path | as `s3` | Endpoint, bucket, CA path, credentials path |
| `otlp` | both | An existing OTLP/HTTP endpoint (the customer's collector or observability backend): `--otlp-endpoint`, `--otlp-ca-file`, `--otlp-headers-file` | content stays as configured | Spans: not readable by Fabric (canary tap, 9.3); `--spans` for user runs | Endpoint, CA path, headers file path |

**Deferred:** Azure Blob (no S3 API; needs a new exporter component) and
GCS through its S3 interoperability endpoint (needs qualification against
the content exporter's SSE and checksum behaviour). Both reach Fabric
today through the `otlp` preset to a customer collector that writes
there.

### 9.2 Why a `trial` preset

The audit had to write its own TLS OTLP collector, file exporter and
certificate on both production paths, because the test sink is refused in
production (F9). `trial` is the same thing, generated: it lets a
production-profile Node be verified end to end before a real destination
exists, and it is labelled as a trial everywhere it appears.

### 9.3 Canary tap

For destinations Fabric cannot read back (`otlp`), the Node routes spans
carrying the canary source's binding, and only those, to a bounded local
file (size-capped, overwritten) that `verify` reads. Agent records never
go to the tap. This needs a Node pipeline change (a routing rule on the
authenticated source and a file exporter instance limited to the tap);
it is an E4 work package and OQ-9.

---

## 10. Kubernetes

### 10.1 One-line install

```sh
helm install fabric oci://ghcr.io/singleaxis/charts/fabric --version <release> \
  --namespace fabric-system --create-namespace --set preset=production-host-sensor
```

- **Presets are chart values**, not only local profile files: `local`,
  `production`, `production-host-sensor` select the content of today's
  `shadow-dev.yaml`, `shadow-production.yaml` and
  `shadow-production-host-ingress.yaml` (D16). The profile files keep
  working with `-f` (I8).
- The chart never creates its own release namespace; Helm's
  `--create-namespace` does. `namespace.create` stays for compatibility
  and is documented (F15).
- New values (N5): `content.s3.caSecret` (private CA for an
  S3-compatible store, F6), an egress rule for the emitter in the chart's
  default-deny policy (F5), and a worked host-ingress + content example
  (D13).

### 10.2 Secrets without hand work

A `pre-install,pre-upgrade` hook Job runs the CLI image
(`fabric init --kubernetes --in-cluster`) with a service account that may
only `get` and `create` Secrets in the release namespace and the listed
agent namespaces. It creates each missing Secret and never overwrites or
logs one. The secret values are never part of the Helm release (I7);
deleting the release keeps them unless `--purge` is passed to
`fabric down --kubernetes`. The same generator runs from a laptop with
`fabric init --kubernetes` for clusters that forbid hook Jobs, or writes
manifests with `--render` for GitOps. Existing Secret names and keys of
today's docs are kept (`existingSecret` values), so a manual install
upgrades unchanged.

### 10.3 Agent namespaces

`agentNamespaces: [ns1, ns2]` (chart value) or
`fabric init --kubernetes --agent-namespace NS`: each namespace gets its
own ingest token, CA bundle and id key Secret (Secrets cannot cross
namespaces) and is bound to one agent source on the Node by default
(one tenant per namespace, from a namespace label or the chart value).

### 10.4 Opt-in pod injection

Off by default (`injector.enabled=false`). When enabled, a mutating
admission webhook acts only on pods that match **both** a namespace label
`fabric.singleaxis.ai/injection=enabled` and a pod annotation
`fabric.singleaxis.ai/inject: "python"` (or `"node"` after 055, or
`"env"` for any runtime: environment and mounts only).

What it adds, and nothing else:

- environment variables from the compiled agent configuration (a
  ConfigMap rendered by the chart), never overriding a variable the pod
  already sets;
- read-only mounts under `/var/run/fabric/` for the token, CA bundle and
  id key Secrets of the pod's namespace;
- for `python`: a ConfigMap volume holding the autoload shim
  (`sitecustomize.py`, standard library only, which chains to any
  existing `sitecustomize` and imports `fabric._autoload` from the
  **image's own** SDK; if the SDK is absent it does nothing and records
  why), and `PYTHONPATH` pointing at it;
- a spool volume: `emptyDir` with a `sizeLimit` by default, or a PVC by
  annotation `fabric.singleaxis.ai/spool: pvc`. `doctor` warns that a
  one-shot pod with an `emptyDir` spool can lose its tail (S7).

It never changes the image, command, args, resources, probes, security
context, service account or any existing env var, mount or container.
It adds no init or sidecar container. Webhook settings:
`failurePolicy: Ignore`, `timeoutSeconds: 2`, `sideEffects: None`,
`reinvocationPolicy: Never`, `namespaceSelector` and `objectSelector` so
that pods without both markers never reach it. The worst case for an
annotated pod is up to 2 s of admission latency and then a pod without
capture (I3). The SDK itself must be in the agent image (OQ-6). Pods
running before injection is enabled are untouched until the customer's
own next rollout (I5).

Without the injector, `fabric run --print-env --format k8s` prints the
same patch for the customer to apply.

### 10.5 Host sensor DaemonSet

`hostSensor.enabled=true` (the `production-host-sensor` preset) installs
today's emitter DaemonSet from the chart instead of a template (F19): the
image digest and tenant come from the release, the per-node binding
material is generated by the secrets Job (no files copied onto nodes as
root), and the id key Secret's key name is part of the chart.

Emitter changes (E2):

- **Cgroup discovery (N4, F4).** Find the kubelet's pod cgroup root
  instead of assuming `kubepods.slice` at the cgroup root: search for
  `kubepods` slices and directories to a bounded depth (covers
  `kubelet.slice/kubelet-kubepods.slice`, kind, and cgroupfs layouts),
  and accept an explicit override as today.
- **Report what it cannot see.** Health lines and metrics gain
  `pods_selected`, `pods_scoped`, and `pods_unscoped{reason}` with
  reasons `cgroup_not_found`, `unsupported_runtime` (a pod whose
  RuntimeClass handler is gVisor `runsc` or a Kata handler, read with
  `get` on RuntimeClasses), and `node_not_supported` (kernel or BTF).
  "Selector matched N pods, found 0 cgroups" is a WARN, never silence.
- **Export errors name the cause (N3, F5).** Log the gRPC status code and
  message, and add `doctor`'s NetworkPolicy check.

Nodes where a privileged DaemonSet cannot run (serverless node pools) are
detected by `plan --kubernetes` from node labels and reported as
invisible with the reason.

### 10.6 `fabric verify --kubernetes`

With the user's kube context (read-only; no `exec` into any pod): the
release and preset, Secrets present, the injector and the namespaces it
serves, annotated pods and whether they were injected (an annotation the
webhook adds, `fabric.singleaxis.ai/injected: <version>`), the emitter's
`pods_scoped` / `pods_unscoped` per node, NetworkPolicies, then the
canary and readback of 5.6 through a port-forward the CLI opens and
closes.

---

## 11. Packaging, upgrade and migration

### 11.1 Packaging

| Channel | Artifact | Contents | Notes |
|---|---|---|---|
| PyPI | `singleaxis-fabric` (existing) with a new `[cli]` extra | `fabric.cli` module and the `fabric` / `singleaxis-fabric` console scripts in the base package; the extra adds `PyYAML` and `cryptography` | Base agent installs gain no dependency. Commands that need the extra print the one install line when it is missing. `pipx install "singleaxis-fabric[cli]"`, `uv tool install "singleaxis-fabric[cli]"`, `uvx --from "singleaxis-fabric[cli]" fabric`. |
| GHCR | `ghcr.io/singleaxis/fabric-cli:<version>` (new) | The CLI with all extras, Docker and Helm clients | For Node-only and compiled-binary users, CI, and the chart's secrets Job. Signed and attested by the existing release workflow; same release qualification as the other images. |
| npm | `@singleaxis/fabric` (existing) gains a `fabric` bin | `run` and `doctor` only, reading `.fabric/compiled.env` | Other commands print the container or pipx line. Shared goldens with the Python CLI. |
| Helm | `oci://ghcr.io/singleaxis/charts/fabric` (existing) | Presets, secrets Job, optional injector, optional sensor DaemonSet | |
| Homebrew | Deferred | | `pipx` and `uv` cover macOS; a formula adds a maintained channel with no new capability. OQ-12. |
| `curl \| sh` | **Not provided** | | An unpinned remote script is the supply-chain pattern the release policy avoids. |

A static Go binary (extending `fabricctl`) would avoid a Python install
for every user, but the reader, the wire status and the capture-policy
loader that `verify`, `doctor` and `show` need are Python; a Go CLI would
either duplicate them or shell out to Python anyway. The container image
covers the no-Python case (OQ-2).

### 11.2 Versions and upgrade

- The CLI, SDKs, images and chart are released in lockstep (as today).
  The CLI carries the image digests and chart version of its own release
  as packaged data; `up` never pulls a floating tag.
- **Upgrade:** `pipx upgrade singleaxis-fabric` (or a new image tag),
  then `fabric up`, which prints the changes (image digests, chart
  version, rendered config) and applies them. Node volumes, the spool and
  secrets are kept. Spool and content formats follow 048 compatibility.
- `fabric.yaml` changes are additive within `fabric.config/v1`. A future
  v2 comes with `fabric init --migrate` and a release in which both are
  read.
- `doctor` and `verify` warn when the agent's SDK, the CLI and the Node
  are more than one minor version apart.

### 11.3 Migration from today's setup (nothing breaks)

- The SDK reads the same environment variables with the same meaning;
  the new `FABRIC_OTLP_*`, `FABRIC_WIRE_ID_KEY_FILE`,
  `FABRIC_WIRE_STATUS_FILE` and endpoint-table variables are additive and unset by default.
- The Make targets, Compose files, `preflight-prod.sh`, chart profiles,
  `host-bindings.py` and the DaemonSet template stay and stay tested.
  The docs move them to Reference → Manual setup (14).
- `fabric init --from-env` imports the current `FABRIC_*` and `OTEL_*`
  environment; `--from-env-file node.env` imports a Compose production
  env file; `--from-values values.yaml` imports Helm values. Secrets are
  **referenced by their existing paths**, not copied, unless
  `--import-secrets` is given.
- `fabric doctor`, `verify` and `show` work on a manual install with no
  `fabric.yaml`, from the environment alone.
- `fabricctl` is unchanged (OQ-3).

Tests: each documented manual setup (quickstart §4, production-setup,
the Helm example) is imported with `--from-*` and `verify` passes on it
with the same result as the manual route.

---

## 12. The coverage report

The coverage report answers, for one deployment, "what is recorded, what
is invisible, and what one command fixes each gap". `plan` predicts it;
`verify` measures it.

### 12.1 Rows

Rows are questions a user asks, not field ids. Each row maps to 049 field
ids and capture points in a new registry,
`contracts/coverage/v1/registry/integration-rows-v1.json`, generated and
checked by the existing coverage validator:

| Row | Main fields (049) | Capture points |
|---|---|---|
| Model calls (requests and responses) | S07–S11, N01–N02 | `wire.py.httpx`, `wire.py.aiohttp`, `wire.ts.undici` |
| Tool calls the model asked for, and results fed back | D31–D33, C19–C22 | `reconstruct.parse` over wire bodies |
| Commands the agent ran | N32–N35 | `exec.subprocess`, `exec.audit` |
| Files the agent touched | N45–N46, N49 | `file.audit` |
| Network contacts (non-model HTTP) | N26, N28, N30 | `http.nonmodel` |
| MCP traffic | C24–C29, N22–N25 | `mcp.client`, `mcp.wrapper`, `http.nonmodel` |
| Host evidence (independent of the agent) | C41 | `host.ebpf`, `host.auditd` |
| Permissions and control decisions (057) | G01–G16, D37–D49 | `records.grant`, `records.control`, wire derivation (057 P1) |
| Run, session and end user | X08–X14, C12 | `run.scope`, `install.config` |
| Sub-agents and delegation | X41–X44 | `run.scope`, `sdk.records` |
| Browser and UI automation | N54–N55 | `ui.automation` (054 P5, not built) |
| Realtime and voice | N56–N57 | `rt.websocket` (054 P5, not built) |

### 12.2 Row states

| State | Meaning | Shown with |
|---|---|---|
| `recorded` | A built capture point that supplies the row's fields runs in this shape and runtime and is enabled. | The capture point and its evidence (`httpx`, `endpoint api.openai.com`) |
| `fix` | A built capture point could supply the row here but is off. | The one command or `fabric.yaml` line that turns it on |
| `needs code` | Only a records (`R`) capture point can supply the row (the four cases of 1.1). | The API call, one line |
| `invisible` | No capture point exists for this runtime or shape, or the fact never crosses an observable boundary. | The 049 reason (`unsupported_runtime`, `not_exposed`, …) in words and the alternative if any |
| `partial` (verify only) | Observed but with losses or ambiguity. | Each reason in words with its fix (12.4) |

### 12.3 How `plan` computes it (predicted)

1. Probe facts (5.2) give the shape, the runtime and its version, the
   HTTP and protocol libraries, and sensor loadability.
2. For each row, take its capture points from the registry; keep those
   whose registry `Runtime` matches the probed runtime and whose `State`
   is built; drop the host sensor where it cannot load, with the reason.
3. A kept capture point that the current configuration enables →
   `recorded`; kept but off → `fix` with its enabling flag from the
   registry's `fix` column; only `R` points → `needs code`; none →
   `invisible` with the registry's `Cannot observe` text.
4. Library-specific limits from the registry (`requests` not hooked, Node
   below 24) produce their own `invisible` rows.

### 12.4 How `verify` computes it (observed)

1. Read the run's **capture manifests** (049 §2.8): the active capture
   points and their states for every source epoch of the run. This is the
   ground truth of what was installed, replacing the prediction.
2. Read the **reader report**: per-field coverage statuses (049 §2.6),
   aggregated per row (counts of `captured` and `absent` against
   `not_captured`, `redacted`, `truncated`, `unsupported` with reasons),
   and the chain verdicts (`decisions`, `actions`, `effects`,
   `corroboration`, `controls`) with their reasons.
3. Map each reason to plain words and a fix from the catalogue (13.1).
   Examples: `unattributed_effect` on an `exec` before the first model
   response → "a command ran before the agent's first model call (often a
   client library probing the platform); it is not linked to any tool
   call" (and N8 in 13.5); `ambiguous_attribution` under a `redact`
   policy → "commands are withheld by your privacy policy, so effects of
   parallel tool calls cannot be told apart; retain `terminal.argv` as a
   digest to allow matching"; `tail_unverified` → the exit budget and
   the spool hand-over text of the quickstart.
4. Where prediction and observation disagree (plan said `recorded`, the
   manifest says `not_instrumented`), print a finding with the cause
   (`FW-*` reason from the status file).

### 12.5 Per-shape tables in the docs

The "Choose your shape" pages show one coverage table per shape. The
tables are **generated from the TTFR and scenario jobs' observed reports**
(3.3), committed under `docs/_generated/coverage/` and refreshed by the
release workflow; a test fails when a page's table differs from the
artifact. No hand-written coverage claim appears on these pages.

---

## 13. Diagnostics and fixes outside the CLI

The CLI can only report what the components tell it. These changes make
every silent failure speak (G6, G7).

### 13.1 Diagnostics catalogue

`contracts/diagnostics/v1/messages-v1.json`: every diagnostic the CLI,
the SDKs (status and autoload), the emitter and the reader emit, with a
stable id (`FC-` CLI, `FW-` wire and SDK, `FE-` emitter, `FR-` reader,
`FN-` Node), a fixed text, a fix and a docs anchor. Messages carry no
interpolated value that could hold a secret or content; values that help
the user (a host name, a path, a variable name) appear only in local
output (status files, CLI output), never on telemetry. Test: every
emitted id is in the catalogue and has a non-empty fix; the catalogue
has no unused ids.

### 13.2 SDK (N3)

- **Reasons, not class names (F3, S2).** `install_from_env` maps each
  configuration error to a catalogue reason with fixed text (for example
  `FW-012 otlp_plaintext_non_loopback`: "the OTLP endpoint uses http to a
  non-loopback host; use https with FABRIC_OTLP_CERTIFICATE, or a
  loopback address"), instead of logging only the exception class. The
  original exception text stays unlogged, as today, because it may carry
  values.
- **`status` warnings (F2, S1).** `no_destination` (no OTLP endpoint:
  spans are dropped), `no_store` (content capture on and no store),
  `redacted_roles` (roles a `redact` or `omit` policy withholds under
  autoload, S6), and `endpoint_set` (the endpoint ids in force).
- **Unmatched model-shaped requests (F2).** The tee already routes every
  httpx/aiohttp request (`_routes.decide`). A request that routes `none`
  but whose path ends with a known model suffix (`/chat/completions`,
  `/responses`, `/messages`, `/embeddings`) increments a counter per host
  (bounded table, 32 hosts). Cost: one suffix comparison on an
  already-computed path (053 §4.4 budget). The host list is written to
  the status file, never to telemetry, so `doctor` and `verify` can say
  "3 requests looked like model calls to my-llm.example.modal.run; run
  `fabric init --provider https://my-llm.example.modal.run/v1`".
- **Status file.** `FABRIC_WIRE_STATUS_FILE`: at install and at exit
  (inside the existing shutdown budget), the SDK writes the status JSON
  (the `python -m fabric.wire status` shape plus runtime counters) to
  that path. Under autoload nothing is written to the agent's stdout or
  stderr (the 0.12.1 quiet-autoload rule holds).
- **`fabric.wire.status`** (D6): the documented in-process accessor
  either exists or the docs stop naming it; E1 adds a module-level
  `status()` returning the installed handle's status.

### 13.3 TypeScript SDK (N2, F7, F23)

- Widen the `@opentelemetry/api` peer range to the versions current
  exporters need, or bring the exporter as a dependency of a documented
  `installDefaultProvider()`, so the README's install line is the whole
  install. A CI job installs the README line verbatim with today's latest
  OpenTelemetry packages and runs the README example.
- Adopt the TLS rule of 6.4.
- The reader and `fabric show` accept explicit-API records from the
  TypeScript SDK and label them *reported*; `verify` reports the Node
  path's `decisions` chain as `unsupported(unsupported_runtime)` until
  055 TS-1U, instead of `no runs reconstructed` with no reason (F1, S5).

### 13.4 Reader (N6) and production checks (N7)

- Accept directories of `*.json` and `*.jsonl` OTLP exports, and name the
  accepted forms in the error (F17, D19).
- Default output: one summary line per run (`run …: partial
  (sequence_gap)`), full JSON with `--json` or `--out` (F25, D3).
- `--latest` and run selection by label (F16).
- Peers: when the run's own records carry the peer address of a model
  connection, the reader uses it instead of requiring
  `--endpoint-peer` flags (F13). Recording the peer address of a model
  connection is a capture-side addition (the socket's peer address,
  read from the transport after connect, no I/O); it needs the 053 and
  056 owners' agreement (16.6). Until then `verify` fills the flags from
  the Node's view of the agent's address and the endpoint table.
- `make verify-prod-groups` (F14, E1, small): the ingress-group variant of
  `verify-prod.sh`. `fabric verify --production` (E4) replaces both for
  CLI users and keeps check ids identical to `preflight-prod.sh` (a test
  runs both on the same fixtures and compares ids and outcomes).

### 13.5 Startup effects that make every run `partial` (N8, F10)

The OpenAI Python client runs `uname -p` at import; with the exec hook on
this is an `unattributed_effect` in every run, so a normal run reads
`partial`. Fabric must not guess an attribution. This spec asks spec 056
for a decision (OQ-10). **Done** (revision 2): spec 056 revision 11 rule
S0 reports such effects as `attribution.startup_effects`, never attributed
and not a reason of the `effects` chain (#287). `verify` and `show` word
the startup-effects list (12.4); the TTFR tests need no exception.

---

## 14. Documentation

### 14.1 Structure

```text
docs/
  get-started/        5 minutes: python.md, node.md, other-languages.md, kubernetes.md (15 min)
  shapes/             choose.md (decision table from `fabric plan` rows), laptop.md, linux-host.md,
                      containers.md, kubernetes.md, serverless-and-sandboxes.md, macos-and-windows.md
  production/         index.md (the checked path), linux-host.md, kubernetes.md, destinations.md,
                      secrets-and-rotation.md, sizing.md, upgrade.md
  reference/          cli.md and fabric-yaml.md and env-vars.md (generated), the existing reference
                      pages (reconstruct, explicit APIs, action reconstruction, run record, host
                      sensors, privacy and security, glossary, API stability, qualified-run mode),
                      manual-setup/ (today's quickstart §4, production-setup, deployment)
```

- **Get started** pages: one path each, the commands of 3.2, and nothing
  else. They name no spec, work-package or milestone id (F24, D20); a
  lint test bans `WP\d`, `P\d-[A-Z]`, `M\d` and `spec \d{3}` in
  `get-started/`, `shapes/` and `production/`.
- **Choose your shape** answers the five audit scenarios (VM with shell
  and browser tools, remote sandbox, multi-tenant service, compiled
  binary, MCP-heavy agent) and the runtimes no page covers today
  (gVisor, Fargate, Lambda, Cloud Run, macOS-native, Windows): D21.
- **Go to production** is the checked path: each step ends with the
  `verify --production` check ids it satisfies.
- **Reference** pages generated from the CLI's argument parser, the
  `fabric.yaml` schema and the SDK's variable table are checked for drift
  by tests.
- Every old page path keeps a stub that links to its new home, so no
  inbound link breaks (I8); the relative link check runs on all docs.

### 14.2 Tests

Docs-as-tests (3.3) for every page in `get-started/`, `shapes/` and
`production/`; the existing `test_production_setup_doc.py` checks move
with the manual-setup page; generated pages have drift tests; the
documentation-scope test (`test_recorder_documentation_scope.py`) adds
the new pages to `PRIMARY_DOCS`.

### 14.3 Fixes that cannot wait for the restructure

D1–D12, D14–D17 and D19 state something false or contradictory today.
They are fixed in place in E1, before the restructure, as one
documentation pull request. D13, D18, D20 and D21 (missing or misplaced
content) are closed by the restructure in E3.

---

## 15. Contract and interface additions (applied by the E work packages)

| Addition | Where | Phase |
|---|---|---|
| `fabric.config/v1` schema and fixtures | `contracts/cli-config/v1/` | E1 |
| `fabric.cli-report/v1` (`--json` of `plan`, `verify`, `doctor`, `show --list`) | `contracts/cli-config/v1/` | E1 |
| Built-in endpoint table and schema | `contracts/providers/v1/` | E1 |
| Diagnostics catalogue | `contracts/diagnostics/v1/` | E1 (grows each phase) |
| Integration rows registry | `contracts/coverage/v1/registry/integration-rows-v1.json` | E3 |
| SDK variables `FABRIC_OTLP_*`, `FABRIC_WIRE_ID_KEY_FILE`, `FABRIC_WIRE_STATUS_FILE`, `FABRIC_WIRE_BUILTIN_ENDPOINTS` (additive) | Python SDK; TypeScript SDK for `FABRIC_OTLP_*` | E1 (Python), E3 (TS) |
| Manifest property `endpoint_table_version` (049 delta, additive minor) | 049 §2.8, capture-manifest schema | E1 |
| Chart values: `preset`, `content.s3.caSecret`, `injector.*`, `hostSensor.*`, `agentNamespaces`, emitter egress rule | `charts/fabric` | E2 |
| Emitter health fields `pods_selected`, `pods_scoped`, `pods_unscoped{reason}` | `components/host-emitter` | E2 |
| Node canary tap | `components/otel-collector-fabric` config | E4 |
| Release: `fabric-cli` image; CLI command allowlist test; console scripts | release workflow and `release-policy.json` | E1 |

---

## 16. Phases

### 16.1 E0 — audit (done)

The friction audit of 2026-11-09 (five paths, raw step logs, every file
the user had to write). Acceptance: met; its findings are the inputs of
the friction map (16.7) and the baselines of 3.2.

### 16.2 E1 — local CLI

| WP | Work |
|---|---|
| WP8-1 | `fabric.cli` skeleton: config discovery and precedence, `fabric.config/v1`, `--json` report schema, exit codes, catalogue plumbing, release allowlist test, console scripts, `[cli]` extra |
| WP8-2 | `init` (local), secrets generator (files), compiled env file, `--from-env` |
| WP8-3 | `up`/`down` (Docker, local profile): packaged Compose templates pinned by digest, `local-dir` destination writing spans directly, sensor auto-start on Linux, TLS listener with the generated CA |
| WP8-4 | `run` (Python; env-only for other runtimes), `--print-env` formats, run state, cgroup join |
| WP8-5 | `verify` (local: canary, readback, observed coverage for the rows built so far), `show`, `doctor` (local checks) |
| WP8-6 | SDK: reasons and warnings (13.2), status file, `FABRIC_OTLP_*`, `FABRIC_WIRE_ID_KEY_FILE`, unmatched model-shaped counter, `fabric.wire.status()` |
| WP8-7 | Endpoint table data file, qualification fixtures per row, manifest table version, custom provider line, base-URL derivation |
| WP8-8 | Reader: input forms, summary line, `--latest` (13.4); `make verify-prod-groups` |
| WP8-9 | Container image `fabric-cli`; npm `fabric` bin (`run`, `doctor`) with shared goldens |
| WP8-10 | Documentation fixes of 14.3; Get started → Python page with docs-as-tests; TTFR harness and `ttfr-laptop-python` |

**E1 acceptance:**

- `ttfr-laptop-python` passes G1 (≤ 300 s cold, 1 install + 3 commands, 0
  hand-made items) with the fixture agent on a host outside the table
  reached through `OPENAI_BASE_URL`, and again with one `--provider`
  flag and no base-URL variable.
- G8 passivity matrix passes (valid, broken, missing config; SDK missing;
  Node down), including no socket opened by `run` and no `OTEL_*`
  variable changed.
- S1, S2, S6 produce catalogue reasons with fixes (tests).
- I4 network-namespace test passes for every E1 command.
- Every shipped endpoint row has a passing qualification fixture.
- The quickstart's manual route still passes unchanged (I8).

### 16.3 E2 — Kubernetes

| WP | Work |
|---|---|
| WP8-11 | Chart: `preset` values, namespace ownership fix, `content.s3.caSecret`, emitter egress rule, host-ingress + content example |
| WP8-12 | Secrets hook Job and `init --kubernetes` / `--render` |
| WP8-13 | Injector (opt-in): webhook, autoload shim ConfigMap, agent-namespace Secrets |
| WP8-14 | Sensor DaemonSet in the chart; emitter cgroup discovery, unscoped-pod reasons, RuntimeClass detection, export error codes |
| WP8-15 | `up --kubernetes`, `verify --kubernetes`, `doctor --kubernetes`, `plan --kubernetes` |
| WP8-16 | `ttfr-kubernetes`; Get started → Kubernetes page with docs-as-tests |

**E2 acceptance:** G4 on kind with the production-host-sensor preset: one
`helm install`, one namespace label, one pod annotation, an agent image
with the SDK, 0 hand-made Secrets, `verify --kubernetes` exit 0 with
`corroboration: complete` for a fixture run. The audit's three
workarounds are regression tests that now pass with no manual step (S3 CA
on a private-CA store, emitter behind the default-deny policy, kind's
`kubelet.slice` layout). A gVisor RuntimeClass pod is reported
`unsupported_runtime`, not silently unscoped. Webhook outage test: with
the webhook deployment scaled to zero, annotated pods start within the
2 s timeout and run uncaptured; `doctor` reports why.

### 16.4 E3 — plan, coverage report, docs

| WP | Work |
|---|---|
| WP8-17 | Integration rows registry and validator; full `plan` probes; predicted and observed coverage in `plan` and `verify` |
| WP8-18 | Reason-to-words catalogue for every chain reason (F10) |
| WP8-19 | TypeScript: install fix, TLS rule, `FABRIC_OTLP_*`; reader and `show` support for reported TS records; `ttfr-laptop-node` (G2 before 055) |
| WP8-20 | Docs restructure (14.1), generated reference pages, per-shape coverage tables from observed reports, stubs for old paths, lint for internal ids |
| WP8-21 | `plan-scenarios` job with the five audit scenarios |

**E3 acceptance:** G2 (pre-055 form), G5, G6 and G7 pass; every page in
`get-started/`, `shapes/` and `production/` is executed by docs-as-tests;
an engineer with no Fabric context repeats audit paths P1, P2 and P5 and
reports against 3.2.

### 16.5 E4 — production path

| WP | Work |
|---|---|
| WP8-22 | `init --production`: production capture policy preset written into the project, tokens, keys, derived source ids, client certificates, canary binding, rotation |
| WP8-23 | Destination presets `trial`, `s3`, `s3-compatible`, `otlp`; `queue_size` and sizing advice |
| WP8-24 | `up` for the single-host production shape (driving the ingress-group Compose files and the sensor in production mode) |
| WP8-25 | `verify --production` checks with `preflight-prod.sh` id parity; certificate expiry; canary tap in the Node |
| WP8-26 | `ttfr-host-production`; Go to production pages with docs-as-tests |

**E4 acceptance:** G3 passes on a Linux runner with eBPF; `verify
--production` reports no FAIL on the `trial` preset and on an
S3-compatible store with a private CA; a fresh-context engineer repeats
audit paths P3 and P4 and reports against 3.2.

### 16.6 Ordering, and running alongside spec 057 P1–P3

**Order.** E1 first. E2 and E3 can run in parallel after WP8-1 (the CLI
skeleton) lands. E4 needs E1; its Kubernetes part reuses E2. 055 TS-1U is
not part of this spec; when it ships, `run`, the injector and G2 switch to
the zero-code Node path with no CLI interface change.

**File overlap with 057 P1–P3:**

| Area | 058 work | 057 work | Overlap and order |
|---|---|---|---|
| `wire/__init__.py`, `wire/_status.py`, `wire/_config.py` | WP8-6, WP8-7 (reasons, status file, OTLP variables, endpoint table) | P1 WP7-4–WP7-8 work in `reconstruct/` and the MCP transport hook, not these files | Low. 058 does not touch `_routes.py` or `_match.py` (054 WP5-00a owns them); the unmatched-request counter reads the route decision through one call added beside `decide()`, reviewed by the 054 owner. |
| `reconstruct/__main__.py` | WP8-8 (input forms, summary line, `--latest`) | P1 rules under `reconstruct/` (dialects, MCP method layer); P2 WP7-12 projection | Medium, in argument parsing and output. Land WP8-8 as one small PR before 057 P1's reader PRs, or rebase it after them; owner: the reader owner. |
| Capture policy `security_context` lists | `fabric.yaml` `capture.security_context` passes a path through | P2 WP7-9 loads the lists | 058 defines no vocabulary of its own; the key stays a path until WP7-9 lands, then `init` can write a template. |
| `components/host-emitter` | WP8-14 (cgroup discovery, health fields, RuntimeClass, error codes) | P2 WP7-11 (BPF exit events, watched-path labels in user space) | Same module, different files (`podscope.go` and health vs. BPF programs and event pairing). Both add health counters: agree names in one PR. WP8-14 first; it is a bug fix (F4). |
| `charts/fabric` | WP8-11, 13, 14 | P3 WP7-15 adds the mapping-profile processor value | E2 first; WP7-15 adds its value on top. |
| `sdk/typescript/package.json` | WP8-19 (peer range, exporter) | P3 WP7-16 (TS parity) | WP8-19 first; small. |
| `fabricctl` | none | P3 WP7-17 (operator configuration snapshot) as a `fabricctl` subcommand | Decided by OQ-3. Recommendation: WP7-17 lands as `fabric snapshot` in the new CLI (an operator action outside the agent is the CLI's role), with its own allowlist entry. |
| `docs/` | WP8-10 fixes, WP8-20 restructure | 057 pages for security context | WP8-20 creates the new tree with stubs early in E3; 057 pages land in `reference/` or move with a stub. |
| `AGENTS.md` | One proposed in-scope sentence (OQ-11) | 057 §11 wording (landed with P0) | Append after 057's text; no conflict. |
| Release workflow, `release-policy.json` | New `fabric-cli` image, CLI allowlist | none | None. |

Two questions for other spec owners come out of this spec: whether the
Node ingress accepts a token set for overlap rotation (049 §7.9, 7.3), and
whether the SDK may record a model connection's peer address (053/056,
13.4).

### 16.7 Friction map

Every top-25 audit item, ranked as the audit ranked it, mapped to the
section that removes it or deferred with a reason.

| # | Sev | Item | Addressed by | Phase |
|---|---|---|---|---|
| F1 | S1 | Node.js agent can never get a verified or viewable record; `no runs reconstructed` with no reason | 13.3 (reported TS records in reader and `show`; `unsupported` stated, never a false pass); 5.2 (`plan` says it). **Zero-code Node capture is deferred to 055 TS-1U**, which this spec does not build. | E3; 055 |
| F2 | S1 | Two-variable autoload records nothing; `status` clean | 5.5 (`run` sets everything), 8 (table, base-URL derivation), 13.2 (`no_destination`, unmatched model-shaped requests) | E1 |
| F3 | S1 | Plaintext non-loopback OTLP: capture off, class name only | 6.4 (one TLS rule; CA always generated and passed), 13.2 (reason with fix) | E1 |
| F4 | S1 | eBPF DaemonSet scopes 0 pods on kind, silently | 10.5 (cgroup discovery, `pods_unscoped{reason}`) | E2 |
| F5 | S1 | Chart default-deny NetworkPolicy blocks the emitter; `*status.Error` only | 10.1 (egress rule), 10.5 (gRPC code and message), 5.7 (`doctor` check) | E2 |
| F6 | S1 | No chart value for a private-CA S3 store | 10.1 `content.s3.caSecret`; 9.1 `s3-compatible --ca-file` | E2, E4 |
| F7 | S2 | TS install: missing packages, peer conflict, import crash | 13.3 | E3 |
| F8 | S2 | ≈34 / ≈45 hand-made certs, keys, tokens, env lines, YAML | 7 (all generated), 10.2 (Secrets Job) | E1, E2, E4 |
| F9 | S2 | No production-acceptable trial destination | 9.1 `trial`, 9.2 | E4 |
| F10 | S2 | Normal runs read `partial` (startup `uname -p`, `redact` ambiguity) | 12.4 (each reason in words with a fix); 13.5 and OQ-10 (056 decision) | E3; 056 |
| F11 | S2 | "See what it did" is weak | 5.8 `fabric show` | E1 |
| F12 | S2 | Quickstart builds the Node from Go source | 5.4 (packaged templates, pinned signed images) | E1 |
| F13 | S2 | Reader needs every peer IP; `tentative` connect noise | 13.4 (peers from records, pending 053/056 agreement; `verify` fills flags meanwhile); 5.8 (collapse) | E1, E3 |
| F14 | S2 | `make verify-prod` fails on ingress groups | 13.4 (`verify-prod-groups` now; `verify --production` later) | E1, E4 |
| F15 | S2 | `namespace.create` vs Secrets-first ordering | 10.1 | E2 |
| F16 | S2 | Export and verify take 3 steps; no "latest run" | 5.5 step 4, 5.6, 5.8 `--list`, 9.1 `local-dir` writes directly, 13.4 `--latest` | E1 |
| F17 | S2 | Reader refuses a directory of `.jsonl` | 13.4 | E1 |
| F18 | S2 | No agent Pod example (21 env vars, 5 volumes) | 10.4 injector; `--print-env --format k8s` | E2 |
| F19 | S2 | Emitter DaemonSet is a hand-edited template | 10.5 (chart-managed DaemonSet, generated binding material) | E2 |
| F20 | S2 | MinIO images unpullable; S3-compatible needs a hand-written override | 9.1 (`trial` on SeaweedFS or Garage; `s3-compatible` preset) | E4 |
| F21 | S3 | Custom model host needs hand-written matcher JSON, repeated | 8.2, 8.3 | E1 |
| F22 | S3 | Queue worst case vs free disk; fix is editing collector YAML | 6.1 `node.queue_size`, 5.6 sizing advice | E4 |
| F23 | S3 | Python refuses plaintext OTLP, TS sends it | 6.4, 13.3 | E3 |
| F24 | S3 | 6,900 lines of docs in spec and work-package ids | 14 | E3 |
| F25 | S3 | Reader dumps 320 lines of JSON; README shows one line | 13.4 summary default; D3 fix | E1 |

Plan items N1–N8: N1 → 13.3 and 055; N2 → 13.3; N3 → 13.2, 10.5; N4 →
10.5; N5 → 10.1; N6 → 13.4; N7 → 13.4; N8 → 13.5, OQ-10. Silent failures
S1–S7 → 13.2 (S1, S2, S6), 10.5 (S3, S4), 13.3 (S5), 10.4 and 5.7 (S7).
Documentation defects D1–D21 → 14.3 (the false statements, E1) and 14.1
(the rest, E3).

### 16.8 Already done on main (revision 2)

The friction-audit fixes merged on 2026-11-09 and 2026-11-10 already
deliver part of E1-E3. Build units skip these parts and keep their tests
green; the rest of each work package is unchanged.

| WP | Done by | What is done | Still to build |
|---|---|---|---|
| WP8-6 | #287 | Capture-off reasons that name the fix (F3); `span_destination` and the no-destination warning (F2); the unmatched model-shaped request counter in `stats()`; `content_withheld_roles` (S6) | Status file, `FABRIC_OTLP_*`, `FABRIC_WIRE_ID_KEY_FILE`, `fabric.wire.status()`, the 13.2 catalogue codes |
| WP8-8 | #287, #288 | Reader `--spans` accepts `*.otlp`, `*.json`, `*.jsonl` (F17); one summary line per run, `--json` for the full report (F25); `no runs reconstructed` says why (F1); `make verify-prod-groups` (F14/N7, #288) | `--latest`; the remaining 13.4 input forms |
| WP8-10 | #287, #286 | README "record your own application" route with a destination and endpoints, run as a test; TypeScript README states what is recorded and verified (F1) | The rest of 14.3; Get started pages; TTFR harness |
| WP8-11 | #288 | Namespace ownership fix (F15); `content.s3.caSecret` (F6); `networkPolicy.hostSensorEgress` (F5) | `preset` values; host-ingress + content example |
| WP8-14 | #288 | Emitter finds pods under any kubelet cgroup root, incl. kind (F4/N4); health line `pod_selector_matched`/`pod_cgroups_found`; gRPC code and hint on export errors (F5); `host-bindings.py --emitter-image` (F19) | Sensor DaemonSet in the chart; unscoped-pod reasons; RuntimeClass detection |
| WP8-19 | #286 | `@opentelemetry/api` peer range and pinned install lines with a fresh-install CI test (F7/N2); plaintext OTLP rule parity (F23) | `FABRIC_OTLP_*`; reader and `show` support for reported TS records; `ttfr-laptop-node` |
| 13.5 / OQ-10 | #287 | Startup effects rule S0 (spec 056 revision 11) | Wording in `verify` and `show` |

---

## 17. Open questions for the owner

Each has a recommendation. Ordered by how much they change the build.
**Answered 2026-11-10:** the owner accepted every recommendation as
written.

| # | Question | Recommendation | Owner decision |
|---|---|---|---|
| OQ-1 | **Command name.** `fabric` is short and matches the product, but other tools ship a `fabric` command (an unrelated AI prompt CLI is widely installed under that name; the Python Fabric SSH library uses `fab`). | Keep `fabric` in the docs and always install the alias `singleaxis-fabric`. `doctor` and the install docs explain the alias when `fabric --version` is not ours. | Accepted as recommended (2026-11-10) |
| OQ-2 | **Where the CLI lives.** In the Python distribution, a separate distribution, or a static Go binary (extending `fabricctl`)? | In `singleaxis-fabric` with a `[cli]` extra, plus the `fabric-cli` container image, plus a thin npm `run`/`doctor` launcher (1.4, 11.1). A Go binary would have to duplicate or shell out to the Python reader. | Accepted as recommended (2026-11-10) |
| OQ-3 | **`fabricctl`.** Its declaration is read by nothing. Keep, fold into `fabric`, or deprecate? Where does 057 WP7-17 land? | Keep it unchanged through v1.0 and move its page to Reference. Land WP7-17 as `fabric snapshot`. Decide `fabricctl`'s deprecation at v1.0 with its users. | Accepted as recommended (2026-11-10) |
| OQ-4 | **Endpoint table default for plain autoload.** New qualified rows widen what an existing autoload user captures. | On by default everywhere from the release that ships each row, listed in the CHANGELOG and recorded by table version in the manifest; `FABRIC_WIRE_BUILTIN_ENDPOINTS=legacy` pins today's three. Loopback rows never on by default. | Accepted as recommended (2026-11-10) |
| OQ-5 | **Kubernetes secrets.** Hook Job, Helm template randomness, or CLI only? | Hook Job using the CLI image (values never in the Helm release), with `fabric init --kubernetes` and `--render` for clusters that forbid hook Jobs. No template randomness. | Accepted as recommended (2026-11-10) |
| OQ-6 | **Pod injection of the SDK itself.** Inject env and mounts only, or also copy the SDK into pods whose image lacks it? | Env, mounts and the stdlib-only shim only. Injecting packages into an unknown interpreter risks dependency conflicts in the agent; one dependency line in the image is cleaner. Revisit after E2 with field data. | Accepted as recommended (2026-11-10) |
| OQ-7 | **Should the SDK read `fabric.yaml` directly?** | No. The CLI compiles it into the inputs the SDK and Node already read. One runtime configuration surface per component, and nothing existing changes. | Accepted as recommended (2026-11-10) |
| OQ-8 | **`fabric run` borrowing its own SDK** when the agent's interpreter lacks it. | No in E1: print the one install line for that interpreter. Revisit with E1 data; borrowing across environments is fragile. | Accepted as recommended (2026-11-10) |
| OQ-9 | **Readback for destinations Fabric cannot read** (`otlp`). | Add the canary tap in E4 (canary-bound spans only, bounded local file). User runs on such destinations are read with `--spans`. | Accepted as recommended (2026-11-10) |
| OQ-10 | **Startup effects (N8).** Commands before the first model call make every exec-hook run `partial`. | Ask spec 056 for a reason `before_first_decision` that is reported as a fact and not counted against `effects` completeness, with no attribution guessed. Until decided, `verify` explains it in words. | Accepted as recommended (2026-11-10) |
| OQ-11 | **AGENTS.md wording.** | Add to "In scope": "an operator CLI that plans, configures, starts, launches capture for and verifies the recorder on customer infrastructure, with no fleet management, rollout or phone-home". This keeps retired spec 026's lifecycle out. | Accepted as recommended (2026-11-10) |
| OQ-12 | **Homebrew and `curl \| sh`.** | No `curl \| sh`, ever. Homebrew deferred until users ask; `pipx` and `uv` cover macOS. | Accepted as recommended (2026-11-10) |
| OQ-13 | **Multi-tenant processes.** `FABRIC_TENANT_ID` is process-wide; no page covers one process serving many tenants (audit P5). | Out of 058's scope: a per-run tenant is a 050/051 contract change. 058 makes `plan` report it as `invisible (not_configured)` and documents the limit on the shape page. Ask the 050 owner for a decision. | Accepted as recommended (2026-11-10) |
| OQ-14 | **cgroup join by `fabric run`.** It moves the agent into a cgroup with no limits so the sensor scopes it. | Yes when a delegated cgroup exists, fail-open otherwise; `plan` and `verify` say whether the agent was scoped. | Accepted as recommended (2026-11-10) |

---

## 18. Acceptance of this spec

This spec is ready for `accepted` when the owner has answered section
17, the 049, 053, 054 and 056 owners have agreed to the deltas named in
15 and 16.6, and the release owner has agreed to the new artifact of
11.1.
