---
title: Execution channels — P4 opt-in observed hooks and production host sources
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 2
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: ["049", "050", "051", "052"]
related: ["030", "031", "041", "043", "047", "048", "054", "055"]
---

# 053 — Execution channels (P4)

**Revision 2** applies the v0.9 spec reviews (Astra, Fable) through the
main-session decisions R1–R16, and binds this spec to spec 050 revision 2,
which is now the frozen P1 contract. The changes:
- Every hook records through the records input with provenance `observed`.
  The W-class record (`capture.input=wire` on a hook record) is withdrawn
  (R7). Every structured P4 datum maps onto 050's evidence carrier through
  six registered evidence types (§3.2), owned by contracts WP4-01, which
  depends on 050 WP-00.
- Multi-source Node binding uses static dedicated ingress groups, each a
  proven `bearertokenauth` instance bound to one source, with a bounded
  group count (§6.1, R11). A custom credential-to-source authenticator is
  recorded as a later option.
- Host-sensor production ingress has its own complete subsection (§6.2):
  record schema, sources and epochs, gate rules and fabricguard admission.
  The old WP4-07 is split into buildable work packages (R14).
- Every shared file has one integration owner, and intra-wave
  dependencies are listed (§8, R13).
- One identity rule (R8) and the passivity rules (R9) replace revision 1's
  stricter clear-mode wording (§4.2, §4.3).
- The coding-agent row of the architecture matrix is amended to match what
  the hooks can observe (R15; §10).
- The vector-store dialect (Qdrant REST) and the SSH client (paramiko) are
  frozen as recommended defaults (§9).
- Items closed by 050 revision 2 are no longer open here: uuid4 marker ids
  (R2), segment-attributed losses (R3), the three status inputs (R4),
  descriptor-only bodies (R5) and pre-ack content validation (R10).

---

## 1. Scope and gates

This spec implements 049 P4 under **CAPTURE -> PROTECT -> DELIVER**.
- Every hook is independently opt-in. Installing the package, autoload, an
  execution coverage profile, or enabling another hook never enables it.
- Observations never approve, block, retry, modify or delay the action.
- No framework adapters ship.
- Qualified-run mode (045/046) keeps its separate opt-in journal.

Normative baseline: 049 rev 6.4, spec 050 rev 2 (P1, frozen), spec 051
rev 2 (P2 reporting APIs) and spec 052 rev 2 (D23/D24 contract), plus the
shared owner decisions dated 2026-10-19..22. `file:line` references are
anchors in this worktree at authoring time; build WPs refresh them.
Contract changes below are build instructions. This document changes no
other file.

| Capture point / gate | Fields supplied or reused | Boundary and limits |
|---|---|---|
| `exec.subprocess` / P4-EXEC | N32–N35 | Local process arguments and caller-consumed output; no PTY, descendant capture or extra reader |
| `exec.audit` / P4-AUDIT | N32 | Exec-family audit attempt; no completion or output |
| `file.audit` / P4-FILE | N45 (operation, opt-in digest), N46, N49 | Pre-operation audit event, path and mode; no file contents, byte ranges or inferred success |
| `db.dbapi` / P4-DB | N38–N42, D23–D24 | sqlite3 (observing factories) and psycopg 3 first; fetched values and client transaction observations only |
| `http.nonmodel` / P4-HTTP | N43–N44; N26, N28 for the qualified dialect | httpx/httpx2, explicit host allowlist; no headers, other clients or endpoint scanning |
| `mcp.client` / P4-MCP | C25–C29, N22–N25 | Qualified MCP stdio and Streamable HTTP transport bytes; no server internals |
| `remote.ssh_wrapper` / P4-SSH | N36–N37 | Explicit paramiko wrapper; no remote agent or SSH security changes |
| `sdk.records` / P4-UI-R | N54–N55; N53 is a P1 provider observation | Existing P2 browser/computer-use reporting only; `ui.automation` remains P5 |
| `host.auditd`, `host.ebpf` / P4-HOST | C41; X21 corroboration | Separate host sources with their own epoch, encrypted state and production ingress group (§6.2) |
| Node / P4-BIND | — | Static single-source ingress groups (§6.1) |
| `reconstruct.infer` / P4-JOIN | X21, N48 | Tentative host joins; optional diff from already stored before/after bytes |

All records use the applicable X01–X09, X17–X30, X31–X36, X39–X49 and
S01–S12, S29–S34 where observed, and configured C12/C15/C16/C41 only.
- Parent, run and causal links are inherited or reported, never guessed
  from adjacent timestamps.
- N47 stays explicit observed before/after bytes; file hooks do not supply
  it.
- No new core field id is allocated here.

**Entry, copied from 049 §8.2:** "P2 exit; P1-A harness." Spec 050 is the
P1/P1-A dependency, spec 051 owns the reporting APIs. P3 exit is not a new
prerequisite: P4 reuses 052's D23/D24 contract, not its runtime. The
contract chain 050 WP-00 → 051 WP2-0 → 052 WP3-0 must be merged before
WP4-01 starts (§8).

**Exit, copied from 049 §8.2, per channel:** "a fixture server, driver or
process ledger proves the exact bytes and operation set; no extra reads,
fetches, pipes or requests; retry, parallelism, cancellation, partial
consumption, transactions, timeout after possible commit, detached work;
D2/D3 honoured; hook passivity (raising body, budget, fork, recursion,
audit self-event); header and environment credential canaries never
stored. No channel inherits another's qualification."

Tightening:
- Each driver, sync/async variant, transport and version qualifies
  independently.
- P4-HOST and P4-BIND must pass before production host capture or
  multi-source Nodes are advertised.
- Disabled and unsupported channels appear in manifests. A partial
  release does not claim the full P4 exit.

## 2. Current state and missing work

| Evidence in current code | Consequence |
|---|---|
| `sdk/python/src/fabric/wire/_match.py:11–60`: five API names; POST-only matcher; host/scheme/port/prefix checks | No non-model dispatch table. Keep model matching and add an independent allowlisted route |
| `wire/_model.py:15–21,78–99`: model API union, model roles, `CaptureJob`, nonblocking submit | Hooks use P1's records input (050 §3.4), not fabricated model exchanges |
| `wire/_pipeline.py:249–264,377–449`: queue admission and worker-side protection and spooling | 050 extends the same worker path to `RecordJob`; hooks add no serialisation, redaction RPC or fsync |
| `wire/_config.py:43–45,91–100`: 32 MiB object cap, 64 MiB retention, 16384-entry ceiling with byte budgeting | Hooks share the byte and entry budgets through 050's `max_inflight_bytes` charge |
| `wire/_protect.py:3–14,61–65`: extraction before protection, customer-run redaction service, role validation | All hook content passes the same stage before disk or export; no customer code runs in Fabric |
| `wire/_aiohttp.py:69–84,86–115`: bytes-only request observation, response feed observation | No MCP byte interception or WebSocket capture; no P4 aiohttp network claim |
| `wire/_detect.py:54–65,69–101`: requests/urllib3 model-call loss detector, recursion guard | Keep loss accounting for uninstrumented model clients; do not extend it to all traffic |
| `decision.py:2141–2210`: `record_file_access` file span event with a SHA-256 path hash; no byte-range argument | Not a PEP 578 hook; hooks never call this legacy method on the action path. No API supplies N45's byte range |
| `reconstruct/_inputs.py:518–550`: exchange/loss/heartbeat classification | 050 WP-30 adds records; P4 adds channel projection and host readers through registration hooks |
| `components/otel-collector-fabric/receiver/auditreceiver/translate.go:27–114`: audit-class log records, SHA-256 executable/argv/path, raw peer address, `process.owner`, executable name | Production needs keyed ids, dropped owner/name/address and opt-in digests (§6.2.5) |
| `auditreceiver/durable_state.go:21–22,94–125,169–215`: durable staged logfile batch and cursor with fsync | Keep accepted-cursor semantics; add encryption, source/epoch/position and persisted event ids |
| `auditreceiver/receiver.go:180–188,276–348`; `netlink_linux.go:317–347` | Source-health uncertainty and counted delivery losses exist and become heartbeat evidence |
| `components/host-emitter/emitter.go:130–176`; `spool.go:159–208`; `otlp.go:44–107` | eBPF emits the same audit-class logs, a plaintext durable OTLP spool, TLS/token export and partial-success quarantine; no source/epoch/manifest |
| `fabricguardprocessor/config.go:16–26,70–83`; `processor.go:1013–1065` (`validHostAuditValue`) | One `evidence_source_binding` per instance; host audit-class values are validated, never bound or stamped in production |
| `gate/gate.go:72–100,285–310` | The gate requires exactly one processor named `fabricguard` and one binding; a source list alone is unsafe |
| `charts/fabric/charts/otel-collector/templates/configmap.yaml:21–100`; `deploy/compose/README.md:193–208` | Production deployment is one agent source per Node; host-monitor compose is local only |
| `contracts/coverage/v1/registry/capture-points-v1.json` `http.nonmodel.input = "wire"` | Must become `records` (R7; §7) |
| `telemetry-keys-v1.json` has no rows for `fabric.file.operation`, `fabric.file.path_hash`, `http.request.method`, `http.response.status_code` | They exist only in the legacy allowlist (`P/allowlist.go:111,120`); WP4-01 adds rows with `record` placement |

## 3. Binding to the P1 contract (050 rev 2)

P4 uses these 050 interfaces exactly. A mismatch found during the build is
fixed in 050 by its owner, never worked around in a P4 WP.

| # | Interface P4 uses | 050 |
|---|---|---|
| B1 | `RecordsInput.begin(kind, point, *, provenance="observed", parent_attempt=…) -> Attempt \| None`. It sets `fabric.capture.source=observed` and permits `content_provenance="protocol"` | §3.4 "Provenance" |
| B2 | `Attempt.emit(phase, …)` with phases `start`, `data`, `update`, `end` and three independent inputs `lifecycle`, `result_status`, `otlp_status` | §3.4, R4 |
| B3 | `RecordBody(role, data: bytes \| str, media_type, boundary, content_provenance, stream_id, chunk_index)`; `DescriptorOnlyBody`; `MAX_RECORD_BODIES = 8` including the evidence object; per-object cap `min(role cap, records_max_object_bytes)`; exact bytes or a descriptor, never a prefix | §3.4, §3.5 |
| B4 | One `record.evidence` object per record (`EvidenceDoc.build`, bounds checked before serialising) | §3.4a |
| B5 | `mode_of(role)` before any serialisation; `omit` means no body work | §3.4 |
| B6 | `v2(prefix, value)` and the one identity rule | §3.4, R8 |
| B7 | Rule A: the generated records key table; fabricguard's records class admits `capture.input=records` only | §3.4, §3.14 |
| B8 | One allocator per process; segment-attributed positions and losses; `queue_full` without waiting | §3.3, R3 |
| B9 | `manifest.capture_point_changed(point, state, reason)` and the generated per-build fields table | §3.8 |
| B10 | Fork hooks, registration, spawned-worker visibility (T2) | §3.2, §3.6 |
| B11 | Content validation before acknowledgement, including the evidence envelope; a 200 is acceptance, never durability | §3.14, R10 |
| B12 | Persisted uuid4 event ids on every record and marker | §3.4, §3.5, R2 |
| B13 | The records-only install (`install(patch_httpx=False, patch_aiohttp=False)`) | §3.1 |
| B14 | Fail-open APIs; `FABRIC_RECORDS_STRICT=1` raises in tests | §3.4, R9 |
| B15 | Projection: steps by attempt uid, bounded `event_ids`, registry-driven evidence decoding; channel rules register through 051 WP2-9a's hook in `_project.py` | §3.13, §3.4a item 6 |

Revision 1's assumptions are settled by these rows. Its proposed
"trusted observed-producer constructor" is B1. Its generic `fields`/`links`
bag is replaced by rule A attributes plus one evidence object. Its
200-then-drop fallback no longer applies (B11).

**Hook adapter** (`fabric/hooks/_producer.py`, WP4-00). It is a thin,
internal layer over B1–B6 that adds the enabled flag, the internal-I/O
guard and same-kind ownership. It never raises and never waits.

```python
class HookProducer:                                  # one per hooks handle
    def begin(self, point: HookPoint, kind: StepKind, *,
              parent_attempt: str | None = None) -> Attempt | None: ...
    def mode(self, role: str) -> PrivacyMode: ...    # RecordsInput.mode_of, cached
    def ident(self, prefix: str, value: str) -> str | None: ...   # RecordsInput.v2
    def evidence(self, type_id: str, item: Mapping[str, object], *,
                 continuation: tuple[int, bool] | None = None
                 ) -> EvidenceDoc | DescriptorOnlyBody: ...
    def guard(self) -> ContextManager[None]: ...    # Fabric-internal I/O guard
```

**Phases and status inputs.** Every channel maps its observations the
same way. A channel table in §5 lists only its exceptions.

| Observation | Phase | `lifecycle` | `result_status` | `otlp_status` |
|---|---|---|---|---|
| Operation launched, request written | `start` | `running` | — | `unset` |
| Consumed chunk, fetch, streamed message, intermediate partial output | `data` | `running` | — | `unset` |
| Content observed after the outcome (cumulative output, a late body piece) | `update` | — | — | `unset` |
| The monitored API returned | `end` | `completed` | `ok` | `unset` |
| The monitored API raised | `end` | `completed` | `error`; `timeout` for a qualified timeout class | `error` |
| The monitored API raised a cancellation | `end` | `cancelled` | `cancelled` | `unset` |
| The attempt was abandoned (closed handle, evicted correlation, shutdown) | none | — | — | — |

An attempt with no `end` record projects as result `unknown`. Fabric never
synthesises an `end` it did not observe. An application status inside a
successful call (an exit code, an HTTP 500, an MCP `isError` result) is a
field value, not `result_status=error`.

### 3.1 Delivery on the records input (R7)

- Every hook, including `http.nonmodel`, calls `begin(provenance="observed")`.
  Its records carry `fabric.capture.input=records` and
  `fabric.capture.source=observed`. No hook record carries
  `capture.input=wire`, `fabric.wire.exchange_id` or a marker
  discriminator. Model-traffic exchanges of the wire input are unchanged.
- Bytes observed at the API or transport boundary are `RecordBody` objects
  with `content_provenance="protocol"`. Text the API returned as `str` is
  passed as a `str` body; 050's worker encodes it (descriptor transformation
  `utf8_encode`), and the evidence object records `output_form: text`.
- Scalar metadata with a registry key travels as attributes (rule A).
  Structured metadata travels in the record's one evidence object (§3.2).
  CONTENT appears in neither.
- After allocation, any Fabric failure is a 050 loss for that position.
  Before allocation it is a counter in `hooks.status()`.
- Per-record body budget, with `original_plus_masked` review copies counted:

| Record | Bodies | Worst-case count (≤ 8) |
|---|---|---|
| exec start | `terminal.argv`, `terminal.context`, `terminal.stdin`, evidence | 7 |
| exec outcome | `terminal.stdout`, `terminal.stderr`, evidence | 5 |
| file audit | `artifact.locator`, evidence | 3 |
| db execute | `database.query`, `database.parameters`, evidence | 5 |
| db fetch | `database.rows`, evidence | 3 |
| http start / piece | `network.request` or one `network.response` piece, evidence | 3 |
| mcp message | one `mcp.*` role, evidence | 3 |
| ssh | `remote.request` or `remote.result`/`remote.stream`, evidence | 3 |

**Large streamed bodies.** 050's `RecordBody` holds one `bytes` or `str`.
A response the caller consumes in chunks is therefore emitted as ordered
**pieces** of at most 256 KiB. Each piece is a `data` (or, after the outcome,
`update`) record with `stream_id` = the attempt uid and `chunk_index` =
the piece index. Its evidence carries `continuation {index, final}`. The
hook joins a full window on the app thread; the cost is charged to the
per-chunk budget (§4.4). A body that fits one piece rides the `end` record.
Reconstruct reassembles the pieces in index order (representation
`split`). A missing piece, or no `final: true`, makes the body `partial`.
Pieces never claim the exact full result alone.

### 3.2 Evidence types registered by P4

P4 adds **evidence types**, never a carrier, spool property, input class or
Node component (050 §3.4a). WP4-01 registers all six in the
`evidence_types` block of `field-registry-v1.json`, with schemas under
`contracts/coverage/v1/evidence/`.

**Rules common to every P4 type.**
- Envelope `fabric.record-evidence/v1`, exactly **one item** per record,
  depth ≤ 2, strings ≤ 128 characters, every schema closed
  (`additionalProperties: false`).
- **Protection.** Role `record.evidence`, `default_policy: metadata`,
  allowed modes `retain_original`, `metadata_only` and `omit` (050 §3.4a
  item 3). No P4 type changes this. Under `omit` or `metadata_only` the
  fields a type carries are `not_captured(privacy_policy)`.
- **Values.** META (bounded ints, enums), LABEL (pattern-checked), and ids
  only as 050 `v2` output, clear-mode values under the identity rule
  (§4.2), or Fabric-minted ids. Never a path, argv element, SQL text, URL,
  host name, method name outside the enum, or message text.
- **Node admission** (050 §3.4a item 4): fabriccontent checks the envelope,
  canonical JSON and that `evidence_type` is in the generated list
  (`E/evidence_types_generated.go`). It does not check per-type schemas.
- **Verifier admission:** `reconstruct/_evidence.py` validates the type
  schema and that the record's capture point is in the type's registered
  `points`. A failure makes the type's fields `not_captured(parse_failed)`.
- **Fixtures** (WP4-01), per type: one valid document per enum branch;
  invalid documents for an extra key, an unknown enum value, a string over
  its bound, a CONTENT-shaped value (a path, an argv element, SQL) in a
  LABEL, and a wrong capture point; one records span plus evidence object
  with its expected record digest, added to `seal-digest-v1.json`.

| Evidence type | Capture points | Step kind | Fields it carries (pointer map) | Telemetry keys alongside | Content roles alongside |
|---|---|---|---|---|---|
| `fabric.exec.observation/v1` | `exec.subprocess`, `exec.audit` | `terminal` | N32 form (`/items/0/argv_form`); N33/N34 disposition and form (`/items/0/stdio`, `/items/0/output_form`, `/items/0/cumulative`, `/items/0/timeout_partial`) | `fabric.process.pid`, `.exit_code`, `.signal` (N35) | `terminal.argv`, `terminal.context`, `terminal.stdin`, `terminal.stdout`, `terminal.stderr` |
| `fabric.file.audit/v1` | `file.audit` | `file` | N49 (`/items/0/existence_before`, `/items/0/existence_after`); N46 path kind (`/items/0/path_kind`) | `fabric.file.operation`; `fabric.file.path_hash` only under digest permission (N45) | `artifact.locator` |
| `fabric.db.observation/v1` | `db.dbapi` | `database` | N39 parameter exposure (`/items/0/parameters_exposed`); N40 completeness (`/items/0/rows_partial`, `/items/0/rows_in_record`); D23 scope (`/items/0/savepoint_depth`) | `db.system.name`, `fabric.db.namespace_id` (N38); `fabric.db.rows_fetched`, `.rows_affected` (N41); `fabric.db.transaction_id` (N42); `fabric.side_effect.commit_state`, `.commit_basis` (D23, D24) | `database.query`, `database.parameters`, `database.rows` |
| `fabric.http.observation/v1` | `http.nonmodel` | `network` | N44 redirects and body completeness (`/items/0/redirect_index`, `/items/0/request_body`, `/items/0/response_body`); dialect selection for N26/N28 (`/items/0/dialect`) | `http.request.method`, `http.response.status_code`, `fabric.network.host_id` (N43) | `network.request`, `network.response`, `network.stream` |
| `fabric.mcp.correlation/v1` | `mcp.client` | `mcp_call` | N23 (`/items/0/session_ref`, `/items/0/rpc_ref`); correlation state (`/items/0/correlation`) | `fabric.mcp.method`, `.direction` (N22); `fabric.mcp.error_kind` (N25); C25–C28 keys as 051 defines | `mcp.request`, `mcp.response`, `mcp.notification`, `mcp.server` |
| `fabric.remote.observation/v1` | `remote.ssh_wrapper` | `remote_exec` | N36 verification basis (`/items/0/host_key_basis`); N37 exit status (`/items/0/exit_status`) | `fabric.remote.target_id`, `fabric.remote.host_key_verified` (N36) | `remote.request`, `remote.result`, `remote.stream` |

Closed item schemas (`?` marks optional properties):

```text
fabric.exec.observation/v1
  {api: enum[popen, run, communicate, wait, poll, check_output,
             asyncio_exec, asyncio_shell, asyncio_communicate, asyncio_wait, audit],
   audit_event?: enum[subprocess.Popen, os.system, os.exec, os.posix_spawn],  # api=audit only
   argv_form?: enum[argv, shell_string, not_exposed],
   stdio?: {stdin: D, stdout: D, stderr: D},
           # D = enum[pipe, inherit, devnull, stdout, fd, file_object, not_exposed]
   output_form?: enum[bytes, text, none],
   text_encoding?: LABEL ^[A-Za-z0-9_.-]{1,32}$,
   observation_index?: int 0..65535,
   cumulative?: bool, timeout_partial?: bool, pid_known: bool,
   duplicate_suppressed?: bool,
   error_class?: LABEL ^[A-Za-z_][A-Za-z0-9_.]{0,127}$}

fabric.file.audit/v1
  {audit_event: enum[open, os.rename, os.remove],
   operation: enum[open, rename, delete],
   mode?: LABEL ^[rwxabt+U]{1,5}$, flags?: int 0..2147483647,
   path_kind: P, target_path_kind?: P,
           # P = enum[str, bytes, fd, path_like_not_converted, not_exposed]
   dir_fd_present: bool,
   existence_before: enum[unknown], existence_after: enum[unknown]}

fabric.db.observation/v1
  {driver: enum[sqlite3, psycopg], variant: enum[sync, async],
   call: enum[connect, execute, executemany, fetchone, fetchmany, fetchall,
              iterate, commit, rollback, close, transaction_enter,
              transaction_exit, savepoint_enter, savepoint_exit],
   parameter_sets?: int 0..65535, parameters_exposed?: bool,
   fetch_index?: int 0..2147483647, rows_in_record?: int 0..65536,
   rows_partial?: bool, cells_unsupported?: int 0..1048576,
   codec?: enum["fabric.db-cells/v1"],
   autocommit?: enum[on, off, unknown], savepoint_depth?: int 0..64,
   pipeline_mode?: bool, error_class?: LABEL}

fabric.http.observation/v1
  {rule_index: int 0..255, scheme: enum[http, https], port: int 1..65535,
   redirect_index: int 0..32, redirect_of?: uuid4,           # previous hop's attempt uid
   request_body: B, response_body: B,
           # B = enum[complete, partial, early_close, unconsumed, not_retained, not_exposed]
   dialect: enum[none, jsonrpc2, qdrant_rest_v1],
   error_class?: LABEL}

fabric.mcp.correlation/v1
  {transport: enum[stdio, streamable_http],
   direction: enum[client_to_server, server_to_client],
   message_kind: enum[request, response, error, notification],
   session_ref?: ID mcps-, rpc_ref?: ID rpc-, related_rpc_ref?: ID rpc-,
   id_type?: enum[string, number],
   connection_index: int 0..65535,
   representation: enum[exact_bytes, library_serialised],
   correlation: enum[matched, unmatched, evicted, not_applicable]}

fabric.remote.observation/v1
  {library: enum[paramiko],
   call: enum[connect, run, exec_command, close],
   stream?: enum[stdin, stdout, stderr], observation_index?: int 0..65535,
   pty_requested?: bool,
   host_key_basis: enum[known_before_connect, added_during_connect, not_checked, unknown],
   exit_status?: int -1..255, exit_signal?: LABEL ^[A-Z0-9]{1,16}$,
   error_class?: LABEL}
```

An `ID` property matches `^(?:<prefix>-[0-9a-f]{32}|h-[0-9a-f]{40}|[A-Za-z0-9][A-Za-z0-9._:-]{0,127})$`.
The last two forms are admitted only when the source manifest declares
`identity_mode: clear` (§4.2); the verifier refuses them otherwise.

**Host sensors register no evidence type.** A host record carries only
scalar registry keys (§6.2.3). Host groups have no content ingress, so they
cannot deliver an evidence object. A future sensor that needs structured
evidence needs a content ingress for its group first.

**Tagged value codec** `fabric.db-cells/v1` (WP4-01 schema, used by
`database.parameters` and `database.rows`, media type `application/json`).
It is a content format, not an evidence type:
- a row is an array of cells; `database.rows` is `{"rows": [row, …]}`;
- a cell is `null`, `{"b": bool}`, `{"i": "<decimal>"}`, `{"f": "<float.hex()>"}`
  (finite only), `{"s": "<text>"}`, `{"x": "<base64>"}`, or `{"u": null}`
  for a value of any other type;
- spec-029 canonical JSON, no JSON numbers.

## 4. Hook infrastructure and configuration

Add `sdk/python/src/fabric/hooks/{__init__,_config,_producer,_patches,_audit,_guard}.py`
(WP4-00).
- Patch ownership is `(class or module, attribute, original, our wrapper)`.
  Install is idempotent. Uninstall restores only if the attribute still is
  our wrapper; another instrumentor's patch is never undone.
- Version checks happen at install, against the exact tested ranges in the
  qualification pins (§9).
- No optional driver import and no audit hook installation happens by
  default.

Public API (WP4-00 owns the spelling):

```python
hooks = fabric.hooks.install(
    exec=False, exec_audit=False, file_audit=False,
    db=(),                          # ("sqlite3", "psycopg"), each separately chosen
    http_hosts=(),                  # exact canonical hosts; no wildcard default
    mcp=False,
)
hooks.disable("exec.subprocess")    # audit callbacks stay installed but inert
hooks.status()                      # capability, budget and loss counters only
hooks.close(timeout_s=2.0)          # bounded explicit lifecycle call
```

Equivalent environment switches: `FABRIC_WIRE_EXEC=1`,
`FABRIC_WIRE_EXEC_AUDIT=1`, `FABRIC_WIRE_FILE_AUDIT=1`,
`FABRIC_WIRE_DB_DRIVERS=sqlite3,psycopg`, `FABRIC_WIRE_HTTP_HOSTS` (a JSON
array) and `FABRIC_WIRE_MCP=1`. Absent means disabled. The SSH wrapper has
no switch: the application calls it.

**Activation and configuration errors.**
- Hooks need an installed capture handle (wire install or the records-only
  install, B13). Without one, nothing is patched and `status()` reports
  `no_capture_handle`. Hooks never install the wire tee themselves.
- An explicit `fabric.hooks.install(...)` with contradictory or malformed
  arguments raises `ValueError`. That is configuration, as for 050's
  `install()` (049 §7.3), not a recorder call.
- Environment activation never raises: malformed or contradictory
  environment values leave every hook disabled, `status()` reports
  `invalid_configuration`, and one class-only warning is logged.
- An unavailable or unsupported driver yields a disabled capability with
  reason `unsupported_runtime` or `unsupported_version`, published through
  `manifest.capture_point_changed` (B9). Never an action-time error.

TypeScript exposes the same capability concepts on its own track (spec
055). Python patches are not ported mechanically. The TypeScript manifest
stays `unsupported` for these points until its own goldens, BigInt counters
and passivity gates pass. No Python gate depends on a TypeScript WP.

### 4.1 Callback discipline (R9)

1. **Cheap exits first.** Every callback checks, in order: the enabled
   flag; the fixed event-name set (audit); the Fabric internal-I/O guard;
   same-kind explicit ownership (§4.3). The guard covers the worker,
   sender, resolver, redaction client, spool and logging paths. Guards are
   execution-local with a thread-local audit fallback, reset after fork.
   Unrelated application activity is never suppressed.
2. **No application code.** Inspect only exact primitive types
   (`type(x) is str`, never `isinstance`). Never call `str`, `repr`,
   `format`, `__fspath__`, `__index__`, `__len__` of a non-builtin,
   iterators, getters, serialisers, row factories, adapters or user
   converters. Unsupported values become `not_exposed` or `{"u": null}`. No
   secret-bearing object is retained for later inspection.
3. **Bound work before serialising.** Check element counts, lengths and
   depth on the exact types **before** building any JSON or bytes. Over a
   bound, pass `DescriptorOnlyBody(reason="payload_too_large")`; never
   serialise and then discard. `mode_of(role) == "omit"` means no work.
4. **Errors are class names.** Automatic error capture is the exception
   class's `__qualname__` read from the type object, bounded to 128
   characters, into `error_class`. Never `str(exc)`, `exc.args`, traceback
   text or `__cause__` traversal.
5. **Fail open.** Wrappers, callbacks, `status()`, `disable()` and `close()`
   never raise into the application. `FABRIC_RECORDS_STRICT=1` raises only
   for Fabric-internal misuse in tests, never around the monitored call.
6. **Monitored code runs outside Fabric handlers.** Invoke the original
   once. Catch its `BaseException` only to attach a safe outcome, then
   bare-`raise` the same object. Fabric-only sections catch
   `BaseException`, including cancellation or `MemoryError` injected into a
   callback. Cancellation around the monitored await is never caught.
7. **An unrepresentable value never erases** an otherwise safe lifecycle
   record.

### 4.2 Identity (R8)

One rule, the same as 050 §3.4 and specs 051, 052, 054 and 055:

| Mode | P4 behaviour |
|---|---|
| Pseudonymous (default) | Every caller-derived id is mapped by `v2` with its type prefix, whatever its shape: hosts and peers `hst-`, sandboxes `sbx-`, database namespaces `dbn-`, MCP sessions `mcps-`, JSON-RPC ids `rpc-`. A string that already looks emitted is mapped like any other. Without a key the id is omitted and its field is `not_captured(missing_id_key)`. |
| Clear (explicit opt-in, owner decision 7) | Ids are emitted as given when they match the opaque-id pattern, else in the `h-` form of `encode_opaque_id` (as 050's `run()`). The manifest declares `identity_mode: clear`; a pseudonymous Node rejects them (049 §2.9 rule 7). |

- Fabric-minted values pass through unmapped as `EmittedId`s: attempt
  uids, local transaction labels (`txn-` + 32 CSPRNG hex), connection
  indexes.
- The JSON-RPC id's mapping input is the spec-029 canonical JSON of the
  tuple `[clear_session_id or "", direction_of_request, id_type, clear_id]`,
  so `"1"` and `1`, different sessions and reverse requests never alias.
  The encoding is part of the WP4-01 golden.
- Same clear ids and the same key correlate across processes and hosts.
  Different keys or tenants do not.

Revision 1 required mapping even in clear mode. That conflicted with
owner decision 7 and is withdrawn.

### 4.3 D2 and D3

- **D2 (explicit wins, same kind).** An explicit producer that already
  records an operation (`explicit.subprocess_artifact`,
  `explicit.byte_boundary`, `explicit.final_http`) opens its
  `ExplicitScope` with the step kinds it covers (`kinds`, added to
  `_capture_scope.py` by WP4-00). A hook of the same kind records nothing
  inside that scope; the projection reports the hook's fields
  `not_captured(deferred_to_explicit)`. A withheld explicit scope is
  sticky: the hook never falls back to recording the bytes.
- **Ownership between hooks.** The MCP hook sets an execution-local owner
  marker around its own httpx calls; the `http.nonmodel` route skips them
  (§5.4). One request is never recorded by two channels.
- **D3.** Hooks emit only through the records input (B1). They never use a
  global tracer, and a refused protected provider is a loss, never an
  unprotected export.

### 4.4 Independent latency and behaviour gates

Use the calibration, paired rounds and bounded scale of
`sdk/python/tests/test_wire_passivity.py:10–36,60–76,297–372` and 050's
shared passivity harness (`sdk/python/tests/passivity/`, 050 §3.15 item 7).
- Budgets are median added latency before scaling, measured with retention
  on and off. They include snapshot, `Attempt.emit` and admission work.
- Each channel has its OWN test module and a blocking-injection negative
  control: twice its scaled budget must fail.
- A slow redaction service or a stopped sender cannot change the action
  budget.

| Gate | Matched unit budget | Inactive / nonmatching budget |
|---|---|---|
| P4-EXEC | 50 µs per start or outcome; 2 µs per returned immutable chunk ≤ 4 KiB | 5 µs |
| P4-AUDIT | 20 µs per admitted bounded exec event | 2 µs per unrelated audit event |
| P4-FILE | 20 µs per admitted file event | 2 µs per unrelated audit event |
| P4-DB (sqlite3, psycopg sync, psycopg async separately) | 50 µs per execute or transaction call; 20 µs per fetch of ≤ 64 primitive cells | 5 µs |
| P4-HTTP | 50 µs per exchange; 2 µs per chunk, including the amortised 256 KiB piece join | 5 µs |
| P4-MCP (stdio and Streamable HTTP separately) | 20 µs per message ≤ 4 KiB; 2 µs per forwarding-only chunk | 5 µs |
| P4-SSH | 50 µs per lifecycle call; 2 µs per channel chunk | 5 µs |
| P4-UI-R | P2 reporting budget, tightened to 50 µs per bounded report | 5 µs |

Large values: never loop over an unbounded object on the hot path. Cell
inspection is capped per callback (§5.3); byte streams use pieces (§3.1);
mutable buffers are bounded snapshots within the same budget, or withheld.
Immutable `bytes` transfer by reference.

Tests cover identity and order, the same exception object, cancellation,
full queue, failed worker, fork and spawn, recursion, repeated install and
disable, and other instrumentors. Audit tests run in fresh interpreters,
include a host hook that refuses `sys.addaudithook`, and verify the Fabric
hook never raises. A host may refuse installation silently, so the
capability is `enabled` only after a private sentinel audit event is seen.

## 5. Channel designs and PROTECT mapping

### 5.1 Subprocess and exec audit

`hooks/_exec.py` observes `Popen` construction, `communicate`, `wait`,
`poll` results and the qualified asyncio subprocess equivalents.
- Start state is held in bounded weak associations. Fabric never waits or
  polls.
- `run` and `check_output` use the same Popen observer: duplicate wrapper
  records are suppressed, output is not.
- The attempt uid is minted before the call. A spawn failure emits an
  `end` with `result_status=error` and `pid_known: false`; no pid is
  invented.

**Arguments (N32).** `terminal.argv` is JSON
`{"form": "argv", "args": [cell…]}` or `{"form": "shell", "command": cell}`,
where a cell is `{"t":"str","v":…}`, `{"t":"b64","v":…}` or
`{"t":"not_exposed"}` (a path-like object is never converted). Before
encoding, the hook checks at most 1024 elements and 64 KiB of characters
(× 4 for the UTF-8 bound); over either bound the body is
`DescriptorOnlyBody(payload_too_large)`. `terminal.context` is
`{executable?, cwd?, shell, env_names?}`; names come only from an
explicitly passed exact `dict` with exact `str` keys (at most 256), and
`os.environ` is never enumerated.

**Input and output (N33, N34).**
- N33 records only `communicate(input=...)`, under the explicitly enabled
  `terminal.stdin` role (default `off`).
- N34 records the exact values `communicate`/`run` returned, including the
  partial output of an exposed `TimeoutExpired` (`data` record,
  `timeout_partial: true`). The caller's pipes are never teed and
  `PIPE`/`STDOUT` flags never change.
- Text output is a `str` body with `output_form: text` and the caller's
  encoding in `text_encoding`. It is never claimed to be the original pipe
  bytes.
- A repeated `communicate` after a timeout may return cumulative output.
  Each observation is kept with its `observation_index`; a later one is
  marked `cumulative: true` and is not counted as new bytes.
- Direct pipe reads, inherited output, PTYs and detached descendants give
  `not_captured(not_exposed)` (stdio dispositions in evidence). No
  finalizer waits for a child.

**Outcome (N35).** `fabric.process.pid`, `.exit_code`, `.signal`. A
negative POSIX `returncode` is a positive signal, never a fabricated exit
code. Unknown and zero stay distinct. A nonzero exit is a field value with
`result_status=ok`. `TimeoutExpired` gives `timeout`; the attempt stays
open until a later observed outcome, else projects `unknown`.

**Exec audit.** WP4-00's `hooks/_audit.py` registers one irremovable
callback shared by the independently enabled exec and file handlers.
WP4-02's handler (`hooks/_exec_audit.py`) admits `subprocess.Popen`,
`os.system`, `os.exec` and `os.posix_spawn` as qualified interpreters emit
them; the event names and positional signatures are pinned in fixtures,
never matched speculatively.
- Each event is one `start` record, lifecycle `running`, with no `end`: the
  event precedes execution. Successful exec replacement has no Python
  outcome; its absence is a declared limit.
- When an `exec.subprocess` wrapper already owns the operation, the audit
  record is suppressed through `_audit.py`'s suppression token
  (`duplicate_suppressed` is counted in `status()`). Unmatched exec-family
  events still record attempts.

### 5.2 File audit and explicit artifacts

WP4-03's `hooks/_file.py` handles `open`, `os.rename` and `os.remove` from
the shared callback.
- N45 operation is `open`, `rename` or `delete` (`fabric.file.operation`).
  Mode and flags go to evidence. `artifact.locator` is
  `{"path": cell, "target_path"?: cell}` with the tagged cells of §5.1.
- A file descriptor is a number (`path_kind: fd`), not a resolved path.
  Path conversion, symlink resolution, `stat`, reads, watches and scans
  never happen. A path-like object is `path_like_not_converted` with no
  locator path.
- Telemetry never carries a path. `fabric.file.path_hash` is the existing
  SHA-256 DIGEST field, emitted only when the capture policy explicitly
  permits that digest; it is not anonymisation, and protective modes do not
  export it as a fallback. No new `_id` semantics are given to it.
- N49 before and after are both `unknown`: a pre-operation audit event
  cannot establish existence, creation or deletion.
- **No byte ranges.** N45's `byte_range` part has no P4 producer: the audit
  events carry no ranges and no P2 API reports them (`record_file_access`
  has no range argument). It projects `unsupported(unsupported_api)`. See
  §9 O4-11 and the coding-agent delta in §10.
- N47 is only bytes supplied through explicit producers. Offline N48 uses
  stored complete before/after objects, `diff_algorithm` with a pinned
  version and `derived_from` links. Files are never reread. The diff's
  protection is never weaker than either input. A truncated or partial
  input cannot establish a full diff.

### 5.3 Database

`hooks/db/{_common,sqlite3,psycopg}.py` own driver interception. They
observe `execute`/`executemany`, `fetchone`/`fetchmany`/`fetchall`, cursor
iteration the caller performs, connection convenience methods,
`commit`/`rollback`, transaction contexts and `close`.
- Each execution is an attempt. Fetch observations are `data` records of
  that attempt.
- `executemany` never consumes a parameter iterator ahead of the driver: an
  exact `list` or `tuple` is captured within the bound, anything else is
  `parameters_exposed: false`.
- No extra query, fetch, `EXPLAIN`, transaction-id query or adapter call.

**SQLite construction boundary.** CPython's sqlite3 `Connection` and
`Cursor` methods are native and cannot be patched as Python methods.
- WP4-04a adds `fabric.hooks.db.sqlite3.ObservedConnection` and
  `ObservedCursor` subclasses. The application selects them with
  `sqlite3.connect(..., factory=ObservedConnection)`.
- The original caller-requested factory and `row_factory` run once. The
  hook does not replace another factory, connection or cursor.
- Plain native connections, preexisting connections and unqualified
  custom factories stay uninstrumented and are declared so.
- No mutation of C type dictionaries, no global trace callback, no proxy
  substituting returned values. This qualification limit needs the 049
  delta in §10.

**psycopg 3.** WP4-04b wraps the qualified Python-level sync and async
methods of `psycopg` 3 (`psycopg2` is unsupported). It returns the original
connection, cursor and result objects and preserves row factories,
adapters, transaction nesting, savepoints, autocommit, pipeline mode and
cancellation. Unsupported pipeline or version paths stay manifest gaps.
Native types are never monkey-patched.

| Datum | Carrier and protection |
|---|---|
| Engine | N38 `db.system.name`: fixed `sqlite` or `postgresql` |
| Namespace | N38 `fabric.db.namespace_id`: `dbn-` v2 of a configured or exposed clear namespace; DSNs are never parsed |
| Statement, parameters | N39 `database.query` / `database.parameters`: CONTENT, including literals, user names and table names |
| Rows | N40 `database.rows` in `fabric.db-cells/v1`; caller-fetched values only |
| Counts | N41 `fabric.db.rows_fetched`, `.rows_affected`; driver unknown = −1; a partial count is marked partial |
| Transaction | N42 `fabric.db.transaction_id`: a Fabric-minted `txn-` label per connection transaction; never a server id claim |
| Commit | D23 `fabric.side_effect.commit_state`, D24 `fabric.side_effect.commit_basis=client_observed` |

**Cell bound.** 050's `RecordBody` carries `bytes` or `str`, so cells are
encoded on the app thread.
- Before encoding, the hook checks that rows and parameters are exact
  `tuple`/`list`/`dict` containers of exact primitive cells, at most
  `db_cells_per_fetch` cells per callback (default 64, configurable up to
  4096; the manifest declares the value and the measured budget).
- Beyond the bound the remaining rows are not encoded: `rows_partial: true`,
  `rows_in_record` = rows encoded, and N40 is `partial`.
- A row of any other type (for example `sqlite3.Row`, a namedtuple or a
  user class) is `{"u": null}` per cell, counted in `cells_unsupported`.
- Rows are caller-decoded values, not database protocol bytes. The driver
  ledger proves value equality and the exact serialised form under this
  codec.

**Commit semantics.**
- A successful `commit`/`rollback` call gives `committed`/`rolled_back`
  with `client_observed`. It is not durable service proof.
- Statement success alone keeps `unknown`. An exception or timeout after a
  possible commit stays `unknown`. Autocommit success is not promoted
  without qualified driver evidence.
- A savepoint rollback describes that scope only (`savepoint_depth`).
- SQL text is never parsed to assert a business effect. Console access,
  existing uninstrumented connections and unfetched rows stay uncaptured.

### 5.4 Allowlisted non-model HTTP

`wire/_routes.py` (WP4-00; integration owner) routes every httpx transport
request in this order:
1. internal Fabric I/O: excluded;
2. same-kind explicit ownership (§4.3) and the MCP owner marker: excluded
   from this route;
3. qualified model dialect: the wire input, unchanged;
4. explicit non-model host rule: `http.nonmodel` on the records input;
5. no match: nothing recorded.

Model routing stays available without the HTTP hook. WP4-05 adds its rule
through WP4-00's `register_route` interface. 054 WP5-00a is the next owner
of `wire/_routes.py` after WP4-00 merges (054 §8.2).

- Hosts are normalised at install (IDNA, lower case, port and scheme
  restrictions). Hosts are never substring-matched.
- Redirect targets are matched independently. httpx follows redirects
  through the transport, so each hop is its own attempt, linked by
  `redirect_of`. An unallowlisted redirect target is not recorded because
  the source host was allowed. Fabric follows no redirect itself.
- Fabric's own Node, redaction and export endpoints are excluded.

**Carriers.**
- N43: `http.request.method` (closed enum), `http.response.status_code`
  (numeric), host as `fabric.network.host_id` (`hst-`).
- N44: target, path, query and bodies are CONTENT in `network.request`,
  `network.response` and `network.stream`, all **off by default**. Policy
  must name a retaining network role.
- The protected request JSON holds method, target and a body locator.
  Raw request and response headers are never recorded.
- The request tee forwards chunks unchanged. Response bytes are emitted as
  pieces (§3.1). Early close is `partial`, not EOF.

**Dialects (frozen, §9 O4-4).** Offline parsers in `reconstruct/dialects/`:
- `jsonrpc2`: JSON-RPC 2.0 request, result, error and notification
  structure only. It supplies no N26/N28.
- `qdrant_rest_v1`: Qdrant's REST `POST /collections/{name}/points/query`
  and `POST /collections/{name}/points/search`. N26 points into the stored
  request (`query` or `vector`, `filter`, `limit`). N28 maps
  `result.points[]` (query) or `result[]` (search) to the P2
  `fabric.retrieval-results/v1` rows `{doc_id: id, version, score, rank}`.
  `payload` is never mapped into `title` or `excerpt`. Batch endpoints,
  upserts and deletes are plain `network` steps, never N30 memory writes.
- Parsed views point into the stored bytes and inherit their protection.
  Without retained bytes N26/N28 are `not_captured` with the role's reason.
  No N27 claim until its field and capture-point rows change together.

### 5.5 MCP transport

`hooks/_mcp.py` (WP4-06a) patches the qualified `mcp` Python SDK's client
transport serialisation and parse boundaries, not agent frameworks.
- stdio: the bytes the writer sends and the lines the reader already
  parses.
- Streamable HTTP: the serialised JSON-RPC body the client posts and the
  POST or SSE message payloads the transport already demultiplexes. The
  hook sets the MCP owner marker around its httpx calls (§4.3).
- No second pipe or SSE consumer, no polling, no extra `initialize` or
  inventory calls. Where the library exposes only objects, the hook records
  a string the library already serialised (`representation:
  library_serialised`), or `not_exposed`; it never serialises itself.
- The hook symbols and SDK version are pinned before either transport is
  enabled. Legacy SSE transport is unsupported.

**Attempts.** One `mcp_call` attempt per JSON-RPC request:
- the request is the `start` record; progress and cancel notifications for
  it are `data` records (`related_rpc_ref`); the response or error is the
  `end` record;
- direction is kept independently of request/response, so server-initiated
  requests are their own attempts;
- a notification without an id is its own attempt with one `end` record;
  an absent id is never numeric zero;
- the correlation map is bounded (4096 entries per session, within the
  global byte cap); an evicted request stays without `end`
  (`correlation: evicted` on a late response, which starts its own attempt).

Roles: `mcp.request`, `mcp.response`, `mcp.notification` (server requests
use the notification role as its registry row permits), and `mcp.server`
for initialisation server info. C25 server name is an operator-label
pseudonym by default; C26 version and C27 date are validated; C28 is the
transport enum. An unknown method maps to `other`; the original method
appears only in protected bytes. Reconnect increments `connection_index`;
continuity across reconnects comes only from an exposed clear session id
or an explicit report.

N25 protocol errors are distinct from tool `isError` results. Resources,
prompts, sampling, elicitation and roots are content observations only;
Fabric never answers or authorises them. Session cookies, HTTP headers,
environment values and credentials never enter telemetry or logs.

### 5.6 SSH and browser/computer-use reporting

**SSH (frozen client, §9 O4-5).** `fabric.hooks.ssh` (WP4-06b) is an
explicit wrapper over a caller-constructed `paramiko.SSHClient`. There is
no process-wide interception of ssh or scp.

```python
ssh = fabric.hooks.ssh.observe(client)          # the caller's SSHClient
result = ssh.run("cmd", input=None, timeout=None)  # reads what the caller asked for
stdin, stdout, stderr = ssh.exec_command("cmd")    # paramiko's own objects, unchanged
```

- `run` returns `RemoteResult(stdout: bytes, stderr: bytes, exit_status)`.
  It reads the channel to completion because the caller asked it to; the
  bytes are N37 `remote.result`/`remote.stream`.
- `exec_command` passes through paramiko's objects unchanged and records
  only the request; output and exit status are `not_captured(not_exposed)`.
- N36 target is `hst-`. `host_key_verified` is computed from in-memory
  state without I/O: the host had a key in the client's loaded host keys
  before `connect` and it equals the server key after `connect`
  (`known_before_connect` → true); a key added during `connect` by the
  missing-host-key policy is false; anything else is unknown. The wrapper
  never installs or changes a host-key policy.
- No extra channel reader, PTY allocation, forwarding configuration or
  remote-side guarantee.

**Browser and computer use (P4-UI-R).** Handoff tests use P2's
`record_ui_action` and existing-snapshot reporting through `sdk.records`.
- Executed action N54 (`computer.action`) and N55 (`computer.snapshot`)
  stay **reported**, with origin application. Provider request N53 stays a
  provider assertion.
- They connect through explicit attempt and causal ids; "requested" never
  means "executed".
- Typed text, DOM, selectors, coordinates and URLs are protected CONTENT.
  Fabric never fetches DOM, screenshots, the accessibility tree, URLs or
  browser state. A click is not proof of a business effect. P5 owns
  observed automation.

## 6. Production host ingress and multi-source Node binding

### 6.1 Binding design: static dedicated ingress groups (R11)

A Node serves a **finite configured set of single-source ingress groups**.
Each group binds exactly
`(tenant_id, source_id, kind, credential, telemetry endpoint(s), content endpoint?)`,
where `kind` is `agent`, `host.auditd` or `host.ebpf`. Identity is fixed by
the authenticated ingress the batch arrived on, never by a source claimed
in the payload.

**Why one listener per group.** Stock `bearertokenauth` authenticates
possession but returns no identity in `client.Info.Auth`
(`gate/gate.go:72–75`). A per-group receiver with its own
`bearertokenauth/<group>` instance is the only stock-component way to tie a
credential to one source. It is the proven P0-A shape, repeated.

**Helm values** (`receiver.sourceBindings[]`, WP4-09):

| Property | Rule |
|---|---|
| `name` | `^[a-z][a-z0-9-]{0,31}$`, unique |
| `tenantId` | the bound tenant string |
| `sourceId` | the emitted source id (`s-` + 32 hex), unique within the tenant |
| `kind` | `agent`, `host.auditd` or `host.ebpf` |
| `tokenSecret` | `{name, key}`; the credential bytes differ from every other group's |
| `protocols` | `{grpc?: port, http?: port}`, at least one; ports unique per listener address |
| `content` | `{port}`; `agent` only, optional |

- At most **64 groups** by default; an explicit ceiling of **256**. Each
  group uses one to three listeners, so 64 groups need at most 192.
- No on-demand registration service and no fleet-management API.
- The legacy single-binding values compile to one `agent` group. Mixing the
  old and new forms fails the render.

Rendered components for group B (illustrative names; TLS, timeouts and body
caps stay mandatory):

```yaml
receivers:
  otlp/B:                                   # telemetry ingress of group B only
    protocols:
      grpc: {endpoint: 0.0.0.0:<B-grpc-port>, auth: {authenticator: bearertokenauth/B}}
  otlp/content-B:                           # agent groups with content only
    protocols:
      http: {endpoint: 0.0.0.0:<B-content-port>, auth: {authenticator: bearertokenauth/B}}
processors:
  fabricguard/B:
    profile: production
    source_kind: agent                      # or host.auditd / host.ebpf (§6.2.7)
    evidence_source_binding: {tenant_id: <tenant>, source_id: <source>}
exporters:
  fabriccontent/B:                          # agent groups with content only
    source_binding: {tenant_id: <tenant>, source_id: <source>}
service:
  pipelines:
    traces/B: {receivers: [otlp/B], processors: [memory_limiter, fabricguard/B], exporters: [<approved>]}
    logs/content-B: {receivers: [otlp/content-B], processors: [memory_limiter], exporters: [fabriccontent/B]}
```

**Gate rules for every group** (WP4-08a, `gate/gate.go`). The gate validates
the whole merged pipeline graph:
1. Each group has exactly one `bearertokenauth/<group>` instance, used only
   by that group's receivers.
2. No receiver, `fabricguard` instance or `fabriccontent` exporter is wired
   into another group's pipeline. No unbound alternate receiver exists in
   a production pipeline.
3. No processor after `fabricguard/<group>` mutates spans.
4. `fabricguard/<group>` and every `fabriccontent/<group>` carry the same
   `(tenant_id, source_id)` as the group; `allowed_tenants` is exactly that
   tenant.
5. Resolved credential bytes are compared at startup without logging them
   or their digests. Different paths holding identical secrets fail.
6. Every credential file is watched with the current rotation semantics.
   A cross-group identity or credential swap fails; there is no fallback to
   a default binding.
7. Duplicate keys are refused, and source identity is checked in every
   container (049 §7.9 "Repeated keys").
8. TLS (or the existing loopback exception), no-redirect egress, tenant
   constraints and the encrypted content queue stay required.
9. Several groups may share approved telemetry exporters after guard
   stamping. Content exporters keep separate binding and queue instances,
   even when they target the same customer store.
10. Host-group rules of §6.2.6 apply in addition.

**DaemonSet Nodes.** A Node serves the configured set of workload sources
of its node; epochs change freely within each source. Python per-process
sources derive their `s-` ids from configured clear labels and shared keys.
A source not in the static set cannot use a wildcard binding. Dynamic
source onboarding is outside P4: regenerate the customer configuration or
deploy separate Nodes. Bound ingress authenticates the source credential,
not an individual process or the truth of its reports.

**Later option, not built in P4: a custom credential-to-source
authenticator.** A small collector authenticator extension could map each
credential to `(tenant, source)` in `client.Info.Auth`, so one listener and
one `fabricguard` instance serve many sources, with identity still fixed by
the credential. It would remove the listener multiplication. It needs its
own spec, the same forged-identity and swap tests (§9), and a gate change.
P4 ships the static groups; nothing in P4 depends on the extension.

### 6.2 Host-sensor production ingress

#### 6.2.1 Principles

- A host sensor is a **separate source**: its own source id, epochs,
  positions, encrypted state and ingress group. It never shares the agent
  spool, allocator or credential.
- Host records are **records-class spans** on the records input, with
  provenance `observed` and a capture point of kind `S`. They reuse 050's
  records class, sequence integrity, manifests, heartbeats, losses and
  event ids. They are not a log variant and not a third input class (R7).
- Host sources have **no runs**: no `fabric.run.*` keys, no segments, no
  seals. Integrity is sequence continuity per `(source, epoch)`, the
  manifest chain and heartbeats, as for any 050 position outside a run.
- Host records are corroboration only. They never become agent steps,
  never fill an agent field and never upgrade another record's provenance.
- The local profile keeps today's audit-class log records unchanged. The
  production mode below is a separate, explicitly configured mode.

#### 6.2.2 Sources and epochs

Each sensor process (one auditd receiver instance, or one eBPF emitter)
owns one source.
- **Source id.** `s-` + 32 hex = 050's label pseudonym
  (`_sequence.label_pseudonym("s-", label, key)`, vector
  `run-id-pseudonym-v1.json`) of a configured clear source label with the
  configured id key. Production mode refuses to start without a label and a
  key. auditd and eBPF on one host use different labels (the chart default
  is `<node>/auditd` and `<node>/ebpf`), different state directories and
  different credentials; configuration validation refuses equal labels or
  state directories.
- **Epoch.** A nonzero 63-bit CSPRNG value drawn at every process start.
  It is stored in the encrypted state file `epoch.state` with
  `next_sequence` and a `final` flag.
- **Prior epochs.** At start, if the previous epoch's state lacks
  `final = true`, the sensor first sends a periodic heartbeat for that
  epoch at its last allocated sequence, then lists it in manifest 0's
  `unsealed_prior_epochs` (049 §2.12 rule 5, as 050 §3.2 rule 5).
- **Positions.** A position is allocated when one translated event is
  admitted to the encrypted staging batch (one fsync per batch). Every
  allocated position becomes a record or a counted loss. Events that were
  never translated never get a position (§6.2.4).
- **Event ids.** `fabric.event_id` and `fabric.attempt.uid` are uuid4 values
  minted at staging and persisted in the staged batch. A replay after a
  restart sends the same `(epoch, sequence, event_id)`; it never mints new
  ids and never reallocates positions.

#### 6.2.3 Host record schema

Span name `fabric.sensor_event` (a new branch of fabricguard's category
function, pinned in `span-category-v1.json`). Start time = end time = the
event's timestamp converted to wall-clock nanoseconds. Status `unset`.
There are no bodies, no evidence object and no `fabric.content.object_ids`.

| Key | Req. | Check | Notes |
|---|---|---|---|
| `fabric.tenant_id` | R | equals the group tenant | |
| `fabric.source_id` | R | `^s-[0-9a-f]{32}$`, equals the group source | |
| `fabric.source.epoch` | R | int 1..2^63−1 | |
| `fabric.source.sequence` | R | int ≥ 0 | |
| `fabric.event_id` | R | uuid4 | persisted (§6.2.2) |
| `fabric.attempt.uid` | R | uuid4 | one attempt per event, persisted |
| `fabric.capture.input` | R | `records` | |
| `fabric.capture.source` | R | `observed` | |
| `fabric.capture.point` | R | `host.auditd@<ver>` or `host.ebpf@<ver>`, equal to the group kind | |
| `fabric.sensor.event_class` | R | enum `exec`, `connect`, `file` | today's `syscallClass` |
| `fabric.sensor.syscall` | R | enum `execve`, `execveat`, `connect`, `accept`, `bind`, `socket`, `openat`, `open` | |
| `fabric.sensor.result` | R | enum `success`, `failed`, `unknown` | |
| `fabric.sensor.errno` | O | enum of `errno.go` names plus `other` | only when `failed` |
| `fabric.sensor.pid` | R | int ≥ 1 | |
| `fabric.sensor.ppid` | O | int ≥ 0 | |
| `fabric.sensor.pid_ns` | O | `^[0-9]{1,20}$` (uint64 decimal) | when the sensor supplies it |
| `fabric.sensor.process_start_ns` | O | int ≥ 0, boot-relative | eBPF only |
| `fabric.sensor.boot_time_s` | O | int ≥ 0 | computed once at start from `CLOCK_REALTIME − CLOCK_BOOTTIME`; no file reads |
| `fabric.sensor.cgroup_id` | O | `^[0-9]{1,20}$` | |
| `fabric.sensor.audit_serial` | O | `^[0-9]{1,20}$` | auditd only; unsigned decimal |
| `fabric.sensor.incomplete` | O | enum `path`, `args`, `path_and_args` | |
| `fabric.sensor.peer_family` | O | enum `ipv4`, `ipv6`, `unix`, `other` | `connect` only |
| `fabric.network.host_id` | O | `hst-` v2 of the canonical peer address text | omitted without a key |
| `fabric.sensor.peer_port` | O | int 0..65535 | |
| `fabric.execution.host_id` | O | `hst-` v2 of the configured host label (C41) | |
| `fabric.execution.sandbox_id` | O | `sbx-` v2 of a configured sandbox label (C41) | |
| `fabric.execution.image_digest` | O | DIGEST, from trusted configuration only (C41) | the filesystem is never inspected |
| `fabric.sensor.exe_sha256`, `.argv_sha256`, `.path_sha256` | O | `^sha256:[0-9a-f]{64}$` | only under an explicit digest permission (§6.2.5) |

Host source **markers**, built by the shared library with 050's shapes:
- `fabric.capture_manifest` (marker kind `manifest`): capture-manifest-v1
  with one capture-point row, `inputs: ["records"]`, `source_auth: bound`,
  the enabled syscall classes and digest policy in that row's state, and
  `uncaptured_classes` for disabled classes. No schema change.
- periodic heartbeat, loss and `final` markers, each with a persisted uuid4
  `fabric.event_id` (R2). Loss reasons come from the existing capture/v1
  loss enum, with no schema change: `disk_full`, `internal_error`,
  `span_dropped` (a host record the Node refused, §6.2.9) and `shutdown`.
  `destination_rejected` is not a loss reason: 049 defines it as a refusal
  of a *content* record and 050 (delta 6, OD-1) removed it as a loss; a host
  record is a telemetry record, which `span_dropped` ("the telemetry record
  was refused") covers. A protection failure withholds the field
  (`not_captured(protection_failed)`), as in 050, and is not a position
  loss. Loss markers carry no `segment_id`.
- no `run_start`, `run_end` or `segment_seal`.

All `fabric.sensor.*` keys are new registry rows (WP4-01) with placement
`record` (or `heartbeat`, §6.2.4) and the new key column
`capture_point_kinds: ["S"]`: they are admitted only on records whose
capture point has kind `S`.

#### 6.2.4 Upstream loss is not position loss

Kernel or netlink events lost before translation never had a position, so
they cannot be sequence gaps. They are reported on the next periodic
heartbeat:
- `fabric.sensor.upstream_lost`: int ≥ −1 (−1 = unknown count);
- `fabric.sensor.upstream_loss_reason`: enum `ring_buffer_full`,
  `socket_overflow`, `assembly_evicted`, `rate_limited`, `backlog_limit`,
  `source_rotation_gap`, `source_truncated`, `source_missing`, `restart`,
  `unknown`.

The verifier reports a sensor window with a nonzero or unknown upstream
loss as `partial` for corroboration, and an unknown count stays unknown,
never zero. Netlink events in kernel buffers at a crash are an unknown
upstream loss (`restart`, −1) on the next epoch's first heartbeat.

#### 6.2.5 Protection and local state

- Production defaults drop `process.owner`, the executable name (`comm`)
  and the raw peer address. Executable, argv and path digests are emitted
  only when the sensor's policy sets `digests: permitted` **and** the
  group's `fabricguard` instance sets `host_digests: permitted`. They are
  low-entropy hashes, not anonymisation.
- No raw command, path or content enters the production host stream.
- Every host, user, cgroup or source-derived label is keyed or omitted;
  hashes are never used as ids.
- Staging batches, the spool, the cursor checkpoint and `epoch.state` are
  encrypted with the AES-256-GCM envelope of the collector's
  `fabricenvelope` extension (magic, 12-byte nonce, ciphertext and tag),
  with a host-records magic and the state kind as additional data. The
  envelope vectors are shared with `fabricenvelopeextension`.
- A key failure disables the production stream and the sensitive
  metadata. It never disturbs monitored workloads. The sensor reports health
  through safe counters.

#### 6.2.6 Gate rules for host groups

In addition to §6.1:
1. A host group has only a `traces/<group>` pipeline:
   `otlp/<group>` → `memory_limiter` → `fabricguard/<group>` → approved
   exporters. No logs or metrics pipeline uses its receiver.
2. A host group has no content receiver and no `fabriccontent` exporter.
3. `fabricguard/<group>` sets `profile: production`, the group's binding,
   and `source_kind` equal to the group kind.
4. The Node's own `audit` receiver never appears in a production pipeline.
   It runs in a customer-deployed **sensor collector** (§6.2.8).
5. auditd and eBPF groups on one host have different sources, credentials
   and listeners.

#### 6.2.7 fabricguard admission

`fabricguard/<group>` gains `source_kind` (WP4-08b). For a host instance,
in order:
1. Repeated keys in any container refuse the batch (existing rule).
2. `fabric.source.authenticated` supplied by the sender is removed.
3. Log records are dropped and counted: a host group has no logs in
   production.
4. Each span is classified. Only host records (records class whose
   `fabric.capture.point` kind is `S`) and `manifest`, `periodic`, `final`
   and loss markers are admitted. An exchange, a run marker, a seal, or a
   records span with a non-`S` capture point **refuses the whole batch**
   with non-retryable `INVALID_ARGUMENT`, like a forged identity.
5. `fabric.tenant_id` and `fabric.source_id` must equal the binding, and the
   capture point id must equal `source_kind`. Otherwise the batch is
   refused.
6. Keys outside the host placement are stripped and counted (rule A). A
   failing value of an identity, capture or sequence key drops the span and
   counts it.
7. Digest keys are stripped unless `host_digests: permitted`.
8. `fabric.source.authenticated=true` is stamped.

For an `agent` instance, a span whose capture point has kind `S`, or that
carries any `fabric.sensor.*` key, refuses the batch. An agent can never
present host evidence, and a sensor can never present agent records.

#### 6.2.8 auditd receiver (production mode)

- It runs in a customer-deployed sensor collector, separate from the
  monitored agent and from the Node, whose configuration is the `audit`
  receiver (production mode) → a traces pipeline → one `otlp` exporter to
  its group's endpoint with its own bearer token. A sensor-profile check
  in the collector refuses any other receiver or exporter in that process.
- The receiver's factory gains a traces creator for production mode;
  local mode keeps its logs output.
- Netlink: assembly eviction, socket overflow and backlog limits become
  upstream loss (§6.2.4); there is no cursor.
- Logfile: the accepted cursor advances only after the translated batch is
  durably staged **and** the Node acknowledged its export in full. Staged
  batches and their ids survive restart and key rotation. Rotation,
  truncation and a missing source are upstream loss with their reasons.
- `audit.serial` stays exact as `fabric.sensor.audit_serial`.

#### 6.2.9 eBPF emitter (production mode)

- New flags: `--production`, `--source-label`, `--id-key-file`,
  `--state-dir`, `--spool-key-file`, with the existing endpoint, token and
  TLS flags. It exports traces (host records) instead of audit-class logs.
- Ring-buffer and rate-limit drops are upstream loss.
- The spool becomes encrypted (§6.2.5). Partial OTLP success keeps today's
  quarantine: the batch's positions are declared `span_dropped` loss
  (§6.2.3), the batch is kept encrypted, and it is never silently deleted. A
  record later found in the store supersedes its loss claim; the verifier
  reports the overlap count.

#### 6.2.10 Readback and authentication

- Production host capture is not enabled by choosing `production` in the
  old local host-monitor example; it needs the production sensor mode and a
  host group.
- Authentication verdicts need trusted readback (049 §7.9). Imported host
  spans are `unverified(source_unauthenticated)`.
- No delivery receipts are created or obtained.

### 6.3 Corroboration and projection

`reconstruct/_host.py` (WP4-10b) reads host sources into a **sensor
evidence collection**. They are verified like any source (positions,
manifests, heartbeats) and never enter an agent run's sequence window,
seal or verdict.
- `corroborated_by` links on agent steps target namespace `event` with the
  sensor event id, method `pid_time_join`, provenance `inferred`,
  confidence `tentative`.
- The join uses host identity, the pid, the pid namespace, boot time and
  process start when present, both clock uncertainties and a configurable
  bounded window (default 100 ms).
- No join across different hosts, unknown key domains, clocks outside the
  window or overlapping pid reuse. Several candidates give `ambiguous` with
  every candidate; none gives `unresolved`.
- A matching sensor never upgrades reported content to observed and never
  proves a durable commit. Each sensor source needs its own manifest and
  authentication; unauthenticated corroboration stays visible as uncertain
  evidence and cannot satisfy a required agent field.
- The step-projection schema does not change (links already allow
  `corroborated_by` to `event`). `run-reconstruction-v1` gains an optional
  `sensor_events[]`: only the events a link names as a candidate, at most
  64 per link, plus per-source counts.

## 7. Contract deltas (applied by WP4-01 only)

Registry operations are keyed by id, key or role and preserve every column
not named here. Bump registry revisions, family manifest minor versions and
pins atomically. 049's generated blocks are regenerated by 049's owner. No
Activity Envelope change. No new statuses, step kinds or content roles.

| File / exact row | Operation |
|---|---|
| `capture-points-v1.json`, `http.nonmodel.input` | `wire` → `records` (R7). `kind` stays `W` (the observation mechanism is a transport copy) |
| Same, `http.nonmodel.observes` | Append "recorded on the records input with provenance observed; bodies in pieces of at most 256 KiB" |
| `capture-points-v1.json`, `db.dbapi.supplies` and `D24.observed_by` (field registry) | Add `db.dbapi` to D24 `observed_by`, phase `P3 (R), P4 (H)`; `supplies` is then derived |
| Same, `db.dbapi.activation` | "Opt-in per driver; sqlite3 also requires the caller-selected observing factory; psycopg 3 only." |
| Same, `file.audit.observes` | "Pre-operation `open`, `os.rename`, `os.remove` audit events: supplied path, mode and flags; outcome, existence and byte ranges unknown." |
| Same, `file.audit.cannot_observe` | Add successful completion, existence, file bytes, byte ranges and fd-resolved paths |
| Same, `exec.audit.observes` | Prefix "Pre-execution attempts"; keep supplied executable/argv/cwd; no completion |
| Same, `remote.ssh_wrapper.runtime` | "Python, paramiko (explicit wrapper)" |
| Same, `host.auditd.state`, `host.ebpf.state` | "Built local profile; P4 production: separate bound source with its own epoch, encrypted state and ingress group; records-class host records; corroboration only." |
| Same, both host rows `passivity_gate` | `P4-HOST, P4-BIND` plus the existing 030/031 regression gate |
| Same, both host rows `input` | `records` (unchanged); `observes` adds "host records (§6.2.3) on a production ingress group" |
| `field-registry-v1.json`, X02, X04, X06, X22, X24, X26, X27, X35, X47 `observed_by` | Add both host capture points; meanings unchanged |
| Same, `evidence_types` | Add the six types of §3.2 with schema path, pointer map and points |
| Same, N45 notes | "`byte_range` has no P4 producer; projected `unsupported(unsupported_api)`" |
| `telemetry-keys-v1.json`, new rows | `fabric.file.operation` (N45, enum `open, read, write, append, truncate, rename, delete, stat, create`, `record`); `fabric.file.path_hash` (N45, DIGEST, `record`, digest-gated); `http.request.method` (N43, closed enum, `record`); `http.response.status_code` (N43, int 100..599, `record`); the `fabric.sensor.*` keys of §6.2.3 (`record`) and §6.2.4 (`heartbeat`) |
| Same, existing process, db, network, remote, mcp, commit and C41 rows | Add placement `record`; keep validators; D23 phase stays `P3 (R), P4 (H)`; D24 phase adds `P4 (H)` |
| Same, id rows `fabric.db.namespace_id`, `fabric.network.host_id`, `fabric.remote.target_id`, `fabric.execution.host_id`, `.sandbox_id` | Add the clear-mode alternative (opaque id or `h-` form) admitted only under a clear-mode manifest, as 050 does for marker ids |
| Same, schema | New optional key column `capture_point_kinds` (array of capture-point kinds); the generator emits it to fabricguard and to rule A (050 §3.4 rule A). 054 WP5-01 adds the point-level sibling column `capture_points`; a key carrying both is admitted only when both match |
| `vocabularies-v1.json`, `capture_input` | No change: hooks are covered by the existing `records` meaning ("… or an opt-in hook observes through the SDK"); `wire` stays model traffic |
| `content-roles-v1.json` | No added role. Use the existing `terminal.*`, `artifact.locator`/`.before`/`.after`/`.diff`, `database.*`, `network.*`, `mcp.*`, `remote.*`, `computer.*` rows with their caps, boundaries and provenance lists |

**Schemas and fixtures.**
- `contracts/coverage/v1/evidence/` gains the six type schemas of §3.2 and
  `contracts/content/v2/schema/db-cells-v1.schema.json`.
- `run-reconstruction-v1.schema.json` gains optional `sensor_events[]`
  (§6.3).
- `span-category-v1.json` gains the `fabric.sensor_event` branch.
- `records-span-v1.json` gains host-record cases (admitted and stripped
  keys, S-scoped keys on an agent record, agent keys on a host record).
- New `contracts/capture/v1/fixtures/host/`: a host record per syscall
  class, manifest, periodic heartbeat with upstream loss, loss, `final`;
  invalid cases for duplicated identity keys, agent impersonation by a
  sensor, sensor impersonation by an agent, replay with a changed event
  id, an unknown source kind and a digest key without permission.
- The canonical JSON-RPC id tuple and the `fabric.db-cells/v1` encoding get
  golden vectors.
- No step-projection or capture-manifest schema change.

## 8. Work packages and ownership

Rules for every WP:
- Each WP touches only its **owner area**. A shared file has one
  integration owner, listed below; other WPs use only its interfaces.
- Each WP ends with `ruff` and `mypy --strict` (Python) or `go test ./...`
  (Go) for its area, its own tests and
  `scripts/tests/test_recorder_release_boundary.py`.
- Code-writing WPs run on Opus-class agents; read-only research may use
  Sonnet.
- No TypeScript WP is in this spec; no P4 exit gate depends on one.
- This authoring task changes only this spec and spawns no agents.

**Tracks.** The Python track and the Go track run in parallel after WP4-01.
Host and Node work never blocks the Python hooks, and the reverse.

| Wave | Python track | Go track |
|---|---|---|
| A | WP4-01 (single) | WP4-08a (needs only §6.1 and §6.2.6 of this spec) |
| B | WP4-00 | WP4-07a, WP4-08b |
| C | WP4-02, 03, 04a, 05, 06a, 06b (6 agents); then WP4-04b, WP4-10a, WP4-10b | WP4-07b, WP4-07c; WP4-09 |
| D | WP4-11a | WP4-11b |
| E | WP4-12 (joins both tracks) | |

| WP | Owner area | Depends on | Deliverables | Tests | Exit check |
|---|---|---|---|---|---|
| **WP4-01 Contracts** | `contracts/coverage/v1/**`, `contracts/capture/v1/**`, `contracts/content/v2/schema/db-cells-v1.schema.json`, `scripts/contracts/**`, contract tests; generated tables (`P/coverage_keys.go` table, `E/evidence_types_generated.go`, `_records_keys_generated.py`, `_manifest_fields_generated.py`, `_roles.py`) | 050 WP-00 (carrier, `evidence_types` block, generators); 051 WP2-0 and 052 WP3-0 merged (serial chain). First P4 WP; 054 WP5-01 starts only after it merges | §7: registry operations, six evidence types, sensor keys, `capture_point_kinds`, codec schema, host and channel fixtures and vectors | validator over every new fixture; generator `--check`; C0-1..C0-5 still pass | `validate_coverage_contracts.py` and `validate_capture_contracts.py` pass |
| **WP4-00 Hooks foundation (integration owner)** | `fabric/hooks/__init__.py`, `_config.py`, `_producer.py`, `_patches.py`, `_audit.py`, `_guard.py`; stub channel modules (`_exec.py`, `_exec_audit.py`, `_file.py`, `db/`, `_http.py`, `_mcp.py`, `ssh.py`) with registration entry points; `wire/_routes.py` (new), `wire/_transport.py` (route call site only); `_capture_scope.py` (`kinds`); the scope-kind line in `adapters/synthetic_evidence.py`, `adapters/byte_boundary.py`, `http_dispatch.py`; `sdk/python/pyproject.toml` (extras `hooks-db`, `hooks-mcp`, `hooks-ssh`, test deps); `fabric/__init__.py` export | WP4-01; P1-A and P2 exits | §3 adapter, §4 install/config/status, §4.1 discipline, §4.2 identity, §4.3 D2/D3 and owner marker, audit callback with sentinel and suppression token, route table, manifest capability states | admission and loss races; mixed explicit and hook scopes; config error matrix (explicit raises, environment never); inactive budgets for every channel; privacy canary; fresh-interpreter audit tests | every hook installs, disables and closes with no-op channels; route-table golden; P1 invariants hold with mixed inputs |
| **WP4-02 Exec** | `hooks/_exec.py`, `hooks/_exec_audit.py`, `tests/test_hooks_exec*` | WP4-00 | §5.1 | process ledger; cumulative timeout output; pipe identity; detach; argv bounds before encoding; credential canaries | P4-EXEC and P4-AUDIT pass |
| **WP4-03 File** | `hooks/_file.py`, `tests/test_hooks_file*` | WP4-00 | §5.2 | pre-call semantics; silent installation refusal; huge and malformed paths; path-like not converted; fork recursion; raised `BaseException` | P4-FILE passes |
| **WP4-04a DB codec and sqlite3** | `hooks/db/_common.py`, `hooks/db/sqlite3.py`, `tests/test_hooks_db_sqlite*` | WP4-00 | §5.3 codec, cell bound, observing factories | property row shapes and generators; transactions; custom factories and converters declared uninstrumented; privacy | P4-DB (sqlite3) passes |
| **WP4-04b psycopg** | `hooks/db/psycopg.py`, `tests/test_hooks_db_psycopg*` | WP4-00; **WP4-04a merged** (intra-wave: `_common.py`) | §5.3 psycopg 3 sync and async | server ledger; timeout after commit; savepoints; pipeline mode declared; cancellation | P4-DB (psycopg sync, async) passes |
| **WP4-05 HTTP and dialects** | `hooks/_http.py`, `reconstruct/dialects/{__init__,jsonrpc2,qdrant_rest_v1}.py`, `tests/test_hooks_http*` | WP4-00 | §5.4: host rules via `register_route`, pieces, redirects, dialects | host confusion, ports and path overlaps; partial consumption and cancellation; Qdrant fixture server; canaries | P4-HTTP passes |
| **WP4-06a MCP** | `hooks/_mcp.py`, `tests/test_hooks_mcp*` | WP4-00 | §5.5 | fixture message ledgers (stdio, Streamable HTTP); reverse RPC; progress and cancel; eviction; no double record with HTTP | P4-MCP passes per transport |
| **WP4-06b SSH** | `hooks/ssh.py`, `tests/test_hooks_ssh*` | WP4-00 | §5.6 | fixture SSH server ledger; host-key basis cases; `exec_command` pass-through identity; canaries | P4-SSH passes |
| **WP4-10a Channel projection** | `reconstruct/_channels.py`, `reconstruct/_diff.py`, tests | WP4-01 fixtures; 051 WP2-9a hook | channel field wrappers from evidence and keys; piece reassembly; N48 protected diff | per-type projection fixtures; no false completeness | C1-3, C1-5 for P4 steps |
| **WP4-10b Host corroboration** | `reconstruct/_host.py`, the `sensor_events` writer in the report (through the WP-30 report interface), tests | WP4-01 host fixtures | §6.3 | pid reuse, clock uncertainty, ambiguity, imported-stamp negatives, upstream-loss windows | joins tentative; no agent verdict change |
| **WP4-07a host-records library** | `components/host-records/**` (new Go module) | WP4-01 | §6.2.2–§6.2.5: label and v2 pseudonyms, `epoch.state`, allocator, persisted ids, envelope, staging batch, span builders, upstream-loss accumulator | vectors equal Python's (`pseudonym-v2`, `run-id-pseudonym-v1`, span category, host fixtures); envelope vectors equal `fabricenvelope`'s; property tests for ids and replay | vector parity; corruption, key-rotation and restart tests |
| **WP4-07b auditreceiver production mode** | `receiver/auditreceiver/**`, `ocb-config.yaml` (host-records replace line), `examples/host-sensor-production/` | **WP4-07a merged** | §6.2.8 | logfile cursor and restart; netlink overflow; staged replay keeps ids; canaries in staging and spool | Linux audit ledger survives restart with no source-id or event-id churn |
| **WP4-07c host-emitter production mode** | `components/host-emitter/**` | **WP4-07a merged** | §6.2.9 | ring overrun; encrypted spool; partial-OTLP quarantine; restart replay | eBPF ledger survives restart with no id churn |
| **WP4-08a Gate** | `gate/**` | this spec §6.1, §6.2.6 | multi-group graph validation | forged, mixed and swapped groups; duplicate credentials by bytes; host-group pipeline rules; legacy single binding still passes | P4-BIND gate matrix |
| **WP4-08b fabricguard** | `processor/fabricguardprocessor/**` (non-generated) | WP4-01 generated tables | `source_kind`, §6.2.7 admission, S-scoped keys, `fabric.sensor_event` name, agent-side refusal of host spans | per-key admitted and stripped tests; forged and mixed classes; repeated keys; restart | P4-BIND processor matrix; no broadening of the single-source path |
| **WP4-09 Deployment** | `charts/**`, `deploy/compose/**` and their tests | **WP4-08a and WP4-08b merged** | `sourceBindings[]` values and schema, Services, ports, Secrets, NetworkPolicy, sensor-collector and eBPF production examples, DaemonSet example | rendered bypass and cross-wiring negatives; 64/256 limits; legacy form | packaged chart and compose refuse every unbound route |
| **WP4-11a Channel qualification** | `qualification/execution-channels/**`, `scripts/qualification/execution_channels*`; agent-matrix rows (`qualification/agent-matrix/**`, merged to main first, R16) | WP4-02 … WP4-06b, WP4-10a | §9 matrix, ledgers, fixture servers, canary corpus, pins | — | every enabled channel gate; C1-x regressions |
| **WP4-11b Host and binding qualification** | `qualification/host-ingress/**`; chaos rows (`qualification/chaos/**`, merged to main first, R16) | WP4-07b, 07c, 08a, 08b, 09, 10b; **after WP4-11a** for the shared harness files | two-agent, two-sensor production e2e; token, identity and endpoint swaps; chaos faults | — | P4-HOST, P4-BIND |
| **WP4-12 Release boundary and exit report** | `scripts/tests/test_recorder_release_boundary.py` (P4 additions), `docs/execution-channels.md`, `docs/host-sensors.md` (production section), CHANGELOG | WP4-11a, WP4-11b | artifact-content checks for wheel, chart and images; exit report | — | P4 exit, C0A-2 and release-boundary tests pass |

**Shared files and their integration owners (R13).**

| File or area | Integration owner | Other WPs |
|---|---|---|
| `fabric/hooks/{__init__,_patches,_guard}.py` | WP4-00 | call its interfaces only |
| `fabric/hooks/_config.py`, hooks public API | WP4-00 | next owner 054 WP5-00a (P5 switches only) |
| `fabric/hooks/_producer.py` | WP4-00 | next owner 054 WP5-00b (`deferred=` passthrough) |
| `fabric/hooks/_audit.py` | WP4-00 | WP4-02, WP4-03 register handlers through `register_audit_handler(event_names, fn)` |
| `wire/_routes.py` (new), the route call in `wire/_transport.py` | WP4-00 | WP4-05 uses `register_route`; next owner of `_routes.py` 054 WP5-00a |
| `wire/_match.py`, `_model.py`, `_config.py`, `_detect.py`, `wire/__init__.py` | not edited in P4 (WP4-00 touches none of them) | 054 WP5-00a follows the P2 owner directly |
| `_capture_scope.py` and the three explicit-adapter scope lines | WP4-00 | — |
| `sdk/python/pyproject.toml` | WP4-00 (lands every P4 extra first) | — |
| `hooks/db/_common.py` | WP4-04a | WP4-04b imports it |
| Contracts, registries and generated tables | WP4-01 | serial chain: 050 WP-00 → 051 WP2-0 → 052 WP3-0 → **053 WP4-01** → 054 WP5-01 → 055 WP-01 (shared rows; 055's TS-only rows follow 050 WP-00 directly, 055 §8) |
| `reconstruct/_project.py`, `reconstruct/_evidence.py` | not edited in P4 | WP4-10a and WP4-10b register through 051 WP2-9a's hook; 054 WP5-08b follows 051 WP2-9a |
| `processor/fabricguardprocessor/**` (non-generated) | WP4-08b (053's last `P/` owner) | next owner 054 WP5-01g |
| `gate/**` | WP4-08a | — |
| `ocb-config.yaml` | WP4-07b | — |
| `charts/**`, `deploy/compose/**` | WP4-09 | WP4-11b adds no template change |
| `qualification/agent-matrix/**`, `qualification/chaos/**` | WP4-11a, then WP4-11b | sequential |
| `scripts/tests/test_recorder_release_boundary.py` | WP4-12 | — |

**Intra-wave dependencies.** WP4-04b after WP4-04a; WP4-07b and WP4-07c
after WP4-07a; WP4-09 after WP4-08a and WP4-08b; WP4-11b after WP4-11a for
the shared harness files. Every other WP in a wave is independent of the
others in that wave.

## 9. Qualification, risks and open owner decisions

**Qualification.** `qualification/execution-channels/` holds `matrix.json`,
ledgers, reproducible fixture servers and processes, the canary corpus,
`pins.json` and `run.py`.
- Matrix rows key capture point, runtime and client version, OS, sync or
  async path, operation, boundary, role, privacy mode, input (`records`),
  expected field statuses and passivity budget.
- Real CPython sqlite3, psycopg 3 against Postgres, a Qdrant server, MCP
  stdio and Streamable HTTP servers, and an SSH server.
- Agent-matrix clients call these channels without framework adapters;
  direct unsupported clients are bypass cases.
- Each row stores measured overhead, runtime pins and a fresh
  customer-store readback.

**Chaos** adds queue saturation and disk full, a slow or dead redaction
service, sender and Node restart, credential rotation, wrong-source
ingress, audit log rotation and truncation, eBPF ring overrun, killed and
spawned workers, fork while a callback is active, and shutdown before an
outcome. Lost or unwritten events stay gaps; unknown kernel loss never
becomes zero.

**Production e2e** uses two agent groups plus auditd and eBPF groups.
Swapping every pair of tokens, identities and content endpoints must fail.
The action ledger and application output are compared with recording on
and off.

**Privacy canaries** cover argv, environment values, cwd and paths, SQL,
rows and DSNs, bearer headers, query strings, MCP session ids and custom
methods, the SSH target, UI typed text, and the sensor's peer address,
owner and executable name. They are scanned in the decrypted test spool,
sensor staging and checkpoint, the Node queue, telemetry, store
descriptors, evidence objects, diagnostic logs and default reports.
Masked-only never persists the original; a transformation failure
withholds, including a derived diff. Same clear ids correlate across hosts;
emitted-looking caller strings are remapped in pseudonymous mode; keys and
tenants do not correlate.

**Conformance.** P4-EXEC/AUDIT/DB/HTTP/FILE/MCP/SSH are the capture-point
gate ids of 049 §2.8 (049 §8.2 defines no numbered P4 suite). P4-HOST,
P4-BIND, P4-UI-R and P4-JOIN are this spec's additional gates. Regress
C0-1..5, C0A-1..4, C1-1..7, C1A-1..3 and the P1-A mixed-capture and
qualified-run parity. New channels never imply 046 qualification.
`scripts/tests/test_recorder_release_boundary.py` checks the installed
wheel, chart and image contents and that no evaluator, policy engine,
enforcement or proprietary pack is introduced. Qualification output, not
draft manifests, changes claims.

**Risks.**

| # | Risk | Mitigation |
|---|---|---|
| K1 | PID reuse and clock skew create false host joins | Tentative, namespace-aware joins with boot time and process start; an absent discriminator is never upgraded; ambiguity keeps every candidate |
| K2 | Up to 192 listeners on a 64-group Node | Bounded counts; one protocol per group where possible; the custom authenticator is the later reduction (§6.1) |
| K3 | Large fetches are only partially captured | Declared `rows_partial`; configurable bound with a measured budget (O4-10) |
| K4 | Sensors are privileged | Customer-deployed only; never installed or privileged by default; production mode drops owner, name and address |
| K5 | A host may silently refuse audit hooks | Capability `enabled` only after the sentinel event |

**Open owner decisions.** Each default is **Recommended — pending owner
confirmation** (RPOC). Build agents follow it unless the owner changes it.
They are bounded implementation choices or scope clarifications, not a
reopening of approved decisions 1–25.

| # | Decision | Default | Status |
|---|---|---|---|
| O4-1 | sqlite3 qualification surface | Caller-selected observing `Connection`/`Cursor` factories. Plain native connections stay declared uninstrumented. No proxy or C-type mutation. Full sqlite3 qualification waits for the §10 wording | RPOC (both reviews approve) |
| O4-2 | Multi-source Node binding (R11) | Static dedicated ingress groups, one `bearertokenauth` per source, 64 by default and 256 at most, including separate auditd and eBPF groups. A custom credential-to-source authenticator is a later option with its own spec. This is configured-source DaemonSet support, not dynamic workload discovery | RPOC (Astra approves; Fable preferred the authenticator, R11 chose groups) |
| O4-3 | Host digests | Executable, argv and path digests are omitted by default; both the sensor policy and the group's fabricguard must permit them. Keyed host and source mapping always | RPOC |
| O4-4 | Vector-store dialect (frozen) | **Qdrant REST** (`points/query`, `points/search`) through `qdrant-client` over httpx (`prefer_grpc=False`; gRPC unsupported), plus structure-only JSON-RPC 2.0. Qdrant server 1.x and `qdrant-client` 1.x; WP4-01 pins the exact minors current at freeze in `pins.json`. No other store is advertised from this fixture | RPOC |
| O4-5 | SSH client (frozen) | **paramiko** 4.x through the explicit `fabric.hooks.ssh.observe` wrapper (`run` captures output; `exec_command` records the request only). WP4-01 pins the minor current at freeze; paramiko 3.x and asyncssh are unsupported | RPOC |
| O4-6 | MCP SDK | The `mcp` Python SDK 1.x minor current at freeze (Streamable HTTP and stdio), hook symbols pinned in `pins.json`; legacy SSE unsupported | RPOC |
| O4-7 | Audit installation | Capability `enabled` only after sentinel confirmation; no output or existence claim from audit; an unsupported event never aborts the action | RPOC |
| O4-8 | Host joins | Tentative, namespace-aware `pid_time_join`, 100 ms default window; sensors are separately deployed | RPOC |
| O4-9 | Host record carrier (new) | Records-class spans on the records input, on traces-only host groups; no host log variant in production; local profile unchanged (§6.2.1) | RPOC |
| O4-10 | DB cell bound (new) | 64 cells per fetch callback by default, configurable to 4096 with the measured budget in the manifest. Lifting it needs a 050 extension (an immutable tuple body encoded on the worker), proposed for a later P1 minor, not assumed here | RPOC |
| O4-11 | N45 byte ranges and the coding-agent row (R15) | No P4 producer; projected `unsupported(unsupported_api)`; the matrix row is amended (§10). A reported range would be a later P2 API addition | RPOC |
| O4-12 | Hook configuration errors | Explicit `fabric.hooks.install` raises on malformed arguments (configuration); environment activation never raises and leaves hooks disabled | RPOC |
| — | Hook input class (R7) | Records with `capture.source=observed`; W-class records withdrawn | Closed by R7 and 050 OD-9 |
| — | Marker event ids | Persisted uuid4 | Closed by 050 R2 / OD-8 |
| — | Content validation before acknowledgement | Built in P1 | Closed by 050 R10 / OD-1 |
| — | Clear identity mode | One rule (§4.2) | Closed by 050 R8 / OD-10 |

## 10. Spec 049 deltas (for its owner; do not edit 049 here)

Line anchors refer to 049 rev 6.4 in this worktree. Quote the existing text
when applying, in case concurrent revisions move lines.

| # | Location and existing text | Proposed text |
|---|---|---|
| D4-1 | 049:949, `http.nonmodel` capture-point row, column "Input": `wire` | `records`. Append to "Observes": "recorded on the records input with provenance observed (`fabric.capture.source=observed`); `capture.input` is never `wire` for a hook" (consistent with 050 delta 14) |
| D4-2 | 049:2864, "`db.dbapi` (sqlite3 and psycopg first)" | "`db.dbapi`: caller-selected observing sqlite3 `Connection`/`Cursor` factories and qualified psycopg 3 methods first. Native sqlite3 and custom-factory connections stay uninstrumented; no returned-object proxy or native type mutation." Open decision O4-1 |
| D4-3 | 049:950, `file.audit` row "Observes", and N49 at 049:1560 | "PEP 578 events are pre-operation observations: `open` is not a read, rename and delete are attempts, and existence, outcome and byte ranges stay unknown unless independently reported or observed at another qualified boundary." |
| D4-4 | 049:1556, N45 notes | Append "`byte_range` has no P4 producer (`file.audit` sees no ranges; no reporting API takes one); projected `unsupported(unsupported_api)`." |
| D4-5 | 049:2933, coding-agent row, column "3 Content": "P4 consumed output and observed file ranges" | "P4 consumed exec output and pre-operation file attempts with paths; file bytes and diffs only through explicit producers (N47) and offline N48. Limit: no file contents or byte ranges from hooks; no PTY changes, no extra reads" |
| D4-6 | 049:956–957, host rows "State": "built (031) … corroboration only" | "Built local-profile sensors. P4 production: each `host.auditd`/`host.ebpf` source has its own bound ingress group, source id, epoch and encrypted state, and emits records-class host records; sensor evidence provides corroboration only." |
| D4-7 | 049:2545–2549, "today accepts only evidence logs and rejects every trace batch (`processor.go:472-473`). From P0-A it covers …" | Replace the stale current-state clause with "P0-A binds trace batches and content descriptors as implemented; a production Node binds one agent source until P4, which adds a finite set of dedicated single-source ingress groups, including separate host-source groups." |
| D4-8 | 049:2581–2587, "One agent source per Node … is a P4 design item." | Append "P4 design (053 §6.1): static dedicated ingress groups, each with its own `bearertokenauth` instance, receivers and `fabricguard`/`fabriccontent` instances, at most 64 by default and 256 in total; a credential-to-source authenticator is a later option." |
| D4-9 | 049:2589–2593, "Host sensors (decision 23). The production gate admits only …" | Append "P4 adds production host groups (traces only, no content ingress) and a production sensor mode whose records-class host records carry their own source and epoch (053 §6.2)." |
| D4-10 | 049:2863–2872, P4 work list ending "(decision 23; design to be settled in its own spec before build)" | Replace the parenthesis with "(decision 23; settled in 053 §6.1 as static dedicated ingress groups)". Append "browser and computer-use reporting through P2 records (observed `ui.automation` stays P5)" |
| D4-11 | 049:2873–2881, P4 exit | Append "Production host and multi-source claims require distinct audit, eBPF and agent credentials, source-swap and cross-pipeline rejection, encrypted sensor state, trusted readback and tentative namespace-aware corroboration." |
| D4-12 | 049:1557, N46 notes | Append "`file.audit` records `{path, target_path?}` as tagged cells; mode and flags are metadata in `fabric.file.audit/v1` evidence." |

Revision 1's delta on the 16384-entry ceiling is dropped: 049 rev 6.4
already states it correctly (049:245, 049:2320).
