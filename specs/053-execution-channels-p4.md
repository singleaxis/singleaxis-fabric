---
title: Execution channels — P4 opt-in observed hooks and production host sources
status: draft
qualification: NO_COVERAGE_CLAIM
revision: 1
last_updated: 2026-10-22
owner: recorder-engineering
depends_on: ["049", "050", "051"]
related: ["030", "031", "041", "043", "047", "048", "052", "054"]
---

# 053 — Execution channels (P4)

## 1. Scope and gates

Implement 049 P4, under **CAPTURE -> PROTECT -> DELIVER**. Every hook is
independently opt-in. Installation, autoload, an execution coverage profile,
or enabling another hook MUST NOT enable it. Observations never approve,
block, retry, modify or delay the action. No framework adapters ship.
Qualified-run mode (045/046) retains its separate opt-in journal.

Normative baseline: 049 rev 6.3 plus the shared CONTEXT.md owner decisions
dated 2026-10-19..22. References below are worktree file:line anchors at the
start of this task; later build changes must refresh them. Contract changes
below are implementation instructions, not changes made by this document.

| Capture point / gate | Fields supplied or reused | Boundary and limits |
|---|---|---|
| `exec.subprocess` / P4-EXEC | N32–N35 | Local process arguments and caller-consumed output; no PTY, descendant capture or extra reader |
| `exec.audit` / P4-AUDIT | N32 | Exec-family audit attempt; no completion or output |
| `file.audit` / P4-FILE | N45–N46, N49 | Pre-operation audit event, path and mode; no file contents or inferred success |
| `db.dbapi` / P4-DB | N38–N42, D23–D24; N30 only for a registered dialect | sqlite3 and psycopg first; fetched values and client transaction observations only |
| `http.nonmodel` / P4-HTTP | N43–N44; N26, N28, N30 for qualified dialects | httpx/httpx2, explicit host allowlist; no headers, other clients or arbitrary endpoint scanning |
| `mcp.client` / P4-MCP | C25–C29, N22–N25 | Qualified MCP stdio and Streamable HTTP transport bytes; no server internals |
| `remote.ssh_wrapper` / P4-SSH | N36–N37 | Explicit client-side wrapper; no remote agent or SSH security changes |
| `sdk.records` / P4-UI-R | N54–N55; N53 is P1 provider observation | Existing P2 browser/computer-use reporting only; `ui.automation` remains P5 |
| `host.auditd`, `host.ebpf` / P4-HOST | C41; X21 corroboration | Separate host sources, separate spools/cursors, production bound ingress per source |
| `reconstruct.infer` / P4-JOIN | X21, N48 | Tentative host joins; optional diff from already stored before/after bytes |

All records use applicable X01–X09, X17–X30, X31–X36, X39–X47;
S01–S12, S29–S34 where observed; configured C12/C15/C16/C41 only.
Parent, run and causal links are inherited/reported, never guessed from
adjacent timestamps. N47 remains explicit observed before/after bytes;
file hooks do not supply it. No new core field id is allocated here.

**Entry copied from 049 §8.2:** “P2 exit; P1-A harness.” Spec 050 is the
P1/P1-A dependency; the P2 build spec owns reporting APIs. P3 exit is not a
new prerequisite: reuse its D23/D24 contract, not its runtime implementation.

**Exit copied from 049 §8.2, per channel:** “a fixture server, driver or
process ledger proves the exact bytes and operation set; no extra reads,
fetches, pipes or requests; retry, parallelism, cancellation, partial
consumption, transactions, timeout after possible commit, detached work;
D2/D3 honoured; hook passivity (raising body, budget, fork, recursion,
audit self-event); header and environment credential canaries never
stored. No channel inherits another's qualification.”

Tightening: qualify each driver, sync/async variant, transport and version
independently. P4-HOST and P4-BIND must pass before advertising production
host capture or multi-source Nodes. Disabled/unsupported channels appear
in manifests; a partial release does not claim the full P4 exit.

## 2. Current state and missing work

| Evidence in current code | Consequence |
|---|---|
| `sdk/python/src/fabric/wire/_match.py:11–60`: five API names; POST-only matcher; host/scheme/port/prefix checks | No non-model dispatch table; preserve existing model matching while adding an independent allowlisted route |
| `wire/_model.py:15–21,78–99`: model API union, model roles, CaptureJob and nonblocking submit | Hooks need P1's general records producer, not fabricated model exchanges |
| `wire/_pipeline.py:249–264,377–449`: queue admission and worker-side protection/spooling | Reuse worker path; no serialization, redaction RPC or fsync in hooks |
| `wire/_config.py:43–45,91–100`: 32 MiB object cap, 64 MiB retention design, 16384 entry ceiling with byte budgeting | Do not copy 048's obsolete 256-entry default; new producers share byte and entry budgets |
| `wire/_protect.py:3–14,61–65`: extraction before protection, customer-run redaction service, role validation | All hook content passes the same stage before disk/export; no customer code execution |
| `wire/_aiohttp.py:69–84,86–115`: bytes-only request observation, response feed observation | Does not provide MCP byte interception or WebSocket capture; no P4 aiohttp network claim |
| `wire/_detect.py:54–65,69–101`: requests/urllib3 model-call loss detector, recursion guard | Keep loss accounting for uninstrumented model clients; do not silently extend it to all network traffic |
| `_sequence.py:160–167,286–316,363–414`: wire-only allocator guard and process-issued EmittedId identities | P1 generalizes allocation; caller strings must never gain emitted-id privileges by prefix |
| `decision.py:2141–2210`: explicit file span event, SHA-256 path, optional clear mode, validation raises | Not a PEP 578 hook or unified P1 record today; hooks must not call this legacy method on the action path |
| `decision.py:2213,2325,2341`: explicit model, embeddings, tool APIs | Reuse P2 records semantics; the file has no `record_ui_action` implementation yet |
| `reconstruct/_inputs.py:518–550`: exchange/loss/heartbeat classification | P1 must make generic records visible; host logs and channel projections need additional readers |
| `components/otel-collector-fabric/receiver/auditreceiver/translate.go:27–114`: audit logs, SHA-256 executable/argv/path, raw peer address and owner fields | Existing minimization is not sufficient for the proposed production host path |
| `auditreceiver/durable_state.go:21–22,94–125,169–215`: durable staged logfile batch/cursor and fsync | Preserve stable replay identities and accepted-cursor semantics; add protection and encrypted state |
| `auditreceiver/receiver.go:180–188,276–348`; `netlink_linux.go:317–347` | Source-health uncertainty and counted delivery losses exist; multicast netlink is already built, not a P4 prerequisite |
| `components/host-emitter/emitter.go:130–176`; `spool.go:159–208`; `otlp.go:44–107` | eBPF emits minimized audit logs, durable plaintext OTLP spool, TLS/token exporter; lacks P1 source/epoch/manifest binding |
| `fabricguardprocessor/config.go:16–26,70–83`; `processor.go:488,527–530`; `fabriccontentexporter/config.go:96–100,157–192` | Single-source production binding and receiver-owned authentication stamps exist; no identity-to-credential routing |
| `components/otel-collector-fabric/gate/gate.go:73–220,291–307` | Gate assumes one authenticated ingress and one matching content binding; adding a source list alone is unsafe |
| `charts/fabric/charts/otel-collector/templates/configmap.yaml:21–100`; `deploy/compose/README.md:193–208` | Current production deployment is one agent source per Node; host-monitor compose remains local only |
| Coverage registries: `capture-points-v1.json`, `field-registry-v1.json`, `telemetry-keys-v1.json`, `content-roles-v1.json` | P4 field/role rows mostly exist; supplies must be widened symmetrically for D24 and cross-cutting sensor identity |

## 3. Explicit P1 interface assumptions (spec 050 integration contract)

These are required behaviours, not claims that 050 already chose these
symbol names. WP4-00 supplies a narrow adapter to 050's actual API; channel
WPs import that adapter and MUST NOT modify P1 internals independently.

1. One process source, one allocator per `(source_id, epoch)`, shared by
   wire and records. Generic records have spool kind `record`; exchanges
   retain `exchange`; losses use `loss`; manifest/run/segment records use
   `marker` with their registered marker kind. Markers/losses do not spend
   ordinary record positions. No hook-specific spool or sequencer.
2. A nonblocking producer can reserve an attempt/lifecycle handle, submit
   immutable bounded observations, and account loss for each allocated
   position. Multiple lifecycle records share a minted attempt uid and
   step id; every record has its own stable event uuid4 and position.
   Allocation/drop, manifest boundary and seal admission are atomic at
   their respective P1 boundaries. Detached outcomes cannot land outside
   a sealed segment; missing outcomes are gaps, not successful completion.
3. Admission carries typed metadata, field evidence, content-role drafts,
   content links and the scope snapshot. Raw bytes are memory-only until
   the shared worker applies PROTECT. Production spool and Node queue are
   encrypted. The byte budget includes queued/retained mutable snapshots,
   not merely final serialized length.
4. P1 exposes producer capability registration, immutable manifest
   revisions, authenticated trusted readback, generic-record projection,
   canonical seal keys and event-id deduplication. New metadata schemas
   are validated before they can become completeness evidence.
5. D2 has a same-kind explicit-scope token with sticky withholding and
   deferred adoption; D3 is checked at install AND emit. A generic hook
   must not fall back to unprotected/global-tracer export when refused.
6. EmittedId passes through only if minted by this process/issuer.
   Every caller string, including `r-`, `s-`, `txn-` and `rpc-` shaped
   strings, is mapped through its keyed pseudonym function. Same clear id
   plus same key gives cross-process continuity. Serialized emitted ids
   do not. Resume tokens remain Fabric-issued values. No-key behaviour
   follows 049 §2.9, including omission of host-derived ids in production.
7. Fork resets locks, guard state and handles; creates its own epoch;
   registers declared child branches through P1. Spawn epoch registration
   is a P1 gate. Pool termination may lose unwritten work; never assert
   complete for it. No hook adds fork-time disk/network I/O.
8. Current Node content acceptance may return 200 before validation/drop.
   These specs do not treat 200 as content retention or durability. P1 may
   move validation before acknowledgment; until then descriptor/readback
   absence is `destination_rejected`/unverified evidence, never success.
9. New field-bearing record data survives the protected records carrier
   even when no telemetry key exists. CONTENT values are content locators
   in default projections; field values must not become span attributes.

Proposed internal facade in `fabric/hooks/_producer.py`:

```python
# All methods contain Fabric failures and never wait for capacity or I/O.
begin(kind, point, scope, safe_metadata) -> ObservationHandle | None
observe(handle, phase, *, fields=(), content=(), links=()) -> bool
lose(handle, reason) -> None
# phase: start | item | outcome; one submitted record per call.
# ContentDraft(role, media_type, encoding, bytes, boundary, provenance)
# is bounded, owned memory, never an iterator, file handle or callback.
```

The facade uses the P1 records carrier and shared queue. W-class network
observations keep `capture.input=wire` while using shared admission
machinery. H/R/S observations use `records`; source markers omit input.
This resolves an input-description ambiguity explicitly in §10.

### 3.1 Alignment with the concurrently delivered 050 draft

050 §3.4 is now available: `RecordsInput.begin(...) -> Attempt`,
`Attempt.emit(start|data|update|end, ..., bodies=...)`, `mode_of`, `v2`,
immutable bytes/str `RecordBody`, `MAX_RECORD_BODIES=8`, and X48
`fabric.content.object_ids` (max 8). Map this spec's facade `item` to
`data` while running, late content to `update`, and `outcome` to `end`.
Use `mode_of` before serializing/copying; omit means no body work. Charge
str at its P1 UTF-8 upper bound and encode on the worker. Include X48 in
the inherited field set. A single lifecycle record's protected originals
and review copies must fit eight references; split excess body observations
into additional `data`/`update` records under the same attempt, never drop
review copies or exceed the bound. Exec start and output naturally occupy
different records.
Apply P1's exact-or-descriptor-only records cap
`min(role cap, records_max_object_bytes)`; over-cap objects become
`not_captured(body_cap)`, not silent prefixes. An explicitly segmented
channel may emit additional independently located pieces; it must declare
partiality and cannot label a prefix the exact full result.

Required additions to 050's interfaces are owned by WP4-00/01 and merged
sequentially with its owner, without altering 050 in this authoring task:

- Its RecordBody currently fixes provenance to caller_reported. Add a
  trusted internal observed-producer constructor permitting `protocol`
  content provenance and `fabric.capture.source=observed`; ordinary
  reporting APIs remain reported/caller_reported. Bind permitted point,
  input, provenance and role set through an internal capability, never
  a caller-controlled attribute override.
- Its record parser/Go onRecord class currently requires input=records.
  Admit record-shaped W observations only for registered `http.nonmodel`
  (and later rt.websocket): require attempt.uid and the qualified point,
  input=wire, and **no** wire.exchange_id or marker discriminator. Keep
  mutually exclusive record/exchange/marker classes in spool validation,
  verifier classification, generated key placement and seal vectors.
- `fields`/`links` in the facade are not arbitrary span maps. Registered
  metadata uses 050's generated Rule A admission; other structured
  evidence requires a closed protected records carrier/role locator as
  specified in §7. The current Attempt.emit signature has no generic
  unprotected field bag; no WP may invent one as a shortcut.
- Use 050's process-issued identity checks; its optional clear-mode
  return path cannot bypass the shared owner's always-map rule for these
  producers' caller-supplied ids. Preserve keyed ids as internal EmittedId
  values to avoid double mapping. Runtime configuration incapable of
  meeting this rule disables those identity fields with a declared reason.
- 050 §3.14 now selects stateless validation before acknowledgment. Make
  its T4 gate the integration target: invalid content gives 400 before
  queueing. This spec's description of 200-then-drop is current-code
  baseline/fallback only, not permission to omit that P1 deliverable;
  post-queue store conflicts and durability still require readback.

050's provenance/input limitations are phase-boundary integration work,
not new input lines or changes to the two-input architecture. Matching
Python/Go category and seal fixtures must pass before observed hooks ship.
Its §3.5 proposes uuid5 marker ids, while baseline 049 §2.4 requires uuid4
event ids. Host markers must use the eventual frozen P1/049 vector, not
introduce a third algorithm. Recommended reconciliation: mint/persist uuid4
before first marker admission and replay that id; this preserves 049.

## 4. Hook infrastructure and configuration

Add `sdk/python/src/fabric/hooks/{__init__,_config,_producer,_patches,_audit}.py`.
Patch ownership is `(class/module, attribute, original, our_wrapper)`;
install is idempotent, uninstall restores only if the attribute still is
our wrapper. Do not undo another instrumentor's patch. Version checks
happen at install, with exact tested dependency ranges in the manifest.
No optional driver import or audit hook installation occurs by default.

Proposed public API (configuration spelling is owned by WP4-00):

```python
hooks = fabric.hooks.install(
    exec=False, exec_audit=False, file_audit=False,
    db=(),                         # ("sqlite3", "psycopg") separately chosen
    http_hosts=(),                  # exact canonical hosts; no wildcard default
    mcp=False,
)
hooks.disable("exec.subprocess")    # audit callbacks remain installed but inert
hooks.status()                     # safe capability/budget/loss counters only
hooks.close(timeout_s=2.0)          # bounded explicit lifecycle call
```

Add equivalent explicit environment switches `FABRIC_WIRE_EXEC=1`,
`FABRIC_WIRE_EXEC_AUDIT=1`, `FABRIC_WIRE_FILE_AUDIT=1`,
`FABRIC_WIRE_DB_DRIVERS=sqlite3,psycopg`, `FABRIC_WIRE_HTTP_HOSTS` (JSON
array), `FABRIC_WIRE_MCP=1`. Absent means disabled. Contradictory explicit
arguments/environment or malformed install configuration fail at install;
an unavailable/version-unsupported driver yields a disabled capability
with `unsupported_runtime`/`unsupported_version`, not an action-time error.
TypeScript exposes the same capability concepts on its parallel track;
Python patches are not mechanically ported. TS manifest stays unsupported
until its own byte goldens, BigInt counters and passivity gates pass.

Every callback first checks enabled flag, fixed event-name set (audit),
Fabric internal-I/O guard, and explicit-scope ownership. Guard both the
worker and sender, resolver, redaction client, spool and logging paths.
Use execution-local guards plus a thread-local audit fallback; reset both
after fork. No broad suppression of unrelated application activity. Copy
only exact primitive types with bounded elements/depth/bytes; never call
arbitrary `repr`, `str`, `__fspath__`, serializers, row factories, getters,
iterators or user converters. Unsupported values get `not_exposed`; no
secret-bearing object retained for later inspection. An unrepresentable
value must not erase an otherwise safe lifecycle record.

Monitored code executes outside Fabric exception handlers that could
swallow its failures. Invoke original once; catch its BaseException only
to attach a safe outcome, then bare-raise the same object. Fabric-only
sections catch BaseException, including cancellation/MemoryError injected
into a callback. Do not catch cancellation around the monitored await.

### 4.1 Independent latency and behaviour gates

Use `sdk/python/tests/test_wire_passivity.py:10–36,60–76,297–372` calibration,
paired rounds and bounded scale. Budgets below are median added latency
before scaling, measured with retention both on and off. Each channel has
its OWN test module and blocking-injection negative control (twice its
scaled budget must fail). Limits include snapshot/admission work; a slow
redaction service or stopped sender cannot change the action budget.

| Gate | Matched unit budget | Inactive/nonmatching budget |
|---|---|---|
| P4-EXEC | 50 µs per start/outcome; 2 µs per returned immutable byte chunk ≤4 KiB | 5 µs |
| P4-AUDIT | 20 µs per admitted bounded exec event | 2 µs per unrelated audit event |
| P4-FILE | 20 µs per admitted file event | 2 µs per unrelated audit event |
| P4-DB (separate sqlite3, psycopg sync, psycopg async) | 50 µs execute/transaction call; 20 µs fetch ≤64 primitive cells | 5 µs |
| P4-HTTP | Existing 50 µs/exchange and 2 µs/chunk | Existing 5 µs |
| P4-MCP (separate stdio/HTTP) | 20 µs/message ≤4 KiB; 2 µs forwarding-only chunk | 5 µs |
| P4-SSH | 50 µs lifecycle; 2 µs/channel chunk | 5 µs |
| P4-UI-R | P2 reporting budget, tightened to 50 µs per bounded report | 5 µs |

For larger values, never loop over an unbounded object on the hot path:
cap primitive-cell inspection at 64 per callback, use existing bounded
body retention for byte streams, and mark the remainder truncated.
Immutable bytes may transfer ownership without copying; mutable buffers
must be bounded snapshots within the same admission budget, or withheld.
Tests cover identity/order, same exception object, cancellation, full
queue, failed worker, fork/spawn, recursion, repeated install/disable and
other instrumentors. Audit tests run in fresh interpreters, include a
host hook refusing `sys.addaudithook`, and verify the Fabric hook never
raises. A host may silently refuse installation; confirm it with a
private sentinel audit event before publishing capability `enabled`.

## 5. Channel designs and PROTECT mapping

### 5.1 Subprocess and exec audit

`hooks/_exec.py` observes Popen construction, `communicate`, `wait`, poll
results and qualified asyncio subprocess equivalents, with start state
held in bounded weak associations. No waiting/polling done by Fabric.
`run` uses the same Popen observer: suppress duplicate wrapper records,
not output. Invocation uid is minted before the call; on failure emit an
error outcome without pretending a pid existed. Shell command strings
and argv arrays retain distinct tagged representations in `terminal.argv`.
`terminal.context` JSON is `{executable?, cwd?, shell, env_names?}`; names
only from an explicitly passed plain mapping, never enumerate os.environ.

N33 records only supplied `communicate(input=...)` under an explicitly
enabled `terminal.stdin` role. N34 observes the exact returned bytes or
text values from communicate/run, including exposed TimeoutExpired
partial output. Never tee a caller's pipe or alter PIPE/STDOUT flags.
Text is tagged as caller-decoded text with encoding evidence; it is not
claimed to be original pipe bytes. Repeated communicate after timeout
may return cumulative output: preserve both observation events with their
locators and distinguish them; do not count them as new stdout bytes.
Direct pipe reads, inherited output, PTYs and detached descendants yield
`not_captured(not_exposed)`. No finalizer waits for a child.

N35 uses `fabric.process.pid`, `.exit_code`, `.signal`. Negative POSIX
returncode means positive signal, not a fabricated exit code. Unknown
and zero remain distinct. `error.type` is a bounded class name; exception
messages, command lines and stderr are CONTENT, never log messages.

`hooks/_audit.py` registers one irremovable callback shared by independently
enabled exec/file branches. Exec allowset: `subprocess.Popen`, `os.system`,
`os.exec`, `os.posix_spawn` as emitted by qualified interpreters. Pin actual
event names and positional signatures in fixtures; do not match `os.exec*`
strings speculatively. Record N32 only, lifecycle running/result unknown:
the event precedes execution. When an exec.subprocess wrapper already owns
the operation, suppress duplicate N32 observation at that exact scope.
Unmatched exec-family audit events still record attempts. Successful
exec replacement has no Python outcome; its absence is a declared limit.

### 5.2 File audit and explicit artifacts

`hooks/_file.py` handles `open`, `os.rename`, `os.remove` from the shared
callback. Emit N45 operation `open`, `rename` or `delete`; retain open
mode/flags as protected `artifact.locator` JSON `{path, target_path?,
mode?, flags?, dir_fd?}`. A file descriptor is a number, not a resolved
path. Do not invoke path conversion, resolve symlinks, stat, read, watch
or scan. Platform-specific path bytes are preserved as tagged base64 in
the content object; telemetry never contains them.

`fabric.file.path_hash` is the existing SHA-256 DIGEST field, emitted only
if capture policy explicitly permits that digest. It is not anonymisation;
protective modes do not export a raw locator digest as a fallback. Clear
path is N46 CONTENT under `artifact.locator`. No new `_id` semantics are
silently assigned to `path_hash`. N49 before/after both remain `unknown`:
pre-call audit cannot establish existence, successful creation or deletion.
No byte range unless the application explicitly reports one through P2.
N47 is only supplied bytes through explicit producers. Offline N48 uses
stored complete before/after objects, `diff_algorithm` with pinned version
and `derived_from` links; no file rereads, and diff protection cannot be
weaker than either input. Truncated inputs cannot establish a full diff.

### 5.3 Database

`hooks/db/{_common,sqlite3,psycopg}.py` owns driver interception. Observe
execute/executemany, fetchone/fetchmany/fetchall, cursor iteration actually
performed by the caller, connection convenience methods, commit/rollback,
transaction contexts and connection close. Each execution is an attempt;
fetch observations link to that attempt. `executemany` never consumes a
parameter iterator ahead of the driver: capture an exact plain bounded
list/tuple only, otherwise parameters are `not_exposed`. No extra query,
fetch, EXPLAIN, transaction-id query or adapter invocation.

**SQLite construction boundary:** CPython sqlite3 native Connection/Cursor
methods cannot be patched as ordinary Python methods. Implement explicit
`fabric.hooks.db.sqlite3.ObservedConnection`/`ObservedCursor` subclasses,
selected by the application with `sqlite3.connect(...,
factory=ObservedConnection)`. The opt-in connect hook observes those
instances and does not replace another factory, connection or cursor.
The original caller-requested factory and row_factory run once. Plain
native connections, preexisting connections and unqualified custom
factories remain uninstrumented and are declared as such. No unsafe
mutation of C type dictionaries, global trace callback replacement or
proxy substituting returned values. This necessary qualification limit
needs the 049 delta in §10; do not claim arbitrary sqlite3 coverage.

Psycopg wrappers intercept qualified Python-level sync/async methods,
return the original connection/cursor/result objects, and preserve user
row factories, adapters, transaction nesting, savepoints, autocommit,
pipeline mode and cancellation. Unsupported pipelines/version paths
remain manifest gaps until qualified. Never monkey-patch native types
when a supported interception point is absent.

| Datum | Carrier and protection |
|---|---|
| Engine | N38 `db.system.name`, fixed public `sqlite`/`postgresql` |
| Namespace | N38 `fabric.db.namespace_id=dbn-…`; use configured/exposed clear namespace, no DSN parsing that exports credentials |
| Statement/parameters | N39 `database.query` / `database.parameters`; SQL and values are CONTENT, including literals, usernames and table names |
| Rows | N40 `database.rows`, tagged primitive serialization, caller-fetched values only; never arbitrary object stringification |
| Counts | N41 `fabric.db.rows_fetched`, `.rows_affected`; driver unknown = −1; partial observed count explicitly partial |
| Transaction | N42 `fabric.db.transaction_id=txn-…`; local minted transaction label scoped to connection, or keyed exposed clear id; never a server id claim |
| Commit | D23 `fabric.side_effect.commit_state`, D24 `.commit_basis=client_observed`; mutation detail in `database.mutation` |

Rows/parameters representation: canonical JSON tagged cells `null`, bool,
int, finite float, text, bytes/base64; unsupported typed cells represented
by a field gap, not `str(cell)`. Preserve row boundaries, fetch index and
the fact that rows are caller-decoded values, not exact database protocol
bytes. Driver operation ledger must establish value equality and exact
serialized representation under this declared codec.

Successful commit/rollback call yields `committed`/`rolled_back` with
`client_observed`, not durable service proof. Statement success alone
keeps `unknown`. An exception/timeout after possible commit stays unknown;
autocommit success is not promoted without qualified driver evidence.
Savepoint rollback describes that scope only. Arbitrary SQL text is not
parsed to assert a durable business effect. DB console access, existing
uninstrumented connections and unfetched rows stay uncaptured.

### 5.4 Allowlisted non-model HTTP

`wire/_routes.py` (shared owner WP4-00) routes in order: internal Fabric
I/O exclusion; same-kind explicit ownership; qualified protocol owner
(model/MCP, later P5 endpoint); explicit non-model host rule; no match.
Existing model routing remains available without opting into HTTP hooks.
One exchange is never independently emitted by both MCP and generic HTTP.
Caller-provided exact hosts are normalized at install (IDNA, lower case,
port/scheme restrictions); never substring-match hosts. Redirect targets
are matched independently. An unallowlisted redirect destination is not
retained because the source host was allowed. No redirect is followed by
Fabric itself. Fabric's own Node/redaction/export endpoints are excluded.

Add a non-model route/result type rather than inserting arbitrary hosts
into `_match.py`'s model dialects. N43 method/status are closed/numeric;
host uses `fabric.network.host_id=hst-…`. N44 target/path/query/redirect
detail and body are in `network.request`, `network.response`,
`network.stream`, all **off by default**. Protected request JSON includes
method/target plus body locator; never raw request/response headers.
Policy must explicitly name a retaining network role. A bounded request
tee forwards chunks unchanged; early response close is partial, not EOF.

Registered offline dialect parsers initially cover one pinned vector-store
query/result schema and JSON-RPC 2.0 request/result/error/notification.
Use P2 retrieval schema for N26/N28 and memory op schema for N30 only
when explicitly identified by that dialect. Generic SQL/HTTP success is
not a memory write or commit. Preserve exact network bytes; parsed views
point into them and inherit their protection, never log raw JSON fields.
No N27 auto-claim until its field/capture-point rows are amended together.

### 5.5 MCP transport

`hooks/_mcp.py` patches qualified `mcp` client transport serialization/
parse boundaries, not agent frameworks. Observe the bytes the stdio
writer sends and reader already parses; for Streamable HTTP observe
outbound serialized JSON-RPC and incoming POST/SSE message payloads where
the client's transport already demultiplexes them. No second pipe/SSE
consumer, no server polling, no extra initialize or inventory calls.
Session/model objects without exposed source bytes yield a declared
decoded representation or `not_exposed`, never invented “exact bytes”.
Pin the concrete hook symbols and library versions in qualification before
enabling either transport. Legacy SSE transport remains unsupported.

Each message is an immutable `mcp_call` record; preserve client/server
direction independent of request/response. Use `mcp.request`,
`mcp.response`, `mcp.notification` (server requests use notification role
as its registry definition permits). Initialization server info is
`mcp.server`. C25 server name is operator-label pseudonymized by default;
C26 software version validated; C27 date validated; C28 transport enum.
Unknown method maps to `other`; original method only in protected bytes.

N23 session id uses `mcps-`, JSON-RPC id uses `rpc-`. Key the latter from
a canonical tagged tuple `(clear_session_id, direction_of_request,
jsonrpc_id_type, clear_id)` so string `"1"`, integer 1, different sessions
and reverse requests cannot alias. Canonical tuple encoding is part of
the golden; do not accept pre-pseudonymized strings as emitted ids.
Responses, progress/cancel notifications link by the request tuple.
Absent id is a notification, not numeric zero. Bound outstanding map
(4096 entries/session, existing global byte cap); evictions leave
unresolved links. Reconnect mints a connection attempt; continuity only
from exposed clear session identity or an explicit report.

N25 protocol errors are distinct from tool `isError` results. Resources,
prompts, sampling, elicitation and roots are content observations only;
Fabric never answers or authorizes them. Session cookies/HTTP headers,
environment values and credentials never enter telemetry or logs.

### 5.6 SSH and browser/computer-use reporting

Add explicit `hooks/ssh.py` wrapper for one qualified client library;
customer invokes the wrapper, never process-wide interception of ssh/scp.
Observe existing command/channel callbacks and exit result. N36 target
uses `hst-`; host-key-verified boolean only from the client's actual
verification result, otherwise unknown. Do not install permissive host-key
policies. N37 `remote.request/result/stream` content; no extra channel
reader, PTY allocation, forwarding configuration or remote-side guarantee.

P4 browser handoff tests use P2 `record_ui_action` and existing-snapshot
reporting via `sdk.records`. Executed action N54 (`computer.action`) and
N55 (`computer.snapshot`) remain **reported**, with origin application.
Provider request N53 remains provider assertion. Connect through explicit
attempt/causal ids, never assume “requested” means “executed”. Typed text,
DOM, selectors, coordinates and URLs are protected CONTENT. Do not fetch
DOM, screenshot, accessibility tree, URL or browser state. A click is not
proof of a business effect. P5 owns observed automation patches.

## 6. Production host ingress and multi-source Node binding

### 6.1 Binding design: static independent ingresses

Implement shared-context decisions 3 and 4 using a finite configured set
of **single-source ingress groups**, not a shared credential plus payload
source lookup. Each group binds exactly `(tenant_id, emitted_source_id,
source_kind, credential_file, telemetry endpoints, content endpoint?)`.
`source_kind` is `agent`, `host.auditd` or `host.ebpf`. Identity is fixed by
the authenticated ingress, never selected by a request's claimed source.

Proposed Helm value `receiver.sourceBindings[]`: objects with `name`,
`tenantId`, `sourceId`, `kind`, `tokenSecret:{name,key}`,
`ports:{grpc,http,content?}`. Names match `^[a-z][a-z0-9-]{0,31}$`; ports
unique on a listener address; sources unique within tenant; credentials
different across groups. Maximum 64 groups by default (explicit ceiling
256); no on-demand registration service or fleet-management API. Legacy
single-binding values compile to one group; mixing old/new forms fails.

Rendered components per group B:

```yaml
# illustrative names; TLS/timeouts/body caps stay mandatory
receivers:
  otlp/B:                         # dedicated telemetry endpoints
    protocols:
      grpc:
        endpoint: 0.0.0.0:<B-grpc-port>
        auth: {authenticator: bearertokenauth/B}
processors:
  fabricguard/B:
    profile: production
    evidence_source_binding: {tenant_id: <tenant>, source_id: <emitted-source>}
# group B trace/log pipelines accept only otlp/B -> memory_limiter -> fabricguard/B
# Agent groups may also have otlp/content-B -> fabriccontent/B with the SAME
# source binding, credential, tenant and encrypted queue namespace.
```

Host groups are logs-only, have no content ingress and cannot submit agent
exchanges. Auditd and eBPF on the same host have DIFFERENT bound sources,
credentials and listeners. Do not feed the Node's local `audit` receiver
into an agent-bound pipeline. Deploy auditreceiver in a customer-selected
host sensor process/collector which exports only its own source group.
That producer is separate from the monitored agent and from Node admission.

Extend `gate/gate.go` to validate the entire merged pipeline graph per
group: one credential authenticator; no receiver/guard/content-exporter
cross-wiring; no unbound alternate receiver; no post-guard mutation;
duplicate keys rejected; source identity checked in every container.
Compare resolved credential bytes at startup without logging them or
their digests: separate paths with identical secrets must also fail.
Watch each credential file with current rotation semantics. Cross-group
identity or credential swaps fail; no fallback to a default binding.
TLS/mTLS, no-redirect egress, tenant constraints and encrypted queues
remain required. Multiple sources may share approved telemetry exporters
after guard stamping; content exporters retain separate binding/queue
instances even if they target the same customer store.

DaemonSet Nodes support a configured set of workload source labels per
node, epochs changing within each label. P1's per-process sources must
derive from configured clear labels and shared keys; a source not in the
static set cannot use a wildcard binding. Dynamic ephemeral source
onboarding is explicitly outside this iteration; use regenerated customer
configuration or separate Nodes. Parallel worker epochs under one source
label remain distinguishable. Bound ingress authenticates the source
credential, not an individual process or the truth of its reports.

### 6.2 Host record and protection path

Add shared Go producer support in `components/host-records/` (own Go
module) consumed by auditreceiver and host-emitter. It implements keyed
ids using existing vectors, source epoch/position allocation, event uid,
manifest/loss/heartbeat records and encrypted durable batch envelopes.
It is not a new product service. Python and Go emit the same record
contract; host source storage never shares the agent spool directory.

New capture/v1 host-record variant is an OTLP log record, not a forged
model span: standard X02/X04/X06/X22/X24/X26/X27/X47 metadata;
`capture.input=records`, capture point `host.auditd@<emitter-version>` or
`host.ebpf@<emitter-version>`,
provenance of its own observation `observed`. Host records can be retained
as sensor evidence without claiming N32 argv content or agent scope
completeness. C41 host/sandbox ids use hst-/sbx-; image digest only from
trusted configured/exposed identity, never inspect the filesystem.

Closed payload carries audit source/event/syscall/result enums, pid/ppid,
event timestamp, optional source cursor and loss counts. Preserve audit
serial as unsigned decimal text, stable `log.record.uid`, and precise
cursor generation. Link internal record event uid to replay uid once;
never mint a new event uid on replay. Add keyed peer host id through
existing `fabric.network.host_id`; port is a bounded numeric observation.
PID namespace, host boot and process-start discriminator, when supplied
by the sensor/configuration, are protected optional evidence in the
records carrier; no extra `/proc` reads. Missing discriminators weaken
joins, they never default to a globally meaningful PID.

Production default drops `process.owner`, executable name and raw
`network.peer.address`; raw argv/path/executable SHA digests are exported
only under an explicit digest-permitting policy. No raw command/path
content in this iteration's host stream. Counts, syscall/result enums,
pid and times are bounded metadata. Source/host/user/cgroup-derived
labels require keyed mapping or omission; do not use hashes as ids.
Sensor-local spool/checkpoint retains only minimized protected records
and necessary encrypted cursor state. Key failure disables host content
and sensitive metadata, never disturbs monitored workloads; the sensor
reports health uncertainty through safe counters where possible.

Logfile source commits accepted cursor only after protected batch durable
admission and downstream acceptance according to its existing replay
contract. Staged batch/ids survive restart and key rotation. Netlink
assembly eviction, socket overflow, missing source and eBPF ring loss
remain loss/health evidence, not invented sequence ranges for events
never observed. A position allocated by the producer must be a record or
counted loss. Unknown upstream missing-event cardinality is explicitly
unverified. Preserve eBPF partial-OTLP quarantine; partial success is not
full acceptance and cannot silently delete rejected evidence.

Guard validates host record shape/source before stamping
`fabric.source.authenticated=true`; remove caller-supplied stamps first.
Production host source is not enabled merely by choosing `production` in
the old local host-monitor example. Node/store trusted readback is required
for authentication verdicts; imported host logs remain authentication
unverified. No delivery receipts are automatically created or obtained.

### 6.3 Corroboration and projection

Extend reconstruct with `_channels.py` and `_host.py`. Host logs have a
separate sensor-evidence collection with source positions; they are not
added to the agent's sequence window or seal. `corroborated_by` links
reference sensor event ids. Use `pid_time_join`, provenance `inferred`,
confidence `tentative`, with host identity, pid namespace/boot/start
evidence when present, both clock uncertainties and a configurable
bounded time window (default 100 ms). Do not join across different hosts,
unknown key domains, uncertain clocks outside the window or overlapping
PID reuse. Multiple candidates produce `ambiguous` with every candidate;
no candidate is unresolved. A matching sensor never upgrades reported
content to observed or proves durable commit. Each log requires its own
manifest and source authentication; unauthenticated corroboration remains
visible as uncertain evidence and cannot satisfy a required agent field.

## 7. Contract deltas (apply in build WPs only)

Registry operations are keyed by id/key/role, preserving all columns not
named here. Bump registry revisions, family manifest minor versions and
pins atomically; regenerate 049 generated blocks in its owning change.
No Activity Envelope v2 change. No new statuses or core step kinds.

| File / exact row | Required operation |
|---|---|
| `capture-points-v1.json`, `db.dbapi.supplies` | Add `D24`; retain N30,N38–N42,D23; state names explicit observing sqlite factory and qualified psycopg versions |
| `field-registry-v1.json`, `D24.observed_by` | Add `db.dbapi`; phase `P3 (R), P4 (H)` |
| `capture-points-v1.json`, `file.audit.observes` | Replace with “Pre-operation open, os.rename, os.remove audit events: supplied path/mode/flags; outcome and existence unknown.” |
| Same, `file.audit.cannot_observe` | Add successful completion, existence, file bytes, fd-resolved paths; retain existing limits |
| Same, `db.dbapi.activation` | “Opt-in per driver; sqlite3 additionally requires caller-selected observing factory.” |
| Same, `exec.audit.observes` | Prefix “Pre-execution attempts”; retain supplied executable/argv/cwd; no completion |
| Same, `host.auditd.state`, `host.ebpf.state` | “Built local profile; P4 production: independent authenticated bound source, own protected encrypted cursor/spool, corroboration only.” |
| Same, both host rows `passivity_gate` | `P4-HOST, P4-BIND` plus existing 030/031 regression gate |
| Same, both host rows `supplies` | Add X02,X04,X06,X22,X24,X26,X27,X35,X47 to C41 |
| `field-registry-v1.json`, those nine X rows `observed_by` | Add both host capture-point ids; no change to field meanings |
| `telemetry-keys-v1.json`, existing process/db/network/file/commit rows | Retain validators/defaults; D24 emission phase adds `P4 (H)`; no free-text SQL/path/argv key |
| Same, `fabric.file.operation` (add row if absent) | change `changed`, field N45, phase P4; check `{type:enum, values:[open,read,write,append,truncate,rename,delete,stat,create]}`; synchronize Go admission without routing audit through the legacy four-operation Decision API |
| Same, `fabric.capture.source` / `fabric.capture.input` key placement | Add records-class admission for observed H/S producers and qualified W record variants; values remain the existing closed enums, with the trusted point/input/provenance restrictions of §3.1 |
| `vocabularies-v1.json`, `capture_input` wire meaning | “Automatic in-process tee of qualified model or allowlisted network traffic, including qualified realtime traffic; shares admission with records.” |
| Same, `capture_input` records meaning | Change “an opt-in hook” to “an H-class opt-in hook or out-of-process records producer”; preserve application reporting |
| `content-roles-v1.json` | No added role. Use existing terminal.*, artifact.locator/before/after/diff, database.*, network.*, mcp.*, remote.*, computer.* with their exact caps, boundary and provenance lists |

Schema changes: add `contracts/capture/v1/schema/host-record-v1.schema.json`
with closed host payload and standard record identity above; require
nonnegative positions, 63-bit epoch, dashed event uuid4, positive pid,
uint64-decimal serial/cgroup values and fixed source/event enums. Reuse
existing audit enum allowlists (never accept arbitrary strings). Include
manifest, loss and heartbeat variants in the same host log transport,
distinguished by registered record kind; they retain P1 counting rules.
The audit log allowlist must explicitly admit the standard identity,
capture, manifest/loss/heartbeat and C41 keys carried by this variant;
source binding and duplicate-key checks run before audit class filtering.
Only validated host variants may receive the authentication stamp. Existing
unbound/local audit logs remain readable and cannot manufacture a bound
source merely by supplying those attributes.
Add valid/invalid fixtures for duplicated identity keys, agent impersonation,
replay uid mismatch and unknown source kinds. Source markers contain no
`capture.input`. Transport auth stamp is receiver-owned and excluded from
emitter seal input. Closed content parser continues to reject agent-supplied
`source_authenticated`.

Extend P1's records schema with closed channel field evidence and the
tagged DB-value codec; CONTENT appears only as protected role locators
after admission. Extend its spool `record` branch to accept input=wire
only for the mutually exclusive W record discriminator of §3.1; update
Python/Go classification and canonical seal vectors atomically. Add an
optional protected `sensor_evidence` collection
and sensor-event link targets to step-projection/v1 if P1's event collection
cannot already represent them. It has standard event/source/capture
metadata plus closed host payload; imports preserve evidence but never
authenticate it. N23 pairing is projection data, not new telemetry keys.
Host auxiliary boot/namespace/start evidence lives in protected optional
`x-fabric.host_*` fields and never satisfies a required field. Use existing
schema extension mechanism; no arbitrary telemetry extension keys.

## 8. Work packages and ownership

All build agents work in a shared tree: do not revert others' changes.
Ownership below is exclusive unless a sequential handoff is named. These
are build instructions for a future swarm; this authoring task uses no
sub-agents and changes only this spec and 054.

| WP | Exclusive owner area | Dependencies | Deliverable, tests and own exit check |
|---|---|---|---|
| WP4-00 shared producer/router | `fabric/hooks/_producer.py`, `_config.py`, `_patches.py`, hooks public API; `wire/_routes.py`, wire install/config/model/transport integration | P1/P1-A, P2; WP4-01 contract freeze | Stable facade, opt-ins, same-kind D2/D3, ownership/recursion/fork guard. Unit/property admission/loss races, mixed explicit hooks, negative latency injection, privacy canary; exit: P1 invariant preserved with mixed inputs |
| WP4-01 contracts | `contracts/coverage/v1`, `contracts/capture/v1`, contract validator/generator tests | First; coordinate with 050/054 contract owner; sequential registry merge | Exact §7 operations, host/codec goldens, schema negatives, pins. C0-1..5; exit: validator and all pinned fixtures pass; 049 edits only by its owner |
| WP4-02 exec | `hooks/_exec.py`, tests `test_hooks_exec*` | WP4-00 | Popen/run/async and consumed output; driver ledger, cumulative timeout output, pipe identity, detach, credential canaries. Exit: P4-EXEC independently passes |
| WP4-03 audit/file | `hooks/_audit.py`, `_file.py`, tests `test_hooks_audit*`, `test_hooks_file*` | WP4-00; coordinate audit dedup token with WP4-02 | Single callback with separate flags; pre-call semantics, silent installation refusal, huge/malformed paths, fork recursion and raised BaseException. Exit: P4-AUDIT and P4-FILE each pass |
| WP4-04 DB | `hooks/db/`, `test_hooks_db*` | WP4-00; sqlite decision in §9 | Explicit sqlite factories, psycopg hooks and codec. Property row shapes/generators/transactions, server ledger, timeout-after-commit, custom factories/converters, privacy. Exit: P4-DB passes per qualified driver/variant; unsupported paths declared |
| WP4-05 network dialects | `hooks/_http.py`, `reconstruct/dialects/nonmodel_*`, `test_hooks_http*` | WP4-00 route table | Host rules, JSON-RPC/vector-store parser, redirects. Property host confusion/ports/path overlaps, partial consumption/cancellation, canaries. Exit: P4-HTTP; route integration handed back to WP4-00 |
| WP4-06 MCP/SSH | `hooks/_mcp.py`, `hooks/ssh.py`, their tests | WP4-00, byte-boundary contract from WP4-05 | Version-pinned transport hooks and explicit SSH wrapper. Fixture message/channel ledgers, reverse RPC, progress/cancel, auth redaction, reconnect; own P4-MCP and P4-SSH exits |
| WP4-07 host producers | `components/host-records/`, auditreceiver, host-emitter and their go modules/tests | WP4-01 host schema; no dependency on Python WPs | Protected/encrypted source records, manifests, replay/cursor semantics; property ids, corruption/key-rotation/restart, overflow/unknown loss, canaries. Exit: Linux audit and eBPF ledgers survive restart with no source-id churn/replay uid change |
| WP4-08 Node ingress | collector gate, fabricguardprocessor, fabriccontentexporter and own Go tests | WP4-01; independent of WP4-07 implementation | Per-source graph/stamp validation; forged/mixed identities, repeated keys, duplicate credentials, partial reject, restart tests. Exit: P4-BIND Go matrix; no broadening of old single-source path |
| WP4-09 deployment | `charts/`, `deploy/compose/` source-group configuration/preflights, related tests | WP4-08 schema freeze; sequential template ownership | Values schema, services/ports/secrets/network policy and static DaemonSet example; rendered bypass and cross-wiring negatives, two-agent/two-sensor production e2e. Exit: packaged chart/compose refuses every unbound route |
| WP4-10 reconstruction | `reconstruct/_channels.py`, `_host.py`, their tests | WP4-01, WP4-00/07 record goldens | Channel field wrappers, tentative sensor links and protected diff; property PID reuse/clock uncertainty/ambiguity, imported-stamp negatives, seal/dedup. Exit: C1-3/C1-5 with no false completeness |
| WP4-11 qualification/integration | `qualification/execution-channels/`; new runner/tests under `scripts/qualification/` and qualification-specific tests | Each WP's fixtures; final run sequential after WP4-09/10 | Agent matrix, chaos, UI reporting bridge, installed artifacts. Exit: all enabled channel gates plus P4-HOST/P4-BIND, C0A-2 and release-boundary tests pass |

Parallelize WP4-02..07/08/10 after shared interfaces/goldens freeze. Only
WP4-00 edits shared Python transport files. Only WP4-01 edits registries;
054 submits its deltas to that owner sequentially. TypeScript has its own
owners/tests after interface freeze and never gates Python P4.

## 9. Qualification, risks and open owner decisions

Add `qualification/execution-channels/matrix.json`, ledgers, reproducible
fixture servers/processes, canary corpus and `run.py`. Matrix rows key
capture point, runtime/client version, OS, sync/async path, operation,
boundary, role, privacy mode, input, expected field statuses and passivity
budget. Use real CPython/sqlite and psycopg/Postgres, MCP stdio/HTTP and
SSH fixtures. Agent-matrix clients call these channels without framework
adapters; direct unsupported clients are bypass cases. Store per-row
measured overhead, runtime pins and fresh customer-store readback.

Chaos adds queue saturation/disk full, slow or dead redaction service,
sender/Node restart, credential rotation, wrong-source ingress, audit log
rotation/truncation, eBPF ring overrun, killed/spawned workers, fork while
callback active and runtime shutdown before outcome. Lost/unwritten
events remain gaps; unknown kernel loss cannot become “zero”. Production
e2e uses two agent source groups plus auditd and eBPF groups; swapping
every pair of tokens, identities and content endpoints must fail. Compare
action ledger and application output with recording enabled/disabled.

Privacy canaries cover argv, env values, cwd/path, SQL/rows/DSNs, bearer
headers, query strings, MCP session/custom methods, SSH target, UI typed
text and sensor address/owner. Inspect decrypted test spool/checkpoint,
Node queue, telemetry, store descriptors, diagnostic logs and default
reports. Masked-only must never persist original; transformation failure
withholds, including derived diff. Same CLEAR ids correlate across hosts;
emitted-looking input strings are remapped; keys/tenants do not correlate.

Conformance mapping: P4-EXEC/AUDIT/DB/HTTP/FILE/MCP/SSH are the capture-point
gate ids in 049 §2.8; 049 §8.2 defines no separate numbered P4 suite.
P4-HOST/BIND/UI-R/JOIN are this spec's additional gates. Regress C0-1..5,
C0A-1..4, C1-1..5 and P1-A mixed-capture/qualified-run parity; new channels
must not imply 046 qualification. Run installed wheel/npm/chart/image
artifact-content checks via `scripts/tests/test_recorder_release_boundary.py`;
verify no evaluator, policy engine, enforcement or proprietary pack is
introduced. Qualification output, not draft manifests, changes claims.

| Risk / open decision | Recommended default and release consequence |
|---|---|
| SQLite immutable native types versus transparent global interception | Approve explicit observing factories as the qualified sqlite3 surface. Plain native connections stay declared uninstrumented. Until the §10 wording is accepted, factory implementation may proceed but full sqlite/P4 qualification is blocked; no proxy/unsafe C mutation workaround |
| Multi-source static ingress port/credential cardinality | Ship static per-source groups (64 default, 256 hard ceiling), including separate audit/eBPF groups. Dynamic authenticated source registration is a later design; do not call this arbitrary-workload DaemonSet support |
| Host digest leakage and tenant scope | Production sensor policy defaults omit low-entropy argv/path hashes and owner/address text; explicit digest permission required. Keyed host/source mapping always; exact existing DIGEST semantics retained |
| Which vector-store/SSH client versions qualify first? | One fixture-pinned vector-store HTTP dialect and one SSH library selected in WP4-01 qualification manifest; everything else unsupported. Freeze concrete names/versions before implementation merges, never advertise a family from one fixture |
| Concurrent audit refusal/host hooks and output capture limits | Capability enabled only after sentinel confirmation; no output/existence claim from audit. Unsupported events do not abort the action |
| Concurrent 050 marker uuid5 proposal versus 049's uuid4 contract | Freeze P1/049 marker vectors before host producer merge; recommend persisted uuid4, retaining the already approved contract |
| PID reuse/clock skew and host privilege | Joins tentative, namespace-aware where available; absent discriminator never upgraded. Sensors are customer-deployed and never installed/privileged by default |

These are bounded implementation choices or explicit scope clarifications,
not invitations to reopen approved decisions 1–20. Production host ingress
and multi-source binding are required P4 work by shared decisions 3/4.

## 10. Spec 049 deltas (for its owner; do not edit 049 here)

Line anchors refer to the supplied rev-6.3 worktree; include the quoted
text when applying if concurrent revision changes line numbers.

| Exact location / existing text | Proposed text |
|---|---|
| 049:118, “Opt-in hooks (P4/P5) also emit through the records input, with provenance `observed`.” | “H-class opt-in hooks emit through records with provenance observed. W-class http.nonmodel and rt.websocket retain capture.input=wire; both use shared admission, allocator, spool, PROTECT and verifier.” Update capture_input vocabulary rows at 441–442 consistently |
| 049:920 and 2701, “db.dbapi (sqlite3 and psycopg first)” | “db.dbapi: caller-selected observing sqlite3 Connection/Cursor factories and qualified psycopg methods first. Existing native sqlite3/custom-factory connections remain uninstrumented; no return-object proxy or native type mutation.” This is the open qualification-surface decision in §9 |
| 049:922 file.audit observes and N49 at 1473 | “PEP 578 events are pre-operation observations; open is not a read, rename/delete are attempts, and file existence/outcome remain unknown unless independently reported or observed at another qualified boundary.” |
| 049:928–929, host state “built (030/031)” | “Built local-profile sensors. Production binding is P4: each host.auditd/host.ebpf source has its own bound ingress, source/epoch and protected encrypted cursor/spool; sensor evidence provides corroboration only.” |
| 049:2427–2431, binding “today accepts only evidence logs and rejects every trace batch” | Replace stale current-state claim with “P0-A now binds trace batches and content descriptors as implemented; the currently deployed Node binds one agent source. P4 adds a finite set of dedicated single-source ingress groups and separate production host-source ingresses.” |
| 049:2700–2703, P4 work list | Append “production host ingress, separate bound ingress per host source; static multi-source Node binding for configured DaemonSet sources; browser/computer-use reporting through P2 records (observed ui.automation stays P5).” |
| 049:2704–2710, P4 exit | Append “Production host and multi-source claims require distinct audit/eBPF/agent credentials, source-swap and cross-pipeline rejection, encrypted sensor state, trusted readback and tentative namespace-aware corroboration.” |
| 049:202 and 2316, old whole-chunk/body size claims; 048 queue default 256 noted by CONTEXT | Refresh current-state citations to `_config.py:43–45,91–100`: 16384 entry ceiling AND shared byte budget, 32 MiB object/64 MiB side retention defaults. Do not describe 16384 as a byte limit. Existing typed extraction remains authoritative |
