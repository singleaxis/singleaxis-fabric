# Fabric chaos qualification — capture + delivery under failure, load and attack

Branch `test/chaos` at `22d1085` (feat/four-layer-p0a). Node image `fabric/node:chaos`,
built 2026-10-19 21:59 IST from that tree. Host: macOS (Apple silicon), Docker Desktop.
Model: a loopback OpenAI-compatible fake (`lib/fakemodel.py`); no real keys, no network
egress. The Node is the shipped Compose production profile
(`docker-compose.yml` + `.production.yml` + `.content.yml`, `.s3-eval.yml` for the S3
cases) with its documented TLS edits, a bound source, sealed content store, and an HTTPS
fsync sink standing in for the customer destination. Fabric code was not modified.

## Invariants

| Id | Assertion | How it is checked |
|----|-----------|-------------------|
| I1 | App results, exceptions and latency unchanged within budget | per-call ledger (fsync'd) vs expected bytes; exception classes vs baseline; thread-path p50 overhead ≤ 5 ms |
| I2 | `fabric.reconstruct` never reports complete when anything was lost | every run reported `complete_*` must hold a verified exchange for every request the model served for it (model log = ground truth) |
| I3 | No protected content (canary) or its digest outside the content store | sink records + raw bodies, Node logs, agent stderr, reconstruct report, spool files, Node volumes |
| I4 | Spool on disk ≤ bound (+1 MiB reserve) | 20 Hz sampler over `.rec`/`.tmp-`/`.corrupt`/`.ack` |
| I5 | After recovery every record is delivered or accounted | (a) every exchange on disk at the fault reaches the sink; (b) spool empty; (c) **new:** Node exporter queues empty at teardown and served-but-missing ≤ drops the agents reported |
| AUTH | (added) A record is never attributed to a source that did not send it | S6 T1/T6 |

## Summary

| Scenario | I1 | I2 | I3 | I4 | I5 | Notes |
|----------|----|----|----|----|----|-------|
| S1 concurrency (200 threads + 1000 asyncio tasks, 12k calls, 50% SSE) | ✅ | ✅ | ✅ | ✅ | ✅ | 45.5% of exchanges load-shed (accounted, run reported `partial`) — D4 |
| S2a kill -9 loop (250 attempts, 224 SIGKILLs landed: random, protect, send, spool-write, mid-stream) | ✅ | ✅ | ✅ | ✅ | ✅ | 0 corrupt, 0 falsely complete |
| S2b fork / mp fork·spawn·forkserver / gunicorn --preload / uvicorn --workers | ✅ | ✅ (run 1) | ✅ | ✅ | ✅ run 1 / ⚠️ run 2 | run 2: reconstruct OOM-killed (**D6**), drain window too short (H6) |
| S3 Node kill -9 ×2 + restart mid-batch | ✅ | ✅ | ✅ | ✅ | ✅ | 1261/1261 delivered |
| S3 Node down 10 min | ✅ | ✅ | ✅ | ✅ | ✅ | 1451/1451 delivered, 146/146 complete |
| S3 S3-store down 207 s | ✅ | ✅ | ✅ | ✅ | ✅ | 1101/1101 |
| S3 S3-store +1.5 s/packet for 92 s | ✅ | ✅ | ✅ | ✅ | ✅ | 801/801 |
| S3 agent spool disk full (24 MiB HFS+ image, real ENOSPC) | ✅ | ✅ | ✅ | ✅ | ❌ | **D1**: 469 exchanges lost, 18 runs vanish without any record (the run predates `check_i5_accounting` and printed I5 held; `reaudit.py` finds 469 unaccounted) |
| S3 Node content queue full (40 MiB tmpfs behind a full 16 MiB store) | ✅ | ✅ | ✅ | ✅ | ✅ | queue hit 64 batches; after growing both tmpfs, drained to 0; 234 drops = 234 missing |
| S3 Node content store full (16 MiB tmpfs) | ✅ | ✅ | ✅ | ✅ | ✅ | backpressure to the agent spool (66.6 of 65+1 MiB); after growing the tmpfs, 183/183 spooled records delivered; 188 drops = 188 missing |
| S3 agent clock ±2 h, −1 h step mid-run | ✅ | ✅ | ✅ | ✅ | ✅ | 253/253 complete |
| S4 network: latency, 25% loss, 5% corruption, partition, RST, flapping | ✅ | ✅ | ✅ | ✅ | ✅ | 4601/4601 delivered (after harness fix H1) |
| S5 payloads (0 B…100 MiB, deep JSON, bad UTF-8, 1M SSE, gzip/brotli) | ✅ | ✅ | ✅ | ✅ | ✅ | every verdict honest |
| S6 adversarial (T1–T10) | ✅ | ✅ | ✅ | ✅ | ✅ | AUTH ❌: **D2** duplicate-key source spoof, **D3** plaintext spool downgrade |
| S7 soak 120 min @ ~9.8 calls/s | ✅ | ✅ | ✅ | ✅ | ✅ | agent flat; Node memory = reclaimable slab — D5 |

## Scenario details

**S1 concurrency.** One process: 200 threads (6000 calls) + an asyncio loop with 1000
concurrent tasks (6000 calls), 50% streaming, against the production Node; the same
workload first without capture (baseline). Thread path p50/p99/max: baseline 1.52/20.0/175
ms, captured 2.19/7.9/32.9 ms (+0.67 ms p50). Async path: baseline 5.0/29.3/39.2 s,
captured 7.7/37.3/57.6 s (CPU-saturated loop, see D4). 6536 exchanges delivered, 5464
dropped `queue_full` and accounted (6536 + 5464 = 12000 − 1 `ReadError`); reconstruct:
`partial`. Spool peak 1.9 MB of a 257 MiB bound.

**S2a kill -9 loop.** 250 agent processes with `CHAOS_FAULT` hooks (`lib/hooks`) that
SIGKILL at a random instant, inside PROTECT, inside the sender (after a body was accepted,
after export before retire), inside `Spool.write` (before/after open, write, pwrite,
fsync, close, rename), or mid-SSE-stream; 224 kills landed at 15 distinct steps. After a
clean recovery agent: 147 records on disk at the fault, all delivered; 0 `.corrupt`; 212
runs reported — 35 complete (all verified against the model log), 7 partial, 170
unverified (every mid-stream kill is `unverified`, correctly); 0 falsely complete. App p50
1.8 ms, p99 11.9 ms.

**S2b fork / multiprocessing / server workers.** One shared spool and Node. Per start
method (`os.fork`, `mp` fork/spawn/forkserver), a parent captured by the autoload runs a
busy loop of scoped calls while 4 children each make 6 calls in their own run, with and
without `flush()` in the child; then gunicorn `--preload` (sync workers forked after
capture is installed) and uvicorn `--workers` (spawned), 300 requests each with worker
SIGKILLs and reloads. Run 1 (`results/s2-fork-v1`): 40,341 calls, 0 app failures, all
I1–I5 held, 4279 runs complete and 0 falsely complete; gunicorn 300/300 and uvicorn
300/300 delivered and complete. Run 2 (with per-process stats added): 46,208 calls, 0 app
failures, I1/I3/I4 held. The stats confirm the run-1 hypothesis: each parent's busy loop
**shed 5,729–8,029 exchanges** (`dropped`, accounted; D4), and children that exit with
`os._exit` leave 12–20 queued jobs unprocessed (no atexit; those runs are never reported
complete). Run 2's reconstruct was SIGKILLed by the OS (D6), so I2 could not be judged
in-harness, and 2648 of 6740 spooled records were still pending when the recovery agent's
180 s flush ended (H6). In those 180 s a single drainer cleared 4092 records
(**~23 records/s, ~75 KB/s**), a slow but correct recovery rate. Fork children's
`flush()` returns `False` by design (they only write; the parent drains).

**S3 Node faults** (steady load: back-to-back agent processes, 20 calls each, 2 threads).

| Case | Fault window | Served | At sink | Runs complete | Spool peak | App p50/p99 |
|------|--------------|-------:|--------:|--------------:|-----------:|------------:|
| kill_restart | kill -9 at 20 s, start 31 s, graceful restart 52 s, kill -9 + immediate start 69 s | 1261 | 1261 | 43/43 | 0.4 MB | 2.3/10.2 ms |
| down10 | Node stopped 600.6 s | 1451 | 1451 | 146/146 | 5.6 MB | 1.4/5.6 ms |
| store_down | SeaweedFS stopped 207.8 s | 1101 | 1101 | 56/56 | 2.5 MB | 1.3/4.1 ms |
| store_slow | netem 1500 ms on the store, 92 s | 801 | 801 | 41/41 | 1.0 MB | 1.3/4.5 ms |
| spool_full | Node stopped 90.6 s, spool on 24 MiB volume | 1341 | 872 | 44/49 reported | 24.2 MB (disk) | 1.5/3.1 ms |
| clock_skew | agents +2 h, −2 h, −1 h step mid-run | 3031 | 3031 | 253/253 | 0.1 MB | 1.2/11.8 ms |

`store_full` and `queue_full` (re-run with an in-place `tmpfs` grow, H3): with the store
full the Node refuses content, agents keep records on the spool up to the 64 MiB bound
(peak 66.6 MB, within bound + reserve), then drop and count new exchanges
(`spool_full_drops`; reconstruct `partial` for all 19 / 22 runs, none complete). After the
grow, everything drained: store_full 183/183 spooled records delivered, Node queues 0 in
7 s; queue_full reached `fabriccontent` queue depth 64 during the fault and drained to 0.
In both cases served-but-missing equals exactly the agent-reported drops (188, 234):
nothing acknowledged was lost. App p50/p99 3.8/8.3 ms and 3.1/9.9 ms (512 KiB bodies).

During outages agents exit with `flush()` = `False` after their 5–8 s budget (never
blocking the app beyond it); the next process drains the shared spool when the Node
returns. Node memory during store outages: ~20 MiB.

**S4 network** (netem/iptables in the Node's namespace from a pinned netshoot sidecar,
60 s each, 15 s gaps): `delay 400ms 100ms`, `loss 25%`, `corrupt 5%`, DROP on 4318/4319
(silent partition), REJECT tcp-reset, 2 s/2 s flapping for 124 s. 4601/4601 served
exchanges delivered, 231/231 runs complete, 0 agent failures, app p50/p99/max
1.3/4.2/35.7 ms, spool peak 8.9 MB of 65 MiB, Node queues drained to 0.

**S5 payloads** (each case without and with capture; app result identical in every case):

| Case | Verdict | Why |
|------|---------|-----|
| 0 B request, 1 B request, invalid UTF-8 request/response, 100k-deep JSON request/response | `unverified` (`unparsed_exchange`) | bytes stored and verified; reconstruct refuses to claim it parsed them |
| gzip response, brotli response, 63 MiB request, 63 MiB response, 200k SSE events | `complete_for_observed_scopes` | verified end to end |
| 65 MiB and 100 MiB request (over the 64 MiB cap) | `partial` (`truncated`) | request object `not_stored`, `body_cap` |
| 80 MiB response, 1M SSE events | `partial` (`truncated`) | stored truncated, `body_cap` |

Capture added ≤ 0.1 s to the 1M-event stream (13.36 → 13.46 s wall) and ~2 s to the
63 MiB cases (protection + fsync of 63 MiB, off the app's response path: per-call latency
unchanged). Spool peak 132 MB of a 289 MiB bound; Node memory 300 MiB at the end
(large bodies).

**S6 adversarial** (raw OTLP with the Node's real ingress token):

| Test | Result |
|------|--------|
| T1 duplicate `fabric.source_id`, bound first | ❌ accepted, delivered authenticated with the foreign id (D2) |
| T1 duplicate, foreign first | ✅ 400 |
| T2 sender-set `source_authenticated` on content | ✅ stamp not honoured (receiver-owned) |
| T3 wrong source binding: span / content | ✅ 400 / acked then dropped `source_unbound`, not stored |
| T4 cross-tenant content | ✅ dropped `tenant_not_allowed`, not stored |
| T5 replay identical / changed bytes same id | ✅ idempotent / dropped `conflict`, stored object unchanged |
| T6 spool truncate, bit flip, rename | ✅ 6/6 quarantined each |
| T6 spool plaintext downgrade | ❌ 6/6 accepted (D3) |
| T7 bit-flipped sealed Node directory → reconstruct | ✅ `partial`: 7 `digest_mismatch`, 4 `missing_object`, `tail_unverified`; no canary in report |
| T8 1200 fuzzed descriptors through the Node | ✅ no crash, no canary in sealed store or logs |
| T9 `../../../../etc/passwd` object id | ✅ dropped `bad_descriptor`, nothing outside the store |
| T10 2 MiB attribute value, 2000 attributes | ✅ accepted, stripped by the allowlist before the sink |

**S7 soak — 120.05 min** (stated honestly: one run, one host; 4 threads, ~9.8 paired
calls/s, each call made once without and once with capture so added latency is pairwise;
70,540 captured calls, 7054 runs).

| Window (10 min) | added p50 µs | added p99 µs | baseline p50 µs |
|---:|---:|---:|---:|
| 0 | 167 | 3368 | 1053 |
| 1 | 265 | 11298 | 1875 |
| 2 | 217 | 8466 | 1332 |
| 3 | 209 | 3659 | 1285 |
| 4 | 165 | 2598 | 1008 |
| 5 | 148 | 2677 | 954 |
| 6 | 372 | 3062 | 1671 |
| 7 | 251 | 3095 | 1547 |
| 8 | 426 | 3104 | 1705 |
| 9 | 440 | 3156 | 1787 |
| 10 | 459 | 3198 | 1725 |
| 11 | 416 | 2964 | 1753 |

Overall added p50 226 µs, p99 3.57 ms. Added p50 roughly doubled in the second hour
(150–265 → 416–459 µs) while the baseline p50 also rose (~1.0 → ~1.7 ms), so it tracks host
load, not a trend in Fabric; the 30-min S7-mem re-run held flat at 134–223 µs. Agent
process: RSS 66 MiB at start, 36.5–50 MiB steady, slope −1.1 MiB/h in the second half;
FDs 6 → 18 (max 19); threads 4 → 10; spool 0–28 KB (bound 257 MiB); queue depth 0;
0 drops, 0 internal errors; 84,648 records spooled = delivered; reconstruct 7054/7054
complete. Node: see D5.

## Ranked defects

Order by severity: **D1** (P1) disk-full loss without evidence · **D2** (P1) duplicate-key
source spoof · **D6** (P1) reconstruct quadratic blow-up · **D3** (P2) plaintext spool
downgrade · **D4** (P2) capture throughput ceiling · **D5** (P3) content-store file count.
P0 (silent loss of acknowledged data, a false `complete`, or a content leak) was **not**
found in any scenario.

### D1 (P1) — Disk-full spool loses exchanges *and* the evidence of their loss

**Observed (S3 spool_full).** Node stopped, agent spool on a 24 MiB volume with the
default 1 GiB bound, so the disk fills before the bound. 1341 calls served, 872 reached
the destination, 469 never did. The agents reported `dropped=0`, `spool_full_drops=0`,
`internal_errors=469`, `markers_dropped=38`. Runs `sf-9`…`sf-26` (18 processes, 360
exchanges) have **no record at all** at the destination — not an exchange, not a loss
range, not a heartbeat — so `fabric.reconstruct` cannot even report them `partial`; they
simply do not exist. I2 technically holds (nothing is reported complete), but the record
is silently incomplete, which is the failure Fabric exists to prevent. The application
was unaffected (I1 held, 0 failures).

**Minimal repro.**
```bash
hdiutil create -size 24m -fs HFS+ -volname s /tmp/s.dmg && hdiutil attach /tmp/s.dmg -mountpoint /tmp/s
# Node stopped (or any unreachable FABRIC_* endpoint); FABRIC_WIRE_SPOOL_DIR=/tmp/s/spool,
# FABRIC_WIRE_SPOOL_MAX_BYTES unset (1 GiB); 20 calls per process with 256 KiB bodies in
# back-to-back short-lived processes for 90 s; then start the Node and drain.
.venv/bin/python s3_node_faults.py --case spool_full --down-s 90
python3 reaudit.py results/s3-spool_full   # unaccounted: 469
```

**Hypothesis.** `Spool.write` (`sdk/python/src/fabric/wire/_spool.py:583-597`) re-raises
the `OSError(ENOSPC)` from `os.write`/`fsync`; `_Pipeline._spool`
(`sdk/python/src/fabric/wire/_pipeline.py:416-420`) catches it as a generic
`internal_error` instead of mapping it to the `queue_full`/spool-full outcome, and the loss
range recorded by `_lose` (`_pipeline.py:240-241`) lives only in memory: writing the loss
record hits the same full disk (`markers_dropped`), and a process that exits during the
outage takes it with it. The 048 §2 disk admission check in `_reserve`
(`_spool.py:438`) did not prevent the writes on HFS+. Fix direction: treat ENOSPC/EDQUOT
as spool-full; reserve (preallocate) room for loss/marker records so the evidence of loss
is always durable; and surface a source-level gap when a process exits with unwritten
loss ranges.

### D2 (P1) — Duplicate `fabric.source_id` keys let a bound agent attribute spans to another source, stamped authenticated

**Observed (S6 T1).** A trace span carrying `fabric.source_id` twice — the bound source
first, a foreign `s-ffff…` second — is accepted (HTTP 200), stamped
`fabric.source.authenticated=true`, and delivered with both keys. Any last-wins consumer
(Python protobuf→dict, the sink JSONL, `fabric.reconstruct --spans` input) reads the span
as an *authenticated* span from the foreign source. The foreign-first order is refused
(400). Reproduced on both runs (`results/s6-v1`, `results/s6`).

**Minimal repro.** `lib/rawclient.py` `RawClient.trace([[... , ("fabric.source_id", bound),
("fabric.source_id", "s-" + "f"*32)]])` with the Node's ingress token; then
`grep s-ffffffff results/s6/node/sink/records.jsonl`.

**Hypothesis.** `boundTraceBatch`
(`components/otel-collector-fabric/processor/fabricguardprocessor/processor.go:532-540`)
checks `attrs.Get("fabric.source_id")`, which returns the *first* match; nothing rejects
or dedupes repeated keys, and `PutBool(sourceAuthenticatedKey, true)` (`processor.go:519`)
then authenticates the whole span. Fix direction: refuse any batch whose resource, scope
or span attributes repeat a key (at least any `fabric.*` key), before binding checks.
Requires the bound source's ingress token (a buggy or compromised agent), hence P1 not P0.

### D6 (P1) — `fabric.reconstruct` blows up quadratically on loss-heavy sources (10 GB RSS, 5 GB report)

**Observed (S2b run 2).** Over a 35,682-span sink and a 298 MB sealed store (16,261 runs
from 4 sources that each load-shed thousands of exchanges), the in-harness reconstruct was
SIGKILLed by macOS (exit −9). Re-run by hand under `/usr/bin/time -l`: **442 s, peak RSS
10.1 GB, peak memory footprint 32 GB, report 4.97 GB**, with **8.33 M gap entries**
(7,680 runs carry > 100 gaps each, max 2,356). The verifier fails exactly when there is
loss to report: it is the tool that tells the customer what is missing.

**Minimal repro.** One process, one source: 1000+ short scoped runs while the capture
queue sheds load (e.g. `fork_agent.py --parent-busy` or S1 with a small
`FABRIC_WIRE_QUEUE_MAX_ITEMS`), so the source has thousands of fragmented
`missing_sequences`; then `python -m fabric.reconstruct --spans records.jsonl ...` and
watch RSS grow with runs × missing ranges.

**Hypothesis.** `_near_gaps`
(`sdk/python/src/fabric/reconstruct/_verify.py:704-722`, spec 047 §9.5 rule b) adds
**every** missing segment of the source at or after a run's window as its own
`unverified` gap to **that run**, and the open-ended `_inside_gaps(key, high + 1, None)`
(`_verify.py:676`) does the same for unclosed scopes; each becomes a `Gap` object and a JSON
entry per run (`_verify.py:742-757`). Gap count is O(runs × later missing segments). Fix
direction: one aggregated "later loss on source S from sequence N" gap per run referencing
the source-level `missing_sequences`, which the report already carries once per source;
stream the report.

### D3 (P2) — A keyed (encrypted) spool accepts plaintext records

**Observed (S6 T6).** Replacing each sealed spool record with its valid plaintext
`FWSPOOL1` frame: all 6 were read back and sent to the Node as the bound source (the
spool drained, none quarantined). Truncation, bit flip and rename were all correctly quarantined
(`.corrupt`, 6/6 each). So anyone who can write the spool directory, without the spool
key, can inject arbitrary records that the agent delivers under its bound source identity
(and the Node then stamps authenticated).

**Minimal repro.** `_downgrade` in `s6_adversarial.py`: `open_spool_record(p, key)` →
write the frame back to `p` → run a clean agent with the same `FABRIC_WIRE_SPOOL_KEY*`.

**Hypothesis.** `unseal` (`sdk/python/src/fabric/wire/_spool.py:101-102`) returns any
data not starting with `FWSPENC1` as-is even when a cipher is configured (a migration
allowance for records "written before the envelope was configured"). Fix direction: with a
key configured, refuse plaintext records (quarantine), or allow them only up to a recorded
cut-over marker. P2 because it needs write access to a 0700 spool directory.

### D4 (P2, capacity) — One capture worker per process: ~90 exchanges/s ceiling, then load-shed

**Observed (S1).** 200 threads + 1000 asyncio tasks in one process offered ~170 calls/s;
6536 of 12000 were captured, 5464 (45.5%) dropped as `queue_full`. Drops are accounted
(`dropped` counter, loss ranges), reconstruct reports the run `partial`, the app was
unaffected on the thread path (+0.67 ms p50) — this is the designed shed-don't-block
behavior, but the ceiling is low. On the asyncio path, end-to-end latency rose from
p50 5.0 s / p99 29.3 s (baseline) to 7.7 s / 37.3 s and wall time 51.9 s → 70.8 s
(+36%): with 1000 tasks the loop is CPU-saturated and the capture hook's per-call work runs
on it. 1 `ReadError` with capture vs 0 in baseline (not significant at n=1).

**Hypothesis.** A single `fabric-wire-capture` worker thread
(`_pipeline.py:237`) behind a 256-item queue (`_config.py:93`, `_pipeline.py:249-254`)
does protection (hashing, AES-GCM, framing, fsync) for the whole process under the GIL.
Fix direction: document the ceiling; batch fsyncs; consider a worker pool or moving
digest/encrypt out of the hot loop.

### D5 (P3, operational) — Node memory in `docker stats` grows with the content store's file count; not a heap leak

**Observed (S7, 120 min).** `docker stats` for the Node rose from 18 MiB to 323 MiB, about
4 MiB/min after minute 53, with no plateau (two drops, at 16 and 45 min, to ~60–77 MiB).

**Diagnosed (S7-mem, 30 min re-run with collector metrics and cgroup `memory.stat`).**
Go heap stayed at 9–15 MiB, collector RSS 35–53 MiB, cgroup `anon` 26–29 MiB, all flat.
The growth is kernel memory: at minute ~13, `docker stats` 71 MiB = anon 29 + active page
cache 10 + **slab 35 MiB, 34 MiB of it reclaimable** (dentry/inode cache) for **37,344
files** in the content store: two files per object (`<tenant>/evidence/<id>` and
`<tenant>/evidence/meta/<id>.json`), two objects per exchange, in two flat directories
(19,090 entries each at that point). Reclaimable slab counts
against a container memory limit but is reclaimed under pressure, so this is not a leak.
It is a sizing signal: at 10 exchanges/s the file store creates ~4 M files/day, which
exhausts inodes on a default ext4 volume long before bytes run out, and makes
`du`/backup/retention walks and lookups slow as two single directories reach millions of
entries. The layout is by design (`exporter/fabriccontentexporter/record.go:616,620`,
`doc.go:11-12`); fix direction: shard the directories by id prefix, and alert on inode use,
not only bytes.

S7-mem samples (Node, every ~3 min; `docker stats` vs the collector's own numbers):

| min | `docker stats` MiB | collector RSS MiB | Go heap MiB | content store MiB |
|----:|---:|---:|---:|---:|
| 0.0 | 17.0 | 40.8 | 12.4 | 0.1 |
| 6.4 | 52.3 | 49.4 | 9.7 | 13.5 |
| 12.8 | 55.4 | 33.8 | 12.1 | 26.9 |
| 19.2 | 83.1 | 38.7 | 9.7 | 40.3 |
| 25.7 | 41.5 | 38.1 | 14.9 | 54.1 |
| 28.9 | 62.5 | 38.3 | 11.9 | 60.8 |

The `docker stats` swings (83 → 41 MiB) are the kernel reclaiming that cache; the
collector's heap never trends.

## Observations (not defects)

- **Content ingress acks before judging.** Mis-bound (T3), cross-tenant (T4), traversal
  (T9) and fuzzed (T8) content records get HTTP 200, then are dropped asynchronously with a
  counted reason (`source_unbound`, `tenant_not_allowed`, `bad_descriptor`, `conflict`) and
  never stored. A *legitimate* agent whose record is dropped as `bad_descriptor` also
  believes it delivered. Acceptable for adversarial input; worth a metric/alert.
- **Spool temp files after SIGKILL.** 34 `.tmp-*` files (66 KiB) remained after the kill
  loop; they are counted against the bound (I4) and swept after `RECEIPT_TTL_S` = 1 h
  (`_spool.py:43,777`). By design.
- **Fork children cannot flush.** `fabric.wire.flush()` in a fork/mp child returns `False`
  (children only write; the parent holds the drain lock). Children's records are delivered
  by the parent or the next drainer. Documented behavior, but surprising to callers.
- **Whole-run loss is invisible per run.** When every exchange of a run is dropped, the loss
  is recorded per source sequence, not per run, so reconstruct cannot list that run at all.

## Harness defects found and fixed during this qualification

These changed verdicts; the affected scenarios were re-run.

- **H1 — test sink wedged under netem.** `scripts/tests/_wire_capture_sink.py` wraps the
  listening socket with the TLS handshake in `accept()` on the only accept thread, no
  timeout. During S4's 5% corruption phase one stalled handshake froze the sink at t=152 s
  for the rest of the run; the first S4 run showed 2814/4101 exchanges "missing" while
  the Node held them in its persistent queue. `lib/sink.py` defers the handshake to the
  handler thread with a 30 s socket timeout. Re-run: 4601/4601 delivered. (The e2e sink
  is test code; worth the same fix there.)
- **H2 — I5 blind spot.** I5 only covered records on the agent's disk at the fault, and
  `wait_for(node queues == 0)` timed out silently, so the wedged-sink S4 run was reported
  *held*. Added `check_i5_accounting` (Node queues empty at teardown; served-but-missing ≤
  agent-reported drops) and `reaudit.py` to apply it offline to every saved result.
- **H3 — `*_full` cases never cleared the fault.** store_full left the store full, so I5
  failed by construction; queue_full never filled the queue. Both now use a capped store,
  then `resize_tmpfs` grows the tmpfs in place via `setns`+`mount(2)` from a privileged
  sidecar (the distroless Node has no `mount`), and require a full drain.
- **H4 — T8 fuzz never reached the Node.** 1092/1200 fuzzed descriptors failed inside the
  SDK encoder client-side. `rawclient` now hand-encodes what the encoder refuses: 1200/1200
  reached the Node — 0 crashes, 0 canary in the sealed store or logs.
- **H5 — mislabeled findings.** T1/T6 were reported as I3 (content leak); they are
  authenticity failures, now reported as AUTH.
- **H6 — S2b drain window.** The recovery agent's 180 s flush was the only drainer, and
  the following 300 s wait drained nothing, so run 2 left 2648 records pending (I5 ❌ by
  construction). The recovery flush is now 1200 s. Reconstruct's peak RSS is now recorded
  in every verdict (`reconstruct_peak_rss_bytes`).
- **Networks.** Every stack now joins one pre-created `fabric-chaos-net` bridge (Docker
  address pools on this host are near exhaustion); stacks therefore run one at a time.

## Limits of this qualification

- One host: macOS on Apple silicon, Docker Desktop's Linux VM. Not run on a Linux host or
  under Kubernetes. D1 was reproduced on HFS+ only; ext4/xfs `ENOSPC` paths are untested.
- Network faults used `tc netem`/`iptables` in the Node's namespace (agent→Node and
  Node→sink/store share it); toxiproxy was not used. Node→destination faults beyond those
  phases were not isolated.
- The Node's clock cannot be skewed per container on Docker Desktop: only agent clocks were
  skewed.
- gunicorn ran sync workers with `--preload`; gevent/eventlet workers were not tested.
- Soak: one 120 min run and one 30 min run at ~10 calls/s. Longer or faster soaks may
  surface effects these did not.
- Results directories (`results/`) and logs are not committed (gitignored); every number
  here comes from `results/*/verdict.json` produced by the committed harness, or from
  `reaudit.py` over those results.

## Reproduce

See `run_all.sh` (serial order, ~4.5 h with the 120 min soak). Each scenario writes
`results/<name>/verdict.json`; `reaudit.py results/*` re-checks end-to-end accounting.
