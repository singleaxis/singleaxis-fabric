# `ts-wire-passivity`: the Node passivity gate

Spec 055 §9.2. Proves, on one exact Node.js build, that the `wire.ts.undici`
capture hook does not change or slow the agent beyond fixed budgets. CI runs
it as the `ts-wire-passivity` job on every tuple that
`sdk/typescript/wire-qualification.json` makes `active`, and fails the PR
when any gate fails.

```sh
cd sdk/typescript && npm ci && cd ../..
node qualification/node-wire/passivity/run.mjs --out report.json
node qualification/node-wire/passivity/run.mjs --quick --out smoke.json   # local smoke, never a qualification report
```

`run.mjs` bundles the capture from the SDK source and compiles the native
lock module for this machine (`lib/build.mjs`, which needs a C compiler; the
packed package replaces it from unit 055-t14), runs every measurement in
fresh child processes and writes one JSON report. It exits 1 when a gate
fails, when a self-test does not fail on its injected fault, or when the
calibration voids the run twice.

Steps (child script, then what fails the gate):

- **Calibration** (`calibrate.mjs`): `scale = clamp(min(before, after) /
  reference, 1, 4)`. Before and after more than 2x apart voids the run, which
  repeats once; a second void fails.
- **Hook cost** (`cost.mjs`): arms `baseline`, `disabled` and `enabled` in
  isolated processes, 30 alternating trials. The median added time per matched
  non-streaming exchange, per 1 KiB stream chunk and per non-matching request
  must stay within 50 µs, 2 µs and 5 µs × scale, by two methods: undici's own
  publications built as undici builds them (no network noise), and real global
  `fetch` calls to a loopback HTTP/SSE provider, timed between marker
  subscribers placed before and after the hook (median per request and per
  chunk, so a garbage-collection pause a hook happens to trigger is not
  charged in full to one sample). An enabled trial that refused
  a chunk, or a stream whose chunks were not 1 KiB, voids the step.
- **Gate self-test** (`cost.mjs` and `eventloop.mjs`, arm `stall`): a stall of
  twice each scaled budget injected between the hook and the end marker, and a
  main-loop stall of twice the scaled maximum delay, must each fail their gate.
- **Event loop** (`eventloop.mjs`): 16 clients at a model's pace (JSON after
  10 ms, 40 SSE events 5 ms apart), 3 alternating rounds. Baseline-subtracted
  p99 delay within 2 ms × scale, maximum within 25 ms × scale, utilization
  delta within 0.05 on the application loop, with a timer-drift probe. An
  unpaced stress case (about 100x an agent's call rate) is reported and not
  gated. The 60 s sustained case is below (unit 055-t13).
- **No forbidden work** (`forbidden.mjs`): trip-wires on synchronous `fs`,
  `net`/`tls`/`http` sends and global `fetch`, `crypto` hashing, `JSON.parse`/`stringify`,
  `Atomics.wait`, `console` and stdout/stderr writes, armed only while a hook
  callback runs, never fire over every hook path; a canary between the markers
  must trip them.
- **Behaviour identity** (`identity.mjs`, `identity.cjs`): the global `fetch`
  row as an ES module and a CommonJS application, capture off then on.
  Server-received bytes, response bytes and chunk boundaries (lockstep), chunk
  types, abort reason identity, abort and transport error classes,
  backpressure, keep-alive, the caller's request buffer and the exit code must
  be identical.
- **Large shapes** (`large.mjs`, unit 055-t8; 40 and 70 MiB from 055-t15):
  matched requests of 0 B, 64 KiB, 1 MiB and 32 MiB through real `fetch`, once
  as one in-memory body (undici publishes it as one chunk: the largest single
  snapshot copy) and once streamed in 64 KiB chunks. The report lists, per
  shape, the bytes copied, the publications and the longest synchronous time
  one publication spent in the hook; these shapes are never averaged into the
  small-body medians. Fails when one publication exceeds 25 ms × scale or a
  shape lost a position.
- **Memory bound** (`memory.mjs`): tiny-chunk storms and zero-body requests in
  10 batches with small configured bounds, with the Fabric worker draining and
  with none (saturated). RSS over baseline within the shared buffers' maximum
  plus per-entry, worker-isolate and slack bytes; the last batch's excess no
  higher than the first half's highest (after warm-up) plus 8 MiB, so a
  one-time allocator step is not growth but a steady leak is; heap flat after
  GC; pool peaks within their bounds; no exchange left open.

- **Stalled recorder** (`recorder.mjs`, unit 055-t13; 055-t16 adds ledger
  and disk-full faults): the whole recorder (explicit `install()` of the wire
  core, the capture pipeline and the sender delivering to a loopback Node, built
  by `lib/build.mjs` as `lib/recorder.ts`) under a paced fan-out of 8 clients
  where every fourth SSE stream is cancelled after 5 events. Arms, each 3
  rounds against the baseline: `enabled`, `stall-fsync` (every spool file fsync
  waits 200 ms), `stall-sender` (the Node never answers), `stall-redaction`
  (the response role is `redact`, the redaction service never answers),
  `stall-admission` (the application thread holds the spool's admission lock)
  and `saturated` (the capture worker takes 200 ms per exchange). The faults
  live only in the harness's worker entry (`lib/recorder-worker.ts`), never in
  the SDK. Fails when requests fall below 95% of the baseline's, a response's
  bytes differ, a cancelled stream ends in another error than `AbortError`, an
  error, rejection or stderr byte reaches the application, or the event-loop
  budgets above are exceeded.
- **Sustained event loop** (`recorder.mjs`, arms `sustained` and
  `sustained-baseline`, unit 055-t13): the same workload for 60 s with the
  whole recorder delivering, plus one 40 MiB request the application mutates
  as soon as `fetch` has it; the event-loop budgets apply, and the run must
  have delivered spans during the run and answered the large request.

`reference.json` holds the calibration reference, the budgets and the memory
parameters. A change to it, or to the calibration workload, is a reviewed
diff; a budget is never loosened to pass on a noisy runner (spec 055 §10.3).

The reports of the tuples the table makes `active` are committed under
`../results/`; each tuple's `report_sha256` is the SHA-256 of its report.
