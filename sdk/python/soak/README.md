# Fabric SDK soak / load harness

An opt-in, locally-runnable endurance check for the SDK hot paths. It
drives a large number of `Decision`s through a realistic path and reports
span counts plus a coarse memory-stability verdict.

It lives **outside `tests/`** (mirroring `benchmarks/`) so the default
`pytest` / coverage run never collects it and it can never flaky-gate CI.

## What it does

- Builds a real `TracerProvider` feeding an `InMemorySpanExporter` and a
  `Fabric` client wired with a no-dependency stub guardrail checker (no
  Presidio / NeMo / network).
- **Sequential phase**: drives `--sequential` decisions on the calling
  thread.
- **Concurrent phase**: spins up `--threads` workers, each driving
  `--per-thread` of its _own_ decisions — one `Decision` per worker per
  turn, never shared, honouring the concurrency contract. This exercises
  the overlap sentinel under real thread pressure without tripping it.
- Each turn: `decision` enter/exit + `guard_input` (stub) +
  `record_retrieval` + `remember` + a child `llm_call` span.
- Drains the in-memory exporter every `--drain-every` decisions so the
  span backlog cannot masquerade as a leak.
- Asserts: no exceptions escaped, the observed span count equals the
  expectation (two spans per turn), and samples memory at start / mid /
  end. `tracemalloc` live growth across the concurrent phase is the
  deterministic stability signal; process RSS is reported and only fails
  the run past a coarse `--max-rss-growth-mb` threshold.
- Prints a short report and exits non-zero on a detected error or leak,
  so it is usable in a manual or scheduled run.

## How to run

From `sdk/python`:

```bash
python -m soak.run
```

Useful flags:

```bash
python -m soak.run --sequential 50000 --threads 8 --per-thread 5000
python -m soak.run --sequential 2000 --threads 4 --per-thread 500   # quick smoke
python -m soak.run --max-rss-growth-mb 96                           # looser RSS budget
```

## Reading the result

The final `RESULT: OK` / `RESULT: FAIL` line drives the exit code. A
`FAIL` means an exception escaped, the span count did not match, or
memory grew past a budget — investigate before assuming the harness is
wrong.

This suite is **informational and machine-dependent**, not a CI gate.
Absolute RSS figures and the `ru_maxrss` peak depend on the platform and
the rest of the process; the `tracemalloc` live-growth verdict is the
portable signal. Run it on a quiet machine for the most stable numbers.
