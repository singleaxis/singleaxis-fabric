# Fabric SDK micro-benchmarks

An opt-in, locally-runnable performance baseline for the SDK's hot
paths. It measures the runtime overhead Fabric adds per agent decision
so the project has reproducible "Fabric adds ~X us per decision" numbers
and can spot gross regressions.

## Important: this is not a CI gate

- These benchmarks live **outside** `tests/`, so the default `pytest`
  run (which sets `testpaths = ["tests"]` and `--cov-fail-under=85`)
  never collects them. They add no timing flakiness to CI and do not
  perturb the coverage gate.
- They are **informational and machine-dependent**. Timing on shared
  runners is unreliable, so there is no pass/fail threshold. Compare
  runs only on the same machine, otherwise idle.

## How to run

From `sdk/python`:

```bash
python -m benchmarks.run
```

Useful flags:

```bash
# Also write machine-readable JSON.
python -m benchmarks.run --json results.json

# Tighter samples (slower, more stable).
python -m benchmarks.run --rounds 100 --inner 500
```

The suite uses only the standard library plus the SDK's own runtime
dependencies (OpenTelemetry). It adds **no** new third-party dependency
and does not change `pip install -e ".[dev]"`. It completes in a few
seconds.

## Why a dependency-free harness (not pytest-benchmark)

We deliberately chose a stdlib harness (`time.perf_counter` +
`statistics`) over `pytest-benchmark`:

- It keeps the dependency tree and the default CI install byte-for-byte
  unchanged (no new optional extra to maintain).
- It is fully reproducible from the standard library alone.
- It runs as a plain `python -m` command, with nothing for the
  `testpaths`-scoped CI `pytest` to accidentally collect.

## What is measured

Each scenario runs against a real (non-noop) `TracerProvider` feeding an
in-process `InMemorySpanExporter`, so the span machinery (attribute
setting, event recording, SHA-256 hashing) is genuinely exercised, but
nothing leaves the process. All rails are no-dependency doubles (a stub
guardrail checker, stub policy engine, stub tool authorizer): no
Presidio, NeMo, LLM, or network. Inputs are fixed and the exporter is
cleared each iteration so memory does not grow.

Scenarios:

- `baseline: bare tracer span` — the floor cost of a plain OTel span,
  so the Fabric marginal cost is interpretable.
- `decision: enter+exit` — the bare decision context (span creation plus
  standard attributes).
- `decision + guard_input` — one input pass through a stub guardrail
  chain.
- `decision + record_retrieval` / `+ remember` / `+ record_side_effect`
  — per-method emit cost (each includes content hashing).
- `decision + evaluate_policy` — input JSON serialization plus SHA-256.
- `decision + authorize_tool_call` — argument hashing plus event emit.
- `decision + llm_call (+set_usage)` — child span open/close with usage.
- `decision + tool_call (args+result hash)` — child span plus argument
  and result hashing.
- `StreamRedactor: 40 chunks + flush` — per-chunk amortized streaming
  redaction cost.

## How to read the output

```text
scenario                                  min us  median us  mean us  stdev us  ops/sec
```

- `min us` — fastest observed per-call time; the cleanest signal,
  least affected by scheduler noise.
- `median us` / `mean us` — central tendency; prefer median.
- `stdev us` — spread across samples; high values mean a noisy machine.
- `ops/sec` — derived from the mean (throughput view).

The marginal overhead of a given path is roughly its `median us` minus
the `baseline: bare tracer span` `median us`.

## Sample numbers (illustrative, machine-dependent)

Captured on an Apple-silicon laptop (Python 3.11, macOS, arm64),
`warmup=200 rounds=50 inner=200`. Your numbers will differ; these are
for shape only, not a target.

```text
scenario                                  min us  median us  mean us  stdev us  ops/sec
---------------------------------------  -------  ---------  -------  --------  -------
baseline: bare tracer span                 8.232      8.775    8.906     0.409  112,278
decision: enter+exit                      15.278     16.638   18.792     4.729   53,214
decision + guard_input                    23.881     26.839   28.056     3.837   35,642
decision + record_retrieval               25.059     26.967   28.378     4.507   35,239
decision + remember                       26.237     26.702   27.080     1.133   36,928
decision + record_side_effect             29.113     29.871   30.714     2.071   32,559
decision + evaluate_policy                27.366     27.897   28.397     1.146   35,215
decision + authorize_tool_call            17.903     19.029   18.833     1.005   53,099
decision + llm_call (+set_usage)          30.632     32.619   34.178     5.909   29,259
decision + tool_call (args+result hash)   28.820     31.572   35.328     9.921   28,306
StreamRedactor: 40 chunks + flush        236.781    273.730  275.860    24.449    3,625
```

Headline: a bare decision context is roughly 8 us over a plain OTel span
(about 17 us absolute), and a fully-evidenced decision step (one emit
method) lands in the mid-20s of microseconds on this machine.
