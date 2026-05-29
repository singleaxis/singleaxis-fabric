# Schema conformance suite

This suite freezes the documented `fabric.*` / `gen_ai.*` span and
span-event attribute contract emitted by the Python SDK, versioned by
`SCHEMA_VERSION = "1.0"` (`fabric.decision.SCHEMA_VERSION`).

It exists to guard against _silent schema drift_: downstream consumers
(Telemetry Bridge, replay engine, audit exporters) and a future
TypeScript SDK all depend on this exact wire contract. The golden
fixtures here are the artifact the TypeScript SDK will be validated
against.

## Layout

- `scenarios.py` — the canonical scenario set. Each scenario is a
  small, deterministic SDK interaction with fixed identifiers and
  seeded stub rails. One scenario per distinct emitted shape.
- `stubs.py` — deterministic stub rails (guardrail checkers, policy
  engine, tool authorizer, content store). No real
  Presidio/NeMo/LLM/OPA.
- `normalize.py` — turns captured spans into stable, comparable dicts.
- `runner.py` — shared harness used by both the runner and the
  regeneration entrypoint.
- `generate.py` — regeneration entrypoint.
- `goldens/<scenario>.json` — the frozen, normalized output per
  scenario.
- `schema/fabric-decision-v1.schema.json` — the formal JSON Schema for
  the decision span and each event type at `SCHEMA_VERSION` 1.0.

The pytest runner lives at `tests/test_conformance.py` and runs in the
normal `sdk/python` pytest invocation, so CI enforces it.

## Normalization

Goldens must be stable across runs and machines, so the normalizer
drops or zeroes every non-deterministic field while keeping everything
that is part of the contract.

- Dropped: `trace_id`, `span_id`, parent id, start/end timestamps,
  span duration, per-event timestamps.
- Dropped: the OTel-internal `exception` event (its stacktrace carries
  machine-dependent paths and line numbers).
- Placeheld with `<normalized>`: generated UUID attributes
  (`fabric.checkpoint.checkpoint_id`, `fabric.eval.eval_id`,
  `fabric.policy.evaluation_id`, `fabric.judge.request_id`) and
  wall-clock latencies (`fabric.guardrail.latency_ms`,
  `fabric.policy.latency_ms`, `fabric.retrieval.latency_ms`). The key
  is kept (so the contract still asserts presence); only the value is
  placeheld.
- Kept verbatim: all SHA-256 hashes. They are deterministic for a
  fixed input and are part of the contract a consumer must reproduce.
- Attribute keys are sorted; spans are ordered by name.

## Regenerating the goldens

An intentional contract change should be a reviewable golden-file diff.
From `sdk/python`:

```sh
python -m tests.conformance.generate
```

This re-runs every scenario and rewrites `goldens/<scenario>.json`
using the same normalization the runner asserts against. Review the
resulting JSON diff, and bump `SCHEMA_VERSION` if the change is
breaking.
