# Adapter conformance kit

A reusable pytest harness that lets anyone who implements a Fabric
extension Protocol **prove** their adapter satisfies the Protocol's
behavioral contract.

This is distinct from the schema conformance suite in the parent
directory: that one freezes the SDK's emitted span output; this one
verifies pluggable *adapter behavior* (valid return types, enum
membership, integrity invariants, ordering, idempotency).

## Covered Protocols

One contract mixin per extension Protocol:

- `GuardrailCheckerContract` — `fabric.guardrails.GuardrailChecker`
- `JudgeWorkerContract` — `fabric.judge.JudgeWorker`
- `QueueTransportContract` — `fabric.judge.QueueTransport`
- `DrainableTransportContract` — `fabric.judge.DrainableTransport`
- `PolicyEngineContract` — `fabric.policy.PolicyEngine`
- `ContentStoreContract` — `fabric.content_store.base.ContentStore`
- `ToolAuthorizerContract` — `fabric.tool_auth.ToolAuthorizer`

## How to use it

1. Import the mixin for the Protocol you implement.
2. Subclass it. The subclass name **must** start with `Test` so pytest
   collects it.
3. Implement the single factory method (for example `make_checker`)
   returning a fresh instance of your adapter.
4. Run pytest. Every inherited contract test runs against your adapter.

```python
from fabric.guardrails import GuardrailChecker
from tests.conformance.adapters.contracts import GuardrailCheckerContract

from my_package import MyChecker


class TestMyChecker(GuardrailCheckerContract):
    def make_checker(self) -> GuardrailChecker:
        return MyChecker(endpoint="https://guardrails.internal/check")
```

```sh
pytest path/to/test_my_checker.py
```

The factory is called fresh per test, so each test gets a clean adapter
instance. For adapters that need setup (a temp dir, a fake endpoint),
wire it with an `autouse` fixture on your subclass and read it inside
the factory — see `test_reference_adapters.py` for the
`LocalFilesystemContentStore` and `HTTPGuardrailChecker` examples.

## What the contract asserts

The mixins are tolerant where behavior legitimately varies and strict
where the contract is fixed.

- Tolerant: a `GuardrailChecker` may `allow` **or** `block` a given
  input; a `PolicyEngine` may return any of the five decisions; a
  `ToolAuthorizer` may `allow` **or** `deny`. The kit asserts the
  verdict is *structurally* valid (correct type, action in the enum,
  field types correct), not a specific decision.
- Strict: `ContentStore.put` must return a `ContentRef` whose
  `content_hash` equals `content_hash(content)` (integrity), and the
  same content must be content-addressed to the same ref;
  `DrainableTransport` must round-trip enqueue then dequeue in FIFO
  order and return `None` when empty; `ToolAuthorization.raise_for_denied`
  must raise only on `deny`; `close()` must be idempotent.

## Why mixins are named `*Contract`, not `Test*`

A `Test*`-prefixed class with an abstract factory would be collected by
pytest directly and error (the factory raises `NotImplementedError`).
Naming the base mixins `*Contract` means pytest only collects the
concrete `Test*` subclasses an implementer writes. The factory methods
raise `NotImplementedError` rather than using a bare `...` body.

## Self-validation

`test_reference_adapters.py` runs each mixin against the SDK's own
reference adapters (and the deterministic stubs the SDK's tests already
use where a real impl needs network or heavy deps), proving the kit
works end to end inside the normal `sdk/python` pytest run.
