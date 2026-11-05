# Remote sandbox qualification: the fixture E2B service

> **Status:** test fixture for spec 056 milestone M2 (WP6-09b). It qualifies
> the `remote.sandbox` hook (`fabric.hooks._sandbox`, provider
> `fabric.hooks._sandbox_e2b`) and is the E2B service AR-1 production
> (WP6-10) runs against. It is not a sandbox: it runs nothing.

The `remote.sandbox` hook observes the E2B Python SDK's own call API
([spec 056 §4.4.1](../../specs/056-agent-action-reconstruction.md#441-remote-sandboxes-e2b-od-3)):
what the agent asked the provider to run and what the SDK returned. To test
that against the real, pinned SDK without an E2B account or network access,
this directory serves the calls that SDK makes on a local address.

| Piece | File | Role |
|---|---|---|
| Pins | [`pins.json`](pins.json) | The SDK series the hook observes (`e2b` 2.62.x, `e2b-code-interpreter` 2.11.x), equal to `fabric.hooks._sandbox_e2b.PINS` and the SDK extra `hooks-sandbox-e2b`; a test holds the three together. |
| Fixture service | [`fixture_e2b.py`](fixture_e2b.py) | One plain-HTTP listener at a configurable address: the control plane (`POST /v2/sandboxes`, `DELETE /sandboxes/<id>`), envd's process service (`/process.Process/Start`, on the SDK's own generated Connect server stub, so the wire format is the SDK's) and health probe, and the code interpreter's `POST /execute` stream. |
| Ledger test | [`test_fixture_ledger.py`](test_fixture_ledger.py) | With the hook on, the ledger equals the agent's own calls (Fabric makes no request of its own), and it keeps names and canary booleans only. |

## Use it

```python
import os, sys
sys.path.insert(0, "qualification/remote-sandbox")
from fixture_e2b import FixtureE2B, Script

with FixtureE2B(api_key="e2b_test", host="127.0.0.1") as fixture:
    fixture.script("make test", Script(stdout="ok\n"))
    os.environ.update(fixture.env())          # E2B_API_URL, E2B_SANDBOX_URL, E2B_API_KEY
    ...                                       # the agent uses e2b as it would in production
    fixture.calls()                           # [("control", "sandboxes.create"), ...]
```

- `host` and `port` choose the address (an IPv6 host such as `::1` works);
  AR-1 production gives the provider an address of its own, distinct from
  the model's and the external host's.
- A command or piece of code does what its `Script` says (output, exit code,
  `run_code` results and error); an unscripted `echo WORDS` prints its words
  and anything else exits 127. `Script(fail=True)` fails the call itself:
  envd answers with a Connect `deadline_exceeded` error and the code
  interpreter with HTTP 502, both raised by the SDK as
  `e2b.exceptions.TimeoutException`.
- `sandbox_ids=` gives the first created sandboxes fixed ids (the interface
  golden's `sbx-` id is derived from one); otherwise ids are `ifx` and a
  counter, never a real E2B id.

## The ledger

`fixture.ledger` holds one entry per request received, in order: its plane
(`control`, `envd`, `interpreter`), its call, the fixture-minted sandbox id,
the **names** of the environment variables it carried, and canary booleans:
whether the API key header equalled the configured key (`api_key`) and
whether an environment value equalled `env_canary` (`env_value`). It never
holds a value: no command, code, output, header, key or environment value,
and nothing received is logged. A test that sees `api_key: true` and
`env_value: true` knows the canaries reached the provider, so their absence
from every Fabric record is meaningful.

## Run the tests

```bash
cd sdk/python && uv sync --all-extras && cd ../..
sdk/python/.venv/bin/python -m pytest qualification/remote-sandbox -q -p no:cacheprovider
sdk/python/.venv/bin/python -m pytest sdk/python/tests/test_hooks_sandbox_e2b.py \
  sdk/python/tests/test_hooks_sandbox_passivity.py -q --no-cov
```

Lint and type-check as the SDK does:

```bash
cd qualification/remote-sandbox
../../sdk/python/.venv/bin/ruff check . && ../../sdk/python/.venv/bin/ruff format --check .
../../sdk/python/.venv/bin/mypy --strict --config-file ../../sdk/python/pyproject.toml \
  fixture_e2b.py test_fixture_ledger.py
```
