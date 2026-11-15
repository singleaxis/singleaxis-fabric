# diagnostics v1

`messages-v1.json` is the catalogue of every diagnostic the `fabric` CLI (`FC-`), the SDKs (`FW-`), the host
emitter (`FE-`), the reader (`FR-`) and the Node (`FN-`) emit (spec 058 §13.1): a stable id, a fixed text, a fix
and a docs anchor (the lowercase id on `docs/diagnostics.md`). Shipped in the Python SDK as
the generated module `sdk/python/src/fabric/_catalogue_data.py` (`sdk/python/scripts/sync_contract_data.py`).

Tests (`sdk/python/tests/test_diagnostics_catalogue.py`): every id the code emits is in the catalogue with a
non-empty fix, the catalogue has no Python id the code never emits, and the docs page lists every entry.

Version 1.1.0 (spec 055 §4.7):

- An entry may carry `sdk`, the SDKs that emit it (`python`, `typescript`); without it the entry is Python's.
  Entries whose text and fix hold for a Node.js agent list both. The Node.js-only entries are `FW-025` to
  `FW-033`; the TypeScript SDK's own test (from unit 055-t2) requires each of them to be emitted by TypeScript
  code, and Python's test exempts them.
- `schema/wire-status-v1.schema.json` is the schema of the `fabric.wire-status/v1` document an SDK writes to
  `FABRIC_WIRE_STATUS_FILE` (spec 058 §13.2) and returns from `status()` / `envStatus()`, with valid and
  refused fixtures under `fixtures/wire-status/`. `scripts/tests/test_wire_status_schema.py` validates them
  and the install, failure, disabled and exit documents the Python SDK really writes, and checks this
  family's pins (`manifest.json`).
