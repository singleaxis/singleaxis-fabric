# diagnostics v1

`messages-v1.json` is the catalogue of every diagnostic the `fabric` CLI (`FC-`), the SDKs (`FW-`), the host
emitter (`FE-`), the reader (`FR-`) and the Node (`FN-`) emit (spec 058 §13.1): a stable id, a fixed text, a fix
and a docs anchor (the lowercase id on `docs/diagnostics.md`). Shipped in the Python SDK as
the generated module `sdk/python/src/fabric/_catalogue_data.py` (`sdk/python/scripts/sync_contract_data.py`).

Tests (`sdk/python/tests/test_diagnostics_catalogue.py`): every id the code emits is in the catalogue with a
non-empty fix, the catalogue has no id the code never emits, and the docs page lists every entry.
