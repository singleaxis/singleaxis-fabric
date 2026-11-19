# diagnostics v1

`messages-v1.json` is the catalogue of every diagnostic the `fabric` CLI (`FC-`), the SDKs (`FW-`), the host
emitter (`FE-`), the reader (`FR-`) and the Node (`FN-`) emit (spec 058 §13.1): a stable id, a fixed text, a fix
and a docs anchor (the lowercase id on `docs/diagnostics.md`). Shipped in the Python SDK as
the generated module `sdk/python/src/fabric/_catalogue_data.py` (`sdk/python/scripts/sync_contract_data.py`).

`reasons-v1.json` (`fabric.reason-words/v1`, schema `schema/reasons-v1.schema.json`; added in 1.1.0 by spec 058
WP8-18) puts every reason a reader verdict can carry in plain words with its fix: every value of the
run-reconstruction `chainReason`, controls chain and unattributed host event enums. `chains` gives a reason the
meaning one chain gives it; `notes` words facts that are not reasons (`startup_effects`). Shipped in the CLI as
`sdk/python/src/fabric/cli/_reasons_data.py`; `fabric verify`, `fabric show` and the coverage report print these
words, and `docs/diagnostics.md` lists each one.

Tests (`sdk/python/tests/test_diagnostics_catalogue.py`, `test_reason_words.py`): every id the code emits is in
the catalogue with a non-empty fix, the catalogue has no id the code never emits, every reader reason has words
and a fix, and the docs page lists every entry.
