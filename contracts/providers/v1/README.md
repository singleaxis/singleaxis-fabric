# providers v1

`builtin-endpoints.json` is the table of model endpoints Fabric records with no configuration (spec 058 §8.1),
shipped in the Python SDK as the generated module `sdk/python/src/fabric/wire/_endpoint_table.py` (the wheel
ships code only; `sdk/python/scripts/sync_contract_data.py` regenerates it and a test keeps it equal) and read
by the `fabric` CLI.

- `rows`: the endpoints in force. A row ships only with qualification fixtures (`fixtures/<name>.json`, recorded
  request and response bytes in the row's dialect) that pass wire parsing and reconstruction
  (`sdk/python/tests/test_builtin_endpoints.py`). Rows with `default: false` are never on unless listed.
- `candidates`: rows the spec names that are not shipped yet. Each needs a response recorded from that provider
  before it moves to `rows`.
- `legacy_endpoint_ids`: what `FABRIC_WIRE_BUILTIN_ENDPOINTS=legacy` pins.
- `table_version`: raised whenever `rows` changes; reported by `fabric version`, `fabric.wire.status()` and
  `python -m fabric.wire status`.

Fixture provenance: `openai-chat`, `openai-chat-stream` and `anthropic-messages` were recorded on 2026-11-10 from
an OpenAI- and Anthropic-compatible model server (vLLM serving an open-weight model). They qualify the dialect
parsing each row relies on; they are not recordings from api.openai.com, api.anthropic.com or Azure OpenAI.
