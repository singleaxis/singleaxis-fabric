# cli-config v1

Contracts of the `fabric` operator CLI (spec 058).

- `schema/fabric-config-v1.schema.json`: `fabric.yaml` (`schema: fabric.config/v1`, spec 058 §6.1). Strict:
  an unknown key is refused. The CLI (`sdk/python/src/fabric/cli/_config.py`) applies the same rules and names the
  nearest valid key; it also refuses duplicate custom provider names, which JSON Schema cannot express.
- `schema/cli-report-v1.schema.json`: the `--json` output of every command (`fabric.cli-report/v1`, §5.1, §15).
  Finding ids, texts and fixes come from `contracts/diagnostics/v1/messages-v1.json`.
- `fixtures/valid/*.yaml`, `fixtures/invalid/*.yaml`: each invalid fixture's first line names the finding id and
  the setting the CLI reports (`# expect: FC-003 capture.exek`). `sdk/python/tests/test_cli_config.py` runs the
  CLI's validator and the JSON schema over every fixture and requires them to agree.
