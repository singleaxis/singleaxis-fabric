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
- `secrets.id_key_file` and `secrets.ca_file` name an existing setup's own files by path (`fabric init --from-env`,
  spec 058 §11.3). `fabric.yaml` never holds a secret: a path-valued setting whose value has the shape of a
  credential (a PEM block, a bearer or API token, a cloud key, a JWT, a long opaque or hex string) is refused
  with `FC-017` (§7.2).
