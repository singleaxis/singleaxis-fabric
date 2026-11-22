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
- `fixtures/print-env/node-v1.json`: the shared `fabric run --print-env` goldens for a Node.js command (spec 055
  §13.1, spec 058 §1.4). Each case names the installed `@singleaxis/fabric`'s state, this machine's Node build, the
  format and the command; its `output` is the exact text from the file's `compiled_env` and `finding_ids` the
  catalogue findings. `sdk/python/tests/test_cli_print_env_node.py` checks the Python CLI against them; the npm
  launcher's `run --print-env` (spec 058 WP8-9) must produce the same text. Regenerate with
  `FABRIC_UPDATE_GOLDENS=1` and re-pin the file's SHA-256 in `manifest.json`.
