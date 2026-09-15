# FabricRecorder v1

`FabricRecorder` is the small public configuration for the passive Fabric OSS
recorder:

```text
CAPTURE -> PROTECT -> DELIVER
```

It identifies the recorder, monitored system and deployment, input method,
approved content representation, privacy configuration, destination and local
installation. Fields contain references and digests, never credentials or raw
content.

This contract does not configure assurance levels, evaluations, judges,
red-team campaigns, runtime controls, policy rollout or governance workflows.
Preparing this file does not install Fabric or contact its destination.

## Schema-valid is not CLI-valid

`schema.json` is the interoperable document shape. The released `fabricctl`
binary (`recorder validate`, `recorder digest`, and the `init` wizard) applies
the same shape plus stricter acceptance rules, so a file can validate against
the schema and still be refused by the CLI:

- `spec.identity.recorderId` must equal `metadata.name`. The schema admits any
  reference-shaped `recorderId`; the CLI binds it to the resource name.
- No name or reference field may be credential-shaped. The CLI rejects values
  that look like bearer tokens, `sk_`/`pk_`/`api_key`/`token`/`secret`-prefixed
  keys, AWS `AKIA`/`ASIA` access key IDs, GitHub `ghp_`-style tokens, JWTs, and
  unseparated opaque or hex strings long enough to be secrets. The schema's
  `reference` pattern alone admits several of these shapes.
- The file must be exactly one YAML document; multi-document input is
  rejected.
- The file must be non-empty and at most 1 MiB.

Unknown and duplicate fields are rejected in both layers. The pinned
`invalid/` fixtures are deliberately schema-valid yet CLI-invalid, so the
stricter rules stay load-bearing instead of being absorbed into the schema.

## Validate

From the repository root:

```bash
python scripts/contracts/validate_recorder_contract.py
```

The validator converts each pinned YAML document to its JSON equivalent,
checks `schema.json`, applies the stricter-than-schema rules above, verifies
every SHA-256 pin in `manifest.json`, and runs the negative fixtures to their
expected stable error codes.

## Naming and versioning notes

- `content.mode` spells the governed mode `governed-reference` with a hyphen.
  This Kubernetes-style configuration contract deliberately uses the
  hyphenated spelling; the Activity Envelope v2 and privacy assertion
  contracts spell the same mode `governed_reference`. The spellings are not
  interchangeable across contracts.
- `manifest.json` identifies this contract family as `version: "v1"` — the
  release pin and directory identity — while each document carries
  `apiVersion: fabric.singleaxis.dev/v1alpha1`. The manifest `v1` label and
  the resource `v1alpha1` apiVersion are the same contract generation; neither
  is renamed because both are pinned public identities.
- All manifest SHA-256 pins cover the **exact bytes** of the named file
  (`digest_scope: exact_file_bytes`). Reserializing or reformatting a pinned
  file changes its digest.
- `manifest.json` pins the schema and every YAML/JSON fixture. Markdown
  documentation, including this README, is not a pinned artifact.
