# Diagnostics

<!-- Generated from contracts/diagnostics/v1/messages-v1.json by
     sdk/python/tests/_diagnostics_doc.py; a test keeps them equal. -->

Every message Fabric prints or writes has a stable id. Search for the id you saw;
each entry says what it means and how to fix it. Messages never carry a secret, a
header, a URL credential or content; a host name or path appears only in local
output (the CLI, the status file), never on telemetry.

## The fabric CLI

### FC-001

`config_not_found`, error: no fabric.yaml was found.

Fix: create fabric.yaml (schema: fabric.config/v1) in the project directory, or pass --config PATH.

### FC-002

`config_unreadable`, error: fabric.yaml could not be read or is not valid YAML.

Fix: check the file; the message names the line and column.

### FC-003

`config_unknown_key`, error: fabric.yaml has a key the schema does not know.

Fix: remove the key or use the suggested one; the schema is contracts/cli-config/v1/fabric-config-v1.schema.json.

### FC-004

`config_invalid_value`, error: a fabric.yaml value is not allowed.

Fix: use one of the values the message lists.

### FC-005

`cli_extra_missing`, error: this command needs the [cli] extra.

Fix: pip install "singleaxis-fabric[cli]" (or pipx install "singleaxis-fabric[cli]").

### FC-006

`unknown_command`, error: unknown command.

Fix: run `fabric help` for the list of commands.

### FC-007

`config_schema_unsupported`, error: fabric.yaml names a schema this CLI does not support.

Fix: set schema: fabric.config/v1, or upgrade the CLI.

### FC-008

`provider_url_invalid`, error: a provider URL is not a usable model endpoint.

Fix: give the base URL the client uses, such as https://my-llm.example.com/v1, optionally prefixed anthropic= for the Anthropic dialect.

### FC-009

`env_overrides_config`, info: an environment variable overrides a fabric.yaml setting.

Fix: unset the variable if fabric.yaml should decide.

### FC-010

`command_not_built`, error: this command is not part of this release yet.

Fix: upgrade the CLI; until then follow docs/quickstart.md.

## The SDKs (wire capture, status, autoload)

### FW-001

`capture_not_installed`, error: wire capture is not installed: the configuration is invalid.

Fix: run `python -m fabric.wire status` with the agent's environment; it names the setting and the fix.

### FW-002

`no_destination`, warning: spans have no destination: no OTLP endpoint is set, so captured spans are dropped.

Fix: set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT) to the Fabric Node, for example http://127.0.0.1:4318 for a local Node.

### FW-003

`no_store`, info: no content store is configured: capture is metadata only, request and response bodies are not kept.

Fix: set FABRIC_WIRE_STORE=node with FABRIC_WIRE_CONTENT_ENDPOINT, or FABRIC_WIRE_STORE=file:///absolute/dir for a local trial.

### FW-004

`redacted_roles`, warning: the capture policy masks some content roles and the autoload has no transformation for them: their content is withheld.

Fix: give those roles retain_original or metadata_only in the capture policy, or install in code with transformations= and FABRIC_REDACTION_ENDPOINT.

### FW-005

`endpoint_set`, info: the model endpoints recorded by this process.

Fix: add a host with FABRIC_WIRE_ENDPOINTS, or pin the built-in rows of an earlier release with FABRIC_WIRE_BUILTIN_ENDPOINTS=legacy.

### FW-006

`unmatched_model_host`, warning: a model-looking request matched no configured endpoint and was not recorded.

Fix: add the host to FABRIC_WIRE_ENDPOINTS; the status lists the exact value for each host.

### FW-007

`otel_sdk_disabled`, warning: capture is disabled by OTEL_SDK_DISABLED: nothing is recorded.

Fix: unset OTEL_SDK_DISABLED in the agent's environment.

### FW-008

`content_capture_disabled`, warning: content capture is disabled for this profile; metadata capture continues.

Fix: the status names the reason; give the production profile a capture policy, an id key and a spool key, or use the local profile.

### FW-009

`spool_backlog`, warning: records wait in the spool and no process is draining it.

Fix: run `python -m fabric.wire drain --until-empty` with the agent's environment; for batch or serverless workers set FABRIC_WIRE_DRAIN_ON_EXIT_S.

### FW-010

`otlp_url_credentials`, error: an endpoint URL carries credentials, a query or a fragment.

Fix: remove user:password@, ?query and #fragment from the URL; send credentials as headers (FABRIC_OTLP_HEADERS_FILE or OTEL_EXPORTER_OTLP_HEADERS).

### FW-011

`otlp_exporter_missing`, error: the OTLP exporter package is not installed.

Fix: pip install "singleaxis-fabric[otlp]" in the agent's environment.

### FW-012

`otlp_plaintext_non_loopback`, error: the OTLP endpoint uses http to a non-loopback host.

Fix: use https with FABRIC_OTLP_CERTIFICATE (or OTEL_EXPORTER_OTLP_CERTIFICATE), or a loopback address (127.0.0.1, localhost, [::1]).

### FW-013

`otlp_endpoint_missing`, error: this delivery mode needs an OTLP traces endpoint.

Fix: set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT) to the Fabric Node, for example http://127.0.0.1:4318 for a local Node.

### FW-014

`endpoints_invalid_json`, error: FABRIC_WIRE_ENDPOINTS is not a JSON array of matcher objects.

Fix: use a JSON array such as [{"endpoint_id":"my-model","dialect":"openai","hosts":["models.example.com"]}].

### FW-015

`endpoint_matcher_invalid`, error: an endpoint matcher is invalid.

Fix: each entry needs an endpoint_id and provider_name of lowercase letters, digits and ._-, dialect openai or anthropic, hosts or host_suffixes, schemes http/https and ports 1-65535.

### FW-016

`protected_global_provider`, error: a Fabric-protected global tracer provider cannot carry wire spans.

Fix: set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT): capture then delivers through its own private tracer provider.

### FW-017

`fabric_otlp_without_endpoint`, error: a FABRIC_OTLP_* setting is set without FABRIC_OTLP_ENDPOINT.

Fix: set FABRIC_OTLP_ENDPOINT, or remove the other FABRIC_OTLP_* variables.

### FW-018

`key_value_and_file`, error: a key is set both as a value and as a file.

Fix: set either the variable or its _FILE variant, not both.

### FW-019

`secret_file_unreadable`, error: a key, certificate or headers file is missing, unreadable or malformed.

Fix: check the path and the permissions of the *_FILE / FABRIC_OTLP_* file the reason names.

### FW-020

`builtin_endpoints_invalid`, error: FABRIC_WIRE_BUILTIN_ENDPOINTS has an unknown value.

Fix: use table (the default: every qualified built-in row) or legacy (the three rows of releases before 0.13).

### FW-021

`llm_content_ignored`, info: FABRIC_CAPTURE_LLM_CONTENT does not affect wire capture.

Fix: remove FABRIC_CAPTURE_LLM_CONTENT; wire capture keeps content off telemetry in the content store.

### FW-022

`spool_migration_ignored`, warning: spool plaintext migration is ignored in the production profile; plaintext spool records are quarantined.

Fix: remove FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT, or migrate under the local profile first.

### FW-023

`status_file_unwritable`, warning: the status file could not be written.

Fix: point FABRIC_WIRE_STATUS_FILE at a writable path in a directory that exists.

### FW-024

`otlp_setting_invalid`, error: an OTLP setting is malformed.

Fix: headers are k=v pairs separated by commas, timeouts are numbers, compression is gzip, deflate or none, and a client key and certificate are set together.
