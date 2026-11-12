# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The diagnostics catalogue (spec 058 §13.1).

Generated from contracts/diagnostics/v1/messages-v1.json by
sdk/python/scripts/sync_contract_data.py; do not edit (a test keeps it equal)."""

from __future__ import annotations

from typing import Any

CATALOGUE: dict[str, Any] = {
    "schema": "fabric.diagnostics/v1",
    "docs": "docs/diagnostics.md",
    "comment": "Spec 058 section 13.1. Every diagnostic the fabric CLI (FC-), the SDKs (FW-), the "
    "host emitter (FE-), the reader (FR-) and the Node (FN-) emit, with a stable id, a "
    "fixed text, a fix and a docs anchor. An SDK entry lists the SDKs that emit it in "
    "sdk (python, typescript); without sdk it is a Python entry (spec 055 §4.7). Texts "
    "and fixes carry no interpolated value: a host name, path or variable value "
    "appears only in local output (status files, CLI output), never on telemetry. Each "
    "id's docs anchor is its lowercase id in the docs page. Ids are never reused; a "
    "retired id stays listed with retired: true.",
    "messages": [
        {
            "id": "FW-001",
            "name": "capture_not_installed",
            "severity": "error",
            "text": "wire capture is not installed: the configuration is invalid",
            "fix": "run `python -m fabric.wire status` with the agent's environment; it "
            "names the setting and the fix",
        },
        {
            "id": "FW-002",
            "name": "no_destination",
            "severity": "warning",
            "sdk": ["python", "typescript"],
            "text": "spans have no destination: no OTLP endpoint is set, so captured spans "
            "are dropped",
            "fix": "set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT) to the Fabric "
            "Node, for example http://127.0.0.1:4318 for a local Node",
        },
        {
            "id": "FW-003",
            "name": "no_store",
            "severity": "info",
            "sdk": ["python", "typescript"],
            "text": "no content store is configured: capture is metadata only, request and "
            "response bodies are not kept",
            "fix": "set FABRIC_WIRE_STORE=node with FABRIC_WIRE_CONTENT_ENDPOINT, or "
            "FABRIC_WIRE_STORE=file:///absolute/dir for a local trial",
        },
        {
            "id": "FW-004",
            "name": "redacted_roles",
            "severity": "warning",
            "text": "the capture policy masks some content roles and the autoload has no "
            "transformation for them: their content is withheld",
            "fix": "give those roles retain_original or metadata_only in the capture "
            "policy, or install in code with transformations= and "
            "FABRIC_REDACTION_ENDPOINT",
        },
        {
            "id": "FW-005",
            "name": "endpoint_set",
            "severity": "info",
            "sdk": ["python", "typescript"],
            "text": "the model endpoints recorded by this process",
            "fix": "add a host with FABRIC_WIRE_ENDPOINTS, or pin the built-in rows of an "
            "earlier release with FABRIC_WIRE_BUILTIN_ENDPOINTS=legacy",
        },
        {
            "id": "FW-006",
            "name": "unmatched_model_host",
            "severity": "warning",
            "sdk": ["python", "typescript"],
            "text": "a model-looking request matched no configured endpoint and was not recorded",
            "fix": "add the host to FABRIC_WIRE_ENDPOINTS; the status lists the exact value "
            "for each host",
        },
        {
            "id": "FW-007",
            "name": "otel_sdk_disabled",
            "severity": "warning",
            "sdk": ["python", "typescript"],
            "text": "capture is disabled by OTEL_SDK_DISABLED: nothing is recorded",
            "fix": "unset OTEL_SDK_DISABLED in the agent's environment",
        },
        {
            "id": "FW-008",
            "name": "content_capture_disabled",
            "severity": "warning",
            "sdk": ["python", "typescript"],
            "text": "content capture is disabled for this profile; metadata capture continues",
            "fix": "the status names the reason; give the production profile a capture "
            "policy, an id key and a spool key, or use the local profile",
        },
        {
            "id": "FW-009",
            "name": "spool_backlog",
            "severity": "warning",
            "text": "records wait in the spool and no process is draining it",
            "fix": "run `python -m fabric.wire drain --until-empty` with the agent's "
            "environment; for batch or serverless workers set "
            "FABRIC_WIRE_DRAIN_ON_EXIT_S",
        },
        {
            "id": "FW-010",
            "name": "otlp_url_credentials",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "an endpoint URL carries credentials, a query or a fragment",
            "fix": "remove user:password@, ?query and #fragment from the URL; send "
            "credentials as headers (FABRIC_OTLP_HEADERS_FILE or "
            "OTEL_EXPORTER_OTLP_HEADERS)",
        },
        {
            "id": "FW-011",
            "name": "otlp_exporter_missing",
            "severity": "error",
            "text": "the OTLP exporter package is not installed",
            "fix": 'pip install "singleaxis-fabric[otlp]" in the agent\'s environment',
        },
        {
            "id": "FW-012",
            "name": "otlp_plaintext_non_loopback",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "the OTLP endpoint uses http to a non-loopback host",
            "fix": "use https with FABRIC_OTLP_CERTIFICATE (or "
            "OTEL_EXPORTER_OTLP_CERTIFICATE), or a loopback address (127.0.0.1, "
            "localhost, [::1])",
        },
        {
            "id": "FW-013",
            "name": "otlp_endpoint_missing",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "this delivery mode needs an OTLP traces endpoint",
            "fix": "set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT) to the Fabric "
            "Node, for example http://127.0.0.1:4318 for a local Node",
        },
        {
            "id": "FW-014",
            "name": "endpoints_invalid_json",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "FABRIC_WIRE_ENDPOINTS is not a JSON array of matcher objects",
            "fix": "use a JSON array such as "
            '[{"endpoint_id":"my-model","dialect":"openai","hosts":["models.example.com"]}]',
        },
        {
            "id": "FW-015",
            "name": "endpoint_matcher_invalid",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "an endpoint matcher is invalid",
            "fix": "each entry needs an endpoint_id and provider_name of lowercase letters, "
            "digits and ._-, dialect openai or anthropic, hosts or host_suffixes, "
            "schemes http/https and ports 1-65535",
        },
        {
            "id": "FW-016",
            "name": "protected_global_provider",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "a Fabric-protected global tracer provider cannot carry wire spans",
            "fix": "set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT): capture then "
            "delivers through its own private tracer provider",
        },
        {
            "id": "FW-017",
            "name": "fabric_otlp_without_endpoint",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "a FABRIC_OTLP_* setting is set without FABRIC_OTLP_ENDPOINT",
            "fix": "set FABRIC_OTLP_ENDPOINT, or remove the other FABRIC_OTLP_* variables",
        },
        {
            "id": "FW-018",
            "name": "key_value_and_file",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "a key is set both as a value and as a file",
            "fix": "set either the variable or its _FILE variant, not both",
        },
        {
            "id": "FW-019",
            "name": "secret_file_unreadable",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "a key, certificate or headers file is missing, unreadable or malformed",
            "fix": "check the path and the permissions of the file the reason names",
        },
        {
            "id": "FW-020",
            "name": "builtin_endpoints_invalid",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "FABRIC_WIRE_BUILTIN_ENDPOINTS has an unknown value",
            "fix": "use table (the default: every qualified built-in row) or legacy (the "
            "three rows of releases before 0.13)",
        },
        {
            "id": "FW-021",
            "name": "llm_content_ignored",
            "severity": "info",
            "text": "FABRIC_CAPTURE_LLM_CONTENT does not affect wire capture",
            "fix": "remove FABRIC_CAPTURE_LLM_CONTENT; wire capture keeps content off "
            "telemetry in the content store",
        },
        {
            "id": "FW-022",
            "name": "spool_migration_ignored",
            "severity": "warning",
            "sdk": ["python", "typescript"],
            "text": "spool plaintext migration is ignored in the production profile; "
            "plaintext spool records are quarantined",
            "fix": "remove FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT, or migrate under the local "
            "profile first",
        },
        {
            "id": "FW-023",
            "name": "status_file_unwritable",
            "severity": "warning",
            "sdk": ["python", "typescript"],
            "text": "the status file could not be written",
            "fix": "point FABRIC_WIRE_STATUS_FILE at a writable path in a directory that exists",
        },
        {
            "id": "FW-024",
            "name": "otlp_setting_invalid",
            "severity": "error",
            "sdk": ["python", "typescript"],
            "text": "an OTLP setting is malformed",
            "fix": "headers are k=v pairs separated by commas, timeouts are numbers, "
            "compression is gzip, deflate or none, and a client key and certificate "
            "are set together",
        },
        {
            "id": "FW-025",
            "name": "node_capture_not_installed",
            "severity": "error",
            "sdk": ["typescript"],
            "text": "wire capture is not installed in this Node.js process: the "
            "configuration is invalid",
            "fix": "run the status command (node -p with "
            "require('@singleaxis/fabric/wire').envStatus()) with the agent's "
            "environment; it names the setting and the fix",
        },
        {
            "id": "FW-026",
            "name": "node_runtime_unqualified",
            "severity": "warning",
            "sdk": ["typescript"],
            "text": "model-call capture is off: this Node.js or undici build is not in the "
            "Fabric compatibility table",
            "fix": "run the agent on a Node.js 24 build listed in the compatibility table "
            "of the release notes, then start it again",
        },
        {
            "id": "FW-027",
            "name": "node_platform_unsupported",
            "severity": "warning",
            "sdk": ["typescript"],
            "text": "model-call capture is off: Fabric has no native lock module for this "
            "operating system or CPU",
            "fix": "run the agent on Linux or macOS, x64 or arm64",
        },
        {
            "id": "FW-028",
            "name": "node_native_unusable",
            "severity": "warning",
            "sdk": ["typescript"],
            "text": "model-call capture is off: Fabric's native lock module could not be used",
            "fix": "reinstall @singleaxis/fabric so its prebuilds directory is complete, "
            "and keep the spool directory on a local disk; the status names the "
            "reason",
        },
        {
            "id": "FW-029",
            "name": "node_hook_disabled",
            "severity": "info",
            "sdk": ["typescript"],
            "text": "a capture point is switched off by its FABRIC_WIRE_UNDICI or "
            "FABRIC_WIRE_NODE_HTTP setting",
            "fix": "set the variable to 1 to record through that capture point",
        },
        {
            "id": "FW-030",
            "name": "node_worker_unattached",
            "severity": "warning",
            "sdk": ["typescript"],
            "text": "a worker thread records nothing: Fabric was not loaded in the main "
            "thread before the worker started, or the worker did not inherit the "
            "preload",
            "fix": "load Fabric with NODE_OPTIONS=--import=@singleaxis/fabric/register so "
            "every thread inherits it",
        },
        {
            "id": "FW-031",
            "name": "node_autoload_off",
            "severity": "info",
            "sdk": ["typescript"],
            "text": "@singleaxis/fabric/register was loaded but did nothing: "
            "FABRIC_WIRE_AUTOLOAD is not 1",
            "fix": "set FABRIC_WIRE_AUTOLOAD=1, or start the agent with `fabric run`",
        },
        {
            "id": "FW-032",
            "name": "node_redacted_roles",
            "severity": "warning",
            "sdk": ["typescript"],
            "text": "the capture policy masks some content roles and no redaction service "
            "is configured: their content is withheld",
            "fix": "set FABRIC_REDACTION_ENDPOINT, or give those roles retain_original or "
            "metadata_only in the capture policy",
        },
        {
            "id": "FW-033",
            "name": "node_spool_backlog",
            "severity": "warning",
            "sdk": ["typescript"],
            "text": "records wait in the spool and no process is draining it",
            "fix": "start the agent again, or set FABRIC_WIRE_DRAIN_ON_EXIT_S for batch or "
            "serverless workers; `python -m fabric.wire drain --until-empty` also "
            "drains a Node.js spool",
        },
        {
            "id": "FC-001",
            "name": "config_not_found",
            "severity": "error",
            "text": "no fabric.yaml was found",
            "fix": "create fabric.yaml (schema: fabric.config/v1) in the project directory, "
            "or pass --config PATH",
        },
        {
            "id": "FC-002",
            "name": "config_unreadable",
            "severity": "error",
            "text": "fabric.yaml could not be read or is not valid YAML",
            "fix": "check the file; the message names the line and column",
        },
        {
            "id": "FC-003",
            "name": "config_unknown_key",
            "severity": "error",
            "text": "fabric.yaml has a key the schema does not know",
            "fix": "remove the key or use the suggested one; the schema is "
            "contracts/cli-config/v1/fabric-config-v1.schema.json",
        },
        {
            "id": "FC-004",
            "name": "config_invalid_value",
            "severity": "error",
            "text": "a fabric.yaml value is not allowed",
            "fix": "use one of the values the message lists",
        },
        {
            "id": "FC-005",
            "name": "cli_extra_missing",
            "severity": "error",
            "text": "this command needs the [cli] extra",
            "fix": 'pip install "singleaxis-fabric[cli]" (or pipx install '
            '"singleaxis-fabric[cli]")',
        },
        {
            "id": "FC-006",
            "name": "unknown_command",
            "severity": "error",
            "text": "unknown command",
            "fix": "run `fabric help` for the list of commands",
        },
        {
            "id": "FC-007",
            "name": "config_schema_unsupported",
            "severity": "error",
            "text": "fabric.yaml names a schema this CLI does not support",
            "fix": "set schema: fabric.config/v1, or upgrade the CLI",
        },
        {
            "id": "FC-008",
            "name": "provider_url_invalid",
            "severity": "error",
            "text": "a provider URL is not a usable model endpoint",
            "fix": "give the base URL the client uses, such as "
            "https://my-llm.example.com/v1, optionally prefixed anthropic= for the "
            "Anthropic dialect",
        },
        {
            "id": "FC-009",
            "name": "env_overrides_config",
            "severity": "info",
            "text": "an environment variable overrides a fabric.yaml setting",
            "fix": "unset the variable if fabric.yaml should decide",
        },
        {
            "id": "FC-010",
            "name": "command_not_built",
            "severity": "error",
            "text": "this command is not part of this release yet",
            "fix": "upgrade the CLI; until then follow docs/quickstart.md",
        },
        {
            "id": "FC-011",
            "name": "option_not_built",
            "severity": "error",
            "text": "this option is not part of this release yet",
            "fix": "use the local profile's defaults; production, Kubernetes and the other "
            "destinations follow docs/production-setup.md and docs/deployment.md "
            "until the CLI builds them",
        },
        {
            "id": "FC-012",
            "name": "secrets_dir_unsafe",
            "severity": "error",
            "text": "the secrets directory is not a private directory of this user",
            "fix": "make it a real directory you own with mode 0700 (chmod 700 DIR), or set "
            "secrets.dir in fabric.yaml to another path",
        },
        {
            "id": "FC-013",
            "name": "secret_file_unsafe",
            "severity": "error",
            "text": "a secret file is a symlink, is not a regular file, or is open to other users",
            "fix": "restore it as your own regular file with mode 0600 (chmod 600 FILE), or "
            "replace it with `fabric init --rotate NAME`",
        },
        {
            "id": "FC-014",
            "name": "secret_set_incomplete",
            "severity": "error",
            "text": "a generated certificate is missing its key or its CA",
            "fix": "run `fabric init --rotate ca` to issue a new CA and Node certificate, "
            "then `fabric up` and restart agents",
        },
        {
            "id": "FC-016",
            "name": "rotation_needs_restart",
            "severity": "warning",
            "text": "a rotated secret is still in use by running processes",
            "fix": "run `fabric up` so the Node restarts with it; restart agents when the "
            "CA or the id key changed",
        },
        {
            "id": "FC-017",
            "name": "config_secret_shaped",
            "severity": "error",
            "text": "fabric.yaml must not hold a secret value",
            "fix": "put the value in a file and name the file's path (start a relative path "
            "with ./); `fabric init` generates and stores secrets itself",
        },
        {
            "id": "FC-018",
            "name": "env_not_imported",
            "severity": "warning",
            "text": "an environment setting could not be written into fabric.yaml",
            "fix": "keep exporting the variable (a variable already set wins over "
            "fabric.yaml), or pass --import-secrets to store a key given by value as "
            "a file",
        },
        {
            "id": "FC-019",
            "name": "docker_missing",
            "severity": "error",
            "text": "Docker with Compose v2 is not installed or not on PATH",
            "fix": "install Docker Engine or Docker Desktop (the `docker compose` plugin "
            "included), then run the command again",
        },
        {
            "id": "FC-020",
            "name": "docker_not_running",
            "severity": "error",
            "text": "the Docker daemon did not answer",
            "fix": "start Docker Desktop or the docker service and check `docker info`; on "
            "Linux add your user to the docker group or use sudo",
        },
        {
            "id": "FC-021",
            "name": "compose_failed",
            "severity": "error",
            "text": "Docker Compose could not apply the Fabric project",
            "fix": "read the detail (Docker's own last lines); `docker compose -p "
            "fabric-PROJECT logs` shows the services' output",
        },
        {
            "id": "FC-022",
            "name": "port_in_use",
            "severity": "error",
            "text": "the Node's port is already in use on this machine",
            "fix": "stop the other listener (an earlier local stack: `fabric down` in that "
            "project, or `make down` in deploy/compose), or set node.endpoint: "
            "https://localhost:PORT in fabric.yaml and run `fabric up` again",
        },
        {
            "id": "FC-023",
            "name": "node_not_healthy",
            "severity": "error",
            "text": "the Fabric Node did not answer over TLS in time",
            "fix": "run `fabric up --wait 180` to allow a slow first image pull; the detail "
            "holds the Node's last log line",
        },
        {
            "id": "FC-024",
            "name": "node_external",
            "severity": "info",
            "text": "node.mode is external: there is nothing for this command to start or stop",
            "fix": "nothing to do; set node.mode: docker in fabric.yaml to have `fabric up` "
            "run a local Node",
        },
        {
            "id": "FC-025",
            "name": "certificate_renewed",
            "severity": "info",
            "text": "the Node certificate was close to expiry and was reissued from the local CA",
            "fix": "nothing to do: agents trust the CA, which did not change",
        },
        {
            "id": "FC-026",
            "name": "project_changed",
            "severity": "info",
            "text": "the running project differed from fabric.yaml or this CLI's pinned "
            "images and was updated",
            "fix": "nothing to do; the detail names what changed",
        },
        {
            "id": "FC-027",
            "name": "ca_expired",
            "severity": "error",
            "text": "the local CA has expired",
            "fix": "run `fabric init --rotate ca`, then `fabric up`, then restart agents so "
            "they load the new CA",
        },
        {
            "id": "FC-028",
            "name": "image_override",
            "severity": "warning",
            "text": "an environment variable replaces an image pinned by this CLI release",
            "fix": "unset the variable to run the pinned, signed release image; keep it "
            "only to test a locally built image",
        },
        {
            "id": "FC-029",
            "name": "state_not_removed",
            "severity": "warning",
            "text": "part of the project's local state could not be removed",
            "fix": "remove the directory named in the detail by hand (files written by a "
            "container running as root need sudo)",
        },
        {
            "id": "FC-030",
            "name": "compose_project_not_this_projects",
            "severity": "error",
            "text": "the Compose project this command would act on holds containers of "
            "another project, so nothing was started, stopped or removed",
            "fix": "two projects with the same name share one Compose project: set a "
            "different `project:` in this directory's fabric.yaml and run the "
            "command again, or run `fabric down` in the directory named in the "
            "detail first",
        },
        {
            "id": "FC-031",
            "name": "referenced_secret_unreadable",
            "severity": "warning",
            "text": "a secret file fabric.yaml references is missing or not a readable "
            "regular file, so agents given the compiled environment would capture "
            "nothing with it",
            "fix": "correct the path in fabric.yaml (secrets.id_key_file or "
            "secrets.ca_file) and run `fabric init` again, or remove the setting so "
            "`fabric init` generates the secret",
        },
        {
            "id": "FC-032",
            "name": "project_flag_not_the_files",
            "severity": "error",
            "text": "--project names another project than the fabric.yaml this command "
            "found, so nothing was done",
            "fix": "drop --project (fabric.yaml names the project), pass --config with that "
            "project's fabric.yaml, or rename this project with `fabric down` and "
            "then `fabric init --project NAME`",
        },
        {
            "id": "FC-040",
            "name": "sensor_started",
            "severity": "info",
            "text": "the host sensor is running and scoped to this project's agent cgroup",
            "fix": "on Linux, start the agent from a shell in the sensor's scope: write "
            "that shell's PID to the cgroup.procs file of the cgroup named in the "
            "detail (`echo $$ | sudo tee DETAIL/cgroup.procs`), then start the agent "
            "from it; `fabric run` will do this for you once it ships",
        },
        {
            "id": "FC-041",
            "name": "sensor_off",
            "severity": "info",
            "text": "the host sensor is off by configuration",
            "fix": "set sensor.kind: auto in fabric.yaml and drop --no-sensor to start it "
            "where it can load",
        },
        {
            "id": "FC-042",
            "name": "sensor_desktop_vm",
            "severity": "info",
            "text": "the host sensor runs inside the Docker VM: it cannot see a process "
            "started directly on this machine",
            "fix": "nothing to do for capture from the SDK, which is unaffected; for "
            "independent host evidence run the agent on a Linux host",
        },
        {
            "id": "FC-043",
            "name": "sensor_kernel_unsupported",
            "severity": "warning",
            "text": "this kernel cannot load the eBPF sensor (it needs Linux 5.8 or later "
            "with BTF and cgroup v2)",
            "fix": "use a host with a newer kernel; capture from the SDK is unaffected, "
            "only independent host evidence is missing",
        },
        {
            "id": "FC-044",
            "name": "sensor_cgroup_not_permitted",
            "severity": "warning",
            "text": "the agent cgroup for the host sensor could not be created",
            "fix": "run `fabric up` once with sudo, or from a systemd user session (a "
            "delegated cgroup); capture from the SDK is unaffected",
        },
        {
            "id": "FC-045",
            "name": "sensor_start_failed",
            "severity": "warning",
            "text": "the host sensor container did not stay running",
            "fix": "read the detail (the sensor's last log line); `fabric up --no-sensor` "
            "continues without host evidence",
        },
        {
            "id": "FC-046",
            "name": "sensor_auditd_available",
            "severity": "info",
            "text": "eBPF cannot load here but auditd is present on this host",
            "fix": "follow docs/host-sensors.md to run the auditd sensor collector; the CLI "
            "does not start it in this release",
        },
        {
            "id": "FC-047",
            "name": "sensor_sandboxed_runtime",
            "severity": "warning",
            "text": "this machine runs inside a sandbox or container that hides the host "
            "kernel from the sensor",
            "fix": "run `fabric up` on the host itself for host evidence; capture from the "
            "SDK is unaffected",
        },
    ],
}
