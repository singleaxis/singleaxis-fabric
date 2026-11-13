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

Fix: remove the key or use the suggested one; the schema is
contracts/cli-config/v1/fabric-config-v1.schema.json.

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

Fix: give the base URL the client uses, such as https://my-llm.example.com/v1, optionally prefixed
anthropic= for the Anthropic dialect.

### FC-009

`env_overrides_config`, info: an environment variable overrides a fabric.yaml setting.

Fix: unset the variable if fabric.yaml should decide.

### FC-010

`command_not_built`, error: this command is not part of this release yet.

Fix: upgrade the CLI; until then follow docs/quickstart.md.

### FC-011

`option_not_built`, error: this option is not part of this release yet.

Fix: use the local profile's defaults; production, Kubernetes and the other destinations follow
docs/production-setup.md and docs/deployment.md until the CLI builds them.

### FC-012

`secrets_dir_unsafe`, error: the secrets directory is not a private directory of this user.

Fix: make it a real directory you own with mode 0700 (chmod 700 DIR), or set secrets.dir in
fabric.yaml to another path.

### FC-013

`secret_file_unsafe`, error: a secret file is a symlink, is not a regular file, or is open to other
users.

Fix: restore it as your own regular file with mode 0600 (chmod 600 FILE), or replace it with `fabric
init --rotate NAME`.

### FC-014

`secret_set_incomplete`, error: a generated certificate is missing its key or its CA.

Fix: run `fabric init --rotate ca` to issue a new CA and Node certificate, then `fabric up` and
restart agents.

### FC-016

`rotation_needs_restart`, warning: a rotated secret is still in use by running processes.

Fix: run `fabric up` so the Node restarts with it; restart agents when the CA or the id key changed.

### FC-017

`config_secret_shaped`, error: fabric.yaml must not hold a secret value.

Fix: put the value in a file and name the file's path (start a relative path with ./); `fabric init`
generates and stores secrets itself.

### FC-018

`env_not_imported`, warning: an environment setting could not be written into fabric.yaml.

Fix: keep exporting the variable (a variable already set wins over fabric.yaml), or pass
--import-secrets to store a key given by value as a file.

### FC-019

`docker_missing`, error: Docker with Compose v2 is not installed or not on PATH.

Fix: install Docker Engine or Docker Desktop (the `docker compose` plugin included), then run the
command again.

### FC-020

`docker_not_running`, error: the Docker daemon did not answer.

Fix: start Docker Desktop or the docker service and check `docker info`; on Linux add your user to
the docker group or use sudo.

### FC-021

`compose_failed`, error: Docker Compose could not apply the Fabric project.

Fix: read the detail (Docker's own last lines); `docker compose -p fabric-PROJECT logs` shows the
services' output.

### FC-022

`port_in_use`, error: the Node's port is already in use on this machine.

Fix: stop the other listener (an earlier local stack: `fabric down` in that project, or `make down`
in deploy/compose), or set node.endpoint: https://localhost:PORT in fabric.yaml and run `fabric up`
again.

### FC-023

`node_not_healthy`, error: the Fabric Node did not answer over TLS in time.

Fix: run `fabric up --wait 180` to allow a slow first image pull; the detail holds the Node's last
log line.

### FC-024

`node_external`, info: node.mode is external: there is nothing for this command to start or stop.

Fix: nothing to do; set node.mode: docker in fabric.yaml to have `fabric up` run a local Node.

### FC-025

`certificate_renewed`, info: the Node certificate was close to expiry and was reissued from the
local CA.

Fix: nothing to do: agents trust the CA, which did not change.

### FC-026

`project_changed`, info: the running project differed from fabric.yaml or this CLI's pinned images
and was updated.

Fix: nothing to do; the detail names what changed.

### FC-027

`ca_expired`, error: the local CA has expired.

Fix: run `fabric init --rotate ca`, then `fabric up`, then restart agents so they load the new CA.

### FC-028

`image_override`, warning: an environment variable replaces an image pinned by this CLI release.

Fix: unset the variable to run the pinned, signed release image; keep it only to test a locally
built image.

### FC-029

`state_not_removed`, warning: part of the project's local state could not be removed.

Fix: remove the directory named in the detail by hand (files written by a container running as root
need sudo).

### FC-030

`compose_project_not_this_projects`, error: the Compose project this command would act on holds
containers of another project, so nothing was started, stopped or removed.

Fix: two projects with the same name share one Compose project: set a different `project:` in this
directory's fabric.yaml and run the command again, or run `fabric down` in the directory named in
the detail first.

### FC-031

`referenced_secret_unreadable`, warning: a secret file fabric.yaml references is missing or not a
readable regular file, so agents given the compiled environment would capture nothing with it.

Fix: correct the path in fabric.yaml (secrets.id_key_file or secrets.ca_file) and run `fabric init`
again, or remove the setting so `fabric init` generates the secret.

### FC-032

`project_flag_not_the_files`, error: --project names another project than the fabric.yaml this
command found, so nothing was done.

Fix: drop --project (fabric.yaml names the project), pass --config with that project's fabric.yaml,
or rename this project with `fabric down` and then `fabric init --project NAME`.

### FC-040

`sensor_started`, info: the host sensor is running and scoped to this project's agent cgroup.

Fix: start the agent with `fabric run -- CMD`, which joins this cgroup on Linux; a process started
another way is outside the sensor's scope unless its shell joins first (`echo $$ | sudo tee
DETAIL/cgroup.procs`).

### FC-041

`sensor_off`, info: the host sensor is off by configuration.

Fix: set sensor.kind: auto in fabric.yaml and drop --no-sensor to start it where it can load.

### FC-042

`sensor_desktop_vm`, info: the host sensor runs inside the Docker VM: it cannot see a process
started directly on this machine.

Fix: nothing to do for capture from the SDK, which is unaffected; for independent host evidence run
the agent on a Linux host.

### FC-043

`sensor_kernel_unsupported`, warning: this kernel cannot load the eBPF sensor (it needs Linux 5.8 or
later with BTF and cgroup v2).

Fix: use a host with a newer kernel; capture from the SDK is unaffected, only independent host
evidence is missing.

### FC-044

`sensor_cgroup_not_permitted`, warning: the agent cgroup for the host sensor could not be created.

Fix: run `fabric up` once with sudo, or from a systemd user session (a delegated cgroup); capture
from the SDK is unaffected.

### FC-045

`sensor_start_failed`, warning: the host sensor container did not stay running.

Fix: read the detail (the sensor's last log line); `fabric up --no-sensor` continues without host
evidence.

### FC-046

`sensor_auditd_available`, info: eBPF cannot load here but auditd is present on this host.

Fix: follow docs/host-sensors.md to run the auditd sensor collector; the CLI does not start it in
this release.

### FC-047

`sensor_sandboxed_runtime`, warning: this machine runs inside a sandbox or container that hides the
host kernel from the sensor.

Fix: run `fabric up` on the host itself for host evidence; capture from the SDK is unaffected.

### FC-048

`node_not_started`, info: `fabric up` has not started this project's local Node, so the agent's
records wait in its spool.

Fix: run `fabric up`; the spool delivers the records once the Node answers.

### FC-049

`sdk_version_skew`, warning: the agent's SDK and this CLI are more than one minor version apart.

Fix: upgrade the older one so both come from the same release (pip install -U
"singleaxis-fabric[otlp]" in the agent's environment, or upgrade the CLI).

### FC-050

`run_sdk_missing`, warning: the agent's Python interpreter cannot load the Fabric SDK, so this run
is not captured; the agent ran unchanged.

Fix: install the SDK in the agent's own environment with the command in the detail (python -m pip
install "singleaxis-fabric[otlp]" with that interpreter), then start the agent again.

### FC-051

`run_otlp_exporter_missing`, warning: the agent's environment has the Fabric SDK but not the OTLP
exporter that sends records to the Node, so this run is not captured; the agent ran unchanged.

Fix: install the [otlp] extra in the agent's environment with the command in the detail, then start
the agent again.

### FC-052

`run_config_unusable`, warning: the project's configuration could not be used, so the agent ran
without capture.

Fix: run `fabric doctor` in the project directory: it names the problem and its fix (the detail
names the first one).

### FC-053

`run_env_only`, info: this command is not a Python program `fabric run` can turn capture on for; it
was given the run's Fabric settings only.

Fix: start a Python agent through its interpreter (fabric run -- python app.py) or the project's
.venv; a launcher script can export `fabric run --print-env` itself; Node.js and compiled agents
record through the explicit API and the host sensor.

### FC-054

`run_cgroup_join_failed`, warning: the agent could not join the host sensor's cgroup, so the sensor
does not observe this run.

Fix: start the agent as the user that ran `fabric up`, or run `fabric up` from a systemd user
session (a delegated cgroup); capture by the SDK is unaffected.

### FC-055

`run_command_not_found`, error: the agent command could not be started.

Fix: check the command name, that it is on PATH and that it is executable; the detail names it.

### FC-056

`run_no_command`, error: `fabric run` needs the agent command after --.

Fix: fabric run -- python agent.py.

### FC-057

`run_state_unwritable`, warning: the run could not be recorded under .fabric/state, so it ran
without capture and `fabric verify` and `fabric show` do not see it.

Fix: make the project's .fabric directory a real directory writable by this user (not a symlink),
then start the agent again.

### FC-058

`run_capture_off_by_flag`, info: capture is off for this run (--no-capture): the agent ran with its
environment unchanged.

Fix: drop --no-capture to record the run.

### FC-059

`run_label_invalid`, warning: the --run label is not usable, so a generated label was used.

Fix: use 1-64 letters, digits and ._- for --run.

### FC-060

`compiled_env_stale`, warning: .fabric/compiled.env is missing or was made from an older
fabric.yaml.

Fix: run `fabric init` (or `fabric up`) to rewrite it; `fabric run` compiles fabric.yaml itself and
is not affected, launchers that read the file are.

### FC-061

`node_unreachable`, error: the Fabric Node did not answer over TLS with the project's CA.

Fix: run `fabric up`; if it is running, `fabric doctor` prints its last log line (docker compose -p
fabric-PROJECT logs fabric-node shows more).

### FC-062

`canary_not_captured`, error: the canary could not record a model exchange with this project's
configuration.

Fix: the detail holds the SDK's reason and fix; `fabric doctor` checks the same configuration.

### FC-063

`canary_not_delivered`, error: the canary's records did not reach the destination in time.

Fix: check that the Node runs (`fabric up`) and answers (`fabric doctor`); on a slow machine allow
more time with fabric verify --wait 120.

### FC-064

`canary_incomplete`, error: the canary run was read back but is not complete.

Fix: each reason in the detail names its fix; python -m fabric.reconstruct --spans DATA/spans --run
LABEL prints the full report.

### FC-065

`canary_complete`, info: the canary went through capture, the Node and the destination and was read
back complete.

Fix: nothing to do.

### FC-066

`no_run_recorded`, info: no `fabric run` is recorded in this project yet, so only the path was
checked.

Fix: start the agent with `fabric run -- CMD`, then run `fabric verify` again.

### FC-067

`run_not_found`, error: the run's records were not found in the destination.

Fix: check the label (`fabric show --list`); a run still in progress or just ended may not be
delivered yet: run the command again after the agent exits.

### FC-068

`run_incomplete`, error: the run's records are not complete in the reader's verdict.

Fix: each reason in the detail names its fix; `fabric show` displays what was recorded.

### FC-069

`run_complete`, info: the run's records were read back complete and its model decisions were
recorded.

Fix: nothing to do.

### FC-070

`run_not_captured`, error: the run was started without capture.

Fix: the detail lists the reasons recorded when it started; `fabric doctor` shows each with its fix.

### FC-073

`records_unreadable`, error: the destination's span files could not be read.

Fix: the detail names the input and the accepted forms; check the destination directory.

### FC-074

`destination_not_readable`, info: this destination is not one Fabric can read back, so records were
checked only up to the Node.

Fix: pass --spans PATH with an export of the destination's spans, or use the local-dir destination.

### FC-080

`no_runs`, info: no `fabric run` is recorded in this project.

Fix: start the agent with `fabric run -- CMD`.

### FC-082

`content_hidden`, info: content is not printed because stdout is not a terminal.

Fix: pass --content to print it.

### FC-090

`manual_setup`, info: no fabric.yaml was found: checking this shell's FABRIC_* environment as a
manual setup.

Fix: nothing to do for a manual setup; `fabric init --from-env` writes fabric.yaml from it.

### FC-091

`sdk_ready`, info: the agent's Python environment loads the Fabric SDK with this project's settings
and reports no problem.

Fix: nothing to do.

### FC-092

`other_fabric_on_path`, warning: another program named fabric comes first on PATH.

Fix: use the singleaxis-fabric command, which is always this CLI, or put this CLI's directory first
on PATH.

### FC-094

`sensor_stopped`, warning: `fabric up` started the host sensor, but its container is not running
now.

Fix: run `fabric up` again; the detail holds the sensor's last log line.

### FC-095

`node_ok`, info: the Fabric Node answers over TLS with the project's CA.

Fix: nothing to do.

### FC-096

`no_status_file`, info: the last run left no status file: its agent never loaded the SDK, or was
stopped before it started.

Fix: start the agent with `fabric run` again; if this repeats, the agent's interpreter is not the
one with the SDK (`fabric doctor` names the one it checked).

### FC-097

`no_problem_found`, info: no problem found.

Fix: nothing to do.

## The SDKs (wire capture, status, autoload)

### FW-001

`capture_not_installed`, error: wire capture is not installed: the configuration is invalid.

Fix: run `python -m fabric.wire status` with the agent's environment; it names the setting and the
fix.

### FW-002

`no_destination`, warning: spans have no destination: no OTLP endpoint is set, so captured spans are
dropped.

Fix: set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT) to the Fabric Node, for example
http://127.0.0.1:4318 for a local Node.

### FW-003

`no_store`, info: no content store is configured: capture is metadata only, request and response
bodies are not kept.

Fix: set FABRIC_WIRE_STORE=node with FABRIC_WIRE_CONTENT_ENDPOINT, or
FABRIC_WIRE_STORE=file:///absolute/dir for a local trial.

### FW-004

`redacted_roles`, warning: the capture policy masks some content roles and the autoload has no
transformation for them: their content is withheld.

Fix: give those roles retain_original or metadata_only in the capture policy, or install in code
with transformations= and FABRIC_REDACTION_ENDPOINT.

### FW-005

`endpoint_set`, info: the model endpoints recorded by this process.

Fix: add a host with FABRIC_WIRE_ENDPOINTS, or pin the built-in rows of an earlier release with
FABRIC_WIRE_BUILTIN_ENDPOINTS=legacy.

### FW-006

`unmatched_model_host`, warning: a model-looking request matched no configured endpoint and was not
recorded.

Fix: add the host to FABRIC_WIRE_ENDPOINTS; the status lists the exact value for each host.

### FW-007

`otel_sdk_disabled`, warning: capture is disabled by OTEL_SDK_DISABLED: nothing is recorded.

Fix: unset OTEL_SDK_DISABLED in the agent's environment.

### FW-008

`content_capture_disabled`, warning: content capture is disabled for this profile; metadata capture
continues.

Fix: the status names the reason; give the production profile a capture policy, an id key and a
spool key, or use the local profile.

### FW-009

`spool_backlog`, warning: records wait in the spool and no process is draining it.

Fix: run `python -m fabric.wire drain --until-empty` with the agent's environment; for batch or
serverless workers set FABRIC_WIRE_DRAIN_ON_EXIT_S.

### FW-010

`otlp_url_credentials`, error: an endpoint URL carries credentials, a query or a fragment.

Fix: remove user:password@, ?query and #fragment from the URL; send credentials as headers
(FABRIC_OTLP_HEADERS_FILE or OTEL_EXPORTER_OTLP_HEADERS).

### FW-011

`otlp_exporter_missing`, error: the OTLP exporter package is not installed.

Fix: pip install "singleaxis-fabric[otlp]" in the agent's environment.

### FW-012

`otlp_plaintext_non_loopback`, error: the OTLP endpoint uses http to a non-loopback host.

Fix: use https with FABRIC_OTLP_CERTIFICATE (or OTEL_EXPORTER_OTLP_CERTIFICATE), or a loopback
address (127.0.0.1, localhost, [::1]).

### FW-013

`otlp_endpoint_missing`, error: this delivery mode needs an OTLP traces endpoint.

Fix: set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT) to the Fabric Node, for example
http://127.0.0.1:4318 for a local Node.

### FW-014

`endpoints_invalid_json`, error: FABRIC_WIRE_ENDPOINTS is not a JSON array of matcher objects.

Fix: use a JSON array such as
[{"endpoint_id":"my-model","dialect":"openai","hosts":["models.example.com"]}].

### FW-015

`endpoint_matcher_invalid`, error: an endpoint matcher is invalid.

Fix: each entry needs an endpoint_id and provider_name of lowercase letters, digits and ._-, dialect
openai or anthropic, hosts or host_suffixes, schemes http/https and ports 1-65535.

### FW-016

`protected_global_provider`, error: a Fabric-protected global tracer provider cannot carry wire
spans.

Fix: set FABRIC_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_ENDPOINT): capture then delivers through its
own private tracer provider.

### FW-017

`fabric_otlp_without_endpoint`, error: a FABRIC_OTLP_* setting is set without FABRIC_OTLP_ENDPOINT.

Fix: set FABRIC_OTLP_ENDPOINT, or remove the other FABRIC_OTLP_* variables.

### FW-018

`key_value_and_file`, error: a key is set both as a value and as a file.

Fix: set either the variable or its _FILE variant, not both.

### FW-019

`secret_file_unreadable`, error: a key, certificate or headers file is missing, unreadable or
malformed.

Fix: check the path and the permissions of the file the reason names.

### FW-020

`builtin_endpoints_invalid`, error: FABRIC_WIRE_BUILTIN_ENDPOINTS has an unknown value.

Fix: use table (the default: every qualified built-in row) or legacy (the three rows of releases
before 0.13).

### FW-021

`llm_content_ignored`, info: FABRIC_CAPTURE_LLM_CONTENT does not affect wire capture.

Fix: remove FABRIC_CAPTURE_LLM_CONTENT; wire capture keeps content off telemetry in the content
store.

### FW-022

`spool_migration_ignored`, warning: spool plaintext migration is ignored in the production profile;
plaintext spool records are quarantined.

Fix: remove FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT, or migrate under the local profile first.

### FW-023

`status_file_unwritable`, warning: the status file could not be written.

Fix: point FABRIC_WIRE_STATUS_FILE at a writable path in a directory that exists.

### FW-024

`otlp_setting_invalid`, error: an OTLP setting is malformed.

Fix: headers are k=v pairs separated by commas, timeouts are numbers, compression is gzip, deflate
or none, and a client key and certificate are set together.

### FW-025

`node_capture_not_installed`, error: wire capture is not installed in this Node.js process: the
configuration is invalid.

Fix: run the status command (node -p with require('@singleaxis/fabric/wire').envStatus()) with the
agent's environment; it names the setting and the fix.

### FW-026

`node_runtime_unqualified`, warning: model-call capture is off: this Node.js or undici build is not
in the Fabric compatibility table.

Fix: run the agent on a Node.js 24 build listed in the compatibility table of the release notes,
then start it again.

### FW-027

`node_platform_unsupported`, warning: model-call capture is off: Fabric has no native lock module
for this operating system or CPU.

Fix: run the agent on Linux or macOS, x64 or arm64.

### FW-028

`node_native_unusable`, warning: model-call capture is off: Fabric's native lock module could not be
used.

Fix: reinstall @singleaxis/fabric so its prebuilds directory is complete, and keep the spool
directory on a local disk; the status names the reason.

### FW-029

`node_hook_disabled`, info: a capture point is switched off by its FABRIC_WIRE_UNDICI or
FABRIC_WIRE_NODE_HTTP setting.

Fix: set the variable to 1 to record through that capture point.

### FW-030

`node_worker_unattached`, warning: a worker thread records nothing: Fabric was not loaded in the
main thread before the worker started, or the worker did not inherit the preload.

Fix: load Fabric with NODE_OPTIONS=--import=@singleaxis/fabric/register so every thread inherits it.

### FW-031

`node_autoload_off`, info: @singleaxis/fabric/register was loaded but did nothing:
FABRIC_WIRE_AUTOLOAD is not 1.

Fix: set FABRIC_WIRE_AUTOLOAD=1 in the agent's environment (`fabric run` sets it for you once it
ships).

### FW-032

`node_redacted_roles`, warning: the capture policy masks some content roles and no redaction service
is configured: their content is withheld.

Fix: set FABRIC_REDACTION_ENDPOINT, or give those roles retain_original or metadata_only in the
capture policy.

### FW-033

`node_spool_backlog`, warning: records wait in the spool and no process is draining it.

Fix: start the agent again, or set FABRIC_WIRE_DRAIN_ON_EXIT_S for batch or serverless workers;
`python -m fabric.wire drain --until-empty` also drains a Node.js spool.
