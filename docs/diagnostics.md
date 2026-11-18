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

### FC-098

`launcher_command_unavailable`, error: the npm launcher has the `run` and `doctor` commands only;
this command is in the Python CLI and the fabric-cli container image.

Fix: install the full CLI with pipx install "singleaxis-fabric[cli]" (or uv tool install), or run
the image: docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:$PWD" -w "$PWD"
ghcr.io/singleaxis/fabric-cli:VERSION COMMAND.

### FC-099

`doctor_no_python`, info: no Python interpreter was found, so the Python SDK check was skipped.

Fix: nothing to do for a Node.js agent, which records through the explicit API; for a Python agent,
put its interpreter on PATH or create the project's .venv and run `fabric doctor` again.

### FC-100

`kubectl_missing`, error: kubectl is not installed or not on PATH, so the Secrets cannot be written
to the cluster.

Fix: install kubectl and select the cluster's context (kubectl config use-context NAME), or write
the Secrets as manifests with `fabric init --kubernetes --render DIR` and apply them with your own
tooling.

### FC-101

`kube_namespace_missing`, error: a namespace the Secrets belong in does not exist.

Fix: create it (kubectl create namespace NAME) and run the command again; neither the chart's
secrets Job nor `fabric init --kubernetes` creates a namespace.

### FC-102

`kube_forbidden`, error: the Kubernetes API refused the request: the identity may not read or create
Secrets there.

Fix: use a kube context that may get and create Secrets in the release namespace and every agent
namespace; for the chart's secrets Job, check that every agent namespace is listed in
agentNamespaces (its Role is created there).

### FC-103

`kube_api_unreachable`, error: the Kubernetes API server could not be reached.

Fix: check the kube context (kubectl cluster-info); in the chart's secrets Job, check that a
NetworkPolicy lets the Job reach the API server (set secretsJob.apiServer.to and .ports when the
chart cannot read them).

### FC-104

`kube_secret_incomplete`, warning: an existing Secret lacks keys this setup needs; it is kept
unchanged.

Fix: delete the Secret the message names and run the command again to generate it (a new id key
changes the namespace's pseudonyms), or add the missing keys it lists yourself.

### FC-105

`kube_ingress_secret_orphaned`, error: an agent namespace's ingress Secret exists in the release
namespace but its agent Secret does not, so a new token and source id would not match it.

Fix: delete the ingress Secret the message names (kubectl delete secret -n RELEASE-NAMESPACE NAME)
and run the command again; both are then generated together.

### FC-106

`kube_option_needs_kubernetes`, error: this option belongs to `fabric init --kubernetes`.

Fix: add --kubernetes, or remove the option.

### FC-107

`injector_ca_bundle`, info: the injector's webhook needs the CA certificate as its caBundle.

Fix: the chart's secrets Job sets it; with secretsJob.enabled=false, set injector.caBundle to the
ca.crt entry of the CA Secret's data, which is base64 already (kubectl get secret fabric-ca -n
RELEASE-NAMESPACE -o yaml).

### FC-108

`kube_webhook_missing`, error: the injector's webhook configuration was not found, so its caBundle
cannot be set.

Fix: install or upgrade the chart with injector.enabled=true first; the post-install hook then sets
the caBundle.

### FC-109

`kube_name_invalid`, error: a namespace, release, source or Secret name is not valid for Kubernetes.

Fix: use lowercase letters, digits and '-' (at most 63 characters for a namespace); a source label
may also use '.', '_' and ':'.

### FC-110

`kube_agent_secret_unusable`, error: an agent namespace's existing Secret holds no ingest credential
or id key this setup can read, so the namespace's ingress Secret cannot be made and the Node, which
reads it, would not start.

Fix: delete the agent Secret the message names (kubectl delete secret -n AGENT-NAMESPACE NAME) and
run the command again, or run helm upgrade again; the agent Secret and its ingress Secret are then
generated together (a new id key changes the namespace's pseudonyms; restart its agents).

### FC-111

`kube_certificate_expiring`, warning: a certificate in a Secret expires within 14 days; Secrets are
never overwritten, so it is not renewed by itself.

Fix: delete the Node's or the injector's Secret the message names and run the command again (helm
upgrade runs the secrets Job): a new certificate is issued from the same CA; then restart the Node
if it was its own. For an agent Secret or the CA Secret follow 'Certificate renewal' in
docs/deployment.md.

### FC-112

`kube_certificate_expired`, error: a certificate in a Secret has expired, so the connections it
secures fail: agents cannot deliver to the Node, or the injector's webhook is skipped and pods start
without capture.

Fix: delete the Node's or the injector's Secret the message names and run the command again (helm
upgrade runs the secrets Job): a new certificate is issued from the same CA; then restart the Node
if it was its own. For an agent Secret or the CA Secret follow 'Certificate renewal' in
docs/deployment.md.

### FC-113

`kube_host_sensor_needs_production`, error: the host sensor's Secrets need a production Node: each
node's sensor is an authenticated source with its own ingress group.

Fix: add --profile production (the chart: preset=production-host-sensor), or leave --host-sensor
out.

### FC-114

`kube_host_source_id_stale`, error: a node's host sensor Secret holds a source id made with another
id key, so the Node would refuse that sensor's records.

Fix: delete the node's Secret the message names (kubectl delete secret -n RELEASE-NAMESPACE NAME)
and run the command again (or helm upgrade): it is made again from the current id key; then restart
the Node.

### FC-115

`kube_agent_id_key_differs`, warning: an agent namespace's Secret holds an id key of its own, not
the release's shared one, so host sensor records do not join that namespace's runs.

Fix: delete the agent Secret and its ingress Secret the message names and run the command again (or
helm upgrade): both are made again with the shared id key; then restart that namespace's agents.

### FC-120

`kubectl_missing_for_read`, error: kubectl is not installed or not on PATH; --kubernetes reads the
cluster of the current kube context through it.

Fix: install kubectl and select the cluster's context (kubectl config use-context NAME), or point
KUBECONFIG at its file.

### FC-121

`helm_missing`, error: helm is not installed or not on PATH; `fabric up --kubernetes` installs the
chart with it.

Fix: install Helm 3.14 or later, or write the values and Secrets for your own pipeline with fabric
up --kubernetes --render DIR.

### FC-122

`kube_release_not_found`, error: no Fabric release installed with a preset was found in the cluster
of the current kube context.

Fix: install it (fabric up --kubernetes, or helm install with --set preset=...); name its namespace
with --namespace when it is not fabric-system; check the context with kubectl config
current-context.

### FC-123

`helm_failed`, error: Helm could not install or remove the Fabric release.

Fix: read the detail (Helm's own last lines); a chart error names the value and its fix, and `fabric
doctor --kubernetes` shows the state of what is installed.

### FC-124

`kube_release_applied`, info: the Fabric release was installed or upgraded with Helm; no workload
other than Fabric's own was restarted.

Fix: nothing to do; agent pods get capture at their next start, by your own rollout.

### FC-125

`kube_secret_missing`, error: a Secret the release needs is missing or lacks a key, so the pods that
mount it do not start or cannot authenticate.

Fix: run helm upgrade (the secrets Job makes each missing Secret) or fabric init --kubernetes with
the same namespaces; an incomplete Secret is never changed: delete it first.

### FC-126

`kube_node_not_ready`, error: the Fabric Node has no ready pod, so no record is accepted.

Fix: the detail holds the pod's state and last log line; kubectl describe pod and kubectl logs in
the release namespace show more.

### FC-127

`kube_node_ready`, info: the Fabric Node's pods are ready and its health endpoint answers.

Fix: nothing to do.

### FC-128

`kube_port_forward_failed`, error: kubectl could not forward a local port to the Fabric Node.

Fix: check that the Node's pods run and that your identity may create pods/portforward in the
release namespace.

### FC-129

`kube_injector_unavailable`, error: the pod injector has no ready pod: annotated pods are admitted
unchanged after the 2 second webhook timeout and run without capture.

Fix: restore it (kubectl describe deployment in the release namespace shows why it is down), then
recreate the affected pods with your own rollout; Fabric never restarts a workload.

### FC-130

`kube_pod_not_injected`, warning: a pod asks for injection with the fabric.singleaxis.ai/inject
annotation but was not injected, so it runs without capture.

Fix: the detail says why; fix that, then recreate the pod with your own rollout: injection happens
only when a pod is created.

### FC-131

`kube_pods_injected`, info: annotated pods in the agent namespaces carry the injected annotation.

Fix: nothing to do.

### FC-132

`kube_namespace_not_labelled`, warning: an agent namespace lacks the label
fabric.singleaxis.ai/injection=enabled, so the injector never sees its pods.

Fix: kubectl label namespace NAME fabric.singleaxis.ai/injection=enabled, then recreate its
annotated pods with your own rollout.

### FC-133

`kube_sensor_not_running`, error: the host sensor is not running on a node it was installed for, so
no host evidence is recorded there.

Fix: the detail holds the pod's state and last log line; a node without Linux 5.8 and BTF cannot run
it: keep it off such nodes with hostSensor.nodeSelector.

### FC-134

`kube_pods_unscoped`, warning: the host sensor selected pods it cannot observe; the detail gives the
node, the count and the reason.

Fix: cgroup_not_found: set EMIT_AGENT_CGROUP_ROOTS through hostSensor.env; unsupported_runtime
(gVisor, Kata): rely on wire capture for that pod or use the default runtime; pod_limit: narrow
hostSensor.agentPodSelector.

### FC-135

`kube_sensor_export_failing`, error: a host sensor cannot deliver its records to the Fabric Node;
the detail holds the gRPC status code.

Fix: Unavailable: the Node is down or a NetworkPolicy blocks the sensor (keep
networkPolicy.hostSensorEgress on); Unauthenticated or PermissionDenied: run helm upgrade so the
node's Secret and ingress group agree.

### FC-136

`kube_sensor_scoped`, info: the host sensor runs and reports the agent pods it observes on each
node.

Fix: nothing to do.

### FC-137

`kube_network_policy_blocks`, warning: a NetworkPolicy selects Fabric's pods and no rule of the
chart allows the traffic the detail names.

Fix: keep the chart's own policies on (otel-collector.networkPolicy.enabled, hostSensorEgress); for
a policy of your own add an allow rule from the pods named to the Node's ingress port.

### FC-138

`kube_runtime_class_unsupported`, warning: a RuntimeClass of this cluster uses gVisor or Kata: the
host sensor cannot observe pods that run under it.

Fix: nothing to change for pods on the default runtime; for a pod under that RuntimeClass rely on
wire capture in the agent (the injector), and expect no host evidence.

### FC-139

`kube_node_without_sensor`, warning: a node cannot run the host sensor or is not in the release's
node list, so pods on it have no host evidence.

Fix: a serverless, virtual or non-Linux node cannot run it: rely on wire capture there; for a node
added after the install run helm upgrade so it gets its Secret and ingress group.

### FC-140

`kube_spool_emptydir_one_shot`, warning: a pod that runs once (a Job, or restartPolicy Never) has an
emptyDir spool: records not delivered when it exits are lost with the pod.

Fix: raise FABRIC_WIRE_DRAIN_ON_EXIT_S for it (injector.env), or give it a persistent spool with the
annotation fabric.singleaxis.ai/spool: pvc.

### FC-141

`kube_run_not_corroborated`, warning: the host sensor is installed but no host record joined this
run, so nothing independent of the agent corroborates it.

Fix: check that the pod carries the sensor's pod label (the injector adds it) and FABRIC_HOST_LABEL,
and that `fabric doctor --kubernetes` shows the pod scoped on its node.

### FC-142

`kube_canary_needs_binding`, info: the canary was not sent: on a production Node every source has
its own ingress binding, and this release generates none for the canary.

Fix: nothing to do; the run's own records are read instead (pass --spans PATH with your
destination's export).

### FC-143

`kube_rendered`, info: the Helm values and the Secret manifests were written for your own pipeline;
nothing was installed.

Fix: apply the Secrets first (kubectl create -f DIR/secrets --recursive), then helm upgrade
--install with the values file; encrypt the manifests before they reach a repository.

### FC-144

`kube_purged`, info: the release was removed and the Secrets Fabric generated for it were deleted.

Fix: nothing to do; an agent pod that still runs keeps the files it mounted until it stops.

### FC-145

`kube_webhook_ca_missing`, error: the injector's webhook has no caBundle, so the API server cannot
verify it and admits annotated pods unchanged.

Fix: run helm upgrade (its post-upgrade Job sets the caBundle from the generated CA), or set
injector.caBundle to the base64 of the CA certificate.

### FC-146

`kube_no_agent_namespace`, warning: the release serves no agent namespace, so no agent pod can
deliver records to this Node.

Fix: name the namespaces of your agents: helm upgrade with --set agentNamespaces=NS (or fabric up
--kubernetes --agent-namespace NS).

### FC-147

`kube_api_forbidden_read`, warning: the identity of the kube context may not read something this
check needs, so that part was skipped.

Fix: the detail names what; ask for get and list on it, or run the command with an identity that may
read the release namespace and the nodes.

### FC-148

`kube_plan_ready`, info: the cluster was read; nothing was changed.

Fix: follow the next command the plan prints.

### FC-149

`kube_released_secrets_kept`, info: the release was removed; the Secrets Fabric generated are kept,
so a new install keeps every key and id.

Fix: nothing to do; fabric down --kubernetes --purge deletes them too.

### FC-150

`kube_host_nodes_needed`, error: the host sensor needs the names of the nodes it runs on, and they
could not be read from the cluster of the current kube context.

Fix: pass --host-node NAME for each node that runs the sensor, oldest first (kubectl get nodes
--sort-by=.metadata.creationTimestamp).

### FC-151

`kube_option_invalid`, error: an option given with --kubernetes cannot be used as given; nothing was
installed or changed.

Fix: the detail names the option and what it takes; `fabric help up` lists the options.

### FC-152

`chart_override`, warning: FABRIC_CHART replaces the chart of this CLI release, so the chart
installed is not the one this release pins.

Fix: unset FABRIC_CHART to install this release's own chart; keep it only to test a chart under
development.

### FC-153

`content_reader_missing`, error: the release delivers model bodies to an S3 content store, and
reading them back needs boto3, which this CLI install lacks.

Fix: pip install "singleaxis-fabric[cli,s3]" on this workstation, then run fabric verify
--kubernetes again.

### FC-154

`content_not_readable`, warning: the release keeps no model bodies where this workstation can read
them, so the agent's model decisions cannot be verified and verify cannot pass.

Fix: deliver content to an S3 or S3-compatible store: otel-collector.content.enabled=true and
content.backend=s3 in your values (docs/get-started/kubernetes.md); this workstation reads it with
your AWS configuration.

### FC-155

`no_capture_policy`, warning: the injector gives agents no capture policy, so on this production
Node they record metadata only: the model bodies the agent's decisions are verified against are
never kept and verify cannot pass.

Fix: set injector.capturePolicy to your fabric.deployment-policy/v1 document in your values
(docs/get-started/kubernetes.md), run fabric up --kubernetes again, then roll out your agents.

### FC-156

`sensor_runtime_class_unread`, warning: the host sensor could not read the RuntimeClass of some
selected pods, so a gVisor or Kata pod among them cannot be reported unsupported_runtime and may be
counted as scoped.

Fix: grant the sensor's service account get on runtimeclasses.node.k8s.io (the chart's ClusterRole
does: run helm upgrade; for deploy/kubernetes/host-emitter-daemonset.yaml apply its current
ClusterRole), and check that each RuntimeClass the pods name exists.

### FC-157

`plan_ready`, info: this machine and the agent were read; nothing was changed, started or contacted.

Fix: follow the next command the plan prints; each fix row names the command that closes its gap.

### FC-158

`plan_sdk_missing`, info: the agent's interpreter does not have the Fabric SDK yet, so nothing is
recorded until it does.

Fix: install it in the agent's own environment with the command in the detail (the plan's next line
starts with it).

### FC-159

`plan_packages_unread`, warning: the agent's installed packages could not be listed, so rows that
depend on a library assume it is present.

Fix: name the agent's interpreter, for example fabric plan -- .venv/bin/python app.py, and check
that it starts.

### FC-160

`plan_runtime_unknown`, warning: the agent's runtime could not be told: no command was given and the
directory has no project manifest.

Fix: give the agent command after --, for example fabric plan -- python app.py.

### FC-161

`plan_mcp_config_unreadable`, error: an --mcp-config file is not a JSON object whose mcpServers
entries have a command or a url.

Fix: pass the MCP client's configuration file: an mcpServers object whose entries have a command (a
stdio server) or a url (an HTTP server).

### FC-162

`coverage_prediction_mismatch`, warning: fabric.yaml turns on a capture point that the run's capture
manifest reports off.

Fix: run fabric doctor for the SDK's reason, and start the agent with fabric run in this project so
it gets the setting.

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

## Reasons in reader verdicts

`fabric verify`, `fabric show` and the reader name each reason a run or one of its chains is not
complete. Each entry says what it means and how to fix it; a chain that gives a reason its own
meaning is listed under it.

### sequence_gap

Records are missing between two that arrived: a process was killed before its spool drained, or
delivery is still in progress.

Fix: let the agent exit normally and run fabric verify again; python -m fabric.wire drain
--until-empty delivers a spool left behind.

On the `controls` chain: records of a control decision or permission are missing between two that
arrived, so a decision may be absent. Fix: let the agent exit normally and run fabric verify again;
python -m fabric.wire drain --until-empty delivers a spool left behind.

### loss

The SDK reported records it could not keep (a full spool or queue, or a client it does not hook).

Fix: give the spool more room (FABRIC_WIRE_SPOOL_MAX_BYTES), keep the Node running, and send model
calls through httpx or aiohttp.

### tail_unverified

The run's last records cannot be proven complete: no final heartbeat arrived (the process was
killed, or is still running).

Fix: let the agent exit normally and run fabric verify after it exits; a batch worker can raise
FABRIC_WIRE_DRAIN_ON_EXIT_S.

### missing_object

A request or response body is not in the content store.

Fix: content may still be on its way: run fabric verify again; check that the agent's
FABRIC_WIRE_STORE is the project's store (fabric doctor).

### digest_mismatch

A stored body does not match the digest its record carries, so the body was changed after capture.

Fix: keep the content store writable by the agent and the Node only, and investigate who changed it.

### truncated

A body was larger than the capture limit and only its first part was kept.

Fix: raise the body limit (max_retain_bytes) in the capture policy if you need whole bodies.

### unparsed_exchange

A model exchange was recorded but could not be parsed in its dialect.

Fix: check the endpoint's dialect: an Anthropic Messages API host needs fabric init --provider
anthropic=URL.

### prefix_break

A model request does not repeat the conversation the previous one ended with, so the two cannot be
chained.

Fix: nothing to fix when the agent rewrites its history on purpose (summarizing, trimming);
otherwise check that one process sends one conversation.

### unmatched_tool_call

A tool call has no result fed back to the model.

Fix: nothing to fix when the agent stopped early; otherwise the result went to the model through a
client Fabric does not hook.

### unresolved_previous_response

A request names a previous response that is not in the record (provider-held conversation state).

Fix: record the run that produced it too (same project), or send the full conversation instead of a
previous response id.

### source_unauthenticated

Records are not authenticated by the Node: they did not arrive through a bound ingress.

Fix: in production, send records through the Node's ingress with its source binding (fabric init
--production, then fabric up).

### segment_missing

A part of the run that another part names as its predecessor is not in the record.

Fix: deliver every process of the run to the same destination; run fabric verify again after all of
them exit.

### segment_conflict

The parts of the run disagree about their order (two roots, a cycle or a replayed resume token).

Fix: resume a run once per resume token, and keep one run label per run (fabric run --run NAME).

### post_terminal_activity

Records of the run arrived after it was declared ended.

Fix: end a run once, after its last step; start a new run for later work.

### run_unterminated

A resumable run never recorded its end and its open-run deadline has passed.

Fix: end the run in code (the run scope's exit), or let the agent process exit normally.

### run_open

The run had not ended when it was read.

Fix: run fabric verify after the agent exits.

### seal_mismatch

The records delivered for part of the run do not reproduce the seal the agent wrote, so a record was
changed or replaced.

Fix: keep the destination append-only, and investigate who changed the records.

### unsealed_segment

Part of the run never wrote its closing seal (the process was killed, or is still running).

Fix: let the agent exit normally and run fabric verify again.

### unsealed_epoch

An earlier process on the same spool never wrote its final records; the next process declared it.

Fix: let agent processes exit normally; python -m fabric.wire drain --until-empty delivers what the
earlier one left.

### manifest_gap

A capture manifest the run's records name is not in the record, so what was switched on cannot be
shown.

Fix: deliver every record of the run to the same destination and run fabric verify again.

### clock_uncertain

Record clocks disagree more than allowed, so time order cannot be trusted.

Fix: keep the agent's, the Node's and the sensor's clocks synchronized (NTP).

### not_instrumented

The capture point that observes this was not installed or not active.

Fix: fabric plan names the line that turns it on; fabric doctor says why an installed one is off.

### hook_disabled

The capture point is installed, but this field is switched off by default.

Fix: turn the field on in the capture policy if you need it.

### not_configured

Nothing is configured to record this.

Fix: fabric plan names the line that turns it on.

On the `corroboration` chain: no host sensor is configured, so nothing independent of the agent
confirms what it did. Fix: on Linux, fabric up starts the sensor (sensor.kind: auto); on Kubernetes
use --set preset=production-host-sensor.

### unsupported_api

The reader does not know this API or item type, so it was kept but not parsed.

Fix: nothing to fix for the run; tell the Fabric maintainers which API it was.

### unsupported_runtime

No capture point exists for this runtime or client library.

Fix: fabric plan names what is recorded in this runtime and the alternative.

### unsupported_version

The runtime or library version is outside the qualified range.

Fix: use a runtime and library version fabric plan lists as supported.

### parse_failed

A body was captured but could not be parsed.

Fix: nothing to fix for the run; the body itself is kept in the content store.

### body_cap

A body was larger than the capture limit and was cut.

Fix: raise max_retain_bytes in the capture policy if you need whole bodies.

### part_cap

A part of a body was larger than the limit: its digest and length are kept, its bytes are not.

Fix: raise max_body_bytes in the capture policy if you need those parts.

### inflight_budget

Too many bytes were in flight at once, so some were not kept.

Fix: raise max_inflight_bytes in the capture policy, or lower the agent's concurrency.

### queue_full

The capture queue was full, so records were dropped (the agent was not slowed).

Fix: keep the Node running and reachable; give the spool more room (FABRIC_WIRE_SPOOL_MAX_BYTES).

### disk_full

The spool's disk was full, so records could not be kept.

Fix: free disk space where the spool lives, or move it (FABRIC_WIRE_SPOOL_DIR).

### shutdown

The process stopped before some records were saved.

Fix: let the agent exit normally; a batch worker can raise FABRIC_WIRE_DRAIN_ON_EXIT_S.

### internal_error

Fabric code failed and dropped records; the agent was not affected.

Fix: run fabric doctor and report the error id it shows to the Fabric maintainers.

### span_dropped

The Node or an exporter refused or sampled out records.

Fix: turn off sampling for Fabric records and check the Node's log (fabric doctor).

### store_failed

The content store did not accept a body after retries.

Fix: check the store's credentials and free space (fabric doctor), then run the agent again.

### destination_rejected

The Node refused a content record (unknown role, bad descriptor or a tenant it does not allow).

Fix: check that the agent's tenant (FABRIC_TENANT_ID) is one the Node allows (fabric doctor).

### transport_incomplete

The client did not read or send the whole body.

Fix: nothing to fix when the agent cancelled the call; otherwise the agent read a body only in part.

### stream_closed_early

The agent closed a streamed response before its end.

Fix: nothing to fix when the agent stopped reading on purpose; otherwise read the stream to its end.

### privacy_policy

Your capture policy withholds this content (omit, metadata only, redact or tokenize).

Fix: nothing to fix if intended; retain the role in the capture policy if you need it.

### protection_failed

The privacy step could not transform this content, so it was withheld, never stored raw.

Fix: check the capture policy's transformation for this role (fabric doctor).

### missing_capture_policy

Content capture needs a capture policy in production and none is configured.

Fix: set FABRIC_CAPTURE_POLICY to your deployment policy file (fabric init --production writes one).

### missing_id_key

A keyed pseudonym was needed and no id key was set.

Fix: start the agent with fabric run (it passes the generated id key), or set
FABRIC_WIRE_ID_KEY_FILE.

### missing_spool_key

Production needs an encrypted spool and no spool key is set, so content capture is off.

Fix: set FABRIC_WIRE_SPOOL_KEY_FILE (fabric init --production generates one).

### provider_redacted

The model provider returned a redaction marker instead of the content.

Fix: nothing to fix: Fabric records what the provider sent.

### provider_encrypted

The model provider returned the content only encrypted or opaque.

Fix: nothing to fix: Fabric records what the provider sent.

### provider_summarised

The model provider returned a summary instead of the original.

Fix: nothing to fix: Fabric records what the provider sent.

### provider_not_returned

The model provider did not return this content.

Fix: nothing to fix: Fabric records what the provider sent.

### provider_held

The content lives in the provider's stored conversation and was not in the observed bytes.

Fix: send the full conversation in each request if you need it in the record.

### caller_omitted

The agent's code called a reporting API without this argument.

Fix: pass the argument in the API call if you need it recorded.

### deferred_to_explicit

The explicit API recorded this exchange, so wire capture left it to that record.

Fix: nothing to fix: the explicit record is the one to read.

### explicit_withheld

The explicit API withheld these bytes under its privacy setting.

Fix: nothing to fix if intended; change the explicit API's privacy setting if you need them.

### not_exposed

This fact never crosses a boundary Fabric can observe.

Fix: record it from the agent's code with the explicit APIs if you need it.

### source_lost

A whole process's records are missing from the record.

Fix: deliver every process to the same destination; python -m fabric.wire drain --until-empty sends
a spool left behind.

### uninstrumented_client

Model calls went through a client Fabric does not hook (requests, urllib3, boto3 or gRPC).

Fix: send model calls through httpx or aiohttp (the provider SDKs do), or record them with
CallRecorder.

### sampling

A sampler dropped records.

Fix: turn off sampling for Fabric records.

### retention_expired

A body existed and was removed by the store's retention.

Fix: verify runs before their retention ends, or lengthen the store's retention.

### deleted

A body existed and was deleted on request.

Fix: nothing to fix if the deletion was intended.

### unattributed_effect

A command ran that no tool call explains (often one the agent's code runs on its own).

Fix: nothing to fix if intended; record the decision with control_check if your code decided it.

### ambiguous_attribution

An effect falls inside two or more tool calls running at once and its output does not tell which one
ran it; under a redact policy commands are withheld, so they cannot be matched.

Fix: retain terminal.argv as a digest in the capture policy to allow matching, or run tool calls one
at a time.

On the `controls` chain: a control decision matches more than one pending request, so it is not
linked to one. Fix: record the gated call's id with the decision (control_check takes it).

### tool_result_missing

A tool call the model asked for has no result in a later model request.

Fix: nothing to fix when the agent stopped early; otherwise the result went to the model through a
client Fabric does not hook.

### exchange_gap

A model exchange the tool chain needs is missing or could not be parsed.

Fix: run fabric verify again after the agent exits; see the decisions chain's reasons for the
missing exchange.

### source_gap

The host sensor was not observing for the whole run (a gap in its records, or its last heartbeat is
older than the run's end).

Fix: keep the sensor running for the whole run and run fabric verify again once its next heartbeat
arrives.

### anchor_missing

A command the agent ran has no matching process event from the host sensor.

Fix: start the agent with fabric run so it joins the sensor's cgroup (on Kubernetes the injector
does it), and keep the sensor running.

### unexplained_host_event

The host sensor saw a process or connection in the agent's scope that no recorded step explains.

Fix: start other programs outside the agent's cgroup, or turn on the exec hook (fabric init --exec)
so the agent's commands explain their processes.

### channel_disabled

No effect of a tool call was observed because the capture point that would see it is off.

Fix: fabric init --exec records commands; fabric init --http-host HOST records HTTP calls.

### no_effect_channel

The tool runs inside the agent process, where no hook observes it.

Fix: nothing to fix: the call and its result are in the model bodies.

### none_in_window

Capture points were on, but no effect happened while the tool call ran.

Fix: nothing to fix when the tool changed nothing outside the process.

### remote_sandbox

The run called a remote sandbox host, and what ran there is not observed.

Fix: for E2B set FABRIC_WIRE_REMOTE_SANDBOX=e2b; for another provider run the host sensor inside the
sandbox.

### control_unmatched

A control or hook record names a call, step or action that is not in the run.

Fix: record the decision in the same process as the call it gates, with the call's id.

### control_pending_at_end

A control was asked to decide and its decision was never recorded before the run ended.

Fix: record the decision (control_check records both the request and its outcome).

### grant_not_recorded

A declared-permission capture point is on but no permission snapshot was recorded.

Fix: call fabric.records.record_grant(...) when the agent starts, or turn that capture point off.

### body_not_retained

An MCP or control host is listed, but its message bodies are not retained, so decisions in them
cannot be read.

Fix: retain the role of those messages in the capture policy.

### invariant_conflict

A control record claims Fabric enforced a decision, which Fabric never does, so it is not trusted.

Fix: record decisions only through fabric.records (enforced_by_fabric is always false).

### other_process

A host event came from a process that is not one of the run's.

Fix: nothing to fix: it is listed, not attributed.

### out_of_scope

A host event came from outside the agent's configured scope.

Fix: nothing to fix: it is listed, not attributed.

### no_run

A host event fell in no run's time window.

Fix: nothing to fix: it is listed, not attributed.

### startup_effects

Commands ran before the agent's first model call (often a client library probing the platform, such
as uname -p); they are listed, not linked to a tool call, and do not make the run partial.

Nothing to fix: they are reported as facts.
