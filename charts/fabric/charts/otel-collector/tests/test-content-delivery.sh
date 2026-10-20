#!/usr/bin/env bash
# Render contract for the spec 048 content path: otlp/content (4319, HTTP
# only, same TLS/mTLS as telemetry) -> logs/content [memory_limiter] ->
# fabriccontent, with the Node as the only content writer.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chart_dir="$(cd "${here}/.." && pwd)"
umbrella_dir="$(cd "${chart_dir}/../.." && pwd)"
profile="${umbrella_dir}/profiles/shadow-production.yaml"

passed=0
failed=0

pass() { printf 'ok: %s\n' "$*"; passed=$((passed + 1)); }
fail() { printf 'FAIL: %s\n' "$*" >&2; failed=$((failed + 1)); }

expect_contains() {
  local label="$1" haystack="$2" needle="$3"
  if grep -q -F -- "${needle}" <<<"${haystack}"; then
    pass "${label}"
  else
    fail "${label}: missing '${needle}'"
  fi
}

expect_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if grep -q -F -- "${needle}" <<<"${haystack}"; then
    fail "${label}: unexpectedly found '${needle}'"
  else
    pass "${label}"
  fi
}

expect_count() {
  local label="$1" haystack="$2" needle="$3" want="$4" got
  got="$(grep -c -F -- "${needle}" <<<"${haystack}" || true)"
  if [[ "${got}" == "${want}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected ${want} x '${needle}', got ${got}"
  fi
}

expect_fail() {
  local label="$1" needle="$2"
  shift 2
  local output
  if output="$(helm template ci "$@" 2>&1)"; then
    fail "${label}: render unexpectedly succeeded"
  elif [[ "${output}" != *"${needle}"* ]]; then
    fail "${label}: expected '${needle}', got: ${output}"
  else
    pass "${label}"
  fi
}

# A pipeline block from the rendered collector config, as one line per key.
pipeline_block() {
  awk -v name="$2" '
    /^      pipelines:$/ { in_pipelines = 1; next }
    in_pipelines && $0 ~ "^        " name ":$" { on = 1; next }
    /^ *#/ { next }
    {
      match($0, /^ */)
      if (on && RLENGTH <= 8) on = 0
    }
    on { print }
  ' <<<"$1"
}

printf '\n=== Disabled by default ===\n'
default_render="$(helm template ci "${chart_dir}")"
expect_not_contains "no content receiver by default" "${default_render}" "otlp/content"
expect_not_contains "no content exporter by default" "${default_render}" "fabriccontent"
expect_not_contains "no content port by default" "${default_render}" "4319"
expect_contains "telemetry memory limit unchanged" "${default_render}" "limit_mib: 512"

s3_args=(
  --set content.enabled=true
  --set 'content.allowedTenants[0]=tenant-a'
  --set 'content.allowedTenants[1]=tenant-b'
  --set content.allowMultipleTenants=true
  --set content.backend=s3
  --set content.s3.bucket=customer-evidence
  --set content.s3.prefix=fabric/content/
  --set content.s3.region=eu-west-1
  --set content.s3.sse=aws:kms
  --set content.s3.kmsKeyId=arn:aws:kms:eu-west-1:111122223333:key/0000
)

printf '\n=== S3 backend (workload identity) ===\n'
s3_config="$(helm template ci "${chart_dir}" "${s3_args[@]}" --show-only templates/configmap.yaml)"
s3_render="$(helm template ci "${chart_dir}" "${s3_args[@]}" \
  --set-json 'serviceAccount.annotations={"eks.amazonaws.com/role-arn":"arn:aws:iam::111122223333:role/fabric-node-writer"}')"
expect_contains "content receiver listens on 4319" "${s3_config}" "endpoint: 0.0.0.0:4319"
expect_contains "content receiver accepts one 64 MiB record" "${s3_config}" "max_request_body_size: 67108864"
expect_contains "content receiver read timeout sized for 64 MiB" "${s3_config}" "read_timeout: 120s"
content_receiver="$(awk '/^      otlp\/content:$/ { on = 1; next } on && /^      [^ ]/ { on = 0 } on && /^$/ { on = 0 } on { print }' <<<"${s3_config}")"
expect_not_contains "content receiver is HTTP only" "${content_receiver}" "grpc"
expect_contains "exporter allows the named tenants" "${s3_config}" '- "tenant-b"'
expect_contains "several tenants render the explicit trust flag" "${s3_config}" "allow_multiple_tenants: true"
expect_contains "exporter uses the s3 backend" "${s3_config}" 'backend: "s3"'
expect_contains "exporter bucket" "${s3_config}" 'bucket: "customer-evidence"'
expect_contains "exporter prefix" "${s3_config}" 'prefix: "fabric/content/"'
expect_contains "exporter region" "${s3_config}" 'region: "eu-west-1"'
expect_contains "exporter sse" "${s3_config}" 'sse: "aws:kms"'
expect_contains "exporter kms key" "${s3_config}" 'kms_key_id: "arn:aws:kms:eu-west-1:111122223333:key/0000"'
expect_contains "path style off by default" "${s3_config}" "use_path_style: false"
expect_not_contains "no custom endpoint for AWS" "${s3_config}" "endpoint: \"http"
expect_contains "content queue blocks instead of dropping" "${s3_config}" "block_on_overflow: true"
expect_contains "content retry never gives up" "${s3_config}" 'max_elapsed_time: "0s"'
expect_contains "memory limiter raised for 64 MiB requests" "${s3_config}" "limit_mib: 768"
content_pipeline="$(pipeline_block "${s3_config}" "logs/content")"
expect_contains "content pipeline receives only otlp/content" "${content_pipeline}" "receivers: [otlp/content]"
expect_contains "content pipeline runs only memory_limiter" "${content_pipeline}" "processors: [memory_limiter]"
expect_contains "content pipeline exports only fabriccontent" "${content_pipeline}" "exporters: [fabriccontent]"
for telemetry in traces logs; do
  block="$(pipeline_block "${s3_config}" "${telemetry}")"
  expect_contains "${telemetry} still runs fabricguard" "${block}" "fabricguard"
  expect_not_contains "${telemetry} never exports content" "${block}" "fabriccontent"
  expect_not_contains "${telemetry} never receives content" "${block}" "otlp/content"
done
expect_contains "service exposes 4319" "${s3_render}" "port: 4319"
expect_contains "pod exposes the content port" "${s3_render}" "name: otlp-content"
expect_contains "IRSA role annotation on the Node service account" "${s3_render}" "eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/fabric-node-writer"
expect_contains "no Kubernetes API token is mounted" "${s3_render}" "automountServiceAccountToken: false"
expect_not_contains "no static cloud keys without a Secret" "${s3_render}" "AWS_ACCESS_KEY_ID"
expect_not_contains "in-memory content queue has no storage" "${s3_config}" "file_storage/fabric_content"
expect_not_contains "in-memory content queue names no queue directory" "${s3_config}" "queue_directory:"

printf '\n=== S3-compatible store with static keys from a Secret ===\n'
minio_render="$(helm template ci "${chart_dir}" \
  --set content.enabled=true \
  --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 \
  --set content.s3.bucket=fabric-content \
  --set content.s3.endpoint=http://minio.storage.svc:9000 \
  --set content.s3.usePathStyle=true \
  --set content.s3.sse=AES256 \
  --set content.s3.credentialsSecret.name=fabric-node-minio)"
expect_contains "custom endpoint renders" "${minio_render}" 'endpoint: "http://minio.storage.svc:9000"'
expect_contains "path style renders" "${minio_render}" "use_path_style: true"
expect_contains "access key comes from the Secret" "${minio_render}" "name: AWS_ACCESS_KEY_ID"
expect_contains "secret key comes from the Secret" "${minio_render}" "name: AWS_SECRET_ACCESS_KEY"
expect_contains "Secret is referenced by name" "${minio_render}" "name: fabric-node-minio"
expect_not_contains "no kms key for AES256" "${minio_render}" "kms_key_id"
expect_not_contains "one tenant needs no trust flag" "${minio_render}" "allow_multiple_tenants"
default_sse="$(helm template ci "${chart_dir}" --set content.enabled=true \
  --set 'content.allowedTenants[0]=tenant-a' --set content.backend=s3 \
  --set content.s3.bucket=customer-evidence --show-only templates/configmap.yaml)"
expect_contains "s3 encrypts with SSE-S3 by default" "${default_sse}" 'sse: "AES256"'

printf '\n=== Durable content queue and file backend on the queue PVC ===\n'
durable_args=(
  --set exporter.endpoint=https://otlp.example.com
  --set exporter.insecure=false
  --set exporter.sendingQueue.persistence.enabled=true
  --set exporter.sendingQueue.persistence.fsync=true
  --set content.enabled=true
  --set 'content.allowedTenants[0]=tenant-a'
  --set content.backend=file
)
durable_render="$(helm template ci "${chart_dir}" "${durable_args[@]}")"
expect_contains "content queue on the same PVC" "${durable_render}" 'directory: "/var/lib/otelcol-fabric/storage/content-queue"'
expect_contains "content queue binds its file storage" "${durable_render}" "storage: file_storage/fabric_content"
expect_contains "content file storage is a started extension" "${durable_render}" "- file_storage/fabric_content"
# Sol F3: queued content is raw model bytes. file_storage creates the queue
# directory private, and fabriccontent tightens an existing one (and its
# database) at start, before the queue opens it.
expect_count "content queue directory is created private" "${durable_render}" 'directory_permissions: "0700"' 1
expect_contains "content exporter tightens its queue directory" "${durable_render}" 'queue_directory: "/var/lib/otelcol-fabric/storage/content-queue"'
expect_count "content queue fsync follows the telemetry queue" "${durable_render}" "fsync: true" 2
expect_contains "file backend defaults inside the queue PVC" "${durable_render}" 'directory: "/var/lib/otelcol-fabric/storage/content"'
expect_not_contains "file backend needs no extra mount (exporter owns its root)" "${durable_render}" "subPath:"
expect_not_contains "persistent file backend has no emptyDir" "${durable_render}" "emptyDir"
expect_count "only one PVC template" "${durable_render}" "volumeClaimTemplates:" 1
explicit_render="$(helm template ci "${chart_dir}" "${durable_args[@]}" \
  --set content.file.directory=/var/lib/otelcol-fabric/storage/evidence)"
expect_contains "explicit directory inside the queue PVC" "${explicit_render}" 'directory: "/var/lib/otelcol-fabric/storage/evidence"'
expect_fail "file backend outside the queue PVC is refused" "must lie inside exporter.sendingQueue.persistence.directory" \
  "${chart_dir}" "${durable_args[@]}" --set content.file.directory=/var/lib/fabric-node/content
expect_fail "file backend cannot share the content queue" "must lie inside exporter.sendingQueue.persistence.directory" \
  "${chart_dir}" "${durable_args[@]}" --set content.file.directory=/var/lib/otelcol-fabric/storage/content-queue/x
dev_file="$(helm template ci "${chart_dir}" --set content.enabled=true \
  --set 'content.allowedTenants[0]=tenant-a' --set content.backend=file)"
expect_contains "development file backend uses an emptyDir" "${dev_file}" "emptyDir: {}"
expect_contains "development emptyDir stands in at the queue directory" "${dev_file}" "mountPath: /var/lib/otelcol-fabric/storage"

printf '\n=== Receiver TLS / mTLS applies to the content receiver ===\n'
tls_config="$(helm template ci "${chart_dir}" "${s3_args[@]}" \
  --set receiver.requireTLS=true \
  --set receiver.requireClientCertificate=true \
  --set receiver.tls.serverCertificateSecret.name=fabric-test-receiver-tls \
  --set receiver.tls.clientCASecret.name=fabric-test-client-ca \
  --show-only templates/configmap.yaml)"
expect_count "gRPC, HTTP and content receivers load the server certificate" "${tls_config}" "cert_file: /etc/fabric/receiver-tls/tls.crt" 3
expect_count "gRPC, HTTP and content receivers verify client certificates" "${tls_config}" "client_ca_file: /etc/fabric/receiver-tls/client-ca.crt" 3

printf '\n=== NetworkPolicy ===\n'
np_render="$(helm template ci "${chart_dir}" "${s3_args[@]}" \
  --set networkPolicy.enabled=true \
  --set-string 'networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true' \
  --set 'networkPolicy.contentEgress.to[0].ipBlock.cidr=198.51.100.0/24' \
  --set 'networkPolicy.contentEgress.ports[0].protocol=TCP' \
  --set 'networkPolicy.contentEgress.ports[0].port=443' \
  --show-only templates/networkpolicy.yaml)"
ingress_rule="$(awk '/^  ingress:/ { on = 1 } /^  egress:/ { on = 0 } on { print }' <<<"${np_render}")"
expect_contains "4319 ingress from the agent peers" "${ingress_rule}" "port: 4319"
expect_count "content shares the single OTLP ingress rule" "${ingress_rule}" "fabric.singleaxis.ai/agent" 1
expect_contains "content store egress peer" "${np_render}" "cidr: 198.51.100.0/24"
np_off="$(helm template ci "${chart_dir}" --set networkPolicy.enabled=true --show-only templates/networkpolicy.yaml)"
expect_not_contains "no 4319 ingress while content is disabled" "${np_off}" "port: 4319"
expect_fail "content egress needs both peers and ports" "networkPolicy.contentEgress requires both" \
  "${chart_dir}" "${s3_args[@]}" --set networkPolicy.enabled=true \
  --set 'networkPolicy.contentEgress.to[0].ipBlock.cidr=198.51.100.0/24'
expect_fail "content egress rejects world CIDRs" "world CIDR" \
  "${chart_dir}" "${s3_args[@]}" --set networkPolicy.enabled=true \
  --set 'networkPolicy.contentEgress.to[0].ipBlock.cidr=0.0.0.0/0' \
  --set 'networkPolicy.contentEgress.ports[0].protocol=TCP' \
  --set 'networkPolicy.contentEgress.ports[0].port=443'
expect_fail "content egress without a policy is misleading" "networkPolicy.enabled=false" \
  "${chart_dir}" "${s3_args[@]}" \
  --set 'networkPolicy.contentEgress.to[0].ipBlock.cidr=198.51.100.0/24' \
  --set 'networkPolicy.contentEgress.ports[0].protocol=TCP' \
  --set 'networkPolicy.contentEgress.ports[0].port=443'

printf '\n=== Fail-closed content invariants ===\n'
expect_fail "content requires allowed tenants" "requires content.allowedTenants" \
  "${chart_dir}" --set content.enabled=true --set content.backend=s3 --set content.s3.bucket=customer-evidence
expect_fail "content requires a backend" "requires content.backend" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a'
expect_fail "several tenants need the explicit trust flag" "lists more than one tenant" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set 'content.allowedTenants[1]=tenant-b' --set content.backend=s3 \
  --set content.s3.bucket=customer-evidence
expect_fail "s3 without sse is refused" "requires content.s3.sse" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence --set content.s3.sse=
expect_fail "unsafe tenant ids are refused" "allowedTenants" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=../etc' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence
expect_fail "s3 requires a bucket" "requires content.s3.bucket" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' --set content.backend=s3
expect_fail "kms key only with aws:kms" "only valid with content.s3.sse=aws:kms" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence --set content.s3.kmsKeyId=k
expect_fail "unknown sse is refused" "sse" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence --set content.s3.sse=aws:kms:dsse
expect_fail "endpoint user info is refused" "endpoint" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence \
  --set 'content.s3.endpoint=https://key:secret@minio:9000'
expect_fail "endpoint query is refused" "endpoint" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence \
  --set 'content.s3.endpoint=https://minio:9000/?X-Amz-Credential=x'
expect_fail "prefix traversal is refused" "content.s3.prefix" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence --set content.s3.prefix=a/../b/
expect_fail "prefix must end with a slash" "prefix" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence --set content.s3.prefix=fabric
expect_fail "required encryption refuses s3 without sse" "requires content.s3.sse" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence --set content.s3.sse= \
  --set content.requireServerSideEncryption=true
expect_fail "required encryption refuses the file backend" "refuses content.backend=file" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=file --set content.requireServerSideEncryption=true
expect_fail "egress TLS requirement covers the content endpoint" "https:// content.s3.endpoint" \
  "${chart_dir}" "${s3_args[@]}" --set exporter.endpoint=https://otlp.example.com \
  --set exporter.insecure=false --set exporter.requireTLS=true \
  --set content.s3.endpoint=http://minio:9000
expect_fail "file backend is single-replica" "requires replicaCount=1" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=file --set replicaCount=2
expect_fail "file backend needs a clean absolute path" "content.file.directory" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=file --set content.file.directory=/var/lib/otelcol-fabric/storage/../content
expect_fail "static keys need both Secret keys" "accessKeyIdKey" \
  "${chart_dir}" "${s3_args[@]}" --set content.s3.credentialsSecret.name=s \
  --set content.s3.credentialsSecret.accessKeyIdKey=
expect_fail "memory limiter must stay below the container limit" "not below resources.limits.memory" \
  "${chart_dir}" "${s3_args[@]}" --set content.memoryLimiterMiB=1024
expect_fail "request bound cannot exceed 64 MiB" "maxRequestBodyBytes" \
  "${chart_dir}" "${s3_args[@]}" --set content.maxRequestBodyBytes=134217728

printf '\n=== Memory limit units and NetworkPolicy egress (m5) ===\n'
# The memory guard reads every Kubernetes quantity form; a limit it could not
# parse used to skip the comparison silently.
for quantity in 800M 805306368 0.75Gi 768Mi; do
  expect_fail "memory limit ${quantity} at or below the limiter is refused" "not below resources.limits.memory" \
    "${chart_dir}" "${s3_args[@]}" --set-string "resources.limits.memory=${quantity}"
done
for quantity in 1G 2147483648 1.5Gi 2048Mi; do
  if helm template ci "${chart_dir}" "${s3_args[@]}" --set-string "resources.limits.memory=${quantity}" >/dev/null 2>&1; then
    pass "memory limit ${quantity} above the limiter renders"
  else
    fail "memory limit ${quantity} above the limiter refused"
  fi
done
expect_fail "an unreadable memory limit fails closed" "must be a Kubernetes memory quantity" \
  "${chart_dir}" "${s3_args[@]}" --set-string resources.limits.memory=lots
numeric_values="$(mktemp)"
printf 'resources:\n  limits:\n    memory: 805306368\n' >"${numeric_values}"
expect_fail "a numeric byte limit is compared, not misread" "not below resources.limits.memory (768 MiB)" \
  "${chart_dir}" "${s3_args[@]}" --values "${numeric_values}"
rm -f "${numeric_values}"
expect_fail "an enabled policy needs content egress for s3" "requires operator-supplied networkPolicy.contentEgress.to" \
  "${chart_dir}" "${s3_args[@]}" --set networkPolicy.enabled=true \
  --set-string 'networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'

printf '\n=== Shadow production ===\n'
production_args=(
  --values "${profile}" --values "${umbrella_dir}/tests/fixtures/production-assertions.yaml"
  --set tenant.id=customer-production
  --set otel-collector.exporter.endpoint=https://otlp.example.com
  --set-string 'otel-collector.networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.fabric\.singleaxis\.ai/agent=true'
  --set 'otel-collector.networkPolicy.exporterEgress.to[0].ipBlock.cidr=203.0.113.10/32'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.exporterEgress.ports[0].port=443'
)
production_content=(
  "${production_args[@]}"
  --set otel-collector.content.enabled=true
  --set 'otel-collector.content.allowedTenants[0]=customer-production'
  --set otel-collector.content.backend=s3
  --set otel-collector.content.s3.bucket=customer-evidence
  --set otel-collector.content.s3.sse=aws:kms
  --set otel-collector.content.s3.kmsKeyId=arn:aws:kms:eu-west-1:111122223333:key/0000
  --set 'otel-collector.networkPolicy.contentEgress.to[0].ipBlock.cidr=198.51.100.0/24'
  --set 'otel-collector.networkPolicy.contentEgress.ports[0].protocol=TCP'
  --set 'otel-collector.networkPolicy.contentEgress.ports[0].port=443'
)
production_default="$(helm template ci "${umbrella_dir}" "${production_args[@]}")"
expect_not_contains "production leaves content off by default" "${production_default}" "otlp/content"
production_render="$(helm template ci "${umbrella_dir}" "${production_content[@]}")"
expect_count "production content receiver requires client certificates" "${production_render}" "client_ca_file: /etc/fabric/receiver-tls/client-ca.crt" 3
# Workload authentication covers the content port too: 4317, 4318 and 4319
# all present the same workload bearer authenticator.
expect_count "workload auth puts the bearer authenticator on 4319" "${production_render}" "authenticator: bearertokenauth/workload" 3
expect_fail "production content tenants must be exactly [tenant.id]" "content.allowedTenants to be exactly [" \
  "${umbrella_dir}" "${production_content[@]}" --set 'otel-collector.content.allowedTenants[0]=other-tenant'
expect_fail "production content refuses a second tenant" "content.allowMultipleTenants must be false" \
  "${umbrella_dir}" "${production_content[@]}" --set otel-collector.content.allowMultipleTenants=true \
  --set 'otel-collector.content.allowedTenants[1]=other-tenant'
expect_contains "production content queue is durable" "${production_render}" "storage: file_storage/fabric_content"
expect_contains "production content queue is private" "${production_render}" 'directory_permissions: "0700"'
expect_contains "production content queue is tightened at start" "${production_render}" 'queue_directory: "'
expect_contains "production content store egress" "${production_render}" "cidr: 198.51.100.0/24"

# Spec 049 P0-A: a production-profile Node binds every batch and seals the
# content queue with the Node key.
expect_count "production profile on fabricguard and fabriccontent" "${production_render}" 'profile: "production"' 2
expect_contains "production binds fabricguard to the workload source" "${production_render}" 'source_id: "s-c5aedfd8a3ee415e277e335bf1517ff4"'
expect_count "fabricguard and fabriccontent share the binding" "${production_render}" 'source_id: "s-c5aedfd8a3ee415e277e335bf1517ff4"' 2
expect_contains "fabricguard is bound" "${production_render}" "evidence_source_binding:"
expect_contains "fabriccontent is bound" "${production_render}" "source_binding:"
expect_contains "identity mode is pseudonymous" "${production_render}" 'identity_mode: "pseudonymous"'
expect_contains "the content queue is sealed" "${production_render}" "storage: fabricenvelope/fabric_content"
expect_contains "the envelope wraps the private queue" "${production_render}" "fabricenvelope/fabric_content:"
expect_contains "the envelope reads the key file" "${production_render}" "key_file: /etc/fabric/content-key/key"
expect_contains "the envelope is active" "${production_render}" "- fabricenvelope/fabric_content"
expect_contains "the key Secret is projected" "${production_render}" 'name: "fabric-node-content-key"'
expect_contains "the key mount" "${production_render}" "mountPath: /etc/fabric/content-key"
expect_not_contains "the key never enters the ConfigMap as a value" "${production_render}" "FABRIC_CONTENT_KEY"
expect_fail "production content requires the Node key" "requires content.encryption.keySecret.name" \
  "${umbrella_dir}" "${production_content[@]}" --set otel-collector.content.encryption.keySecret.name=
expect_fail "production requires the bound source id" "requires receiver.workloadAuthentication.sourceId" \
  "${umbrella_dir}" "${production_args[@]}" --set otel-collector.receiver.workloadAuthentication.sourceId=
# The binding must be the source id agents actually send: s-<32 hex> under
# pseudonymous capture labels (the default); a clear label only with
# fabric.guard.captureLabels=clear.
for bad_source in agent-a S-C5AEDFD8A3EE415E277E335BF1517FF4 s-c5aedfd8a3ee415e277e335bf1517ff s-c5aedfd8a3ee415e277e335bf1517ff4x; do
  expect_fail "pseudonymous production refuses sourceId ${bad_source}" "sourceId must be s-<32 lowercase hex>" \
    "${umbrella_dir}" "${production_args[@]}" --set "otel-collector.receiver.workloadAuthentication.sourceId=${bad_source}"
done
clear_render="$(helm template ci "${umbrella_dir}" "${production_args[@]}" \
  --set otel-collector.fabric.guard.captureLabels=clear \
  --set otel-collector.receiver.workloadAuthentication.sourceId=agent-a)"
expect_contains "clear capture labels accept a clear sourceId" "${clear_render}" 'source_id: "agent-a"'
expect_fail "production pins the production profile" "profile shadow-production requires" \
  "${umbrella_dir}" "${production_args[@]}" --set otel-collector.fabric.profile=local
expect_fail "the production profile needs an authenticated source" "rejects unauthenticated sources" \
  "${chart_dir}" --set fabric.profile=production
expect_fail "production content requires sse" "requires content.s3.sse" \
  "${umbrella_dir}" "${production_content[@]}" --set otel-collector.content.s3.sse= \
  --set otel-collector.content.s3.kmsKeyId=
expect_fail "production content refuses the file backend" "refuses content.backend=file" \
  "${umbrella_dir}" "${production_content[@]}" --set otel-collector.content.backend=file
expect_fail "production pins required encryption" "profile shadow-production requires" \
  "${umbrella_dir}" "${production_content[@]}" --set otel-collector.content.requireServerSideEncryption=false
expect_fail "production content requires store egress peers" "networkPolicy.contentEgress.to" \
  "${umbrella_dir}" "${production_args[@]}" \
  --set otel-collector.content.enabled=true \
  --set 'otel-collector.content.allowedTenants[0]=customer-production' \
  --set otel-collector.content.backend=s3 \
  --set otel-collector.content.s3.bucket=customer-evidence \
  --set otel-collector.content.s3.sse=AES256
expect_fail "production content requires allowed tenants" "requires content.allowedTenants" \
  "${umbrella_dir}" "${production_args[@]}" \
  --set otel-collector.content.enabled=true \
  --set otel-collector.content.backend=s3 \
  --set otel-collector.content.s3.bucket=customer-evidence \
  --set otel-collector.content.s3.sse=AES256

printf '\n=== Separate Node profiles ===\n'
# The dedicated evidence Node (evidenceSourceBinding) never carries content.
expect_fail "content cannot share the dedicated evidence ingress" "content path cannot share the dedicated evidence ingress; deploy a separate Node" \
  "${chart_dir}" --set content.enabled=true --set 'content.allowedTenants[0]=tenant-a' \
  --set content.backend=s3 --set content.s3.bucket=customer-evidence --set content.s3.sse=AES256 \
  --set receiver.evidenceSourceBinding.enabled=true --set receiver.evidenceSourceBinding.tenantId=tenant-a \
  --set receiver.evidenceSourceBinding.sourceId=source-a \
  --set receiver.evidenceSourceBinding.tokenSecret.name=evidence-token \
  --set receiver.requireTLS=true --set receiver.tls.serverCertificateSecret.name=tls

printf '\n--- summary: %d passed, %d failed ---\n' "${passed}" "${failed}"
exit $((failed > 0 ? 1 : 0))
