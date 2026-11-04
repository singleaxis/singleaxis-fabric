{{/*
Static dedicated ingress groups (spec 053 §6.1, §6.2.6; spec 056 §7.3.3 (f),
(g)). A non-empty receiver.sourceBindings renders one group per entry: its own
bearertokenauth/<name>, otlp/<name> (and otlp/content-<name> for an agent group
with content), fabricguard/<name> bound to its tenant and source, and
traces/<name> (plus logs/<name> for agents, logs/content-<name> with content).
Identity is fixed by the ingress a batch arrived on. An empty list keeps the
legacy single binding, rendered as before (053 revision 4 §6.1).

Diagnostics name the field and index only, never a configured value.
*/}}

{{/* "true" when receiver.sourceBindings is non-empty. */}}
{{- define "otel-collector.groupMode" -}}
{{- if gt (len (.Values.receiver.sourceBindings | default list)) 0 -}}true{{- end -}}
{{- end -}}

{{- define "otel-collector.validateSourceBindings" -}}
{{- $r := .Values.receiver -}}
{{- $groups := $r.sourceBindings | default list -}}
{{- if $groups -}}
{{- if or $r.workloadAuthentication.enabled $r.evidenceSourceBinding.enabled -}}
{{- fail "receiver.sourceBindings cannot be combined with receiver.workloadAuthentication or receiver.evidenceSourceBinding: a configuration has the legacy single binding or only ingress groups, never both (spec 053 §6.1)" -}}
{{- end -}}
{{- $max := int $r.maxSourceBindings -}}
{{- if or (lt $max 1) (gt $max 256) -}}
{{- fail "receiver.maxSourceBindings must be 1 to 256 (default 64; spec 053 §6.1)" -}}
{{- end -}}
{{- if gt (len $groups) $max -}}
{{- fail (printf "receiver.sourceBindings has %d groups, more than receiver.maxSourceBindings (%d); the default is 64 and the ceiling 256 (spec 053 §6.1). Deploy one Node per node pool for more" (len $groups) $max) -}}
{{- end -}}
{{- if ne .Values.fabric.profile "production" -}}
{{- fail "receiver.sourceBindings requires fabric.profile=production: every group's fabricguard instance binds its tenant and source (spec 053 §6.1)" -}}
{{- end -}}
{{- if not (and $r.requireTLS $r.tls.serverCertificateSecret.name) -}}
{{- fail "receiver.sourceBindings requires receiver.requireTLS=true and receiver.tls.serverCertificateSecret.name: every group listener uses TLS (spec 053 §6.1 rule 8)" -}}
{{- end -}}
{{- if not (and .Values.exporter.endpoint .Values.exporter.requireTLS) -}}
{{- fail "receiver.sourceBindings requires exporter.endpoint with exporter.requireTLS=true: group pipelines export only to the approved OTLP/HTTP exporter" -}}
{{- end -}}
{{- if .Values.debugExporter.enabled -}}
{{- fail "receiver.sourceBindings requires debugExporter.enabled=false: group pipelines export only to the approved OTLP/HTTP exporter" -}}
{{- end -}}
{{- $clear := eq (.Values.fabric.guard.captureLabels | default "pseudonymous") "clear" -}}
{{- $names := dict -}}
{{- $pairs := dict -}}
{{- $secrets := dict -}}
{{- $ports := dict (toString (int .Values.service.ports.health)) "health" -}}
{{- $contentGroups := 0 -}}
{{- range $i, $g := $groups -}}
{{- $field := printf "receiver.sourceBindings[%d]" $i -}}
{{- if not (kindIs "map" $g) -}}
{{- fail (printf "%s must be an object" $field) -}}
{{- end -}}
{{- $name := $g.name | default "" | toString -}}
{{- if or (not (regexMatch "^[a-z][a-z0-9-]{0,31}$" $name)) (hasPrefix "content" $name) -}}
{{- fail (printf "%s.name must match ^[a-z][a-z0-9-]{0,31}$ and must not start with content (spec 053 §6.1)" $field) -}}
{{- end -}}
{{- if hasKey $names $name -}}
{{- fail (printf "%s.name repeats another group's name" $field) -}}
{{- end -}}
{{- $_ := set $names $name true -}}
{{- $kind := $g.kind | default "" | toString -}}
{{- if not (has $kind (list "agent" "host.ebpf" "host.auditd")) -}}
{{- fail (printf "%s.kind must be agent, host.ebpf or host.auditd" $field) -}}
{{- end -}}
{{- $tenant := $g.tenantId | default "" | toString -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" $tenant) -}}
{{- fail (printf "%s requires a valid nonempty tenantId" $field) -}}
{{- end -}}
{{- $source := $g.sourceId | default "" | toString -}}
{{- if and $clear (eq $kind "agent") -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" $source) -}}
{{- fail (printf "%s requires a valid nonempty sourceId" $field) -}}
{{- end -}}
{{- else if not (regexMatch "^s-[0-9a-f]{32}$" $source) -}}
{{- fail (printf "%s.sourceId must be s-<32 lowercase hex>: the source id as it travels (a host sensor's id from print-source-id or deploy/kubernetes/host-bindings.py; an agent's unless fabric.guard.captureLabels=clear)" $field) -}}
{{- end -}}
{{- $pair := printf "%s\x00%s" $tenant $source -}}
{{- if hasKey $pairs $pair -}}
{{- fail (printf "%s binds the same (tenantId, sourceId) as another group; no two groups bind one source (spec 053 §6.1 rule 7)" $field) -}}
{{- end -}}
{{- $_ := set $pairs $pair true -}}
{{- $secret := $g.tokenSecret | default dict -}}
{{- $secretName := $secret.name | default "" | toString -}}
{{- $secretKey := $secret.key | default "" | toString -}}
{{- if or (gt (len $secretName) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $secretName)) -}}
{{- fail (printf "%s requires a valid tokenSecret.name for an existing Secret" $field) -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9._-]+$" $secretKey) -}}
{{- fail (printf "%s requires a valid tokenSecret.key" $field) -}}
{{- end -}}
{{- $ref := printf "%s\x00%s" $secretName $secretKey -}}
{{- if hasKey $secrets $ref -}}
{{- fail (printf "%s.tokenSecret repeats another group's Secret reference; every group has its own credential (spec 053 §6.1 rules 1 and 5)" $field) -}}
{{- end -}}
{{- $_ := set $secrets $ref true -}}
{{- $protocols := $g.protocols | default dict -}}
{{- if not (or (hasKey $protocols "grpc") (hasKey $protocols "http")) -}}
{{- fail (printf "%s.protocols requires grpc, http or both" $field) -}}
{{- end -}}
{{- $listeners := list -}}
{{- range $protocol := list "grpc" "http" -}}
{{- if hasKey $protocols $protocol -}}
{{- $listeners = append $listeners (dict "field" (printf "%s.protocols.%s" $field $protocol) "port" (index $protocols $protocol)) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $g "content" -}}
{{- if ne $kind "agent" -}}
{{- fail (printf "%s.content: a host group has no content receiver (spec 053 §6.2.6 rule 2)" $field) -}}
{{- end -}}
{{- if not $.Values.content.enabled -}}
{{- fail (printf "%s.content requires content.enabled=true" $field) -}}
{{- end -}}
{{- $listeners = append $listeners (dict "field" (printf "%s.content.port" $field) "port" (($g.content | default dict).port)) -}}
{{- $contentGroups = add1 $contentGroups -}}
{{- end -}}
{{- range $l := $listeners -}}
{{- $port := $l.port -}}
{{- if not (or (kindIs "float64" $port) (kindIs "int" $port) (kindIs "int64" $port)) -}}
{{- fail (printf "%s must be a port number from 1 to 65535" $l.field) -}}
{{- end -}}
{{- if or (lt (int $port) 1) (gt (int $port) 65535) -}}
{{- fail (printf "%s must be a port number from 1 to 65535" $l.field) -}}
{{- end -}}
{{- if hasKey $ports (toString (int $port)) -}}
{{- fail (printf "%s reuses a port another listener (or the health port) has; every group listener has its own (spec 053 §6.1, §6.2.6 rule 5)" $l.field) -}}
{{- end -}}
{{- $_ := set $ports (toString (int $port)) $l.field -}}
{{- end -}}
{{- if hasKey $g "hostDigests" -}}
{{- if eq $kind "agent" -}}
{{- fail (printf "%s.hostDigests applies to host groups only" $field) -}}
{{- end -}}
{{- if not (has ($g.hostDigests | toString) (list "omitted" "permitted")) -}}
{{- fail (printf "%s.hostDigests must be omitted or permitted" $field) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $g "ingressFrom" -}}
{{- if not (kindIs "slice" $g.ingressFrom) -}}
{{- fail (printf "%s.ingressFrom must be a list of NetworkPolicy peers" $field) -}}
{{- end -}}
{{- include "otel-collector.validatePeers" (dict "peers" $g.ingressFrom "field" (printf "%s.ingressFrom" $field)) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.content.enabled (eq $contentGroups 0) -}}
{{- fail "content.enabled=true with receiver.sourceBindings requires an agent group with content.port: content arrives only on its group's own content receiver" -}}
{{- end -}}
{{- if and .Values.content.enabled (gt (len .Values.content.allowedTenants) 0) -}}
{{- fail "content.allowedTenants is not used with receiver.sourceBindings: each content group allows exactly its own tenantId; leave it empty" -}}
{{- end -}}
{{- if and .Values.content.enabled .Values.content.allowMultipleTenants -}}
{{- fail "content.allowMultipleTenants is refused with receiver.sourceBindings: each content group allows exactly its own tenantId" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The NetworkPolicy peers of one group: its own ingressFrom, else the chart's. */}}
{{- define "otel-collector.groupPeers" -}}
{{- $g := .group -}}
{{- if hasKey $g "ingressFrom" -}}
{{- toYaml ($g.ingressFrom | default list) -}}
{{- else -}}
{{- toYaml (.root.Values.networkPolicy.ingressFrom | default list) -}}
{{- end -}}
{{- end -}}

{{/* The TLS block every group listener carries (the chart's receiver-tls mount). */}}
{{- define "otel-collector.groupTLS" -}}
tls:
  cert_file: /etc/fabric/receiver-tls/tls.crt
  key_file: /etc/fabric/receiver-tls/tls.key
  {{- if .Values.receiver.tls.clientCASecret.name }}
  client_ca_file: /etc/fabric/receiver-tls/client-ca.crt
  {{- end }}
{{- end -}}

{{/*
The collector configuration of a Node with ingress groups (spec 056 §7.3.3 (f)).
contracts/capture/v1/fixtures/ingress-groups/valid/agent-ebpf-auditd.yaml and
valid/agent-ebpf-three-nodes.yaml are this render, normalised
(tests/test-source-bindings.sh).
*/}}
{{- define "otel-collector.groupConfig" -}}
{{- $content := .Values.content -}}
{{- $persist := .Values.exporter.sendingQueue.persistence -}}
{{- $groups := .Values.receiver.sourceBindings -}}
{{- $batch := ternary ", batch" "" .Values.batch.enabled -}}
receivers:
  {{- range $g := $groups }}
  otlp/{{ $g.name }}:
    protocols:
      {{- if hasKey $g.protocols "grpc" }}
      grpc:
        endpoint: 0.0.0.0:{{ int $g.protocols.grpc }}
        auth:
          authenticator: bearertokenauth/{{ $g.name }}
        max_recv_msg_size_mib: 8
        max_concurrent_streams: 64
        keepalive:
          enforcement_policy:
            min_time: 10s
            permit_without_stream: false
        {{- include "otel-collector.groupTLS" $ | nindent 8 }}
      {{- end }}
      {{- if hasKey $g.protocols "http" }}
      http:
        endpoint: 0.0.0.0:{{ int $g.protocols.http }}
        auth:
          authenticator: bearertokenauth/{{ $g.name }}
        read_header_timeout: 5s
        read_timeout: 30s
        idle_timeout: 120s
        max_request_body_size: 8388608 # 8 MiB
        {{- include "otel-collector.groupTLS" $ | nindent 8 }}
      {{- end }}
  {{- if hasKey $g "content" }}
  # Content ingress of group {{ $g.name }} (spec 048): HTTP only, the group's
  # own credential; never part of a telemetry pipeline.
  otlp/content-{{ $g.name }}:
    protocols:
      http:
        endpoint: 0.0.0.0:{{ int $g.content.port }}
        auth:
          authenticator: bearertokenauth/{{ $g.name }}
        read_header_timeout: 5s
        read_timeout: 120s
        idle_timeout: 120s
        max_request_body_size: {{ int64 $content.maxRequestBodyBytes }}
        {{- include "otel-collector.groupTLS" $ | nindent 8 }}
  {{- end }}
  {{- end }}

extensions:
  health_check:
    endpoint: 0.0.0.0:{{ .Values.service.ports.health }}
  # Spec 048 H1: the OTLP/HTTP exporter never follows a redirect.
  noredirect: {}
  {{- if $persist.enabled }}
  file_storage/fabric:
    directory: {{ $persist.directory | quote }}
    timeout: 1s
    create_directory: true
    fsync: {{ $persist.fsync }}
  {{- end }}
  {{- range $g := $groups }}
  # Group {{ $g.name }}'s one credential, used only by its own receivers.
  bearertokenauth/{{ $g.name }}:
    filename: /etc/fabric/ingress/{{ $g.name }}/token
    require_single_token: true
  {{- if hasKey $g "content" }}
  file_storage/fabric_content_{{ $g.name }}:
    directory: {{ printf "%s/content-queue-%s" $persist.directory $g.name | quote }}
    timeout: 1s
    create_directory: true
    directory_permissions: "0700"
    fsync: {{ $persist.fsync }}
  # Spec 049 §7.8: the group's content queue, sealed with the Node key.
  fabricenvelope/fabric_content_{{ $g.name }}:
    storage: file_storage/fabric_content_{{ $g.name }}
    key_file: /etc/fabric/content-key/key
  {{- end }}
  {{- end }}

processors:
  memory_limiter:
    check_interval: {{ .Values.memoryLimiter.checkIntervalSeconds }}s
    limit_mib: {{ include "otel-collector.memoryLimitMiB" . }}
  {{- range $g := $groups }}
  fabricguard/{{ $g.name }}:
    event_class_attribute: {{ $.Values.fabric.guard.eventClassAttribute | quote }}
    drop_unknown_classes: {{ $.Values.fabric.guard.dropUnknownClasses }}
    max_field_bytes: {{ $.Values.fabric.guard.maxFieldBytes }}
    profile: "production"
    # Spec 053 §6.2.7: the group's kind decides what fabricguard admits; a
    # sensor can never present agent records, nor an agent host evidence.
    source_kind: {{ $g.kind | quote }}
    {{- if ne $g.kind "agent" }}
    host_digests: {{ $g.hostDigests | default "omitted" | quote }}
    {{- end }}
    evidence_source_binding:
      tenant_id: {{ $g.tenantId | quote }}
      source_id: {{ $g.sourceId | quote }}
    capture_labels: {{ $.Values.fabric.guard.captureLabels | default "pseudonymous" | quote }}
    identity_mode: {{ $.Values.fabric.guard.identityMode | default "pseudonymous" | quote }}
    {{- with $.Values.fabric.guard.extraAllowedFields }}
    extra_allowed_fields:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    {{- with $.Values.fabric.guard.extraAllowedTraceFields }}
    extra_allowed_trace_fields:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    {{- with $.Values.fabric.guard.captureModelAllowlist }}
    capture_model_allowlist:
      {{- toYaml . | nindent 6 }}
    {{- end }}
  {{- end }}
  {{- if .Values.batch.enabled }}
  batch:
    timeout: {{ .Values.batch.timeoutSeconds }}s
    send_batch_size: {{ .Values.batch.sendBatchSize }}
  {{- end }}

exporters:
  otlp_http/fabric:
    endpoint: {{ .Values.exporter.endpoint | quote }}
    timeout: {{ .Values.exporter.timeout | quote }}
    middlewares:
      - id: noredirect
    {{- if .Values.exporter.auth.secret.name }}
    headers:
      {{ .Values.exporter.auth.headerName | quote }}: "${env:FABRIC_EXPORT_AUTH}"
    {{- end }}
    tls:
      insecure: {{ .Values.exporter.insecure }}
      insecure_skip_verify: {{ .Values.exporter.insecureSkipVerify }}
      {{- if .Values.exporter.tls.caSecret.name }}
      ca_file: /etc/fabric/exporter-tls/ca.crt
      {{- end }}
      {{- if .Values.exporter.tls.clientCertificateSecret.name }}
      cert_file: /etc/fabric/exporter-tls/tls.crt
      key_file: /etc/fabric/exporter-tls/tls.key
      {{- end }}
    sending_queue:
      enabled: {{ .Values.exporter.sendingQueue.enabled }}
      {{- if .Values.exporter.sendingQueue.enabled }}
      num_consumers: {{ .Values.exporter.sendingQueue.numConsumers }}
      queue_size: {{ .Values.exporter.sendingQueue.queueSize }}
      block_on_overflow: {{ .Values.exporter.sendingQueue.blockOnOverflow }}
      {{- if $persist.enabled }}
      storage: file_storage/fabric
      {{- end }}
      {{- end }}
    retry_on_failure:
      enabled: {{ .Values.exporter.retry.enabled }}
      {{- if .Values.exporter.retry.enabled }}
      initial_interval: {{ .Values.exporter.retry.initialInterval | quote }}
      max_interval: {{ .Values.exporter.retry.maxInterval | quote }}
      max_elapsed_time: {{ .Values.exporter.retry.maxElapsedTime | quote }}
      {{- end }}
  {{- range $g := $groups }}
  {{- if hasKey $g "content" }}
  # Group {{ $g.name }}'s own content exporter: its binding, exactly its
  # tenant, its own sealed queue (spec 053 §6.1 rules 4 and 9).
  fabriccontent/{{ $g.name }}:
    profile: "production"
    source_binding:
      tenant_id: {{ $g.tenantId | quote }}
      source_id: {{ $g.sourceId | quote }}
    allowed_tenants:
      - {{ $g.tenantId | quote }}
    backend: {{ $content.backend | quote }}
    {{- if eq $content.backend "file" }}
    file:
      directory: {{ include "otel-collector.contentFileDirectory" $ | quote }}
      encryption_key_file: /etc/fabric/content-key/key
    {{- else }}
    s3:
      bucket: {{ $content.s3.bucket | quote }}
      prefix: {{ $content.s3.prefix | quote }}
      {{- with $content.s3.region }}
      region: {{ . | quote }}
      {{- end }}
      {{- with $content.s3.endpoint }}
      endpoint: {{ . | quote }}
      {{- end }}
      use_path_style: {{ $content.s3.usePathStyle }}
      sse: {{ $content.s3.sse | quote }}
      {{- with $content.s3.kmsKeyId }}
      kms_key_id: {{ . | quote }}
      {{- end }}
    {{- end }}
    timeout: {{ $content.timeout | quote }}
    queue_directory: {{ printf "%s/content-queue-%s" $persist.directory $g.name | quote }}
    sending_queue:
      enabled: true
      num_consumers: {{ $content.queue.numConsumers }}
      queue_size: {{ $content.queue.queueSize }}
      block_on_overflow: true
      storage: fabricenvelope/fabric_content_{{ $g.name }}
    retry_on_failure:
      enabled: true
      initial_interval: {{ $content.retry.initialInterval | quote }}
      max_interval: {{ $content.retry.maxInterval | quote }}
      # Never give up on content: it is retried until the store accepts it.
      max_elapsed_time: "0s"
  {{- end }}
  {{- end }}

service:
  extensions:
    - health_check
    - noredirect
    {{- if $persist.enabled }}
    - file_storage/fabric
    {{- end }}
    {{- range $g := $groups }}
    - bearertokenauth/{{ $g.name }}
    {{- if hasKey $g "content" }}
    - file_storage/fabric_content_{{ $g.name }}
    - fabricenvelope/fabric_content_{{ $g.name }}
    {{- end }}
    {{- end }}
  telemetry:
    logs:
      level: info
  pipelines:
    {{- range $g := $groups }}
    traces/{{ $g.name }}:
      receivers: [otlp/{{ $g.name }}]
      processors: [memory_limiter, fabricguard/{{ $g.name }}{{ $batch }}]
      exporters: [otlp_http/fabric]
    {{- if eq $g.kind "agent" }}
    logs/{{ $g.name }}:
      receivers: [otlp/{{ $g.name }}]
      processors: [memory_limiter, fabricguard/{{ $g.name }}{{ $batch }}]
      exporters: [otlp_http/fabric]
    {{- end }}
    {{- if hasKey $g "content" }}
    # Content bodies bypass fabricguard (they must pass unchanged); the
    # group's fabriccontent exporter enforces the closed descriptor itself.
    logs/content-{{ $g.name }}:
      receivers: [otlp/content-{{ $g.name }}]
      processors: [memory_limiter]
      exporters: [fabriccontent/{{ $g.name }}]
    {{- end }}
    {{- end }}
{{- end -}}

{{/* A group's listener ports in order (grpc, http, content), as a YAML list. */}}
{{- define "otel-collector.groupPortNumbers" -}}
{{- $ports := list -}}
{{- if hasKey .protocols "grpc" -}}{{- $ports = append $ports (int .protocols.grpc) -}}{{- end -}}
{{- if hasKey .protocols "http" -}}{{- $ports = append $ports (int .protocols.http) -}}{{- end -}}
{{- if hasKey . "content" -}}{{- $ports = append $ports (int .content.port) -}}{{- end -}}
{{- toYaml $ports -}}
{{- end -}}

{{/*
Container or Service ports of the groups, named g<index>-grpc, g<index>-http
and g<index>-content (Kubernetes port names are at most 15 characters).
Arguments: (dict "groups" LIST "key" "containerPort"|"port").
*/}}
{{- define "otel-collector.groupPorts" -}}
{{- $key := .key -}}
{{- range $i, $g := .groups }}
{{- range $kind := list "grpc" "http" "content" }}
{{- $port := 0 }}
{{- if eq $kind "content" }}
{{- if hasKey $g "content" }}{{ $port = $g.content.port }}{{ end }}
{{- else if hasKey $g.protocols $kind }}
{{- $port = index $g.protocols $kind }}
{{- end }}
{{- if $port }}
- name: g{{ $i }}-{{ $kind }}
  {{ $key }}: {{ int $port }}
  {{- if eq $key "port" }}
  targetPort: g{{ $i }}-{{ $kind }}
  {{- end }}
  protocol: TCP
{{- end }}
{{- end }}
{{- end }}
{{- end -}}
