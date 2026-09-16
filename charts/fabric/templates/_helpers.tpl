{{- define "fabric.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: fabric-node
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fabric
singleaxis.com/profile: {{ .Values.profile.name | quote }}
{{- end -}}

{{/* Production records must have a deployment-owned identity. */}}
{{- define "fabric.validateTenantId" -}}
{{- if and (eq .Values.profile.name "shadow-production") (not (.Values.tenant.id | toString | trim)) -}}
{{- fail "profile shadow-production requires tenant.id (set --set tenant.id=<customer-controlled-id>)" -}}
{{- end -}}
{{- end -}}

{{/*
shadow-production is a named, fail-closed recorder posture. These invariants
are checked after Helm merges overrides, so weakening one cannot silently
retain the production profile label. This is operational hardening, not a
regulatory certification and not proof that a destination persisted a batch.
*/}}
{{- define "fabric.validateShadowProduction" -}}
{{- if eq .Values.profile.name "shadow-production" -}}
{{- $required := dict
      "networkPolicy.denyDefault" true
      "otelCollector.enabled" true
      "otel-collector.fabric.guard.dropUnknownClasses" true
      "otel-collector.fabric.guard.extraAllowedFields" (dict)
      "otel-collector.fabric.guard.extraAllowedTraceFields" (list)
      "otel-collector.receiver.requireTLS" true
      "otel-collector.receiver.requireClientCertificate" true
      "otel-collector.exporter.requireEndpoint" true
      "otel-collector.exporter.requireTLS" true
      "otel-collector.exporter.requireAuth" true
      "otel-collector.exporter.requireDurableQueue" true
      "otel-collector.exporter.sendingQueue.enabled" true
      "otel-collector.exporter.sendingQueue.blockOnOverflow" true
      "otel-collector.exporter.sendingQueue.persistence.enabled" true
      "otel-collector.exporter.sendingQueue.persistence.fsync" true
      "otel-collector.exporter.retry.enabled" true
      "otel-collector.exporter.retry.maxElapsedTime" "0s"
      "otel-collector.debugExporter.enabled" false
      "otel-collector.batch.enabled" false
      "otel-collector.networkPolicy.enabled" true
      "otel-collector.networkPolicy.requireExplicitIngress" true
      "otel-collector.networkPolicy.exporterEgress.requireExplicit" true
      "otel-collector.service.type" "ClusterIP"
      "otel-collector.podSecurityContext.runAsNonRoot" true
      "otel-collector.securityContext.allowPrivilegeEscalation" false
-}}
{{- range $path, $expected := $required -}}
  {{- $cur := $.Values -}}
  {{- $missing := false -}}
  {{- range $seg := splitList "." $path -}}
    {{- if and (kindIs "map" $cur) (hasKey $cur $seg) -}}
      {{- $cur = index $cur $seg -}}
    {{- else -}}
      {{- $missing = true -}}
      {{- $cur = dict -}}
    {{- end -}}
  {{- end -}}
  {{- if $missing -}}
    {{- fail (printf "profile shadow-production requires %q but the value is missing" $path) -}}
  {{- end -}}
  {{- if not (deepEqual $cur $expected) -}}
    {{- fail (printf "profile shadow-production requires %q=%v; effective value is %v" $path $expected $cur) -}}
  {{- end -}}
{{- end -}}
{{/* Pinned image identity: a mutable tag or the empty tag fallback is not a
     production identity. A sha256 digest is the recommended pin; an explicit
     non-latest tag is accepted. */}}
{{- $collector := index $.Values "otel-collector" | default dict -}}
{{- $image := dict -}}
{{- if kindIs "map" $collector -}}
  {{- $image = index $collector "image" | default dict -}}
{{- end -}}
{{- if not (kindIs "map" $image) -}}
  {{- $image = dict -}}
{{- end -}}
{{- $digest := $image.digest | default "" | toString | trim -}}
{{- $tag := $image.tag | default "" | toString | trim -}}
{{- if and (not $digest) (or (eq $tag "") (eq $tag "latest")) -}}
  {{- fail "profile shadow-production requires a pinned Collector image: set otel-collector.image.digest (recommended, sha256:...) or an explicit non-latest otel-collector.image.tag; \"latest\" and the empty appVersion fallback are not a production image identity" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the Collector subchart's fullname from the umbrella context by
reusing the subchart's own helper, so nameOverride/fullnameOverride keep
parent templates (NOTES.txt) correct.
*/}}
{{- define "fabric.collectorFullname" -}}
{{- $otel := index .Values "otel-collector" | default dict -}}
{{- $cond := index .Values "otelCollector" | default dict -}}
{{- if dig "enabled" true $cond -}}
{{- include "otel-collector.fullname" (dict "Values" $otel "Chart" (dict "Name" "otel-collector") "Release" .Release) -}}
{{- else -}}
{{- /* Subchart disabled: its templates are not registered, so compute the
   name inline (same default the subchart helper would produce). */ -}}
{{- $name := dig "nameOverride" "otel-collector" $otel -}}
{{- if (dig "fullnameOverride" "" $otel) -}}
{{- dig "fullnameOverride" "" $otel | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}
