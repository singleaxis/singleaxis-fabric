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
      "otel-collector.securityContext.readOnlyRootFilesystem" true
      "otel-collector.securityContext.runAsNonRoot" true
      "otel-collector.podSecurityContext.seccompProfile.type" "RuntimeDefault"
      "otel-collector.enableServiceLinks" false
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
{{/* A tag is mutable even when version-shaped. Check the final effective
     value here too, so --skip-schema-validation cannot admit a short digest. */}}
{{- $collector := index $.Values "otel-collector" -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $collector.image.digest) -}}
{{- fail "profile shadow-production requires a pinned Collector image: otel-collector.image.digest must be a full sha256 digest; tags alone are not immutable identities" -}}
{{- end -}}
{{- $workload := $collector.receiver.workloadAuthentication -}}
{{- if $workload.enabled -}}
{{- if ne $workload.tenantId $.Values.tenant.id -}}
{{- fail "profile shadow-production requires receiver.workloadAuthentication.tenantId to match tenant.id" -}}
{{- end -}}
{{- else if $collector.receiver.evidenceSourceBinding.enabled -}}
{{- if ne $collector.receiver.evidenceSourceBinding.tenantId $.Values.tenant.id -}}
{{- fail "profile shadow-production requires receiver.evidenceSourceBinding.tenantId to match tenant.id" -}}
{{- end -}}
{{- else -}}
{{- fail "profile shadow-production requires receiver.workloadAuthentication.enabled=true or a dedicated evidenceSourceBinding" -}}
{{- end -}}
{{- $storage := $collector.exporter.sendingQueue.persistence -}}
{{- if and (empty $storage.storageClass) (empty $storage.existingClaim) -}}
{{- fail "profile shadow-production requires an explicit queue storageClass or existingClaim; a default StorageClass is not an encryption decision" -}}
{{- end -}}
{{- if and $storage.storageClass $storage.existingClaim -}}
{{- fail "profile shadow-production requires only one of queue storageClass or existingClaim; the attestation must identify the storage actually used" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$" $storage.encryptionAttestationRef) -}}
{{- fail "profile shadow-production requires queue encryptionAttestationRef; storage selection alone does not attest encryption" -}}
{{- end -}}
{{- if or $collector.securityContext.privileged $collector.securityContext.capabilities.add -}}
{{- fail "profile shadow-production rejects privileged containers and added capabilities" -}}
{{- end -}}
{{- if and $collector.securityContext.seccompProfile (ne $collector.securityContext.seccompProfile.type "RuntimeDefault") -}}
{{- fail "profile shadow-production rejects a container seccompProfile that overrides RuntimeDefault" -}}
{{- end -}}
{{- if and (hasKey $collector.securityContext "runAsGroup") (le (int $collector.securityContext.runAsGroup) 0) -}}
{{- fail "profile shadow-production rejects a root container runAsGroup" -}}
{{- end -}}
{{- if not (deepEqual $collector.securityContext.capabilities.drop (list "ALL")) -}}
{{- fail "profile shadow-production requires securityContext.capabilities.drop=[ALL]" -}}
{{- end -}}
{{- range $field, $value := dict "podSecurityContext.runAsUser" $collector.podSecurityContext.runAsUser "podSecurityContext.runAsGroup" $collector.podSecurityContext.runAsGroup "securityContext.runAsUser" $collector.securityContext.runAsUser "podSecurityContext.fsGroup" $collector.podSecurityContext.fsGroup -}}
{{- if or (empty $value) (le (int $value) 0) -}}
{{- fail (printf "profile shadow-production requires a positive non-root %s" $field) -}}
{{- end -}}
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
