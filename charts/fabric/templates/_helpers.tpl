{{- define "fabric.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: fabric
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fabric
singleaxis.com/profile: {{ .Values.profile.name | quote }}
{{- end -}}

{{/*
Validate that ``tenant.id`` is set for any non-dev profile.

Empty tenant ID stamps every emitted span with no tenant attribution,
which silently corrupts downstream multi-tenant analysis. The
permissive-dev profile is allowed to skip this since it's intended
for evaluation on a single-user laptop.
*/}}
{{- define "fabric.validateTenantId" -}}
{{- if and (not (.Values.tenant.id | toString | trim)) (ne .Values.profile.name "permissive-dev") -}}
{{- fail (printf "tenant.id is required when profile.name=%q (set --set tenant.id=<uuid>; only the 'permissive-dev' profile may leave it blank)." .Values.profile.name) -}}
{{- end -}}
{{- end -}}
