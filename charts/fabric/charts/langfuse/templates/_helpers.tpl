{{/*
Expand the name of the chart.
*/}}
{{- define "langfuse.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "langfuse.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "langfuse.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "langfuse.labels" -}}
helm.sh/chart: {{ include "langfuse.chart" . }}
{{ include "langfuse.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fabric
{{- end -}}

{{- define "langfuse.selectorLabels" -}}
app.kubernetes.io/name: {{ include "langfuse.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "langfuse.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "langfuse.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the Secret name that holds NEXTAUTH_SECRET and SALT. Tenants
that bring their own Secret bypass the auto-generated one.
*/}}
{{- define "langfuse.authSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-auth" (include "langfuse.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Validate database config: exactly one of url or dsnSecret.name.
*/}}
{{- define "langfuse.validateDatabase" -}}
{{- $url := .Values.database.url -}}
{{- $secret := .Values.database.dsnSecret.name -}}
{{- if and (not $url) (not $secret) -}}
{{- fail "langfuse: set database.url or database.dsnSecret.name" -}}
{{- end -}}
{{- if and $url $secret -}}
{{- fail "langfuse: set only one of database.url / database.dsnSecret" -}}
{{- end -}}
{{- end -}}
