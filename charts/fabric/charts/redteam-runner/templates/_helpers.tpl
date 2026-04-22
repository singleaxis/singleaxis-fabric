{{/*
Expand the name of the chart.
*/}}
{{- define "redteam-runner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "redteam-runner.fullname" -}}
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

{{- define "redteam-runner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "redteam-runner.labels" -}}
helm.sh/chart: {{ include "redteam-runner.chart" . }}
{{ include "redteam-runner.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fabric
app.kubernetes.io/component: redteam-runner
{{- end -}}

{{- define "redteam-runner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "redteam-runner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "redteam-runner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "redteam-runner.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the image tag. `image.tag` defaults to `.Chart.AppVersion`;
`image.suffix` lets the operator pick between the bare and `-suites`
variants without having to rewrite the tag.
*/}}
{{- define "redteam-runner.image" -}}
{{- $base := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s%s" .Values.image.repository $base (.Values.image.suffix | default "") -}}
{{- end -}}

{{/*
Resolve the ConfigMap name holding run.yaml. Either the chart-owned
ConfigMap rendered from runConfig.inline, or the operator-supplied
one via runConfig.existingConfigMap.
*/}}
{{- define "redteam-runner.configMapName" -}}
{{- if .Values.runConfig.existingConfigMap -}}
{{- .Values.runConfig.existingConfigMap -}}
{{- else -}}
{{- printf "%s-run-config" (include "redteam-runner.fullname" .) -}}
{{- end -}}
{{- end -}}
