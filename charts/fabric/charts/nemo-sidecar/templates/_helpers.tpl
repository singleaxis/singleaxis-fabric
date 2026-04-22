{{- define "nemo-sidecar.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nemo-sidecar.fullname" -}}
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

{{- define "nemo-sidecar.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nemo-sidecar.labels" -}}
helm.sh/chart: {{ include "nemo-sidecar.chart" . }}
{{ include "nemo-sidecar.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fabric
app.kubernetes.io/component: nemo-sidecar
{{- end -}}

{{- define "nemo-sidecar.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nemo-sidecar.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- /*
Effective rails ConfigMap name. Resolves operator override first,
then the in-chart starter bundle. Emits empty string when neither is
set, which the deployment template treats as "no mount, passthrough".
*/ -}}
{{- define "nemo-sidecar.effectiveRailsConfigMapName" -}}
{{- if .Values.railsConfigMap.name -}}
{{- .Values.railsConfigMap.name -}}
{{- else if .Values.starterRails.enabled -}}
{{- printf "%s-rails-starter" (include "nemo-sidecar.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "nemo-sidecar.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "nemo-sidecar.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
