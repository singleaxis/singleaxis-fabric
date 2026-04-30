{{/*
Expand the name of the chart.
*/}}
{{- define "otel-collector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. Supports .Values.fullnameOverride.
*/}}
{{- define "otel-collector.fullname" -}}
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

{{- define "otel-collector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "otel-collector.labels" -}}
helm.sh/chart: {{ include "otel-collector.chart" . }}
{{ include "otel-collector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fabric
{{- end -}}

{{- define "otel-collector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "otel-collector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "otel-collector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "otel-collector.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Validate fabric.sampler config: when enabled, exactly one of
hmacKey / hmacKeySecret.name must be set.
*/}}
{{- define "otel-collector.validateSampler" -}}
{{- if .Values.fabric.sampler.enabled -}}
{{- $inline := .Values.fabric.sampler.hmacKey -}}
{{- $secret := .Values.fabric.sampler.hmacKeySecret.name -}}
{{- if and (not $inline) (not $secret) -}}
{{- fail "fabric.sampler.enabled=true requires fabric.sampler.hmacKey or fabric.sampler.hmacKeySecret.name" -}}
{{- end -}}
{{- if and $inline $secret -}}
{{- fail "fabric.sampler: set only one of hmacKey / hmacKeySecret" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate fabric.redact config.

``fabric.redact.enabled: true`` wires the fabricredact processor to a
Unix socket at ``fabric.redact.unixSocket``. The Collector chart does
not render a Presidio sidecar — that ships in components/presidio-sidecar
as a dedicated chart (TBD). Without a socket provider this processor
will permanently error.

Fail-closed unless the operator has explicitly acknowledged one of:

  fabric.redact.existingSocketProvider: <name>
      Name of an out-of-band component (e.g. sidecar chart, DaemonSet)
      that mounts the socket into this pod.

  fabric.redact.acceptMissingProvider: true
      Escape hatch for CI / smoke renders. The Collector will boot
      but the redact processor will fail on every event — suitable
      only for template verification, never for a real install.
*/}}
{{- define "otel-collector.validateRedact" -}}
{{- if .Values.fabric.redact.enabled -}}
{{- $provider := .Values.fabric.redact.existingSocketProvider | default "" -}}
{{- $accept := .Values.fabric.redact.acceptMissingProvider | default false -}}
{{- if and (eq $provider "") (not $accept) -}}
{{- fail (printf "fabric.redact.enabled=true but no socket provider configured. Set fabric.redact.existingSocketProvider to the name of the component mounting %s, or fabric.redact.acceptMissingProvider=true for smoke renders. The Presidio sidecar chart is not yet part of the umbrella release — see components/presidio-sidecar/." .Values.fabric.redact.unixSocket) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate the OTLP exporter endpoint.

The exporter endpoint must be set to a real OTLP/HTTP-speaking backend
(bundled Langfuse, Datadog, Honeycomb, your own collector, or — for
SingleAxis commercial deployments — the Telemetry Bridge ingest URL).
A render-time fail here prevents the most common silent-broken state:
operator installs the chart, the Collector boots happily, every span
is dropped on egress because the configured endpoint resolves to no
service in the cluster (the historical default `fabric-ingest:8080`
was such a phantom — see CHANGELOG 0.1.3).

Escape hatch: ``exporter.acceptUnsetEndpoint: true`` lets CI smoke
renders proceed without a real endpoint. Never set this in a production
values file; the Collector will boot but every export will fail.
*/}}
{{- define "otel-collector.validateExporter" -}}
{{- $endpoint := .Values.exporter.endpoint | default "" -}}
{{- $accept := .Values.exporter.acceptUnsetEndpoint | default false -}}
{{- if and (eq $endpoint "") (not $accept) -}}
{{- fail "otel-collector.exporter.endpoint is empty. Set it to the OTLP/HTTP backend you want spans to land in (bundled Langfuse: http://langfuse:3000; Datadog/Honeycomb/etc.: their OTLP intake; commercial Telemetry Bridge: the bridge ingress URL). For CI smoke renders only, pass --set otel-collector.exporter.acceptUnsetEndpoint=true. See charts/fabric/charts/otel-collector/values.yaml for example endpoints." -}}
{{- end -}}
{{- end -}}
