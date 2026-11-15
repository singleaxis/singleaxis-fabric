{{/*
Spec 058 §10.2-10.4: the secrets hook Job, the opt-in pod injector, and what
they share. Every helper here runs after "fabric.applyPreset" (templates/preset/),
so it sees the effective values.
*/}}

{{/* The Fabric CLI image (the secrets Job and the injector). */}}
{{- define "fabric.cliImage" -}}
{{- $image := .Values.cliImage -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $image.repository $image.digest -}}
{{- else -}}
{{- printf "%s:%s" $image.repository ($image.tag | default .Values.global.fabric.version) -}}
{{- end -}}
{{- end -}}

{{/* A name of this release for an object of the umbrella chart (at most 63). */}}
{{- define "fabric.objectName" -}}
{{- printf "%s-%s" .root.Release.Name .suffix | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fabric.injectorName" -}}
{{- include "fabric.objectName" (dict "root" . "suffix" "fabric-injector") -}}
{{- end -}}

{{/* The webhook configuration is cluster-scoped: the namespace is in its name. */}}
{{- define "fabric.webhookName" -}}
{{- printf "fabric-injector-%s-%s" .Release.Namespace .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fabric.componentLabels" -}}
{{ include "fabric.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* The Collector's values after the preset (a map, possibly empty). */}}
{{- define "fabric.collectorValues" -}}
{{- index .Values "otel-collector" | default dict | toYaml -}}
{{- end -}}

{{/*
What the secrets Job generates, as YAML: {render, production, content,
nodeTls, clientCa, contentKey, agents}. render is "true" when there is
anything to generate: agent namespaces, the injector, or a production preset.
*/}}
{{- define "fabric.secretsPlan" -}}
{{- $collector := include "fabric.collectorValues" . | fromYaml -}}
{{- $agents := include "fabric.agentNamespaces" . | fromYamlArray -}}
{{- $production := include "fabric.nodeIsProduction" . | eq "true" -}}
{{- $presetProduction := and .Values.preset (ne .Values.preset "local") -}}
{{- $render := and .Values.secretsJob.enabled .Values.otelCollector.enabled (or $agents .Values.injector.enabled $presetProduction) -}}
{{- dict
      "render" $render
      "production" $production
      "content" (and $production (dig "content" "enabled" false $collector))
      "nodeTls" (dig "receiver" "tls" "serverCertificateSecret" "name" "" $collector)
      "clientCa" (dig "receiver" "tls" "clientCASecret" "name" "" $collector)
      "contentKey" (dig "content" "encryption" "keySecret" "name" "" $collector)
      "agents" $agents
  | toYaml -}}
{{- end -}}

{{/* The names the secrets Job may read back (Role resourceNames for get). */}}
{{- define "fabric.secretsReleaseNames" -}}
{{- $plan := include "fabric.secretsPlan" . | fromYaml -}}
{{- $names := list .Values.secretsJob.caSecretName -}}
{{- with $plan.nodeTls }}{{ $names = append $names . }}{{ end -}}
{{- if $plan.production -}}
{{- with $plan.clientCa }}{{ $names = append $names . }}{{ end -}}
{{- if $plan.content }}{{ with $plan.contentKey }}{{ $names = append $names . }}{{ end }}{{ end -}}
{{- range $plan.agents }}{{ $names = append $names .nodeSecret }}{{ end -}}
{{- end -}}
{{- if .Values.injector.enabled }}{{ $names = append $names .Values.injector.tlsSecretName }}{{ end -}}
{{- $names | uniq | toYaml -}}
{{- end -}}

{{/* The fabric init arguments of the secrets Job. */}}
{{- define "fabric.secretsArgs" -}}
{{- $plan := include "fabric.secretsPlan" . | fromYaml -}}
- init
- --kubernetes
- --in-cluster
- --namespace={{ .Release.Namespace }}
- --release={{ .Release.Name }}
- --node-service={{ include "fabric.collectorFullname" . }}
- --cluster-domain={{ .Values.clusterDomain }}
- --secret-name=ca={{ .Values.secretsJob.caSecretName }}
- --secret-name=agent={{ .Values.secretsJob.agentSecretName }}
{{- with $plan.nodeTls }}
- --secret-name=node-tls={{ . }}
{{- end }}
{{- if $plan.production }}
- --profile=production
{{- with $plan.clientCa }}
- --secret-name=client-ca={{ . }}
{{- end }}
{{- if and $plan.content $plan.contentKey }}
- --content
- --secret-name=content-key={{ $plan.contentKey }}
{{- end }}
{{- end }}
{{- if .Values.injector.enabled }}
- --injector
- --injector-service={{ include "fabric.injectorName" . }}
- --secret-name=injector-tls={{ .Values.injector.tlsSecretName }}
{{- end }}
{{- range $plan.agents }}
- --agent-namespace={{ .name }}={{ .source }}
{{- end }}
{{- end -}}

{{/* A restricted container security context (the chart's posture). */}}
{{- define "fabric.restrictedContainer" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
capabilities:
  drop: [ALL]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "fabric.restrictedPod" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
The SDK spool bound of an injected pod with the emptyDir spool, in bytes: a
quarter of injector.spool.sizeLimit. The kubelet evicts a pod whose emptyDir
grows past its sizeLimit, and it counts disk blocks while the spool counts
record bytes (one small file per record), so the spool's own bound has to sit
well under the limit: a spool that fills while the Node is away must never
cost an agent its pod. injector.env.FABRIC_WIRE_SPOOL_MAX_BYTES sets it by
hand instead.
*/}}
{{- define "fabric.injectorSpoolMaxBytes" -}}
{{- $quantity := .Values.injector.spool.sizeLimit | toString -}}
{{- $units := dict "" 1 "k" 1000 "M" 1000000 "G" 1000000000 "T" 1000000000000 "Ki" 1024 "Mi" 1048576 "Gi" 1073741824 "Ti" 1099511627776 -}}
{{- $unit := regexFind "[A-Za-z]+$" $quantity -}}
{{- if not (regexMatch "^([0-9]{1,6}(Ki|Mi|Gi|Ti|k|M|G|T)|[0-9]{1,18})$" $quantity) -}}
{{- fail "injector.spool.sizeLimit is not a size this chart reads. Use a whole number of at most 6 digits with a unit (1Gi, 512Mi), or a number of bytes" -}}
{{- end -}}
{{- $bytes := mul (regexFind "^[0-9]+" $quantity | int64) (index $units $unit | int64) -}}
{{- if lt $bytes 536870912 -}}
{{- fail "injector.spool.sizeLimit is too small. Use 512Mi or more: the SDK's spool is bounded to a quarter of it (so the kubelet never evicts an agent pod for its spool) and needs 65 MiB at least. To set the bound yourself, give injector.env.FABRIC_WIRE_SPOOL_MAX_BYTES" -}}
{{- end -}}
{{- div $bytes 4 -}}
{{- end -}}

{{/*
The injector's configuration (JSON): for each agent namespace, the variables
an injected container gets. Paths are the mounts the injector adds; the Node
address is this release's Collector Service, on the namespace's own ingress
group on a production Node.
*/}}
{{- define "fabric.injectorConfig" -}}
{{- $collector := include "fabric.collectorValues" . | fromYaml -}}
{{- $plan := include "fabric.secretsPlan" . | fromYaml -}}
{{- $host := printf "%s.%s.svc.%s" (include "fabric.collectorFullname" .) .Release.Namespace .Values.clusterDomain -}}
{{- $secrets := "/var/run/fabric/secrets" -}}
{{- $namespaces := dict -}}
{{- range $agent := $plan.agents -}}
{{- $http := dig "service" "ports" "otlpHttp" 4318 $collector | int -}}
{{- $content := dig "service" "ports" "otlpContent" 4319 $collector | int -}}
{{- if $plan.production -}}
{{- $ports := include "fabric.agentGroupPorts" (dict "root" $ "index" $agent.index) | fromYaml -}}
{{- $http = $ports.http | int -}}
{{- $content = $ports.content | int -}}
{{- end -}}
{{- $env := dict
      "FABRIC_OTLP_ENDPOINT" (printf "https://%s:%d" $host $http)
      "FABRIC_OTLP_CERTIFICATE" (printf "%s/ca.crt" $secrets)
      "FABRIC_WIRE_ID_KEY_FILE" (printf "%s/id.key" $secrets)
      "FABRIC_WIRE_SPOOL_DIR" "/var/lib/fabric/spool"
      "FABRIC_WIRE_SPOOL_KEY_FILE" (printf "%s/spool.key" $secrets)
      "FABRIC_SOURCE_ID" $agent.source
-}}
{{- with $agent.tenantId }}{{ $_ := set $env "FABRIC_TENANT_ID" . }}{{ end -}}
{{- if $plan.production -}}
{{- $_ := set $env "FABRIC_OTLP_HEADERS_FILE" (printf "%s/headers" $secrets) -}}
{{- if dig "receiver" "requireClientCertificate" false $collector -}}
{{- $_ := set $env "FABRIC_OTLP_CLIENT_CERTIFICATE" (printf "%s/tls.crt" $secrets) -}}
{{- $_ := set $env "FABRIC_OTLP_CLIENT_KEY" (printf "%s/tls.key" $secrets) -}}
{{- end -}}
{{- end -}}
{{- if dig "content" "enabled" false $collector -}}
{{- $_ := set $env "FABRIC_WIRE_CONTENT_ENDPOINT" (printf "https://%s:%d/v1/logs" $host $content) -}}
{{- end -}}
{{- range $name, $value := $.Values.injector.env -}}
{{- $_ := set $env $name ($value | toString) -}}
{{- end -}}
{{- $_ := set $namespaces $agent.name (dict "env" $env) -}}
{{- end -}}
{{- $spoolMaxBytes := 0 -}}
{{- if not (hasKey (.Values.injector.env | default dict) "FABRIC_WIRE_SPOOL_MAX_BYTES") -}}
{{- $spoolMaxBytes = include "fabric.injectorSpoolMaxBytes" . | int64 -}}
{{- end -}}
{{- dict
      "version" .Chart.AppVersion
      "secret" .Values.secretsJob.agentSecretName
      "shimConfigMap" "fabric-autoload"
      "spoolSizeLimit" .Values.injector.spool.sizeLimit
      "spoolMaxBytes" $spoolMaxBytes
      "spoolClaim" "fabric-spool"
      "namespaces" $namespaces
  | toJson -}}
{{- end -}}
