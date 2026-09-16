{{- define "otel-collector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

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

{{- define "otel-collector.image" -}}
{{- if .Values.image.digest -}}
{{ printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else -}}
{{ printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end -}}
{{- end -}}

{{- define "otel-collector.validateReceiver" -}}
{{- $r := .Values.receiver -}}
{{- $server := $r.tls.serverCertificateSecret -}}
{{- $clientCA := $r.tls.clientCASecret -}}
{{- if and $r.requireTLS (not $server.name) -}}
{{- fail "receiver.requireTLS=true requires receiver.tls.serverCertificateSecret.name" -}}
{{- end -}}
{{- if and $r.requireClientCertificate (not $r.requireTLS) -}}
{{- fail "receiver.requireClientCertificate=true requires receiver.requireTLS=true" -}}
{{- end -}}
{{- if and $r.requireClientCertificate (not $clientCA.name) -}}
{{- fail "receiver.requireClientCertificate=true requires receiver.tls.clientCASecret.name" -}}
{{- end -}}
{{- if and $clientCA.name (not $server.name) -}}
{{- fail "receiver.tls.clientCASecret.name requires receiver.tls.serverCertificateSecret.name; client-certificate verification cannot run without receiver TLS" -}}
{{- end -}}
{{- if and $server.name (not $server.certKey) -}}
{{- fail "receiver.tls.serverCertificateSecret.name requires receiver.tls.serverCertificateSecret.certKey" -}}
{{- end -}}
{{- if and $server.name (not $server.keyKey) -}}
{{- fail "receiver.tls.serverCertificateSecret.name requires receiver.tls.serverCertificateSecret.keyKey" -}}
{{- end -}}
{{- if and $clientCA.name (not $clientCA.key) -}}
{{- fail "receiver.tls.clientCASecret.name requires receiver.tls.clientCASecret.key" -}}
{{- end -}}
{{- end -}}

{{/*
Every NetworkPolicyPeer an operator supplies must name an explicit
restriction. An empty peer ({}) selects all sources/destinations, and an
ipBlock of 0.0.0.0/0 or ::/0 is equivalent to no policy; both silently
bypass the explicit-peers model, so they are rejected at render time.
*/}}
{{- define "otel-collector.validatePeers" -}}
{{- range $i, $peer := .peers -}}
{{- if or (not (kindIs "map" $peer)) (eq (len $peer) 0) -}}
{{- fail (printf "%s[%d] is an empty peer, which selects all sources/destinations; name an explicit podSelector, namespaceSelector, or ipBlock" $.field $i) -}}
{{- end -}}
{{- if hasKey $peer "ipBlock" -}}
{{- $block := index $peer "ipBlock" -}}
{{- if not (kindIs "map" $block) -}}
{{- fail (printf "%s[%d].ipBlock must be an object with a cidr" $.field $i) -}}
{{- end -}}
{{- $cidr := index $block "cidr" | default "" | toString | trim -}}
{{- if eq $cidr "" -}}
{{- fail (printf "%s[%d].ipBlock.cidr is required" $.field $i) -}}
{{- end -}}
{{- if or (eq $cidr "0.0.0.0/0") (eq $cidr "::/0") -}}
{{- fail (printf "%s[%d] uses world CIDR %s, which is equivalent to no policy; name a specific CIDR or selector" $.field $i $cidr) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "otel-collector.validateNetworkPolicy" -}}
{{- $np := .Values.networkPolicy -}}
{{- $ee := $np.exporterEgress -}}
{{- $hasIngressPeers := gt (len $np.ingressFrom) 0 -}}
{{- $hasPeers := gt (len $ee.to) 0 -}}
{{- $hasPorts := gt (len $ee.ports) 0 -}}
{{- include "otel-collector.validatePeers" (dict "peers" $np.ingressFrom "field" "networkPolicy.ingressFrom") -}}
{{- include "otel-collector.validatePeers" (dict "peers" $ee.to "field" "networkPolicy.exporterEgress.to") -}}
{{- include "otel-collector.validatePeers" (dict "peers" $np.egressTo "field" "networkPolicy.egressTo") -}}
{{- if and (kindIs "map" $np.monitoringNamespaceSelector) (gt (len $np.monitoringNamespaceSelector) 0) -}}
{{- if and (empty (index $np.monitoringNamespaceSelector "matchLabels")) (empty (index $np.monitoringNamespaceSelector "matchExpressions")) -}}
{{- fail "networkPolicy.monitoringNamespaceSelector must name matchLabels or matchExpressions; an empty selector would open the health port to every namespace" -}}
{{- end -}}
{{- end -}}
{{- if $np.requireExplicitIngress -}}
{{- if not $np.enabled -}}
{{- fail "networkPolicy.requireExplicitIngress=true requires networkPolicy.enabled=true" -}}
{{- end -}}
{{- if not $hasIngressPeers -}}
{{- fail "networkPolicy.requireExplicitIngress=true requires an operator-supplied networkPolicy.ingressFrom peer" -}}
{{- end -}}
{{- end -}}
{{- if and (or $hasPeers $hasPorts) (not $np.enabled) -}}
{{- fail "networkPolicy.exporterEgress is configured but networkPolicy.enabled=false; enable the policy or remove the misleading rule" -}}
{{- end -}}
{{- if ne $hasPeers $hasPorts -}}
{{- fail "networkPolicy.exporterEgress requires both non-empty to and ports lists" -}}
{{- end -}}
{{- if $ee.requireExplicit -}}
{{- if not $np.enabled -}}
{{- fail "networkPolicy.exporterEgress.requireExplicit=true requires networkPolicy.enabled=true" -}}
{{- end -}}
{{- if not .Values.exporter.endpoint -}}
{{- fail "networkPolicy.exporterEgress.requireExplicit=true requires exporter.endpoint" -}}
{{- end -}}
{{- if not $hasPeers -}}
{{- fail "networkPolicy.exporterEgress.requireExplicit=true requires an operator-supplied networkPolicy.exporterEgress.to peer" -}}
{{- end -}}
{{- if not $hasPorts -}}
{{- fail "networkPolicy.exporterEgress.requireExplicit=true requires operator-supplied networkPolicy.exporterEgress.ports" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "otel-collector.validateExporter" -}}
{{- if and .Values.exporter.requireEndpoint (not .Values.exporter.endpoint) -}}
{{- fail "otel-collector.exporter.endpoint is empty and this profile sets exporter.requireEndpoint=true. Pod stdout is a development fallback, not durable delivery; configure a customer-selected OTLP/HTTP destination." -}}
{{- end -}}
{{- end -}}

{{- define "otel-collector.validateDelivery" -}}
{{- $e := .Values.exporter -}}
{{- $p := $e.sendingQueue.persistence -}}
{{- if and $e.endpoint (not (regexMatch "^https?://" $e.endpoint)) -}}
{{- fail "exporter.endpoint must be an absolute http:// or https:// URL" -}}
{{- end -}}
{{- if $e.requireTLS -}}
{{- if not (hasPrefix "https://" $e.endpoint) -}}
{{- fail "exporter.requireTLS=true requires an https:// exporter.endpoint" -}}
{{- end -}}
{{- if $e.insecure -}}
{{- fail "exporter.requireTLS=true requires exporter.insecure=false" -}}
{{- end -}}
{{- if $e.insecureSkipVerify -}}
{{- fail "exporter.requireTLS=true rejects exporter.insecureSkipVerify=true" -}}
{{- end -}}
{{- end -}}
{{- if and $e.requireAuth (not $e.auth.secret.name) -}}
{{- fail "exporter.requireAuth=true requires exporter.auth.secret.name" -}}
{{- end -}}
{{- if $e.auth.secret.name -}}
{{- if not $e.auth.secret.key -}}
{{- fail "exporter.auth.secret.name requires exporter.auth.secret.key" -}}
{{- end -}}
{{- if not (regexMatch "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$" $e.auth.headerName) -}}
{{- fail "exporter.auth.headerName must be a valid HTTP header token" -}}
{{- end -}}
{{- end -}}
{{- if $p.enabled -}}
{{- if not $e.endpoint -}}
{{- fail "exporter.sendingQueue.persistence.enabled=true requires exporter.endpoint; the debug exporter has no persistent queue" -}}
{{- end -}}
{{- if not $e.sendingQueue.enabled -}}
{{- fail "exporter.sendingQueue.persistence.enabled=true requires exporter.sendingQueue.enabled=true" -}}
{{- end -}}
{{- if not (hasPrefix "/" $p.directory) -}}
{{- fail "exporter.sendingQueue.persistence.directory must be an absolute container path" -}}
{{- end -}}
{{- if and $p.existingClaim (ne (int .Values.replicaCount) 1) -}}
{{- fail "exporter.sendingQueue.persistence.existingClaim can only be used with replicaCount=1; multiple Collectors must not share one file-storage database" -}}
{{- end -}}
{{- end -}}
{{- if $e.requireDurableQueue -}}
{{- if not $e.endpoint -}}
{{- fail "exporter.requireDurableQueue=true requires exporter.endpoint" -}}
{{- end -}}
{{- if not (and $e.sendingQueue.enabled $p.enabled) -}}
{{- fail "exporter.requireDurableQueue=true requires an enabled persistent sending queue" -}}
{{- end -}}
{{- if not $e.retry.enabled -}}
{{- fail "exporter.requireDurableQueue=true requires exporter.retry.enabled=true" -}}
{{- end -}}
{{- if ne (toString $e.retry.maxElapsedTime) "0s" -}}
{{- fail "exporter.requireDurableQueue=true requires exporter.retry.maxElapsedTime=0s so transient failures are not discarded after a time limit" -}}
{{- end -}}
{{- if not $e.sendingQueue.blockOnOverflow -}}
{{- fail "exporter.requireDurableQueue=true requires exporter.sendingQueue.blockOnOverflow=true so a full queue backpressures OTLP senders instead of immediately rejecting telemetry" -}}
{{- end -}}
{{- if not $p.fsync -}}
{{- fail "exporter.requireDurableQueue=true requires exporter.sendingQueue.persistence.fsync=true to request a filesystem sync after each queue write" -}}
{{- end -}}
{{- if .Values.batch.enabled -}}
{{- fail "exporter.requireDurableQueue=true requires batch.enabled=false so acknowledged OTLP does not wait in volatile pre-queue memory" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "otel-collector.exporterNames" -}}
{{- $names := list -}}
{{- if .Values.exporter.endpoint -}}
{{- $names = append $names "otlp_http/fabric" -}}
{{- end -}}
{{- if or .Values.debugExporter.enabled (not .Values.exporter.endpoint) -}}
{{- $names = append $names "debug" -}}
{{- end -}}
{{- if not $names -}}
{{- fail "otel-collector: no exporters resolved" -}}
{{- end -}}
{{- join ", " $names -}}
{{- end -}}
