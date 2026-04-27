{{/*
Expand the name of the chart.
*/}}
{{- define "update-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "update-agent.fullname" -}}
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

{{- define "update-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "update-agent.labels" -}}
helm.sh/chart: {{ include "update-agent.chart" . }}
{{ include "update-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fabric
app.kubernetes.io/component: update-agent
{{- end -}}

{{- define "update-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "update-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "update-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "update-agent.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "update-agent.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
TLS secret holding the webhook serving cert + key.
Always named predictably so ValidatingWebhookConfiguration can
reference it regardless of TLS mode.
*/}}
{{- define "update-agent.tlsSecretName" -}}
{{- printf "%s-tls" (include "update-agent.fullname" .) -}}
{{- end -}}

{{- define "update-agent.configMapName" -}}
{{- printf "%s-config" (include "update-agent.fullname" .) -}}
{{- end -}}

{{- define "update-agent.webhookName" -}}
{{- printf "%s.fabric.singleaxis.dev" (include "update-agent.fullname" .) -}}
{{- end -}}

{{- define "update-agent.certificateName" -}}
{{- printf "%s-cert" (include "update-agent.fullname" .) -}}
{{- end -}}

{{/*
Resolve the webhook serving cert + CA bundle ONCE per render.

On a fresh install both the Secret and the ValidatingWebhookConfiguration
templates need to agree on the same caBundle — but they render in
separate passes. We use the ``$``-hash memoization idiom:

  1. First check ``lookup`` — on ``helm upgrade`` we reuse the cert
     already in-cluster so the API server's cached caBundle doesn't
     go stale.
  2. If nothing is found, generate a CA + signed cert ONCE and stash
     the base64-encoded result on ``$._tls``. The stash on ``$``
     survives across every ``include`` call in this render pass, so
     the Secret and the VWC see the same bytes.
  3. Return YAML so callers can ``fromYaml`` it back.

Callers:
  {{- $tls := fromYaml (include "update-agent.tlsData" .) -}}
  ... $tls.caCert / $tls.cert / $tls.key ...
*/}}
{{- define "update-agent.tlsData" -}}
{{- $top := . -}}
{{- if not (index $top "_tls") -}}
{{- $svcName := include "update-agent.fullname" $top -}}
{{- $ns := $top.Release.Namespace -}}
{{- $cn := printf "%s.%s.svc" $svcName $ns -}}
{{- $altNames := list $cn (printf "%s.%s.svc.cluster.local" $svcName $ns) -}}
{{- $existing := lookup "v1" "Secret" $ns (include "update-agent.tlsSecretName" $top) -}}
{{- $caCert := "" -}}
{{- $cert := "" -}}
{{- $key := "" -}}
{{- if and $existing $existing.data -}}
{{- $caCert = index $existing.data "ca.crt" | default "" -}}
{{- $cert = index $existing.data "tls.crt" | default "" -}}
{{- $key = index $existing.data "tls.key" | default "" -}}
{{- end -}}
{{- if or (eq $cert "") (eq $key "") (eq $caCert "") -}}
{{- $ca := genCA (printf "%s-ca" $svcName) 3650 -}}
{{- $signed := genSignedCert $cn nil $altNames 3650 $ca -}}
{{- $caCert = $ca.Cert | b64enc -}}
{{- $cert = $signed.Cert | b64enc -}}
{{- $key = $signed.Key | b64enc -}}
{{- end -}}
{{- $_ := set $top "_tls" (dict "caCert" $caCert "cert" $cert "key" $key) -}}
{{- end -}}
{{- $tls := index $top "_tls" -}}
caCert: {{ $tls.caCert | quote }}
cert: {{ $tls.cert | quote }}
key: {{ $tls.key | quote }}
{{- end -}}

{{/*
Validate trusted keys before rendering into a ConfigMap.

Fail-closed if any trustedKey entry still carries the placeholder
literal — shipping ``REPLACE_AT_INSTALL_TIME…`` into a "production"
install silently disables verification.

Operators reviewing the chart with ``helm template`` or ``helm lint``
can opt out of the placeholder check by setting:

  --set update-agent.config.allowPlaceholderKey=true

The flag is INSTALL-time only. The deployed update-agent binary
re-validates the key shape at startup and refuses to run with a
placeholder, so a real ``helm install`` cannot bypass the check
even if the renderer was told to.

Empty-string keys still fail unconditionally — there is no
legitimate dry-run path that ships an empty key.
*/}}
{{- define "update-agent.validateTrustedKeys" -}}
{{- $allowPlaceholder := .Values.config.allowPlaceholderKey | default false -}}
{{- range concat .Values.config.trustedKeys .Values.config.extraTrustedKeys -}}
{{- if hasPrefix "REPLACE_AT_INSTALL_TIME" (.publicKey | toString) -}}
{{- if not $allowPlaceholder -}}
{{- fail (printf "update-agent.config.trustedKeys: entry id=%q has placeholder publicKey. Supply a real base64 Ed25519 key at install time, or pass --set update-agent.config.allowPlaceholderKey=true for dry-renders only." .id) -}}
{{- end -}}
{{- end -}}
{{- if eq (.publicKey | toString) "" -}}
{{- fail (printf "update-agent.config.trustedKeys: entry id=%q has empty publicKey." .id) -}}
{{- end -}}
{{- end -}}
{{- end -}}
