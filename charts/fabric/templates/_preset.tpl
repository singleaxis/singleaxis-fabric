{{/*
Presets (spec 058 §10.1). `preset` selects the content of a profile file as
chart values, so one `--set preset=...` replaces `-f profiles/<file>.yaml`:

  local                   profiles/shadow-dev.yaml
  production              profiles/shadow-production.yaml
  production-host-sensor  profiles/shadow-production.yaml, then
                          profiles/shadow-production-host-ingress.yaml

Order of precedence: the chart defaults, then the preset, then the values the
operator gives. A template cannot see which values the operator gave, so a
preset value is applied where the effective value still equals the chart
default (presets/defaults.yaml records those defaults; tests/test-presets.sh
keeps the file equal to values.yaml). A value set back to its chart default on
purpose is therefore taken as "not set": use the profile file with -f for that.
The profile files keep working with -f exactly as before.
*/}}
{{- define "fabric.presetFiles" -}}
{{- $files := dict
      "local" (list "profiles/shadow-dev.yaml")
      "production" (list "profiles/shadow-production.yaml")
      "production-host-sensor" (list "profiles/shadow-production.yaml" "profiles/shadow-production-host-ingress.yaml")
-}}
{{- if not (hasKey $files (toString .)) -}}
{{- fail (printf "preset %q is not a preset of this chart. Use one of: local, production, production-host-sensor (or leave preset empty and pass a profile file with -f)" (toString .)) -}}
{{- end -}}
{{- index $files (toString .) | toYaml -}}
{{- end -}}

{{/* Apply .src under .dst: a leaf of .src is written where .dst has no value
     or still has the chart default (.def). Maps are merged key by key. */}}
{{- define "fabric.presetMerge" -}}
{{- $dst := .dst -}}
{{- $def := .def | default dict -}}
{{- range $key, $value := .src -}}
{{- if kindIs "map" $value -}}
{{- if not (hasKey $dst $key) -}}
{{- $_ := set $dst $key dict -}}
{{- end -}}
{{- $child := index $dst $key -}}
{{- if kindIs "map" $child -}}
{{- $childDef := dict -}}
{{- if and (hasKey $def $key) (kindIs "map" (index $def $key)) -}}
{{- $childDef = index $def $key -}}
{{- end -}}
{{- include "fabric.presetMerge" (dict "dst" $child "src" $value "def" $childDef) -}}
{{- end -}}
{{- else if not (hasKey $dst $key) -}}
{{- $_ := set $dst $key $value -}}
{{- else if and (hasKey $def $key) (deepEqual (index $dst $key) (index $def $key)) -}}
{{- $_ := set $dst $key $value -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
agentNamespaces (spec 058 §10.3), normalised: a YAML list of
  name       the namespace
  tenantId   its tenant (default tenant.id)
  source     the clear source label of its agents (default the namespace name)
  nodeSecret the Secret of the release namespace with this namespace's token
             and source id, as the Node reads them
  index      its position, which fixes its ingress group's name and ports
An entry is a namespace name or {name, tenantId, source}.
*/}}
{{- define "fabric.agentNamespaces" -}}
{{- $out := list -}}
{{- $seen := dict -}}
{{- range $i, $entry := (.Values.agentNamespaces | default list) -}}
{{- $item := $entry -}}
{{- if kindIs "string" $entry -}}
{{- $item = dict "name" $entry -}}
{{- end -}}
{{- $name := $item.name | default "" | toString -}}
{{- if or (gt (len $name) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name)) -}}
{{- fail (printf "agentNamespaces[%d] is not a namespace name. Give the name of an existing namespace, or {name: <namespace>, tenantId: <id>, source: <label>}" $i) -}}
{{- end -}}
{{- if hasKey $seen $name -}}
{{- fail (printf "agentNamespaces[%d] repeats a namespace. List each namespace once" $i) -}}
{{- end -}}
{{- if eq $name $.Release.Namespace -}}
{{- fail (printf "agentNamespaces[%d] is the release namespace. Agents run in their own namespaces; remove it from the list" $i) -}}
{{- end -}}
{{- $_ := set $seen $name true -}}
{{- $nodeSecret := printf "fabric-ingress-%s" $name -}}
{{- if gt (len $name) 40 -}}
{{- $nodeSecret = printf "fabric-ingress-%s-%s" ($name | trunc 31 | trimSuffix "-") (sha256sum $name | trunc 8) -}}
{{- end -}}
{{- $source := $item.source | default $name | toString -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" $source) -}}
{{- fail (printf "agentNamespaces[%d].source is not a valid source label. Use letters, digits and ._:- (at most 128)" $i) -}}
{{- end -}}
{{- $out = append $out (dict "name" $name "tenantId" ($item.tenantId | default $.Values.tenant.id | toString) "source" $source "nodeSecret" $nodeSecret "index" $i) -}}
{{- end -}}
{{- $out | toYaml -}}
{{- end -}}

{{/* "true" when the Node authenticates sources (the production profile). */}}
{{- define "fabric.nodeIsProduction" -}}
{{- $collector := index .Values "otel-collector" | default dict -}}
{{- if eq (dig "fabric" "profile" "" $collector | toString) "production" -}}true{{- end -}}
{{- end -}}

{{/* The ports of agent namespace number . (an ingress group each). */}}
{{- define "fabric.agentGroupPorts" -}}
{{- $base := int .root.Values.agentIngress.basePort -}}
{{- $first := add $base (mul 3 (int .index)) -}}
{{- dict "grpc" $first "http" (add $first 1) "content" (add $first 2) | toYaml -}}
{{- end -}}

{{- define "fabric.applyPreset" -}}
{{- $collector := index .Values "otel-collector" -}}
{{- if not (kindIs "map" $collector) -}}
{{- $collector = dict -}}
{{- $_ := set .Values "otel-collector" $collector -}}
{{- end -}}
{{- if hasKey $collector "fabricCollectorRendered" -}}
{{- fail "this Helm version rendered the Collector before the chart preset was applied, so preset and agentNamespaces would be ignored. Use Helm 3.15 or later, or pass the profile file instead: -f profiles/shadow-production.yaml" -}}
{{- end -}}
{{- if not (hasKey .Values "fabricPresetApplied") -}}
{{- $_ := set .Values "fabricPresetApplied" true -}}
{{- if .Values.preset -}}
{{- $preset := dict -}}
{{- range $file := (include "fabric.presetFiles" .Values.preset | fromYamlArray) -}}
{{- $content := $.Files.Get $file | fromYaml -}}
{{- if or (not $content) (hasKey $content "Error") -}}
{{- fail (printf "preset %q needs %s, which this chart package does not hold. Use an unmodified chart package" $.Values.preset $file) -}}
{{- end -}}
{{- $preset = mergeOverwrite $preset $content -}}
{{- end -}}
{{- $defaults := .Files.Get "presets/defaults.yaml" | fromYaml -}}
{{- include "fabric.presetMerge" (dict "dst" .Values "src" $preset "def" $defaults) -}}
{{- /* A preset knows the tenant: fill it into the groups it brought. */ -}}
{{- range $group := (dig "receiver" "sourceBindings" list $collector) -}}
{{- if and (kindIs "map" $group) (not ($group.tenantId | default "")) -}}
{{- $_ := set $group "tenantId" ($.Values.tenant.id | toString) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $agents := include "fabric.agentNamespaces" . | fromYamlArray -}}
{{- $receiver := $collector.receiver | default dict -}}
{{- $tls := dig "tls" "serverCertificateSecret" dict $receiver -}}
{{- if and (or $agents .Values.injector.enabled) (kindIs "map" $tls) (not ($tls.name | default "")) -}}
{{- /* Agents in another namespace reach the Node over TLS only (§6.4): the
     secrets Job issues this certificate from the generated CA. */ -}}
{{- $_ := set $tls "name" "fabric-node-receiver-tls" -}}
{{- end -}}
{{- if and $agents (include "fabric.nodeIsProduction" .) -}}
{{- /* One ingress group per agent namespace: its own token, ports and source
     binding. Ingress groups replace the single workload binding. */ -}}
{{- $_ := set ($receiver.workloadAuthentication | default dict) "enabled" false -}}
{{- $groups := list -}}
{{- range $group := ($receiver.sourceBindings | default list) -}}
{{- /* Drop the profile's placeholder agent group (no source id yet). */ -}}
{{- if not (and (eq ($group.kind | default "") "agent") (not ($group.sourceId | default "")) (not (hasKey $group "sourceIdSecret"))) -}}
{{- $groups = append $groups $group -}}
{{- end -}}
{{- end -}}
{{- range $agent := $agents -}}
{{- $ports := include "fabric.agentGroupPorts" (dict "root" $ "index" $agent.index) | fromYaml -}}
{{- $group := dict
      "name" (printf "agents-%d" (int $agent.index))
      "kind" "agent"
      "tenantId" $agent.tenantId
      "sourceId" ""
      "sourceIdSecret" (dict "name" $agent.nodeSecret "key" "source-id")
      "tokenSecret" (dict "name" $agent.nodeSecret "key" "token")
      "protocols" (dict "grpc" (int $ports.grpc) "http" (int $ports.http))
      "ingressFrom" (list (dict "namespaceSelector" (dict "matchLabels" (dict "kubernetes.io/metadata.name" $agent.name))))
-}}
{{- if dig "content" "enabled" false $collector -}}
{{- $_ := set $group "content" (dict "port" (int $ports.content)) -}}
{{- end -}}
{{- $groups = append $groups $group -}}
{{- end -}}
{{- $_ := set $receiver "sourceBindings" $groups -}}
{{- end -}}
{{- end -}}
{{- end -}}
