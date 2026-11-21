{{/*
Spec 058 §10.5: the chart-managed host sensor DaemonSet (the eBPF host
emitter, production mode) and what it shares with the secrets Job, the Node's
ingress groups and the injector. Every helper runs after "fabric.applyPreset".
*/}}

{{- define "fabric.hostSensorName" -}}
{{- include "fabric.objectName" (dict "root" . "suffix" "fabric-host-sensor") -}}
{{- end -}}

{{- define "fabric.hostSensorImage" -}}
{{- $image := .Values.hostSensor.image -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $image.repository $image.digest -}}
{{- else -}}
{{- printf "%s:%s" $image.repository ($image.tag | default .Values.global.fabric.version) -}}
{{- end -}}
{{- end -}}

{{/* Node labels that mark a node no DaemonSet pod can run on (serverless and
     virtual nodes): label -> value. */}}
{{- define "fabric.hostSensorExcludedNodes" -}}
eks.amazonaws.com/compute-type: fargate
type: virtual-kubelet
kubernetes.azure.com/mode: virtual
{{- end -}}

{{/*
The nodes that run the sensor, normalised: a YAML list of
  name    the node
  index   its position, which fixes its group name (ebpf-<index>) and port
  port    its OTLP/gRPC port on the Node
  secret  the Secret of the release namespace with its token, state key and
          source id: fabric-host-<first 12 hex of sha256(name)>
From hostSensor.nodes, or read from the cluster. Computed once per render.
*/}}
{{- define "fabric.hostSensorNodes" -}}
{{- if not (hasKey .Values "fabricHostSensorNodes") -}}
{{- $names := list -}}
{{- range $i, $name := (.Values.hostSensor.nodes | default list) -}}
{{- $name = $name | toString -}}
{{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" $name)) -}}
{{- fail (printf "hostSensor.nodes[%d] is not a node name. List node names as `kubectl get nodes` prints them" $i) -}}
{{- end -}}
{{- if has $name $names -}}
{{- fail (printf "hostSensor.nodes[%d] repeats a node. List each node once" $i) -}}
{{- end -}}
{{- $names = append $names $name -}}
{{- end -}}
{{- if not $names -}}
{{- $excluded := include "fabric.hostSensorExcludedNodes" . | fromYaml -}}
{{- $found := dict -}}
{{- range $node := (dig "items" list (lookup "v1" "Node" "" "")) -}}
{{- $labels := $node.metadata.labels | default dict -}}
{{- $ok := eq (index $labels "kubernetes.io/os" | default "linux") "linux" -}}
{{- range $key, $value := $excluded -}}
{{- if eq (index $labels $key | default "") $value }}{{ $ok = false }}{{ end -}}
{{- end -}}
{{- range $key, $value := ($.Values.hostSensor.nodeSelector | default dict) -}}
{{- if ne (index $labels $key | default "" | toString) ($value | toString) }}{{ $ok = false }}{{ end -}}
{{- end -}}
{{- if $ok -}}
{{- /* Oldest first, so a new node is added at the end and keeps the ports of the others. */ -}}
{{- $_ := set $found (printf "%s/%s" ($node.metadata.creationTimestamp | toString) $node.metadata.name) $node.metadata.name -}}
{{- end -}}
{{- end -}}
{{- range $key := (keys $found | sortAlpha) -}}
{{- $names = append $names (index $found $key) -}}
{{- end -}}
{{- end -}}
{{- if not $names -}}
{{- fail "hostSensor.enabled=true needs the names of the nodes that run the sensor, and this render cannot read them from the cluster (helm template, a client-side dry run, or no node matches hostSensor.nodeSelector). Set hostSensor.nodes to the node names (kubectl get nodes -o name), oldest first" -}}
{{- end -}}
{{- $out := list -}}
{{- range $i, $name := $names -}}
{{- $out = append $out (dict
      "name" $name
      "index" $i
      "port" (add (int $.Values.hostSensor.basePort) $i)
      "secret" (printf "fabric-host-%s" (sha256sum $name | trunc 12))
    ) -}}
{{- end -}}
{{- $_ := set .Values "fabricHostSensorNodes" $out -}}
{{- end -}}
{{- .Values.fabricHostSensorNodes | toYaml -}}
{{- end -}}

{{/*
Called by "fabric.applyPreset": with the sensor on, one host.ebpf ingress group
per node on the Node. The profile's placeholder group (no source id) goes.
*/}}
{{- define "fabric.hostSensorGroups" -}}
{{- if .Values.hostSensor.enabled -}}
{{- if not (include "fabric.nodeIsProduction" .) -}}
{{- fail "hostSensor.enabled=true needs a production Node: each node's sensor is an authenticated source with its own ingress group. Use preset=production-host-sensor (or the production profile files), or turn hostSensor off" -}}
{{- end -}}
{{- $collector := index .Values "otel-collector" -}}
{{- $receiver := $collector.receiver | default dict -}}
{{- $nodes := include "fabric.hostSensorNodes" . | fromYamlArray -}}
{{- $groups := list -}}
{{- $taken := dict -}}
{{- range $group := ($receiver.sourceBindings | default list) -}}
{{- $placeholder := and (eq ($group.kind | default "") "host.ebpf") (not ($group.sourceId | default "")) (not (hasKey $group "sourceIdSecret")) -}}
{{- if not $placeholder -}}
{{- if and (eq ($group.kind | default "") "agent") (not ($group.sourceId | default "")) (not (hasKey $group "sourceIdSecret")) -}}
{{- fail "hostSensor.enabled=true (preset=production-host-sensor) needs the namespaces of your agents, so each gets its ingress group and Secret: --set 'agentNamespaces={NAMESPACE}'. With ingress groups of your own, give the agent group its sourceId" -}}
{{- end -}}
{{- $groups = append $groups $group -}}
{{- $_ := set $taken ($group.name | default "" | toString) true -}}
{{- end -}}
{{- end -}}
{{- $limit := int ($receiver.maxSourceBindings | default 64) -}}
{{- if gt (add (len $groups) (len $nodes)) $limit -}}
{{- fail (printf "hostSensor: %d nodes and %d other ingress groups are more than one Node serves (otel-collector.receiver.maxSourceBindings=%d, at most 256). Raise it, or limit the sensor to a node pool with hostSensor.nodeSelector and install one release per pool" (len $nodes) (len $groups) $limit) -}}
{{- end -}}
{{- $peer := dict
      "namespaceSelector" (dict "matchLabels" (dict "kubernetes.io/metadata.name" .Release.Namespace))
      "podSelector" (dict "matchLabels" (dict "app.kubernetes.io/name" "fabric-host-emitter"))
-}}
{{- range $node := $nodes -}}
{{- $name := printf "ebpf-%d" (int $node.index) -}}
{{- if hasKey $taken $name -}}
{{- fail (printf "hostSensor: the ingress group name %s is already used by otel-collector.receiver.sourceBindings. Rename that group, or turn hostSensor off and keep your own host groups" $name) -}}
{{- end -}}
{{- $groups = append $groups (dict
      "name" $name
      "kind" "host.ebpf"
      "tenantId" ($.Values.tenant.id | toString)
      "sourceId" ""
      "sourceIdSecret" (dict "name" $node.secret "key" "source-id")
      "tokenSecret" (dict "name" $node.secret "key" "token")
      "protocols" (dict "grpc" (int $node.port))
      "hostDigests" ($.Values.hostSensor.digests | toString)
      "ingressFrom" (list $peer)
    ) -}}
{{- end -}}
{{- $_ := set $receiver "sourceBindings" $groups -}}
{{- end -}}
{{- end -}}

{{/* "true" when the operator gave a host.ebpf group of their own (a source id
     or a sourceIdSecret): the hand-deployed DaemonSet route. */}}
{{- define "fabric.hasOwnHostGroups" -}}
{{- $collector := index .Values "otel-collector" | default dict -}}
{{- range $group := (dig "receiver" "sourceBindings" list $collector) -}}
{{- if and (kindIs "map" $group) (eq ($group.kind | default "") "host.ebpf") (or ($group.sourceId | default "") (hasKey $group "sourceIdSecret")) -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{/* The node -> endpoint map (ConfigMap data): ebpf-<index>.endpoint. */}}
{{- define "fabric.hostSensorEndpoints" -}}
{{- $host := printf "%s.%s.svc.%s" (include "fabric.collectorFullname" .) .Release.Namespace .Values.clusterDomain -}}
{{- $out := dict -}}
{{- range $node := (include "fabric.hostSensorNodes" . | fromYamlArray) -}}
{{- $_ := set $out (printf "ebpf-%d.endpoint" (int $node.index)) (printf "%s:%d" $host (int $node.port)) -}}
{{- end -}}
{{- $out | toYaml -}}
{{- end -}}
