// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Static dedicated ingress groups (spec 053 §6.1, §6.2.6; spec 056 §7.3.3
// (f)). A Node either has the legacy single binding (one plain fabricguard,
// checked by checkDedicatedEvidenceIngress, unchanged) or only group
// instances fabricguard/<group>. Each group binds one (tenant, source, kind,
// credential, listeners): stock bearertokenauth authenticates possession but
// returns no identity, so a per-group receiver with its own authenticator is
// the only stock way to tie a credential to one source.
//
// The rules are checked over the merged graph before the general pipeline
// rules, in the order of the reference checker
// (scripts/contracts/ingress_groups.py), so a refused configuration is
// reported with the rule it breaks. The error texts equal the "errors" of
// contracts/capture/v1/fixtures/ingress-groups/index.json; diagnostics name
// groups and component ids, never paths, tokens or their digests.

// groupErrors are the refusal texts per rule, as pinned by the goldens.
var groupErrors = map[string]string{
	"name":   "an ingress group name matches ^[a-z][a-z0-9-]{0,31}$ and does not start with content (053 §6.1)",
	"mixing": "a configuration has the legacy single binding or only fabricguard/<group> instances, never both (053 §6.1)",
	"r1":     "each group has exactly one bearertokenauth/<group>, used only by that group's receivers (053 §6.1 rule 1)",
	"r2":     "a group pipeline uses only its own receiver, guard and content exporter; no unbound receiver (053 §6.1 rule 2)",
	"r3":     "no processor after fabricguard/<group> but batch (053 §6.1 rule 3)",
	"r4":     "fabricguard/<group> and fabriccontent/<group> carry the group's tenant and source; allowed_tenants is exactly that tenant (053 §6.1 rule 4)",
	"r5":     "group credentials differ byte for byte (053 §6.1 rule 5)",
	"r6":     "a group credential is one watched token file with require_single_token: true (053 §6.1 rule 6)",
	"r7":     "no two groups bind one (tenant, source) (053 §6.1 rule 7)",
	"r8":     "a group listener uses TLS unless it is loopback (053 §6.1 rule 8)",
	"r9":     "each fabriccontent/<group> has its own binding and encrypted queue (053 §6.1 rule 9)",
	"h1":     "a host group has only its traces pipeline (053 §6.2.6 rule 1)",
	"h2":     "a host group has no content receiver and no fabriccontent exporter (053 §6.2.6 rule 2)",
	"h3":     "fabricguard/<group> sets profile production, source_kind and the group's evidence_source_binding (053 §6.2.6 rule 3)",
	"h4":     "the audit receiver never runs in a production Node pipeline (053 §6.2.6 rule 4)",
	"h5":     "no two group listeners share an address; auditd and eBPF groups have their own (053 §6.1, §6.2.6 rule 5)",
	"s1":     "the sensor-collector profile holds exactly the production audit receiver, one traces pipeline from [memory_limiter, batch] and one otlp_http exporter (056 §7.3.3 (f))",
	"s2":     "the sensor collector exports with TLS or to loopback, refuses redirects and authenticates with a client bearertokenauth token file (056 §7.3.3 (f))",
}

// Errors outside the goldens' rule set.
const (
	errGroupLimit  = "a Node serves at most 64 ingress groups, or up to 256 with FABRIC_GATE_MAX_GROUPS (053 §6.1)"
	errGroupExport = "group telemetry pipelines export only to otlp_http exporters over verified HTTPS (053 §6.1 rule 8)"
)

// Group limits (053 §6.1): 64 by default, FABRIC_GATE_MAX_GROUPS raises the
// limit up to the ceiling. Each group uses one to three listeners.
const (
	defaultMaxGroups = 64
	ceilingMaxGroups = 256
)

var (
	groupNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	groupSourceID    = regexp.MustCompile(`^s-[0-9a-f]{32}$`)
)

// groupKinds are the fabricguard source kinds of a group (056 §7.3.3 (e)).
var groupKinds = map[string]bool{"agent": true, "host.auditd": true, "host.ebpf": true}

func groupRefusal(subject, rule string) error {
	return fmt.Errorf("%s: %s", subject, groupErrors[rule])
}

// groupGuards returns the fabricguard/<group> processors keyed by group name;
// an empty map means the configuration has no ingress groups.
func groupGuards(cfg map[string]any) map[string]any {
	processors, _ := cfg["processors"].(map[string]any)
	groups := map[string]any{}
	for id, node := range processors {
		typ, name, _ := strings.Cut(id, "/")
		if typ == "fabricguard" && name != "" {
			groups[name] = node
		}
	}
	return groups
}

// groupOf maps a receiver or pipeline name part to its group:
// "content-<g>" belongs to <g>.
func groupOf(name string) (group string, content bool) {
	if rest, ok := strings.CutPrefix(name, "content-"); ok {
		return rest, true
	}
	return name, false
}

// maxGroups reads FABRIC_GATE_MAX_GROUPS (unset: 64; at most 256).
func maxGroups() (int, error) {
	raw, set := os.LookupEnv("FABRIC_GATE_MAX_GROUPS")
	if !set || raw == "" {
		return defaultMaxGroups, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > ceilingMaxGroups {
		return 0, fmt.Errorf("FABRIC_GATE_MAX_GROUPS must be an integer from 1 to %d (053 §6.1)", ceilingMaxGroups)
	}
	return n, nil
}

// groupBinding is a group's resolved identity and kind.
type groupBinding struct {
	kind, tenant, source string
}

// checkIngressGroups applies 053 §6.1 rules 1–10 and §6.2.6 rules 1–5 to a
// configuration that has fabricguard/<group> instances. Token files are read
// to compare their bytes (rule 5); their format, permissions and watching are
// checked afterwards by checkGroupCredentials, like the legacy binding's.
func checkIngressGroups(cfg map[string]any, guards map[string]any) error {
	processors, _ := cfg["processors"].(map[string]any)
	receivers, _ := cfg["receivers"].(map[string]any)
	exporters, _ := cfg["exporters"].(map[string]any)
	extensions, _ := cfg["extensions"].(map[string]any)
	service, _ := cfg["service"].(map[string]any)
	pipelines, _ := service["pipelines"].(map[string]any)
	active := map[string]bool{}
	for _, id := range idList(service["extensions"]) {
		active[id] = true
	}
	if _, legacy := processors["fabricguard"]; legacy {
		return groupRefusal("ingress groups", "mixing")
	}
	limit, err := maxGroups()
	if err != nil {
		return err
	}
	if len(guards) > limit {
		return fmt.Errorf("ingress groups: %d groups configured, limit %d: %s", len(guards), limit, errGroupLimit)
	}
	names := sortedKeys(guards)
	for _, g := range names {
		if !groupNamePattern.MatchString(g) || strings.HasPrefix(g, "content") {
			return groupRefusal(fmt.Sprintf("ingress group %q", g), "name")
		}
	}
	for _, id := range sortedKeys(receivers) {
		if componentType(id) == "audit" {
			return groupRefusal(fmt.Sprintf("receiver %q", id), "h4")
		}
	}

	// Guards: production, the kind and the binding (§6.2.6 rule 3; 056
	// §7.3.3 (e)). Identities may come from the environment; the kind and
	// the profile are literal.
	bindings := map[string]groupBinding{}
	for _, g := range names {
		guard, _ := guards[g].(map[string]any)
		identity, _ := guard["evidence_source_binding"].(map[string]any)
		kind, _ := guard["source_kind"].(string)
		tenant, _ := identity["tenant_id"].(string)
		source, _ := identity["source_id"].(string)
		tenant, source = expandEnvRefs(tenant), expandEnvRefs(source)
		digests, hasDigests := guard["host_digests"]
		if guard["profile"] != "production" || !groupKinds[kind] ||
			!safeEvidenceIdentity(tenant) || !groupSourceID.MatchString(source) ||
			kind == "agent" && hasDigests ||
			hasDigests && digests != "omitted" && digests != "permitted" {
			return groupRefusal(fmt.Sprintf("fabricguard/%s", g), "h3")
		}
		bindings[g] = groupBinding{kind: kind, tenant: tenant, source: source}
	}

	// Credentials (rules 1, 6): one single-token file authenticator per
	// group, active in the service.
	for _, g := range names {
		id := "bearertokenauth/" + g
		auth, isMap := extensions[id].(map[string]any)
		filename, _ := auth["filename"].(string)
		_, inline := auth["tokens"]
		if !isMap || expandEnvRefs(filename) == "" || inline || auth["require_single_token"] != true || !active[id] {
			return groupRefusal(fmt.Sprintf("extension %q", id), "r6")
		}
	}

	// Receivers (rules 1, 2; §6.2.6 rule 2): every receiver is otlp/<g> or
	// otlp/content-<g> of a configured group, authenticated by that group's
	// authenticator on every protocol.
	for _, id := range sortedKeys(receivers) {
		typ, name, _ := strings.Cut(id, "/")
		g, content := groupOf(name)
		binding, known := bindings[g]
		if typ != "otlp" || !known {
			return groupRefusal(fmt.Sprintf("receiver %q", id), "r2")
		}
		if content && binding.kind != "agent" {
			return groupRefusal(fmt.Sprintf("receiver %q", id), "h2")
		}
		receiver, _ := receivers[id].(map[string]any)
		protocols, _ := receiver["protocols"].(map[string]any)
		for _, protocol := range sortedKeys(protocols) {
			if protocolAuthenticator(receiver, protocol) != "bearertokenauth/"+g {
				return groupRefusal(fmt.Sprintf("receiver %q", id), "r1")
			}
		}
	}
	for _, g := range names {
		if _, ok := receivers["otlp/"+g]; !ok {
			return groupRefusal(fmt.Sprintf("ingress group %q", g), "r2")
		}
	}
	// No exporter presents a group credential as a client.
	for _, id := range sortedKeys(exporters) {
		exporter, _ := exporters[id].(map[string]any)
		auth, _ := exporter["auth"].(map[string]any)
		authenticator, _ := auth["authenticator"].(string)
		if g, ok := strings.CutPrefix(strings.TrimSpace(expandEnvRefs(authenticator)), "bearertokenauth/"); ok && bindings[g].kind != "" {
			return groupRefusal(fmt.Sprintf("exporter %q", id), "r1")
		}
	}

	// Pipelines (rules 2, 3; §6.2.6 rules 1, 2).
	approved := map[string]bool{}
	for id := range exporters {
		if componentType(id) == "otlp_http" {
			approved[id] = true
		}
	}
	for _, id := range sortedKeys(pipelines) {
		signal, name, _ := strings.Cut(id, "/")
		g, content := groupOf(name)
		binding, known := bindings[g]
		if !known {
			return groupRefusal(fmt.Sprintf("pipeline %q", id), "r2")
		}
		if binding.kind != "agent" && content {
			return groupRefusal(fmt.Sprintf("pipeline %q", id), "h2")
		}
		if binding.kind != "agent" && signal != "traces" {
			return groupRefusal(fmt.Sprintf("pipeline %q", id), "h1")
		}
		pipeline, _ := pipelines[id].(map[string]any)
		steps, stepsOK := stringList(orEmptyList(pipeline["processors"]))
		if content {
			if signal != "logs" || !exactStringList(pipeline["receivers"], []string{"otlp/content-" + g}) ||
				!exactStringList(pipeline["exporters"], []string{"fabriccontent/" + g}) {
				return groupRefusal(fmt.Sprintf("pipeline %q", id), "r2")
			}
			if !stepsOK || len(steps) > 1 || len(steps) == 1 && steps[0] != "memory_limiter" {
				return groupRefusal(fmt.Sprintf("pipeline %q", id), "r3")
			}
			continue
		}
		if signal != "traces" && signal != "logs" || !exactStringList(pipeline["receivers"], []string{"otlp/" + g}) {
			return groupRefusal(fmt.Sprintf("pipeline %q", id), "r2")
		}
		guard := -1
		for i, step := range steps {
			if componentType(step) != "fabricguard" {
				continue
			}
			if step != "fabricguard/"+g || guard != -1 {
				return groupRefusal(fmt.Sprintf("pipeline %q", id), "r2")
			}
			guard = i
		}
		if !stepsOK || guard == -1 {
			return groupRefusal(fmt.Sprintf("pipeline %q", id), "r2")
		}
		before, after := steps[:guard], steps[guard+1:]
		if len(before) > 1 || len(before) == 1 && before[0] != "memory_limiter" ||
			len(after) > 1 || len(after) == 1 && after[0] != "batch" {
			return groupRefusal(fmt.Sprintf("pipeline %q", id), "r3")
		}
		routes := idList(pipeline["exporters"])
		if len(routes) == 0 {
			return groupRefusal(fmt.Sprintf("pipeline %q", id), "r2")
		}
		for _, exporter := range routes {
			if !approved[exporter] {
				return groupRefusal(fmt.Sprintf("pipeline %q", id), "r2")
			}
		}
	}
	for _, g := range names {
		if bindings[g].kind == "agent" {
			continue
		}
		if _, ok := exporters["fabriccontent/"+g]; ok {
			return groupRefusal(fmt.Sprintf("ingress group %q", g), "h2")
		}
		if _, ok := pipelines["traces/"+g]; !ok {
			return groupRefusal(fmt.Sprintf("ingress group %q", g), "h1")
		}
	}

	// Bindings (rules 4, 7, 9).
	pairs := map[[2]string]string{}
	for _, g := range names {
		pair := [2]string{bindings[g].tenant, bindings[g].source}
		if other, dup := pairs[pair]; dup {
			return groupRefusal(fmt.Sprintf("ingress groups %q and %q", other, g), "r7")
		}
		pairs[pair] = g
	}
	queues, stores, directories := map[string]string{}, map[string]string{}, map[string]string{}
	for _, id := range sortedKeys(exporters) {
		typ, g, _ := strings.Cut(id, "/")
		if typ != "fabriccontent" {
			continue
		}
		binding, known := bindings[g]
		if !known {
			return groupRefusal(fmt.Sprintf("exporter %q", id), "r2")
		}
		exporter, _ := exporters[id].(map[string]any)
		own, _ := exporter["source_binding"].(map[string]any)
		tenant, _ := own["tenant_id"].(string)
		source, _ := own["source_id"].(string)
		tenants := tenantList(exporter["allowed_tenants"])
		if expandEnvRefs(tenant) != binding.tenant || expandEnvRefs(source) != binding.source ||
			len(tenants) != 1 || tenants[0] != binding.tenant || configTrue(exporter["allow_multiple_tenants"]) {
			return groupRefusal(fmt.Sprintf("exporter %q", id), "r4")
		}
		queue, _ := exporter["sending_queue"].(map[string]any)
		storage, _ := queue["storage"].(string)
		envelope, _ := extensions[storage].(map[string]any)
		keyFile, _ := envelope["key_file"].(string)
		inner, _ := envelope["storage"].(string)
		directory, _ := exporter["queue_directory"].(string)
		if storage != "fabricenvelope/fabric_content_"+g || keyFile == "" || !active[storage] {
			return groupRefusal(fmt.Sprintf("exporter %q", id), "r9")
		}
		// Two groups never share an encrypted queue, its file_storage or its
		// directory, even when they target one customer store.
		for _, unique := range []struct {
			seen  map[string]string
			value string
		}{{queues, storage}, {stores, inner}, {directories, directory}} {
			if other, dup := unique.seen[unique.value]; dup && unique.value != "" {
				return groupRefusal(fmt.Sprintf("exporters %q and %q", other, id), "r9")
			}
			unique.seen[unique.value] = id
		}
	}

	// Credential bytes (rule 5), compared without logging them or digests.
	var credentials []tokenFile
	for _, g := range names {
		auth, _ := extensions["bearertokenauth/"+g].(map[string]any)
		filename, _ := auth["filename"].(string)
		credentials = append(credentials, tokenFile{extension: "bearertokenauth/" + g, path: expandEnvRefs(filename), group: g})
	}
	if err := checkGroupTokensDiffer(credentials); err != nil {
		return err
	}

	// Listeners (rule 8; §6.1 ports unique; §6.2.6 rule 5).
	listeners := map[string]string{}
	for _, id := range sortedKeys(receivers) {
		receiver, _ := receivers[id].(map[string]any)
		protocols, _ := receiver["protocols"].(map[string]any)
		for _, protocol := range sortedKeys(protocols) {
			endpoint := listenerEndpoint(receiver, protocol)
			port := endpoint[strings.LastIndex(endpoint, ":")+1:]
			if other, dup := listeners[port]; dup {
				return groupRefusal(fmt.Sprintf("receivers %s and %q", other, id), "h5")
			}
			listeners[port] = fmt.Sprintf("%q", id)
			tls := protocolTLS(receiver, protocol)
			if !loopbackHostPort(endpoint) && (!serverTLS(tls) || configTrue(tls["insecure"])) {
				return groupRefusal(fmt.Sprintf("receiver %q protocol %q", id, protocol), "r8")
			}
		}
	}

	// Approved telemetry exporters (rule 8): otlp_http over verified HTTPS;
	// no other exporter type is defined on a group Node.
	for _, id := range sortedKeys(exporters) {
		switch componentType(id) {
		case "fabriccontent":
			continue
		case "otlp_http":
			exporter, _ := exporters[id].(map[string]any)
			if !verifiedHTTPS(exporter) {
				return fmt.Errorf("exporter %q: %s", id, errGroupExport)
			}
		default:
			return fmt.Errorf("exporter %q: %s", id, errGroupExport)
		}
	}
	return nil
}

// checkGroupCredentials finishes the group rules once the general checks
// have passed: every component declares the production profile, every
// fabriccontent/<group> keeps the production content rules with its group's
// binding (spec 049 §7.8–§7.9), and every group token file meets the
// dedicated-ingress token rules and is watched as a group credential, so the
// supervisor re-checks its format and its difference from every other
// group's token after each rotation (rules 5, 6).
func checkGroupCredentials(cfg map[string]any, guards map[string]any, watched []tokenFile) error {
	production, err := declaredProduction(cfg)
	if err != nil {
		return err
	}
	if !production {
		return groupRefusal("ingress groups", "h3")
	}
	exporters, _ := cfg["exporters"].(map[string]any)
	extensions, _ := cfg["extensions"].(map[string]any)
	for _, id := range sortedKeys(exporters) {
		typ, g, _ := strings.Cut(id, "/")
		if typ != "fabriccontent" {
			continue
		}
		guard, _ := guards[g].(map[string]any)
		identity, _ := guard["evidence_source_binding"].(map[string]any)
		tenant, _ := identity["tenant_id"].(string)
		source, _ := identity["source_id"].(string)
		binding := map[string]any{"tenant_id": expandEnvRefs(tenant), "source_id": expandEnvRefs(source)}
		if err := checkProductionContentExporter(cfg, id, binding); err != nil {
			return err
		}
	}
	for _, g := range sortedKeys(guards) {
		id := "bearertokenauth/" + g
		auth, _ := extensions[id].(map[string]any)
		filename, _ := auth["filename"].(string)
		path := expandEnvRefs(filename)
		if err := checkDedicatedTokenFile(id, path); err != nil {
			return fmt.Errorf("ingress group %q: %w", g, err)
		}
		marked := false
		for i := range watched {
			if watched[i].extension == id && watched[i].path == path {
				watched[i].dedicated, watched[i].group = true, g
				marked = true
			}
		}
		if !marked {
			return groupRefusal(fmt.Sprintf("extension %q", id), "r6")
		}
	}
	return checkGroupTokensDiffer(watched)
}

// checkGroupTokensDiffer reads every group credential and refuses two
// groups holding the same bytes (rule 5), including two groups naming one
// file. It runs at startup and after every rotation; the bytes are compared
// in memory and never logged, digested or echoed.
func checkGroupTokensDiffer(files []tokenFile) error {
	owner := map[string]string{}
	for _, tf := range files {
		if tf.group == "" {
			continue
		}
		data, err := os.ReadFile(tf.path)
		if err != nil {
			return groupRefusal(fmt.Sprintf("ingress group %q", tf.group), "r6")
		}
		if other, dup := owner[string(data)]; dup {
			return groupRefusal(fmt.Sprintf("ingress groups %q and %q", other, tf.group), "r5")
		}
		owner[string(data)] = tf.group
	}
	return nil
}

// listenerEndpoint is a receiver protocol's endpoint as the collector binds
// it: env-expanded, or the OTLP default when unset.
func listenerEndpoint(receiver map[string]any, protocol string) string {
	protocols, _ := receiver["protocols"].(map[string]any)
	settings, _ := protocols[protocol].(map[string]any)
	endpoint, _ := settings["endpoint"].(string)
	endpoint = strings.TrimSpace(expandEnvRefs(endpoint))
	if endpoint != "" {
		return endpoint
	}
	if protocol == "grpc" {
		return "localhost:4317"
	}
	return "localhost:4318"
}

// loopbackHostPort: host:port (or [v6]:port) naming a loopback host.
func loopbackHostPort(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = strings.Trim(hostport, "[]")
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// exportURLAllowed: an https:// URL, or http:// to a loopback host when
// loopback is allowed.
func exportURLAllowed(raw string, loopback bool) bool {
	value := strings.TrimSpace(expandEnvRefs(raw))
	if strings.HasPrefix(value, "https://") {
		return len(value) > len("https://")
	}
	rest, ok := strings.CutPrefix(value, "http://")
	if !ok || !loopback {
		return false
	}
	authority, _, _ := strings.Cut(rest, "/")
	if strings.Contains(authority, ":") && !strings.HasSuffix(authority, "]") {
		return loopbackHostPort(authority)
	}
	return loopbackHostPort(authority + ":0")
}

// exportsOver reports whether every URL field an OTLP/HTTP exporter sends to
// (endpoint and the per-signal overrides) passes exportURLAllowed, with at
// least one set, and its TLS verification is not disabled.
func exportsOver(exporter map[string]any, loopback bool) bool {
	set := 0
	for _, field := range otlpEndpointFields {
		raw, present := exporter[field]
		if !present || raw == nil {
			continue
		}
		value, isString := raw.(string)
		if !isString || !exportURLAllowed(value, loopback) {
			return false
		}
		set++
	}
	tls, _ := exporter["tls"].(map[string]any)
	return set > 0 && !configTrue(tls["insecure"]) && !configTrue(tls["insecure_skip_verify"])
}

func verifiedHTTPS(exporter map[string]any) bool {
	return exportsOver(exporter, false)
}

// orEmptyList treats an absent processors list as empty.
func orEmptyList(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

// sensorProfile reports whether the configuration is a sensor collector
// (056 §7.3.3 (f)): an audit receiver sets mode: production. The mode must
// be literal, so the gate and the receiver agree on which profile applies.
func sensorProfile(cfg map[string]any) (bool, error) {
	receivers, _ := cfg["receivers"].(map[string]any)
	sensor := false
	for _, id := range sortedKeys(receivers) {
		if componentType(id) != "audit" {
			continue
		}
		receiver, _ := receivers[id].(map[string]any)
		mode, present := receiver["mode"]
		if !present || mode == nil {
			continue
		}
		text, isString := mode.(string)
		if !isString || strings.Contains(text, "$") {
			return false, fmt.Errorf("receiver %q must set mode literally (local or production)", id)
		}
		if text == "production" {
			sensor = true
		}
	}
	return sensor, nil
}

// checkSensorProfile applies the sensor-collector profile: exactly the
// production audit receiver, one traces pipeline with processors from
// [memory_limiter, batch] and one otlp_http exporter (the only OTLP exporter
// of the Node build) that exports with TLS or to loopback, refuses redirects
// and authenticates with a client bearertokenauth token file. Nothing else
// runs in the process: no other receiver, processor, exporter, pipeline or
// connector.
func checkSensorProfile(cfg map[string]any) error {
	receivers, _ := cfg["receivers"].(map[string]any)
	processors, _ := cfg["processors"].(map[string]any)
	exporters, _ := cfg["exporters"].(map[string]any)
	extensions, _ := cfg["extensions"].(map[string]any)
	service, _ := cfg["service"].(map[string]any)
	pipelines, _ := service["pipelines"].(map[string]any)
	if len(receivers) != 1 || len(pipelines) != 1 || len(exporters) != 1 || !isEmpty(cfg["connectors"]) {
		return groupRefusal("sensor collector", "s1")
	}
	audit, exporterID, pipelineID := sortedKeys(receivers)[0], sortedKeys(exporters)[0], sortedKeys(pipelines)[0]
	for id := range processors {
		if id != "memory_limiter" && id != "batch" {
			return groupRefusal(fmt.Sprintf("processor %q", id), "s1")
		}
	}
	pipeline, _ := pipelines[pipelineID].(map[string]any)
	steps, stepsOK := stringList(orEmptyList(pipeline["processors"]))
	allowed := stepsOK && len(steps) <= 2
	for i, step := range steps {
		allowed = allowed && (step == "memory_limiter" && i == 0 || step == "batch" && i == len(steps)-1)
	}
	if componentType(audit) != "audit" || componentType(pipelineID) != "traces" || componentType(exporterID) != "otlp_http" ||
		!exactStringList(pipeline["receivers"], []string{audit}) || !exactStringList(pipeline["exporters"], []string{exporterID}) || !allowed {
		return groupRefusal(fmt.Sprintf("pipeline %q", pipelineID), "s1")
	}
	exporter, isMap := exporters[exporterID].(map[string]any)
	auth, _ := exporter["auth"].(map[string]any)
	authenticator, _ := auth["authenticator"].(string)
	client, _ := extensions[authenticator].(map[string]any)
	filename, _ := client["filename"].(string)
	_, inline := client["tokens"]
	active := false
	for _, id := range idList(service["extensions"]) {
		active = active || id == authenticator
	}
	noRedirect := false
	middlewares, _ := exporter["middlewares"].([]any)
	for _, m := range middlewares {
		entry, _ := m.(map[string]any)
		id, _ := entry["id"].(string)
		noRedirect = noRedirect || componentType(id) == "noredirect"
	}
	if !isMap || !exportsOver(exporter, true) || !noRedirect || componentType(authenticator) != "bearertokenauth" ||
		client == nil || expandEnvRefs(filename) == "" || inline || !active {
		return groupRefusal(fmt.Sprintf("exporter %q", exporterID), "s2")
	}
	return nil
}

// checkSensorCollector runs the general rules that apply to the sensor
// collector after its profile: readable exporter blocks, the no-redirect
// middleware defined and enabled, and no credential in an endpoint. The
// fabricguard pipeline rules do not apply: the sensor collector carries only
// host records, and the Node's fabricguard/<group> admits them (053 §6.2.7).
func checkSensorCollector(cfg map[string]any) error {
	if err := checkSensorProfile(cfg); err != nil {
		return err
	}
	for _, check := range []func(map[string]any) error{checkExportersReadable, checkRedirectMiddleware, checkExporterEndpoints, checkExporterHeaders} {
		if err := check(cfg); err != nil {
			return err
		}
	}
	return nil
}
