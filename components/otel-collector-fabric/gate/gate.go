// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// tokenFile is a bearertokenauth token-file path the gate must keep watching
// after startup: the pinned extension re-reads its file via fsnotify, so a
// mid-run rotation to an unsafe format would re-open the empty-credential
// bypass the boot check closed.
type tokenFile struct {
	extension string
	path      string
}

// validateArgs resolves every --config source the collector would load,
// deep-merges them the way confmap does (later files win key-by-key), and
// enforces the recorder-v1 invariants on the effective configuration. It
// returns the token files that must be re-validated while the collector runs.
func validateArgs(args []string) ([]tokenFile, error) {
	sources, err := configSources(args)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no --config supplied; refusing to boot an unverifiable configuration")
	}
	merged := map[string]any{}
	for _, src := range sources {
		raw, err := readConfigSource(src)
		if err != nil {
			return nil, err
		}
		var parsed map[string]any
		if err := yaml.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
		deepMerge(merged, parsed)
	}
	if err := checkPipelines(merged); err != nil {
		return nil, err
	}
	return checkBearerTokenAuth(merged)
}

// configSources collects --config values in both pflag spellings
// (--config=URI and --config URI). The collector accepts the flag multiple
// times and merges the sources, so each is validated rather than only the
// last.
//
// --set is refused outright, in both spellings (--set=k=v and --set k=v):
// the pinned collector (otelcol v0.150.0 flags.go) turns each --set into a
// configuration source merged after every --config, so a single
// --set=service.pipelines.traces.processors=[batch] would remove fabricguard
// after the gate had approved the files. Overrides belong in an additional
// --config file, which the gate merges and validates like any other.
func configSources(args []string) ([]string, error) {
	var sources []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--set" || strings.HasPrefix(arg, "--set="):
			return nil, fmt.Errorf("--set overrides are not accepted by the recorder gate; put overrides in an additional --config file so they are validated")
		case arg == "--config":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--config requires a value")
			}
			i++
			sources = append(sources, args[i])
		case strings.HasPrefix(arg, "--config="):
			sources = append(sources, strings.TrimPrefix(arg, "--config="))
		}
	}
	return sources, nil
}

// readConfigSource loads a confmap URI. Only local sources are verifiable;
// a remote or unknown scheme is refused because the gate cannot assert the
// invariants over content it cannot read.
func readConfigSource(src string) ([]byte, error) {
	switch {
	case strings.HasPrefix(src, "env:"):
		name := strings.TrimPrefix(src, "env:")
		v, ok := os.LookupEnv(name)
		if !ok {
			return nil, fmt.Errorf("config source env:%s is not set", name)
		}
		return []byte(v), nil
	case strings.HasPrefix(src, "yaml:"):
		return []byte(strings.TrimPrefix(src, "yaml:")), nil
	case strings.HasPrefix(src, "file:"):
		return readLocalConfig(strings.TrimPrefix(src, "file:"))
	case strings.Contains(src, "://") || strings.HasPrefix(src, "http:") || strings.HasPrefix(src, "https:"):
		return nil, fmt.Errorf("remote config source %q cannot be verified by the recorder gate", src)
	default:
		return readLocalConfig(src)
	}
}

func readLocalConfig(path string) ([]byte, error) {
	path = expandEnvRefs(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read collector config %q: %w", path, err)
	}
	return data, nil
}

// deepMerge folds overlay into base the way confmap merges --config sources:
// maps merge recursively, scalars and sequences are replaced.
func deepMerge(base, overlay map[string]any) {
	for k, v := range overlay {
		if ov, ok := v.(map[string]any); ok {
			if bv, ok := base[k].(map[string]any); ok {
				deepMerge(bv, ov)
				continue
			}
		}
		base[k] = v
	}
}

// checkPipelines enforces the recorder's pipeline invariants on the merged
// configuration:
//
//   - every pipeline signal is traces or logs (spec 042);
//   - every telemetry pipeline runs fabricguard itself, followed only by inert
//     processors (spec 042). The processor only protects the pipelines it is
//     wired into: a metrics or profiles pipeline, a pipeline with no
//     fabricguard, or one relying on a sibling's guard would export
//     unfiltered records;
//   - content (spec 043 §5) stays on its own path: a content receiver
//     (otlp/content*) and the fabriccontent exporter appear only in content
//     pipelines (logs/content*), which carry only content receivers, only
//     memory_limiter and only fabriccontent; no content receiver speaks gRPC
//     and no connector can bridge content into a telemetry pipeline;
//   - a fabriccontent exporter allows one tenant unless it sets
//     allow_multiple_tenants: true (the record names its tenant), and all
//     fabriccontent exporters sharing a receiver or pipeline together allow
//     one tenant unless every one of them sets it;
//   - no OTLP destination or fabriccontent S3 endpoint carries user info, a
//     query or a fragment (credentials belong in Secret-backed headers or
//     the AWS credential chain, never in the URL).
func checkPipelines(cfg map[string]any) error {
	service, _ := cfg["service"].(map[string]any)
	pipelines, _ := service["pipelines"].(map[string]any)
	if len(pipelines) == 0 {
		return fmt.Errorf("service.pipelines defines no pipelines")
	}
	if connectors, ok := cfg["connectors"]; ok && !isEmpty(connectors) {
		return fmt.Errorf("connectors are not accepted by the recorder; a connector could bridge content records into a telemetry pipeline")
	}
	if err := checkContentReceivers(cfg); err != nil {
		return err
	}
	if err := checkContentTenants(cfg); err != nil {
		return err
	}
	if err := checkSharedIngressTenants(cfg, pipelines); err != nil {
		return err
	}
	if err := checkExporterEndpoints(cfg); err != nil {
		return err
	}
	names := make([]string, 0, len(pipelines))
	for name := range pipelines {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		signal, _, _ := strings.Cut(name, "/")
		if signal != "traces" && signal != "logs" {
			return fmt.Errorf("pipeline %q uses signal %q; the recorder allows only traces and logs (fabricguard cannot protect other signals)", name, signal)
		}
		pipeline, _ := pipelines[name].(map[string]any)
		processors, _ := pipeline["processors"].([]any)
		if isContentPipeline(name) {
			if err := checkContentPipeline(name, pipeline); err != nil {
				return err
			}
			continue
		}
		for _, id := range idList(pipeline["receivers"]) {
			if isContentReceiver(id) {
				return fmt.Errorf("pipeline %q uses content receiver %q; content receivers may only feed logs/content pipelines", name, id)
			}
		}
		for _, id := range idList(pipeline["exporters"]) {
			if componentType(id) == "fabriccontent" {
				return fmt.Errorf("pipeline %q uses exporter %q; fabriccontent may only run in logs/content pipelines", name, id)
			}
		}
		if err := checkGuarded(name, processors); err != nil {
			return err
		}
	}
	return nil
}

// isContentPipeline: a logs pipeline whose name part starts with "content".
func isContentPipeline(id string) bool {
	signal, name, _ := strings.Cut(id, "/")
	return signal == "logs" && strings.HasPrefix(name, "content")
}

// isContentReceiver: an otlp receiver whose name part starts with "content".
func isContentReceiver(id string) bool {
	typ, name, _ := strings.Cut(id, "/")
	return typ == "otlp" && strings.HasPrefix(name, "content")
}

func componentType(id string) string {
	typ, _, _ := strings.Cut(id, "/")
	return typ
}

// idList returns the component ids of a pipeline list; a value that is not a
// list of strings yields entries that match no rule ("" ids), so a content
// pipeline with such a list is refused.
func idList(v any) []string {
	items, ok := v.([]any)
	if !ok {
		if v == nil {
			return nil
		}
		return []string{""}
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		id, _ := item.(string)
		ids = append(ids, id)
	}
	return ids
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	default:
		return false
	}
}

// checkContentPipeline: only content receivers, only memory_limiter (never
// fabricguard, which would scrub the bodies), and only fabriccontent, so a
// content body can never reach the OTLP destination exporter.
func checkContentPipeline(name string, pipeline map[string]any) error {
	receivers := idList(pipeline["receivers"])
	if len(receivers) == 0 {
		return fmt.Errorf("content pipeline %q has no receivers", name)
	}
	for _, id := range receivers {
		if !isContentReceiver(id) {
			return fmt.Errorf("content pipeline %q uses receiver %q; only otlp/content receivers may feed a content pipeline", name, id)
		}
	}
	for _, id := range idList(pipeline["processors"]) {
		if componentType(id) != "memory_limiter" {
			return fmt.Errorf("content pipeline %q runs processor %q; only memory_limiter may run on the content path", name, id)
		}
	}
	exporters := idList(pipeline["exporters"])
	if len(exporters) == 0 {
		return fmt.Errorf("content pipeline %q has no exporters; it must export only to fabriccontent", name)
	}
	for _, id := range exporters {
		if componentType(id) != "fabriccontent" {
			return fmt.Errorf("content pipeline %q exports to %q; a content pipeline may export only to fabriccontent", name, id)
		}
	}
	return nil
}

// checkContentReceivers refuses gRPC on a content receiver: the content path
// is OTLP/HTTP only (spec 043 §4).
func checkContentReceivers(cfg map[string]any) error {
	receivers, _ := cfg["receivers"].(map[string]any)
	for id, node := range receivers {
		if !isContentReceiver(id) {
			continue
		}
		receiver, _ := node.(map[string]any)
		protocols, _ := receiver["protocols"].(map[string]any)
		if _, grpc := protocols["grpc"]; grpc {
			return fmt.Errorf("content receiver %q configures grpc; the content path is OTLP/HTTP only", id)
		}
	}
	return nil
}

// checkContentTenants refuses a fabriccontent exporter that allows more than
// one tenant without allow_multiple_tenants: true. A content record names its
// own tenant and every authenticated agent reaches the same receiver, so
// several allowed tenants let any agent write under another tenant's prefix
// (Codex r2 #1). The exporter enforces the same rule; the gate refuses it
// before the collector starts.
func checkContentTenants(cfg map[string]any) error {
	exporters, _ := cfg["exporters"].(map[string]any)
	ids := make([]string, 0, len(exporters))
	for id := range exporters {
		if componentType(id) == "fabriccontent" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		exporter, _ := exporters[id].(map[string]any)
		if len(tenantList(exporter["allowed_tenants"])) > 1 && !configTrue(exporter["allow_multiple_tenants"]) {
			return fmt.Errorf("exporter %q allows more than one tenant; run one Node per tenant, or set allow_multiple_tenants: true to trust every authenticated agent to name its tenant", id)
		}
	}
	return nil
}

// checkSharedIngressTenants enforces the single-tenant rule per Node rather
// than per exporter (H2). Every authenticated agent reaching a content
// receiver can send a record naming any tenant, and each exporter authorizes
// only the record's claim; so fabriccontent/a allowing tenant A and
// fabriccontent/b allowing tenant B behind the same receiver let an agent of
// A write under B. Exporters are grouped when they share a pipeline or a
// receiver (transitively); a group may allow more than one distinct tenant
// only when every exporter in it sets allow_multiple_tenants: true. An
// exporter in no pipeline is never instantiated and is checked only by
// checkContentTenants. The diagnostic names exporter ids, never tenant ids.
func checkSharedIngressTenants(cfg map[string]any, pipelines map[string]any) error {
	exporters, _ := cfg["exporters"].(map[string]any)
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] == x {
			return x
		}
		root := find(parent[x])
		parent[x] = root
		return root
	}
	union := func(a, b string) {
		for _, n := range []string{a, b} {
			if _, ok := parent[n]; !ok {
				parent[n] = n
			}
		}
		if ra, rb := find(a), find(b); ra != rb {
			parent[ra] = rb
		}
	}
	// Nodes are "e:<exporter>" and "r:<receiver>"; a pipeline joins its
	// fabriccontent exporters with each other and with its receivers.
	for _, node := range pipelines {
		pipeline, _ := node.(map[string]any)
		var members []string
		for _, id := range idList(pipeline["exporters"]) {
			if componentType(id) == "fabriccontent" {
				members = append(members, "e:"+id)
			}
		}
		if len(members) == 0 {
			continue
		}
		for _, id := range idList(pipeline["receivers"]) {
			members = append(members, "r:"+id)
		}
		for _, m := range members {
			union(members[0], m)
		}
	}
	groups := map[string][]string{}
	for n := range parent {
		if id, ok := strings.CutPrefix(n, "e:"); ok {
			groups[find(n)] = append(groups[find(n)], id)
		}
	}
	roots := make([]string, 0, len(groups))
	for root := range groups {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		ids := groups[root]
		sort.Strings(ids)
		tenants := map[string]bool{}
		allOptedIn := true
		for _, id := range ids {
			exporter, _ := exporters[id].(map[string]any)
			for _, tenant := range tenantList(exporter["allowed_tenants"]) {
				tenants[tenant] = true
			}
			if !configTrue(exporter["allow_multiple_tenants"]) {
				allOptedIn = false
			}
		}
		if len(tenants) > 1 && !allOptedIn {
			return fmt.Errorf("fabriccontent exporters %s share content ingress and together allow more than one tenant; any agent reaching that receiver could write under another tenant. Run one Node per tenant, or set allow_multiple_tenants: true on every one of them", strings.Join(ids, ", "))
		}
	}
	return nil
}

// tenantList returns the allowed_tenants values as the collector would see
// them: a scalar (e.g. one env reference) is expanded and read as YAML, and
// each list entry is env-expanded.
func tenantList(v any) []string {
	if s, ok := v.(string); ok {
		var parsed any
		if err := yaml.Unmarshal([]byte(expandEnvRefs(s)), &parsed); err != nil || parsed == nil {
			return []string{expandEnvRefs(s)}
		}
		v = parsed
	}
	items, ok := v.([]any)
	if !ok {
		if v == nil {
			return nil
		}
		items = []any{v}
	}
	tenants := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			tenants = append(tenants, strings.TrimSpace(expandEnvRefs(s)))
			continue
		}
		tenants = append(tenants, fmt.Sprint(item))
	}
	return tenants
}

// otlpExporterTypes are the OTLP exporter type names (current and legacy
// spellings) whose endpoints the gate checks.
var otlpExporterTypes = map[string]bool{"otlp": true, "otlp_grpc": true, "otlphttp": true, "otlp_http": true}

// otlpEndpointFields are the URL-valued fields of the OTLP exporters.
var otlpEndpointFields = []string{"endpoint", "traces_endpoint", "logs_endpoint", "metrics_endpoint", "profiles_endpoint"}

// checkExporterEndpoints refuses a credential- or query-bearing endpoint on
// any OTLP exporter and on a fabriccontent S3 endpoint (Sol deployment #2).
// A pasted https://user:secret@host or ?token=... URL would put the secret
// in the rendered ConfigMap and in every component that logs the endpoint;
// authorization belongs in Secret-backed headers. Values are env-expanded the
// way the collector resolves them. The diagnostic names the exporter and the
// field only: the URL itself is never echoed.
func checkExporterEndpoints(cfg map[string]any) error {
	exporters, _ := cfg["exporters"].(map[string]any)
	ids := make([]string, 0, len(exporters))
	for id := range exporters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		exporter, _ := exporters[id].(map[string]any)
		switch typ := componentType(id); {
		case otlpExporterTypes[typ]:
			for _, field := range otlpEndpointFields {
				if unsafeEndpoint(exporter[field]) {
					return fmt.Errorf("exporter %q %s must not contain user info, a query or a fragment; put credentials in Secret-backed headers", id, field)
				}
			}
		case typ == "fabriccontent":
			s3, _ := exporter["s3"].(map[string]any)
			if unsafeEndpoint(s3["endpoint"]) {
				return fmt.Errorf("exporter %q s3.endpoint must not contain user info, a query or a fragment; S3 credentials come from the AWS credential chain", id)
			}
		}
	}
	return nil
}

// unsafeEndpoint reports whether an endpoint value (after env expansion)
// carries user info ('@' in the authority), a query ('?') or a fragment
// ('#'). It works on host:port gRPC endpoints without a scheme as well as on
// URLs, and does not depend on the value parsing as a URL.
func unsafeEndpoint(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	s = strings.TrimSpace(expandEnvRefs(s))
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, "?#") {
		return true
	}
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	authority, _, _ := strings.Cut(s, "/")
	return strings.Contains(authority, "@")
}

// configTrue: a YAML true, or a string (after env expansion) reading true.
func configTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(expandEnvRefs(t)), "true")
	default:
		return false
	}
}

// inertAfterGuard are the only processor types allowed after fabricguard:
// they neither add nor rewrite record content. Anything else placed after the
// guard (attributes, resource, transform, k8sattributes...) could re-introduce
// values the allowlist removed, e.g. client metadata or auth context.
var inertAfterGuard = map[string]bool{"batch": true, "memory_limiter": true}

// checkGuarded requires a fabricguard processor in the pipeline's own
// processor list, followed only by inert processors, so every record passes
// the guard before any exporter sees it.
func checkGuarded(pipeline string, processors []any) error {
	guarded := false
	for _, p := range processors {
		id, _ := p.(string)
		typ, _, _ := strings.Cut(id, "/")
		switch {
		case typ == "fabricguard":
			guarded = true
		case guarded && !inertAfterGuard[typ]:
			return fmt.Errorf("pipeline %q runs processor %q after fabricguard; only batch and memory_limiter may follow the guard", pipeline, id)
		}
	}
	if !guarded {
		return fmt.Errorf("pipeline %q does not run fabricguard; every traces and logs pipeline must include it before export", pipeline)
	}
	return nil
}

// checkBearerTokenAuth enforces safe configuration on every bearertokenauth
// extension. The pinned extension (v0.150.0) splits token files on newlines
// and retains empty entries after trimming, so blank lines or a trailing
// newline mint an empty "Bearer " credential that gRPC metadata preserves
// verbatim — an auth bypass. File checks mirror preflight-prod.sh so a
// format rejected there is also rejected here, inside the image.
func checkBearerTokenAuth(cfg map[string]any) ([]tokenFile, error) {
	var watched []tokenFile
	extensions, _ := cfg["extensions"].(map[string]any)
	for name, node := range extensions {
		if name != "bearertokenauth" && !strings.HasPrefix(name, "bearertokenauth/") {
			continue
		}
		ext, _ := node.(map[string]any)
		if ext == nil {
			return nil, fmt.Errorf("extension %q has no usable configuration", name)
		}
		filename, _ := ext["filename"].(string)
		tokens, _ := ext["tokens"].([]any)
		if filename == "" && len(tokens) == 0 {
			return nil, fmt.Errorf("extension %q sets neither filename nor tokens; it would fail collector startup anyway", name)
		}
		if filename != "" {
			path := expandEnvRefs(filename)
			if err := checkTokenFile(name, path); err != nil {
				return nil, err
			}
			watched = append(watched, tokenFile{extension: name, path: path})
		}
		for i, t := range tokens {
			s, _ := t.(string)
			if strings.TrimSpace(expandEnvRefs(s)) == "" {
				return nil, fmt.Errorf("extension %q tokens[%d] is empty; an empty token mints a \"Bearer \" credential", name, i)
			}
		}
	}
	return watched, nil
}

// checkTokenFile applies the same format rules as preflight-prod.sh: the
// file must exist, be non-empty, contain no whitespace-only lines, and must
// not end with a newline (a trailing newline produces the trailing empty
// entry the extension turns into a credential).
func checkTokenFile(extension, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("extension %q token file %q: %w", extension, path, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("extension %q token file %q is empty", extension, path)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			return fmt.Errorf("extension %q token file %q contains a blank line; an empty \"Bearer \" credential would authenticate", extension, path)
		}
	}
	if data[len(data)-1] == '\n' {
		return fmt.Errorf("extension %q token file %q ends with a newline; an empty \"Bearer \" credential would authenticate (rewrite with printf %%s, not echo)", extension, path)
	}
	return nil
}

// expandEnvRefs resolves collector-style environment references in config
// values: ${env:NAME}, ${env:NAME:-default}, ${NAME:-default}, ${NAME}, and
// $NAME. An unset variable without a default expands to empty, which the
// callers treat as a failure rather than a skipped check.
func expandEnvRefs(s string) string {
	return os.Expand(s, func(key string) string {
		key = strings.TrimPrefix(key, "env:")
		name, def, hasDef := strings.Cut(key, ":-")
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		if hasDef {
			return def
		}
		return ""
	})
}
