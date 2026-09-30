// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
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
	dedicated bool
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
	if err := checkExporterHeaders(merged); err != nil {
		return nil, err
	}
	knownTokens, err := checkBearerTokenAuth(merged)
	if err != nil {
		return nil, err
	}
	if err := checkDedicatedEvidenceIngress(merged, knownTokens); err != nil {
		return nil, err
	}
	return knownTokens, nil
}

// A bound source is supported only behind one authenticated OTLP ingress.
// The bearer extension authenticates possession but returns no identity in
// client.Auth, so this gate establishes the one-credential-to-one-source
// deployment mapping. This does not prove exclusive credential ownership.
func checkDedicatedEvidenceIngress(cfg map[string]any, watched []tokenFile) error {
	processors, _ := cfg["processors"].(map[string]any)
	bound := false
	for name, node := range processors {
		processor, _ := node.(map[string]any)
		if _, ok := processor["evidence_source_binding"]; ok {
			if name != "fabricguard" {
				return fmt.Errorf("dedicated evidence ingress requires the fabricguard processor")
			}
			identity, ok := processor["evidence_source_binding"].(map[string]any)
			if !ok || !safeEvidenceIdentity(identity["tenant_id"]) || !safeEvidenceIdentity(identity["source_id"]) {
				return fmt.Errorf("dedicated evidence ingress requires valid tenant and source identities")
			}
			bound = true
		}
	}
	if !bound {
		return nil
	}
	const authName = "bearertokenauth/evidence_source"
	extensions, _ := cfg["extensions"].(map[string]any)
	auth, ok := extensions[authName].(map[string]any)
	if !ok {
		return fmt.Errorf("dedicated evidence ingress requires its bearer authenticator")
	}
	filename, ok := auth["filename"].(string)
	if !ok || filename == "" {
		return fmt.Errorf("dedicated evidence ingress requires a token file")
	}
	if _, inline := auth["tokens"]; inline {
		return fmt.Errorf("dedicated evidence ingress forbids inline or additional tokens")
	}
	if auth["require_single_token"] != true {
		return fmt.Errorf("dedicated evidence ingress requires fail-closed singleton token reload")
	}
	path := expandEnvRefs(filename)
	if err := checkDedicatedTokenFile(path); err != nil {
		return err
	}
	marked := false
	for i := range watched {
		if watched[i].extension == authName && watched[i].path == path {
			watched[i].dedicated = true
			marked = true
		}
	}
	if !marked {
		return fmt.Errorf("dedicated evidence ingress token is not watched")
	}
	service, _ := cfg["service"].(map[string]any)
	activeExtensions, _ := service["extensions"].([]any)
	if !onlyContains(activeExtensions, authName) {
		return fmt.Errorf("dedicated evidence ingress authenticator is not active")
	}
	receivers, _ := cfg["receivers"].(map[string]any)
	otlp, ok := receivers["otlp"].(map[string]any)
	if !ok || len(receivers) != 1 {
		return fmt.Errorf("dedicated evidence ingress requires sole OTLP receiver")
	}
	protocols, _ := otlp["protocols"].(map[string]any)
	if len(protocols) != 2 {
		return fmt.Errorf("dedicated evidence ingress requires HTTP and gRPC")
	}
	for _, protocol := range []string{"grpc", "http"} {
		settings, ok := protocols[protocol].(map[string]any)
		if !ok {
			return fmt.Errorf("dedicated evidence ingress requires authenticated HTTP and gRPC")
		}
		authSettings, _ := settings["auth"].(map[string]any)
		if authSettings["authenticator"] != authName {
			return fmt.Errorf("dedicated evidence ingress requires bearer authentication on both protocols")
		}
		tls, _ := settings["tls"].(map[string]any)
		cert, certOK := tls["cert_file"].(string)
		key, keyOK := tls["key_file"].(string)
		if !certOK || !keyOK || expandEnvRefs(cert) == "" || expandEnvRefs(key) == "" || tls["insecure"] == true {
			return fmt.Errorf("dedicated evidence ingress requires receiver TLS on both protocols")
		}
	}
	pipelines, _ := service["pipelines"].(map[string]any)
	if len(pipelines) != 2 {
		return fmt.Errorf("dedicated evidence ingress requires only logs and traces pipelines")
	}
	for _, signal := range []string{"logs", "traces"} {
		pipeline, ok := pipelines[signal].(map[string]any)
		if !ok || !exactStringList(pipeline["receivers"], []string{"otlp"}) || !exactStringList(pipeline["exporters"], []string{"otlp_http/fabric"}) {
			return fmt.Errorf("dedicated evidence ingress has an unapproved pipeline route")
		}
		steps, ok := stringList(pipeline["processors"])
		if !ok || !approvedEvidenceProcessors(steps) {
			return fmt.Errorf("dedicated evidence ingress requires guard before batching")
		}
	}
	exporters, _ := cfg["exporters"].(map[string]any)
	exporter, ok := exporters["otlp_http/fabric"].(map[string]any)
	if !ok || len(exporters) != 1 {
		return fmt.Errorf("dedicated evidence ingress requires one approved OTLP exporter")
	}
	endpoint, _ := exporter["endpoint"].(string)
	tls, _ := exporter["tls"].(map[string]any)
	if !strings.HasPrefix(expandEnvRefs(endpoint), "https://") || tls["insecure"] == true || tls["insecure_skip_verify"] == true {
		return fmt.Errorf("dedicated evidence ingress requires verified HTTPS export")
	}
	return nil
}

func safeEvidenceIdentity(raw any) bool {
	s, ok := raw.(string)
	if !ok || len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || i > 0 && (r == '.' || r == '_' || r == ':' || r == '-') {
			continue
		}
		return false
	}
	return true
}

func stringList(raw any) ([]string, bool) {
	items, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, len(items))
	for i, item := range items {
		value, ok := item.(string)
		if !ok {
			return nil, false
		}
		result[i] = value
	}
	return result, true
}

func exactStringList(raw any, expected []string) bool {
	actual, ok := stringList(raw)
	if !ok || len(actual) != len(expected) {
		return false
	}
	for i := range expected {
		if actual[i] != expected[i] {
			return false
		}
	}
	return true
}

func onlyContains(raw []any, wanted string) bool {
	for _, item := range raw {
		if item == wanted {
			return true
		}
	}
	return false
}

func approvedEvidenceProcessors(steps []string) bool {
	if len(steps) < 1 || len(steps) > 3 {
		return false
	}
	guardIndex := -1
	for i, step := range steps {
		switch step {
		case "memory_limiter":
			if i != 0 {
				return false
			}
		case "fabricguard":
			if guardIndex != -1 {
				return false
			}
			guardIndex = i
		case "batch":
			if i != len(steps)-1 {
				return false
			}
		default:
			return false
		}
	}
	return guardIndex >= 0 && (len(steps) == 1 || steps[len(steps)-1] != "batch" || guardIndex < len(steps)-1)
}

func checkDedicatedTokenFile(path string) error {
	if err := checkTokenFile("bearertokenauth/evidence_source", path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o027 != 0 {
		return fmt.Errorf("dedicated evidence ingress token file permissions are unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 32 || len(data) > 4096 {
		return fmt.Errorf("dedicated evidence ingress token file length is invalid")
	}
	for _, b := range data {
		if b <= 0x20 || b >= 0x7f {
			return fmt.Errorf("dedicated evidence ingress token file format is invalid")
		}
	}
	return nil
}

// checkExporterHeaders rejects values the Go HTTP client cannot send, and
// empty/unresolved Secret references, before the Collector reports healthy.
// The diagnostic deliberately identifies only the exporter/header, never
// the credential bytes.
func checkExporterHeaders(cfg map[string]any) error {
	exporters, _ := cfg["exporters"].(map[string]any)
	for name, node := range exporters {
		exporter, _ := node.(map[string]any)
		if exporter == nil {
			continue
		}
		rawHeaders, present := exporter["headers"]
		if !present {
			continue
		}
		headers, ok := rawHeaders.(map[string]any)
		if !ok {
			return fmt.Errorf("exporter %q headers must be a map of strings", name)
		}
		for key, raw := range headers {
			value, ok := raw.(string)
			if !ok {
				return fmt.Errorf("exporter %q header %q must be a string", name, key)
			}
			value = expandEnvRefs(value)
			if value == "" || strings.TrimSpace(value) != value {
				return fmt.Errorf("exporter %q header %q is empty or has surrounding whitespace", name, key)
			}
			for i := 0; i < len(value); i++ {
				if value[i] < 0x20 || value[i] > 0x7e {
					return fmt.Errorf("exporter %q header %q contains a control or non-ASCII byte", name, key)
				}
			}
			if strings.EqualFold(key, "Authorization") &&
				strings.EqualFold(value, "Bearer") {
				return fmt.Errorf("exporter %q header %q has no credential", name, key)
			}
		}
	}
	return nil
}

// configSources collects --config values in both pflag spellings
// (--config=URI and --config URI). The collector accepts the flag multiple
// times and merges the sources, so each is validated rather than only the
// last.
func configSources(args []string) ([]string, error) {
	var sources []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
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

// checkPipelines requires every pipeline signal to be traces or logs. The
// fabricguard processor only runs inside the pipelines it is wired into, so
// a metrics or profiles pipeline would export unfiltered records past the
// allowlist.
func checkPipelines(cfg map[string]any) error {
	service, _ := cfg["service"].(map[string]any)
	pipelines, _ := service["pipelines"].(map[string]any)
	if len(pipelines) == 0 {
		return fmt.Errorf("service.pipelines defines no pipelines")
	}
	for name := range pipelines {
		signal := name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			signal = name[:i]
		}
		if signal != "traces" && signal != "logs" {
			return fmt.Errorf("pipeline %q uses signal %q; the recorder allows only traces and logs (fabricguard cannot protect other signals)", name, signal)
		}
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
