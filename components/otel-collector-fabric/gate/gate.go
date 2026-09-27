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
	return checkBearerTokenAuth(merged)
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
