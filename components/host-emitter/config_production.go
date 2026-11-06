// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// version is the capture point version (host.ebpf@<version>); release
// builds set it with -ldflags "-X main.version=...".
var version = "0.11.1"

// Production scope limits (spec 056 §7.3.3 (c)).
const (
	maxStaticRoots = 8
	maxPodRoots    = 64
	// minHeartbeat and maxHeartbeat bound EMIT_HEARTBEAT_INTERVAL.
	minHeartbeat     = time.Second
	maxHeartbeat     = 60 * time.Second
	defaultHeartbeat = 10 * time.Second
)

// Scope values shared with bpf/emit.bpf.c.
const (
	scopeNone    = 0
	scopeAgent   = 1
	scopeSandbox = 2
)

// scopeRoot is one static cgroup root and the scope it admits.
type scopeRoot struct {
	path  string
	scope uint32
}

// staticRoots lists the configured agent roots, then the sandbox roots.
func (c *Config) staticRoots() []scopeRoot {
	roots := make([]scopeRoot, 0, len(c.AgentCgroupRoots)+len(c.SandboxCgroupRoots))
	for _, p := range c.AgentCgroupRoots {
		roots = append(roots, scopeRoot{path: p, scope: scopeAgent})
	}
	for _, p := range c.SandboxCgroupRoots {
		roots = append(roots, scopeRoot{path: p, scope: scopeSandbox})
	}
	return roots
}

// eventClasses is the manifest's list of enabled event classes.
func (c *Config) eventClasses() []string {
	var classes []string
	if c.Exec {
		classes = append(classes, "exec")
	}
	if c.Connect {
		classes = append(classes, "connect")
	}
	if c.FileAccess {
		classes = append(classes, "file")
	}
	return classes
}

// splitList parses a comma-separated environment list; empty items are
// refused rather than skipped.
func splitList(name, value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("%s has an empty item", name)
		}
		out = append(out, p)
	}
	return out, nil
}

// loadProductionConfig reads the production settings. Parse errors are kept
// on the configuration and reported by Validate: a mistyped production
// switch must never fall back to a default silently.
func (c *Config) loadProductionConfig() {
	fail := func(err error) { c.loadErrs = append(c.loadErrs, err) }
	if v := os.Getenv("EMIT_PRODUCTION"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			fail(fmt.Errorf("EMIT_PRODUCTION must be true or false"))
		}
		c.Production = b
	}
	c.TenantID = os.Getenv("EMIT_TENANT_ID")
	c.SourceLabel = os.Getenv("EMIT_SOURCE_LABEL")
	c.HostLabel = os.Getenv("EMIT_HOST_LABEL")
	c.IDKeyFile = os.Getenv("EMIT_ID_KEY_FILE")
	c.StateKeyFile = os.Getenv("EMIT_STATE_KEY_FILE")
	c.StateDir = os.Getenv("EMIT_STATE_DIR")
	c.AgentPodSelector = os.Getenv("EMIT_AGENT_POD_SELECTOR")
	c.NodeName = os.Getenv("EMIT_NODE_NAME")
	c.EndpointFile = os.Getenv("EMIT_ENDPOINT_FILE")
	var err error
	if c.AgentCgroupRoots, err = splitList("EMIT_AGENT_CGROUP_ROOTS", os.Getenv("EMIT_AGENT_CGROUP_ROOTS")); err != nil {
		fail(err)
	}
	if c.SandboxCgroupRoots, err = splitList("EMIT_SANDBOX_CGROUP_ROOTS", os.Getenv("EMIT_SANDBOX_CGROUP_ROOTS")); err != nil {
		fail(err)
	}
	c.Digests = os.Getenv("EMIT_DIGESTS")
	if c.Digests == "" {
		c.Digests = "omitted"
	}
	c.HeartbeatInterval = defaultHeartbeat
	if v := os.Getenv("EMIT_HEARTBEAT_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			fail(fmt.Errorf("EMIT_HEARTBEAT_INTERVAL is not a duration"))
		}
		c.HeartbeatInterval = d
	}
	if c.CgroupRoot == "" {
		c.CgroupRoot = "/sys/fs/cgroup"
	}
}

var (
	// Kubernetes label selector terms: key=value, as kubectl -l takes them.
	labelNamePattern  = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
	labelValuePattern = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)
	dnsSubdomain      = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`)
)

// parseSelector parses EMIT_AGENT_POD_SELECTOR into its equality terms.
func parseSelector(sel string) (map[string]string, error) {
	terms := make(map[string]string)
	for _, term := range strings.Split(sel, ",") {
		key, value, ok := strings.Cut(term, "=")
		if !ok || strings.ContainsAny(value, "=!") || strings.HasSuffix(key, "!") {
			return nil, fmt.Errorf("EMIT_AGENT_POD_SELECTOR terms must be key=value")
		}
		name := key
		if prefix, rest, hasPrefix := strings.Cut(key, "/"); hasPrefix {
			if len(prefix) > 253 || !dnsSubdomain.MatchString(prefix) {
				return nil, fmt.Errorf("EMIT_AGENT_POD_SELECTOR has an invalid label key prefix")
			}
			name = rest
		}
		if !labelNamePattern.MatchString(name) || !labelValuePattern.MatchString(value) {
			return nil, fmt.Errorf("EMIT_AGENT_POD_SELECTOR has an invalid label key or value")
		}
		if _, dup := terms[key]; dup {
			return nil, fmt.Errorf("EMIT_AGENT_POD_SELECTOR repeats a label key")
		}
		terms[key] = value
	}
	return terms, nil
}

// validateRoots checks one root list: at most eight existing, absolute
// directories below the hierarchy root, none repeated.
func validateRoots(name string, roots []string, hierarchy string, seen map[string]string) error {
	if len(roots) > maxStaticRoots {
		return fmt.Errorf("%s holds %d roots; at most %d are allowed", name, len(roots), maxStaticRoots)
	}
	for _, root := range roots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return fmt.Errorf("%s: %q must be an absolute, clean cgroup v2 directory", name, root)
		}
		// The BPF walk starts at level 1: the hierarchy root is never a root;
		// whole-host scope is the explicit EMIT_ALL_HOST.
		if hierarchy != "" && root == filepath.Clean(hierarchy) {
			return fmt.Errorf("%s: the cgroup hierarchy root is not a scope root; use EMIT_ALL_HOST=true", name)
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("%s: cgroup directory %q must exist at start", name, root)
		}
		if other, dup := seen[root]; dup {
			return fmt.Errorf("%s: %q is already a root in %s", name, root, other)
		}
		seen[root] = name
	}
	return nil
}

// validateProduction enforces 053 §6.2.9 and 056 §7.3.3 (c).
func (c *Config) validateProduction() error {
	if c.CgroupPath != "" {
		return fmt.Errorf("EMIT_CGROUP_PATH is local mode only: an exact cgroup cannot scope a pod; set EMIT_AGENT_CGROUP_ROOTS (or EMIT_AGENT_POD_SELECTOR) instead")
	}
	for _, req := range []struct{ name, value string }{
		{"EMIT_TENANT_ID", c.TenantID},
		{"EMIT_SOURCE_LABEL", c.SourceLabel},
		{"EMIT_HOST_LABEL", c.HostLabel},
		{"EMIT_ID_KEY_FILE", c.IDKeyFile},
		{"EMIT_STATE_KEY_FILE", c.StateKeyFile},
		{"EMIT_STATE_DIR", c.StateDir},
	} {
		if req.value == "" {
			return fmt.Errorf("%s is required in production mode", req.name)
		}
	}
	if c.Endpoint == "" && c.EndpointFile == "" {
		return fmt.Errorf("EMIT_ENDPOINT or EMIT_ENDPOINT_FILE is required in production mode")
	}
	if c.DedupeWindow != 0 {
		return fmt.Errorf("EMIT_DEDUPE_WINDOW must be 0 in production mode: every event keeps its own position")
	}
	if c.Digests != "omitted" && c.Digests != "permitted" {
		return fmt.Errorf("EMIT_DIGESTS must be omitted or permitted")
	}
	if c.HeartbeatInterval < minHeartbeat || c.HeartbeatInterval > maxHeartbeat {
		return fmt.Errorf("EMIT_HEARTBEAT_INTERVAL must be between 1s and 60s")
	}
	seen := make(map[string]string)
	if err := validateRoots("EMIT_AGENT_CGROUP_ROOTS", c.AgentCgroupRoots, c.CgroupRoot, seen); err != nil {
		return err
	}
	if err := validateRoots("EMIT_SANDBOX_CGROUP_ROOTS", c.SandboxCgroupRoots, c.CgroupRoot, seen); err != nil {
		return err
	}
	if c.AgentPodSelector != "" {
		if _, err := parseSelector(c.AgentPodSelector); err != nil {
			return err
		}
		if c.NodeName == "" || len(c.NodeName) > 253 || !dnsSubdomain.MatchString(c.NodeName) {
			return fmt.Errorf("EMIT_NODE_NAME (spec.nodeName) is required with EMIT_AGENT_POD_SELECTOR")
		}
	} else if c.NodeName != "" {
		return fmt.Errorf("EMIT_NODE_NAME is used only with EMIT_AGENT_POD_SELECTOR")
	}
	if len(c.AgentCgroupRoots) == 0 && c.AgentPodSelector == "" && !c.AllHost {
		return fmt.Errorf("production needs EMIT_AGENT_CGROUP_ROOTS, EMIT_AGENT_POD_SELECTOR or an explicit EMIT_ALL_HOST=true")
	}
	return nil
}

// readEndpointFile reads EMIT_ENDPOINT_FILE: exactly one line host:port.
func readEndpointFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("EMIT_ENDPOINT_FILE: %w", err)
	}
	line := strings.TrimSuffix(string(data), "\n")
	line = strings.TrimSuffix(line, "\r")
	if line == "" || strings.ContainsAny(line, "\r\n \t") {
		return "", fmt.Errorf("EMIT_ENDPOINT_FILE must hold one line host:port")
	}
	host, port, err := net.SplitHostPort(line)
	if err != nil || host == "" {
		return "", fmt.Errorf("EMIT_ENDPOINT_FILE must hold one line host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("EMIT_ENDPOINT_FILE has an invalid port")
	}
	return line, nil
}

// resolveEndpoint applies EMIT_ENDPOINT_FILE and the production transport
// rule. It runs after Validate and before any connection.
func (c *Config) resolveEndpoint() error {
	if c.EndpointFile != "" {
		endpoint, err := readEndpointFile(c.EndpointFile)
		if err != nil {
			return err
		}
		c.Endpoint = endpoint
	}
	if c.Production && c.Insecure && !loopbackEndpoint(c.Endpoint) {
		return fmt.Errorf("EMIT_INSECURE=true is refused in production mode for a non-loopback endpoint")
	}
	return nil
}

// loopbackEndpoint reports whether host:port names a loopback address.
func loopbackEndpoint(endpoint string) bool {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
