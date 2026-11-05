// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// v0.11.1 (UAT): FABRIC_CONTENT_BACKEND=file with ingress groups ran the Node
// telemetry-only without a word when preflight was bypassed (the groups
// profile has an S3 content exporter only). The gate now refuses a Node whose
// requested content backend no fabriccontent exporter provides.
func TestRequestedContentBackendMustBeConfigured(t *testing.T) {
	root := tokenTree(t)
	groups := golden(t, "valid/agent-ebpf-auditd.yaml", root) // the agent group's S3 content
	t.Run("groups with s3 content, file requested", func(t *testing.T) {
		t.Setenv("FABRIC_CONTENT_BACKEND", "file")
		_, err := runGate(t, groups)
		if err == nil || !strings.Contains(err.Error(), "would record telemetry only") {
			t.Fatalf("FABRIC_CONTENT_BACKEND=file with ingress groups accepted: %v", err)
		}
		if strings.Contains(err.Error(), root) {
			t.Fatalf("diagnostic echoes a path: %v", err)
		}
	})
	for _, backend := range []string{"s3", ""} {
		t.Run("groups with s3 content, requested "+backend, func(t *testing.T) {
			t.Setenv("FABRIC_CONTENT_BACKEND", backend)
			if _, err := runGate(t, groups); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	t.Run("unknown value", func(t *testing.T) {
		t.Setenv("FABRIC_CONTENT_BACKEND", "gcs")
		if _, err := runGate(t, groups); err == nil || !strings.Contains(err.Error(), "must be s3 or file") {
			t.Fatalf("unknown backend accepted: %v", err)
		}
	})
	// The shipped groups configuration without its content overlay: telemetry only.
	shipped := loadYAML(t, composeConfigDir+"collector-production-groups.yaml")
	for _, backend := range []string{"file", "s3"} {
		t.Setenv("FABRIC_CONTENT_BACKEND", backend)
		if err := checkRequestedContent(shipped); err == nil {
			t.Fatalf("FABRIC_CONTENT_BACKEND=%s without the content overlay accepted", backend)
		}
	}
}

func TestRequestedContentBackendMatchesTheExporter(t *testing.T) {
	file := contentConfig + "exporters:\n  fabriccontent:\n    allowed_tenants: [tenant-a]\n" +
		"    backend: file\n    file:\n      directory: /var/lib/fabric-node/content\n"
	t.Setenv("FABRIC_CONTENT_BACKEND", "file")
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, file)}); err != nil {
		t.Fatalf("file backend requested and configured, refused: %v", err)
	}
	t.Setenv("FABRIC_CONTENT_BACKEND", "s3")
	if _, err := validateArgs([]string{"--config=" + writeConfig(t, file)}); err == nil ||
		!strings.Contains(err.Error(), "no fabriccontent exporter with backend s3") {
		t.Fatalf("s3 requested with only a file exporter accepted: %v", err)
	}
}
