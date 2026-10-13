// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

// The Go rule reproduces every shared H4 vector, including custom allowlists,
// and its built-in lists equal the fixture's (so the SDK and the Node cannot
// drift apart silently).
func TestModelRule_SharedFixtureVectors(t *testing.T) {
	v := loadModelVectors(t)
	if !slices.Equal(v.DefaultAllowlist, defaultModelAllowlist) {
		t.Errorf("default allowlist drifted from the fixture:\n go:      %v\n fixture: %v", defaultModelAllowlist, v.DefaultAllowlist)
	}
	words := make([]string, 0, len(modelSuffixWords))
	for w := range modelSuffixWords {
		words = append(words, w)
	}
	sort.Strings(words)
	fixtureWords := slices.Clone(v.SuffixWords)
	sort.Strings(fixtureWords)
	if !slices.Equal(words, fixtureWords) {
		t.Errorf("suffix vocabulary drifted from the fixture:\n go:      %v\n fixture: %v", words, fixtureWords)
	}
	for _, tc := range v.Cases {
		if got := modelAllowed(tc.Value, tc.Allowlist); got != tc.Allowed {
			t.Errorf("%s: modelAllowed(%q) = %v, want %v", tc.Name, tc.Value, got, tc.Allowed)
		}
		if got := exposeModel(tc.Value, tc.Allowlist); got != tc.Exposed {
			t.Errorf("%s: exposeModel(%q) = %q, want %q", tc.Name, tc.Value, got, tc.Exposed)
		}
	}
}

// capture_model_allowlist reaches the processor: custom-allowlist vectors
// are exposed exactly as the fixture says.
func TestModelRule_ConfiguredAllowlistInProcessor(t *testing.T) {
	v := loadModelVectors(t)
	checked := 0
	for _, tc := range v.Cases {
		if len(tc.Allowlist) == 0 || !validModelName(tc.Value) {
			continue
		}
		checked++
		cfg := createDefaultConfig()
		cfg.CaptureModelAllowlist = tc.Allowlist
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: %v", tc.Name, err)
		}
		attrs := wireExchangeAttrs()
		attrs["gen_ai.response.model"] = tc.Value
		span := processOne(t, newTestGuard(t, cfg), "native", attrs)
		if got, _ := span.Attributes().Get("gen_ai.response.model"); got.Str() != tc.Exposed {
			t.Errorf("%s: exposed %q, want %q", tc.Name, got.Str(), tc.Exposed)
		}
	}
	if checked == 0 {
		t.Fatal("no custom-allowlist vectors checked")
	}
}

func TestConfig_CaptureModelAllowlistValidated(t *testing.T) {
	for _, bad := range [][]string{{"*"}, {""}, {" gpt-*"}, {"https://x/*"}, {"acme model"}, {"ok-1", "a@b"}} {
		cfg := createDefaultConfig()
		cfg.CaptureModelAllowlist = bad
		err := cfg.Validate()
		if err == nil {
			t.Errorf("capture_model_allowlist %q accepted", bad)
			continue
		}
		for _, entry := range bad {
			if entry != "" && entry != "*" && strings.Contains(err.Error(), entry) {
				t.Errorf("diagnostic echoes the entry: %v", err)
			}
		}
	}
	cfg := createDefaultConfig()
	cfg.CaptureModelAllowlist = []string{"acme-chat-v1", "acme-*", "ft:gpt-4o:acme::*"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid allowlist rejected: %v", err)
	}
}
