// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// H3: a caller-supplied run id leaves the SDK only as its pseudonym
// r-<32 hex>; generated fallbacks keep their forms (trace:<32 hex>,
// source:<source id>:<epoch>, or h-<40 hex> when that is too long). The Node
// admits exactly these forms for fabric.run.id, so a clear caller id
// ("patient-Jane-Doe-12345") from a non-conforming or old sender is dropped.
func TestCaptureRunID_OnlyPseudonymAndFallbackForms(t *testing.T) {
	good := []string{
		"r-0123456789abcdef0123456789abcdef",
		"trace:0af7651916cd43dd8448eb211c80319c",
		"source:wire-0123456789abcdef:1759800000000000000",
		"source:h-0123456789abcdef0123456789abcdef01234567:1759800000000000000",
		"h-0123456789abcdef0123456789abcdef01234567",
	}
	bad := []any{
		"patient-Jane-Doe-12345",
		"run-1",
		"run-travel-42",
		"r-0123456789ABCDEF0123456789ABCDEF",  // uppercase
		"r-0123456789abcdef0123456789abcde",   // 31 hex
		"r-0123456789abcdef0123456789abcdef0", // 33 hex
		"trace:0af7651916cd43dd8448eb211c80319",
		"trace:patient-jane",
		"source:wire-1:not-an-epoch",
		"source::1",
		"h-0123",
		"", int64(1),
	}
	for _, attrs := range []func() map[string]any{wireExchangeAttrs, wireHeartbeatAttrs} {
		for _, id := range good {
			a := attrs()
			a["fabric.run.id"] = id
			span := processOne(t, newTestGuard(t, nil), "native", a)
			if got, ok := span.Attributes().Get("fabric.run.id"); !ok || got.Str() != id {
				t.Errorf("valid run id %q removed or changed", id)
			}
		}
		for i, id := range bad {
			a := attrs()
			a["fabric.run.id"] = id
			span := processOne(t, newTestGuard(t, nil), "native", a)
			if v, ok := span.Attributes().Get("fabric.run.id"); ok {
				t.Errorf("clear or malformed run id bad[%d] survived as %q", i, v.AsString())
			}
			if _, ok := span.Attributes().Get("fabric.source_id"); !ok {
				t.Errorf("bad[%d]: unrelated source id removed", i)
			}
		}
	}
	// Outside capture spans the key stays value-closed by the same rule.
	span := processOne(t, newTestGuard(t, nil), "chat model-a", map[string]any{
		"gen_ai.request.model": "model-a",
		"fabric.run.id":        "patient-Jane-Doe-12345",
	})
	if _, ok := span.Attributes().Get("fabric.run.id"); ok {
		t.Error("clear run id survived on a non-capture span")
	}
}

// modelVectors is the shared H4 fixture, also used by the Python SDK tests.
type modelVectors struct {
	SchemaVersion    string   `json:"schema_version"`
	DefaultAllowlist []string `json:"default_allowlist"`
	SuffixWords      []string `json:"suffix_words"`
	Cases            []struct {
		Name      string   `json:"name"`
		Value     string   `json:"value"`
		Allowlist []string `json:"allowlist"`
		Allowed   bool     `json:"allowed"`
		Exposed   string   `json:"exposed"`
	} `json:"cases"`
}

const modelFixture = "../../../../contracts/capture/v1/fixtures/model-names/model-exposure-v1.json"

func loadModelVectors(t *testing.T) modelVectors {
	t.Helper()
	raw, err := os.ReadFile(modelFixture)
	if err != nil {
		t.Fatalf("shared model fixture: %v", err)
	}
	var v modelVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.SchemaVersion != "fabric.model-exposure-vectors/v1" || len(v.Cases) == 0 {
		t.Fatalf("unexpected fixture shape: %q, %d cases", v.SchemaVersion, len(v.Cases))
	}
	return v
}

var nodeModelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// H4 (Sol data-exposure #4): a model value under a default prefix is kept
// only when its suffix is version tokens; "gpt-patient-Jane-Doe-12345" is
// pseudonymized to the same m-<16 hex> the SDK emits. Every fixture case with
// the default allowlist is checked end to end through the processor. A value
// outside the 042 pattern (or with "://") is never admitted at the Node: it is
// dropped, which is stricter than hashing, and a conforming SDK never sends
// one (it sends the m- form).
func TestCaptureModel_DefaultAllowlistMatchesSharedFixture(t *testing.T) {
	v := loadModelVectors(t)
	checked := 0
	for _, tc := range v.Cases {
		if len(tc.Allowlist) != 0 {
			continue
		}
		checked++
		attrs := wireExchangeAttrs()
		attrs["gen_ai.response.model"] = tc.Value
		span := processOne(t, newTestGuard(t, nil), "native", attrs)
		got, ok := span.Attributes().Get("gen_ai.response.model")
		if !nodeModelPattern.MatchString(tc.Value) || regexp.MustCompile(`://`).MatchString(tc.Value) {
			if ok {
				t.Errorf("%s: invalid model admitted as %q", tc.Name, got.Str())
			}
			continue
		}
		if !ok || got.Str() != tc.Exposed {
			t.Errorf("%s: model exposed as %q (present %v), want %q", tc.Name, got.Str(), ok, tc.Exposed)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d default-allowlist cases checked", checked)
	}
	// The SDK's pseudonym passes the Node unchanged (never double-hashed).
	attrs := wireExchangeAttrs()
	attrs["gen_ai.response.model"] = "m-1f1cb55a1556d0bd"
	span := processOne(t, newTestGuard(t, nil), "native", attrs)
	if got, _ := span.Attributes().Get("gen_ai.response.model"); got.Str() != "m-1f1cb55a1556d0bd" {
		t.Errorf("m- form changed to %q", got.Str())
	}
}

// The Sol probe values: run id and model must not retain the identifying
// value. service.name and fabric.source_id are operator-chosen labels (H3:
// documented as must-be-opaque, validated by pattern only) and are not
// rewritten here.
func TestCaptureIdentity_SolProbeValuesScrubbed(t *testing.T) {
	const identifying = "patient-Jane-Doe-12345"
	attrs := wireExchangeAttrs()
	attrs["fabric.run.id"] = identifying
	attrs["gen_ai.response.model"] = "gpt-" + identifying
	span := processOne(t, newTestGuard(t, nil), "fabric.model_call", attrs)
	if _, ok := span.Attributes().Get("fabric.run.id"); ok {
		t.Error("identifying run id survived")
	}
	if got, _ := span.Attributes().Get("gen_ai.response.model"); got.Str() != "m-1f1cb55a1556d0bd" {
		t.Errorf("identifying model exposed as %q", got.Str())
	}
}
