// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// Spec 049 conformance C0-4: fabricguard admits each new telemetry key with
// the validator its registry row declares and rejects free text, key by key.
// The registry (contracts/coverage/v1) is the source of truth.

const (
	coverageRegistry = "../../../../contracts/coverage/v1/registry/telemetry-keys-v1.json"
	runMarkerVectors = "../../../../contracts/coverage/v1/fixtures/vectors/run-marker-v1.json"
	manifestVectors  = "../../../../contracts/coverage/v1/fixtures/vectors/manifest-span-v1.json"
)

// coverageFreeText mirrors FREE_TEXT in scripts/contracts/validate_coverage_contracts.py.
var coverageFreeText = []string{
	"Jane Doe asked about her prescription",
	"Bearer sk-live-0123456789",
	"",
	"https://user:secret@example.com/a?b=c",
	`{"prompt": "hi"}`,
}

type registryCheck struct {
	Type       string          `json:"type"`
	Values     []any           `json:"values"`
	Value      any             `json:"value"`
	Min        *int64          `json:"min"`
	Max        *int64          `json:"max"`
	Pattern    string          `json:"pattern"`
	Examples   []any           `json:"examples"`
	Items      *registryCheck  `json:"items"`
	MaxItems   int             `json:"max_items"`
	MinItems   int             `json:"min_items"`
	Unique     bool            `json:"unique"`
	CaptureLbl json.RawMessage `json:"capture_labels"`
}

type registryKey struct {
	Key     string         `json:"key"`
	Change  string         `json:"change"`
	Owner   string         `json:"owner"`
	Check   *registryCheck `json:"check"`
	Pending string         `json:"check_pending"`
}

func decodeJSON(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(into); err != nil {
		t.Fatal(err)
	}
}

func loadCoverageKeys(t *testing.T) []registryKey {
	t.Helper()
	var doc struct {
		Keys []registryKey `json:"keys"`
	}
	decodeJSON(t, coverageRegistry, &doc)
	if len(doc.Keys) < 150 {
		t.Fatalf("registry has %d keys", len(doc.Keys))
	}
	return doc.Keys
}

// raw turns decoded JSON (json.Number) into pcommon-compatible raw values.
func raw(t *testing.T, value any) any {
	t.Helper()
	switch v := value.(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			t.Fatalf("non-integer number %v", v)
		}
		return n
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = raw(t, item)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, item := range v {
			out[k] = raw(t, item)
		}
		return out
	}
	return value
}

func valueOf(t *testing.T, value any) pcommon.Value {
	t.Helper()
	out := pcommon.NewValueEmpty()
	if err := out.FromRaw(raw(t, value)); err != nil {
		t.Fatalf("FromRaw(%v): %v", value, err)
	}
	return out
}

// admitted lists values the check must pass: enum values, consts, both
// booleans, integer bounds and the registry's examples.
func admitted(check *registryCheck) []any {
	switch check.Type {
	case "enum":
		return check.Values
	case "const":
		return []any{check.Value}
	case "bool":
		return []any{true, false}
	case "int":
		out := []any{json.Number(itoa(*check.Min))}
		if check.Max != nil {
			out = append(out, json.Number(itoa(*check.Max)))
		}
		return out
	}
	return check.Examples
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// rejected lists values the check must refuse besides free text: wrong types,
// out-of-range integers, oversized, undersized or duplicated slices.
func rejected(check *registryCheck) []any {
	out := []any{map[string]any{"a": "b"}}
	switch check.Type {
	case "enum", "string", "datetime":
		out = append(out, json.Number("7"), true, []any{"x"})
	case "const":
		switch v := check.Value.(type) {
		case bool:
			out = append(out, !v, "false")
		case string:
			out = append(out, v+"x", true)
		}
	case "bool":
		out = append(out, "true", json.Number("1"))
	case "int":
		out = append(out, "1", true, 1.5)
		if *check.Min > math.MinInt64 {
			out = append(out, json.Number(itoa(*check.Min-1)))
		}
		if check.Max != nil {
			out = append(out, json.Number(itoa(*check.Max+1)))
		}
	case "array":
		element := admitted(check.Items)[0]
		out = append(out, element)
		oversized := make([]any, check.MaxItems+1)
		for i := range oversized {
			oversized[i] = element
		}
		out = append(out, oversized, []any{"Jane Doe"})
		if check.MinItems > 0 {
			out = append(out, []any{})
		}
		if check.Unique {
			out = append(out, []any{element, element})
		}
	}
	for _, text := range coverageFreeText {
		out = append(out, text)
	}
	return out
}

func decisionSpan(key string, value pcommon.Value) ptrace.Traces {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("fabric.decision")
	span.Attributes().PutStr("fabric.decision_id", "dec-1")
	value.CopyTo(span.Attributes().PutEmpty(key))
	return td
}

func keptAs(t *testing.T, g *guard, td ptrace.Traces, key string, want pcommon.Value) bool {
	t.Helper()
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := firstSpan(out).Attributes().Get(key)
	if ok && !reflect.DeepEqual(got.AsRaw(), want.AsRaw()) {
		t.Fatalf("%s kept but changed: %v -> %v", key, want.AsRaw(), got.AsRaw())
	}
	return ok
}

// captureCarrier builds a capture span of the given class carrying key=value,
// on a heartbeat kind that defines the key.
func captureCarrier(class uint8, key string, value pcommon.Value) ptrace.Traces {
	var attrs map[string]any
	switch class {
	case onExchange:
		attrs = wireExchangeAttrs()
	case onLoss:
		attrs = wireLossAttrs()
	default:
		attrs = wireHeartbeatAttrs()
		attrs["fabric.run.scope_id"] = testScopeID
		if kinds, ok := markerKeyKinds[key]; ok {
			for _, kind := range []string{"run_start", "run_end", "segment_seal"} {
				if _, defined := kinds[kind]; defined {
					attrs["fabric.heartbeat.kind"] = kind
					break
				}
			}
		}
	}
	td := makeRawSpan("native", attrs)
	value.CopyTo(firstSpan(td).Attributes().PutEmpty(key))
	return td
}

func TestCoverageKeysMatchTheRegistryKeyByKey(t *testing.T) {
	keys := loadCoverageKeys(t)
	admittedKeys := map[string]struct{}{}
	for _, row := range keys {
		if row.Change != "new" || row.Check == nil || row.Owner == "receiver" {
			continue
		}
		admittedKeys[row.Key] = struct{}{}
	}
	if !reflect.DeepEqual(admittedKeys, coverageKeyNames()) {
		for key := range admittedKeys {
			if _, ok := coverageKeyValidators[key]; !ok {
				t.Errorf("registry admits %q; fabricguard has no validator", key)
			}
		}
		for key := range coverageKeyValidators {
			if _, ok := admittedKeys[key]; !ok {
				t.Errorf("fabricguard admits %q; the registry has no check for it", key)
			}
		}
	}
	for key := range coverageCaptureKeys {
		if _, ok := coverageKeyValidators[key]; !ok {
			t.Errorf("capture placement for unvalidated key %q", key)
		}
	}
	g := newTestGuard(t, nil)
	for _, row := range keys {
		if row.Change != "new" || row.Check == nil || row.Owner == "receiver" {
			continue
		}
		row := row
		t.Run(row.Key, func(t *testing.T) {
			validate := coverageKeyValidators[row.Key]
			if _, ok := TraceAllowedFields[row.Key]; !ok || sensitiveAttributeKey(row.Key) {
				t.Fatalf("%q is not admitted on spans", row.Key)
			}
			for _, value := range admitted(row.Check) {
				v := valueOf(t, value)
				if !validate(v) {
					t.Errorf("validator rejects registry value %v", value)
				}
				if !keptAs(t, g, decisionSpan(row.Key, v), row.Key, v) {
					t.Errorf("decision span drops registry value %v", value)
				}
				classes := coverageCaptureKeys[row.Key]
				for _, class := range []uint8{onExchange, onLoss, onHeartbeat} {
					kept := keptAs(t, g, captureCarrier(class, row.Key, v), row.Key, v)
					if want := classes&class != 0; kept != want {
						t.Errorf("capture class %d: kept=%v, want %v (value %v)", class, kept, want, value)
					}
				}
			}
			for _, value := range rejected(row.Check) {
				v := valueOf(t, value)
				if validate(v) {
					t.Errorf("validator admits %v", value)
				}
				if keptAs(t, g, decisionSpan(row.Key, v), row.Key, v) {
					t.Errorf("decision span keeps %v", value)
				}
				if keptAs(t, g, captureCarrier(onHeartbeat, row.Key, v), row.Key, v) {
					t.Errorf("heartbeat keeps %v", value)
				}
			}
		})
	}
}

func TestPendingCoverageKeysAreNotAdmitted(t *testing.T) {
	g := newTestGuard(t, nil)
	pending := 0
	for _, row := range loadCoverageKeys(t) {
		if row.Change != "new" || row.Check != nil {
			continue
		}
		pending++
		if row.Pending == "" {
			t.Errorf("%q has neither check nor check_pending", row.Key)
		}
		if _, ok := TraceAllowedFields[row.Key]; ok {
			t.Errorf("pending key %q is allowlisted", row.Key)
		}
		for _, value := range []any{"langgraph", "plan", json.Number("1")} {
			if keptAs(t, g, decisionSpan(row.Key, valueOf(t, value)), row.Key, valueOf(t, value)) {
				t.Errorf("pending key %q kept %v", row.Key, value)
			}
		}
	}
	if pending != 9 {
		t.Fatalf("pending new keys = %d, want 9", pending)
	}
}

func TestHeartbeatKindMigrationAdmitsSegmentSeal(t *testing.T) {
	var heartbeat *registryKey
	keys := loadCoverageKeys(t)
	for i := range keys {
		if keys[i].Key == "fabric.heartbeat.kind" {
			heartbeat = &keys[i]
		}
	}
	if heartbeat == nil || heartbeat.Check == nil {
		t.Fatal("registry has no heartbeat.kind check")
	}
	want := map[string]struct{}{}
	for _, value := range heartbeat.Check.Values {
		want[value.(string)] = struct{}{}
	}
	if !reflect.DeepEqual(want, captureHeartbeatKinds) {
		t.Fatalf("heartbeat kinds %v, registry %v", captureHeartbeatKinds, want)
	}
	g := newTestGuard(t, nil)
	seal := withScope(heartbeatOfKind("segment_seal"), testScopeID)
	span := processOne(t, g, "fabric.capture_heartbeat", seal)
	assertKeysKept(t, span, seal)
	if span.Name() != "fabric.capture_heartbeat" {
		t.Fatalf("segment_seal renamed to %q", span.Name())
	}
	for _, kind := range []string{"periodic", "final"} {
		span = processOne(t, g, "fabric.capture_heartbeat", withScope(heartbeatOfKind(kind), testScopeID))
		if _, ok := span.Attributes().Get("fabric.run.scope_id"); ok {
			t.Errorf("%s heartbeat kept a scope id", kind)
		}
	}
}

func TestReceiverOwnedSourceAuthenticatedIsStrippedEverywhere(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.ExtraAllowedTraceFields = []string{"fabric.source.authenticated"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "receiver-owned") {
		t.Fatalf("config accepted a receiver-owned extra field: %v", err)
	}
	cfg2 := createDefaultConfig()
	cfg2.ExtraAllowedFields = map[string][]string{"activity": {"fabric.source.authenticated"}}
	if err := cfg2.Validate(); err == nil {
		t.Fatal("config accepted a receiver-owned extra log field")
	}
	// Even a configuration that skipped validation never admits it.
	g := newTestGuard(t, cfg)
	stamp := valueOf(t, true)
	for name, td := range map[string]ptrace.Traces{
		"decision":  decisionSpan("fabric.source.authenticated", stamp),
		"exchange":  captureCarrier(onExchange, "fabric.source.authenticated", stamp),
		"heartbeat": captureCarrier(onHeartbeat, "fabric.source.authenticated", stamp),
		"loss":      captureCarrier(onLoss, "fabric.source.authenticated", stamp),
	} {
		resource := td.ResourceSpans().At(0).Resource().Attributes()
		resource.PutBool("fabric.source.authenticated", true)
		out, err := g.processTraces(context.Background(), td)
		if err != nil {
			t.Fatal(err)
		}
		rs := out.ResourceSpans().At(0)
		if _, ok := firstSpan(out).Attributes().Get("fabric.source.authenticated"); ok {
			t.Errorf("%s span kept an agent-supplied fabric.source.authenticated", name)
		}
		if _, ok := rs.Resource().Attributes().Get("fabric.source.authenticated"); ok {
			t.Errorf("%s resource kept an agent-supplied fabric.source.authenticated", name)
		}
	}
}

type markerVectors struct {
	Admitted []struct {
		Name          string         `json:"name"`
		CaptureLabels string         `json:"capture_labels"`
		Attributes    map[string]any `json:"attributes"`
	} `json:"admitted"`
	Stripped []struct {
		Name          string `json:"name"`
		CaptureLabels string `json:"capture_labels"`
		Key           string `json:"key"`
		Value         any    `json:"value"`
	} `json:"stripped"`
}

func labelsGuard(t *testing.T, labels string) *guard {
	t.Helper()
	if labels == captureLabelsClear {
		return newTestGuard(t, clearLabelsConfig(t))
	}
	return newTestGuard(t, nil)
}

// The run-marker vectors (contracts/coverage/v1) pass fabricguard intact, and
// each stripped value is removed while the rest of its marker survives.
func TestRunMarkerVectorsPassFabricguard(t *testing.T) {
	var vectors markerVectors
	decodeJSON(t, runMarkerVectors, &vectors)
	if len(vectors.Admitted) == 0 || len(vectors.Stripped) == 0 {
		t.Fatal("empty run-marker vectors")
	}
	byKind := map[string]map[string]any{}
	for _, tc := range vectors.Admitted {
		attrs := raw(t, tc.Attributes).(map[string]any)
		span := processOne(t, labelsGuard(t, tc.CaptureLabels), "native", attrs)
		if span.Name() != "fabric.capture_heartbeat" {
			t.Errorf("%s: name %q", tc.Name, span.Name())
		}
		assertKeysKept(t, span, attrs)
		if got := span.Attributes().Len(); got != len(attrs) {
			t.Errorf("%s: %d attributes kept, want %d", tc.Name, got, len(attrs))
		}
		if tc.CaptureLabels != captureLabelsClear {
			byKind[attrs["fabric.heartbeat.kind"].(string)] = attrs
		}
	}
	for _, tc := range vectors.Stripped {
		base := byKind["run_start"]
		if kinds, ok := markerKeyKinds[tc.Key]; ok {
			if _, onStart := kinds["run_start"]; !onStart {
				for kind := range kinds {
					if candidate, present := byKind[kind]; present {
						base = candidate
					}
				}
			}
		}
		attrs := map[string]any{}
		for k, v := range base {
			attrs[k] = v
		}
		attrs[tc.Key] = raw(t, tc.Value)
		span := processOne(t, labelsGuard(t, tc.CaptureLabels), "native", attrs)
		if got, ok := span.Attributes().Get(tc.Key); ok && reflect.DeepEqual(got.AsRaw(), attrs[tc.Key]) {
			t.Errorf("%s: %s kept", tc.Name, tc.Key)
		}
		if _, ok := span.Attributes().Get("fabric.heartbeat.last_sequence"); !ok {
			t.Errorf("%s: the marker itself was dropped", tc.Name)
		}
	}
}

// A run-marker key never rides on a heartbeat kind, loss record or exchange
// that does not define it.
func TestRunMarkerKeysStayOnTheirKinds(t *testing.T) {
	g := newTestGuard(t, nil)
	segment := "seg-0123456789abcdef0123456789abcdef"
	digest := "sha256:" + hex64("a")
	cases := []struct {
		name  string
		attrs map[string]any
		key   string
	}{
		{"predecessors on a seal", map[string]any{"fabric.heartbeat.kind": "segment_seal", "fabric.run.predecessors": []any{"none"}}, "fabric.run.predecessors"},
		{"seal digest on run_start", map[string]any{"fabric.heartbeat.kind": "run_start", "fabric.segment.seal_digest": digest}, "fabric.segment.seal_digest"},
		{"terminal on run_end", map[string]any{"fabric.heartbeat.kind": "run_end", "fabric.run.terminal": true}, "fabric.run.terminal"},
		{"segment on a periodic heartbeat", map[string]any{"fabric.heartbeat.kind": "periodic", "fabric.run.segment_id": segment}, "fabric.run.segment_id"},
		{"scope status on run_start", map[string]any{"fabric.heartbeat.kind": "run_start", "fabric.run.scope_status": "ok"}, "fabric.run.scope_status"},
		{"manifest id on a seal", map[string]any{"fabric.heartbeat.kind": "segment_seal", "fabric.capture.manifest_id": testScopeID}, "fabric.capture.manifest_id"},
	}
	for _, tc := range cases {
		attrs := wireHeartbeatAttrs()
		for k, v := range tc.attrs {
			attrs[k] = v
		}
		span := processOne(t, g, "native", attrs)
		if _, ok := span.Attributes().Get(tc.key); ok {
			t.Errorf("%s: kept", tc.name)
		}
	}
	exchange := wireExchangeAttrs()
	exchange["fabric.run.segment_id"] = segment
	exchange["fabric.run.predecessors"] = []any{"none"}
	exchange["fabric.capture.input"] = "wire"
	span := processOne(t, g, "fabric.model_call", exchange)
	if _, ok := span.Attributes().Get("fabric.run.predecessors"); ok {
		t.Error("exchange kept fabric.run.predecessors")
	}
	for _, key := range []string{"fabric.run.segment_id", "fabric.capture.input"} {
		if _, ok := span.Attributes().Get(key); !ok {
			t.Errorf("exchange dropped %s", key)
		}
	}
	loss := wireLossAttrs()
	loss["fabric.run.segment_id"] = segment
	if _, ok := processOne(t, g, "native", loss).Attributes().Get("fabric.run.segment_id"); ok {
		t.Error("loss record kept fabric.run.segment_id")
	}
}

// The capture manifest span (contracts/coverage/v1 manifest-span vectors)
// passes fabricguard with its name and every attribute intact.
func TestCaptureManifestSpanPassesIntact(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name       string         `json:"name"`
			Attributes map[string]any `json:"attributes"`
		} `json:"cases"`
	}
	decodeJSON(t, manifestVectors, &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("no manifest span vectors")
	}
	g := newTestGuard(t, nil)
	for _, tc := range vectors.Cases {
		attrs := raw(t, tc.Attributes).(map[string]any)
		span := processOne(t, g, "fabric.capture_manifest", attrs)
		if span.Name() != "fabric.capture_manifest" {
			t.Errorf("%s: renamed to %q", tc.Name, span.Name())
		}
		assertKeysKept(t, span, attrs)
		if got := span.Attributes().Len(); got != len(attrs) {
			t.Errorf("%s: kept %d of %d attributes", tc.Name, got, len(attrs))
		}
		attrs["fabric.manifest.coverage_profile"] = "Jane Doe's coverage"
		span = processOne(t, g, "fabric.capture_manifest", attrs)
		if _, ok := span.Attributes().Get("fabric.manifest.coverage_profile"); ok {
			t.Errorf("%s: free text kept on the manifest span", tc.Name)
		}
	}
}
