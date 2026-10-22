// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const vectorsDirectory = "../../../../contracts/coverage/v1/fixtures/vectors/"

func recordAttrs() map[string]any {
	return map[string]any{
		"fabric.capture.input": "records", "fabric.capture.source": "reported",
		"fabric.capture.point": "sdk.records@0.9.0", "fabric.source_id": testSourceLabel,
		"fabric.source.epoch": int64(1), "fabric.source.sequence": int64(0),
		"fabric.event_id": testScopeID, "fabric.attempt.uid": testScopeID,
		"fabric.run.scope_id":   testScopeID,
		"fabric.run.segment_id": "seg-0123456789abcdef0123456789abcdef",
		"fabric.step.kind":      "agent_turn", "fabric.actor.type": "agent",
	}
}

// Unlike raw, vectorRaw preserves deliberately invalid floating-point values.
func vectorRaw(t *testing.T, value any) any {
	t.Helper()
	switch v := value.(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
		n, err := v.Float64()
		if err != nil {
			t.Fatal(err)
		}
		return n
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = vectorRaw(t, item)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for key, item := range v {
			out[key] = vectorRaw(t, item)
		}
		return out
	}
	return value
}

func TestRecordsSpanVectors(t *testing.T) {
	var vectors struct {
		Keys       []string
		Conditions map[string]map[string][]string
		Cases      []struct {
			Name                 string
			CaptureLabels        string `json:"capture_labels"`
			IdentityMode         string `json:"identity_mode"`
			Attributes, Admitted map[string]any
			Dropped              []string
		}
	}
	decodeJSON(t, vectorsDirectory+"records-span-v1.json", &vectors)
	keys := make([]string, 0, len(recordKeyValidators))
	for key := range recordKeyValidators {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !reflect.DeepEqual(keys, vectors.Keys) || !reflect.DeepEqual(recordKeyConditions, vectors.Conditions) {
		t.Fatal("records table/conditions differ from the shared vectors")
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("empty records vectors")
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			cfg := createDefaultConfig()
			cfg.CaptureLabels = tc.CaptureLabels
			cfg.IdentityMode = tc.IdentityMode
			g := newTestGuard(t, cfg)
			attrs := pcommon.NewMap()
			if err := attrs.FromRaw(vectorRaw(t, tc.Attributes).(map[string]any)); err != nil {
				t.Fatal(err)
			}
			// Rule A runs before class discrimination at the emitter; one vector
			// deliberately includes an exchange marker that rule A must strip.
			g.applyRecordProfile(attrs)
			want := vectorRaw(t, tc.Admitted)
			if !reflect.DeepEqual(attrs.AsRaw(), want) {
				t.Fatalf("admitted=%v, want %v", attrs.AsRaw(), want)
			}
			if n := g.stats.snapshot().NotAllowedRemoved; n != uint64(len(tc.Dropped)) {
				t.Errorf("dropped=%d, want %d", n, len(tc.Dropped))
			}
			span := processOne(t, g, "fabric.tool_call", attrs.AsRaw())
			if !reflect.DeepEqual(span.Attributes().AsRaw(), want) {
				t.Fatalf("Node changed projected record: %v", span.Attributes().AsRaw())
			}
		})
	}
}

func TestCapturePointKinds(t *testing.T) {
	var registry struct {
		Points []struct{ ID, Kind string } `json:"capture_points"`
	}
	decodeJSON(t, "../../../../contracts/coverage/v1/registry/capture-points-v1.json", &registry)
	want := map[string]string{}
	for _, point := range registry.Points {
		want[point.ID] = point.Kind
	}
	if !reflect.DeepEqual(capturePointKinds, want) {
		t.Fatal("runtime capture-point kinds differ from the public registry")
	}
}

func TestRecordConditions(t *testing.T) {
	for _, tc := range []struct {
		name, point string
		condition   map[string][]string
		want        bool
	}{
		{"unconditional", "", nil, true},
		{"point id without version", "mcp.client@1.2.3", map[string][]string{"capture_points": {"mcp.client"}}, true},
		{"wrong point", "mcp.wrapper@1", map[string][]string{"capture_points": {"mcp.client"}}, false},
		{"hook kind", "mcp.client@1", map[string][]string{"capture_point_kinds": {"H"}}, true},
		{"reported kind", "mcp.wrapper@1", map[string][]string{"capture_point_kinds": {"H"}}, false},
		{"unknown point", "unknown.point@1", map[string][]string{"capture_point_kinds": {"H"}}, false},
		{"missing point", "", map[string][]string{"capture_point_kinds": {"H"}}, false},
		{"both restrictions", "mcp.client@1", map[string][]string{"capture_point_kinds": {"H"}, "capture_points": {"mcp.client"}}, true},
		{"both must match", "exec.audit@1", map[string][]string{"capture_point_kinds": {"H"}, "capture_points": {"mcp.client"}}, false},
		{"empty restriction", "sdk.records@1", map[string][]string{"capture_points": {}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := recordConditionHolds(tc.condition, tc.point); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	// Exercise the admission path as well as the predicate. P1 has no
	// conditional rows yet; restore the generated table before the next test.
	saved := recordKeyConditions
	t.Cleanup(func() { recordKeyConditions = saved })
	recordKeyConditions = map[string]map[string][]string{
		"fabric.actor.type": {"capture_point_kinds": {"H"}, "capture_points": {"mcp.client"}},
	}
	for _, point := range []string{"mcp.client@1", "mcp.wrapper@1", "exec.audit@1", "invalid point", ""} {
		attrs := recordAttrs()
		attrs["fabric.capture.point"] = point
		span := processOne(t, newTestGuard(t, nil), "fabric.activity", attrs)
		_, kept := span.Attributes().Get("fabric.actor.type")
		if kept != (point == "mcp.client@1") {
			t.Errorf("point %q: conditional key kept=%v", point, kept)
		}
	}
}

func TestRecordsAndLossKeyAdmission(t *testing.T) {
	var registry struct {
		Keys []struct {
			Key        string
			RawCheck   *registryCheck `json:"check"`
			RawCapture *registryCheck `json:"capture_check"`
			Placement  []string
		}
	}
	decodeJSON(t, coverageRegistry, &registry)
	for _, row := range registry.Keys {
		check := row.RawCapture
		if check == nil {
			check = row.RawCheck
		}
		if check == nil || check.Type == "never" {
			continue
		}
		values := admitted(check)
		for _, class := range []uint8{onRecord, onLoss} {
			t.Run(row.Key+map[uint8]string{onRecord: "/record", onLoss: "/loss"}[class], func(t *testing.T) {
				cfg := clearLabelsConfig(t)
				for _, example := range values {
					attrs := recordAttrs()
					if class == onLoss {
						attrs = wireLossAttrs()
					}
					// Heartbeat discriminator changes the class; tested separately below.
					if row.Key == "fabric.heartbeat.last_sequence" {
						continue
					}
					td := makeRawSpan("fabric.activity", attrs)
					span := firstSpan(td)
					valueOf(t, example).CopyTo(span.Attributes().PutEmpty(row.Key))
					g := newTestGuard(t, cfg)
					if class == onRecord {
						g.applyRecordProfile(span.Attributes())
					} else {
						g.applyCaptureProfile(span)
					}
					_, kept := span.Attributes().Get(row.Key)
					placement := "record"
					if class == onLoss {
						placement = "loss"
					}
					want := slices.Contains(row.Placement, placement)
					if class == onRecord && row.Key == "fabric.capture.input" {
						want = raw(t, example) == "records"
					}
					// Legacy 047 keys have no placement column and remain admitted by
					// the original capture profile on losses.
					if class == onLoss && len(row.Placement) == 0 {
						_, want = captureProfile[row.Key]
					}
					if kept != want {
						t.Errorf("value=%v: kept=%v, want %v", example, kept, want)
					}
				}
				if class == onRecord || slices.Contains(row.Placement, "loss") {
					for _, bad := range rejected(check) {
						attrs := recordAttrs()
						if class == onLoss {
							attrs = wireLossAttrs()
						}
						td := makeRawSpan("fabric.activity", attrs)
						span := firstSpan(td)
						valueOf(t, bad).CopyTo(span.Attributes().PutEmpty(row.Key))
						g := newTestGuard(t, cfg)
						if class == onRecord {
							g.applyRecordProfile(span.Attributes())
						} else {
							g.applyCaptureProfile(span)
						}
						if _, kept := span.Attributes().Get(row.Key); kept {
							t.Errorf("invalid value %v survived", bad)
						}
					}
				}
			})
		}
	}
}

func TestRecordsClassificationAndStrictMetadata(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
		class uint8
	}{
		{"", nil, onRecord},
		{"fabric.wire.exchange_id", "invalid exchange", onExchange},
		{"fabric.loss.reason", "invalid loss", onLoss},
		{"fabric.heartbeat.last_sequence", "invalid heartbeat", onHeartbeat},
		{"fabric.capture.input", "wire", 0},
		{"fabric.capture.input", true, 0},
	} {
		attrs := recordAttrs()
		if tc.key != "" {
			attrs[tc.key] = tc.value
		}
		td := makeRawSpan("fabric.activity", attrs)
		if got := captureClass(firstSpan(td).Attributes()); got != tc.class {
			t.Errorf("%s: class=%d, want %d", tc.key, got, tc.class)
		}
	}
	attrs := recordAttrs()
	delete(attrs, "fabric.source.sequence")
	if isCaptureSpan(firstSpan(makeRawSpan("fabric.tool_call", attrs))) {
		t.Fatal("unsequenced records span classified as capture")
	}
	cfg := createDefaultConfig()
	cfg.ExtraAllowedTraceFields = []string{"customer.secret"}
	td := makeRawSpan("fabric.tool_call", recordAttrs())
	rs := td.ResourceSpans().At(0)
	rs.Resource().Attributes().PutStr("service.name", "clear.service")
	ss := rs.ScopeSpans().At(0)
	ss.Scope().Attributes().PutStr("customer.secret", "scope-secret")
	span := firstSpan(td)
	span.Attributes().PutStr("customer.secret", "secret")
	span.Events().AppendEmpty().SetName("secret")
	span.Links().AppendEmpty()
	out, err := newTestGuard(t, cfg).processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	span = firstSpan(out)
	if span.Attributes().Len() != len(recordAttrs()) || span.Events().Len() != 0 || span.Links().Len() != 0 ||
		rs.Resource().Attributes().Len() != 0 || ss.Scope().Attributes().Len() != 0 {
		t.Fatal("records bypassed strict capture metadata policy")
	}
}

func TestRecordsBindingAndDuplicateRefusal(t *testing.T) {
	for _, tc := range []struct {
		name              string
		change            func(pcommon.Map)
		rejected, dropped bool
	}{
		{"bound", func(pcommon.Map) {}, false, false},
		{"foreign source", func(a pcommon.Map) { a.PutStr("fabric.source_id", foreignSource) }, true, false},
		{"foreign tenant", func(a pcommon.Map) { a.PutStr("fabric.tenant_id", "other") }, true, false},
		{"missing source", func(a pcommon.Map) { a.Remove("fabric.source_id") }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			td := makeRawSpan("fabric.tool_call", recordAttrs())
			tc.change(firstSpan(td).Attributes())
			out, err := traceBoundGuard(t).processTraces(context.Background(), td)
			if tc.rejected {
				if status.Code(err) != codes.InvalidArgument {
					t.Fatalf("binding accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			spans := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
			if tc.dropped {
				if spans.Len() != 0 {
					t.Fatal("unbound record survived")
				}
				return
			}
			stamp, ok := firstSpan(out).Attributes().Get(sourceAuthenticatedKey)
			if !ok || !stamp.Bool() {
				t.Fatal("bound record was not authenticated")
			}
		})
	}
	for _, key := range []string{"fabric.source_id", "fabric.source.sequence", "fabric.capture.input", "fabric.event_id"} {
		td := makeRawSpan("fabric.tool_call", recordAttrs())
		firstSpan(td).Attributes().PutStr(placeholder(key), "forged")
		td = wireDuplicateTraces(t, td, key)
		_, err := traceBoundGuard(t).processTraces(context.Background(), td)
		assertDuplicateRefused(t, err)
		if countKey(firstSpan(td).Attributes(), key) != 2 {
			t.Fatal("duplicate refusal mutated the batch")
		}
	}
}

func TestMarkerEventIDsAndManifestSourceLabels(t *testing.T) {
	for _, kind := range []string{"run_start", "run_end", "periodic", "final", "segment_seal", "manifest"} {
		for _, event := range []string{testScopeID, strings.Replace(testScopeID, "-4", "-1", 1), strings.ToUpper(testScopeID), "private content"} {
			attrs := heartbeatOfKind(kind)
			name := "native"
			if kind == "manifest" {
				attrs = map[string]any{"fabric.source_id": testSourceLabel}
				name = "fabric.capture_manifest"
			}
			attrs["fabric.event_id"] = event
			span := processOne(t, newTestGuard(t, nil), name, attrs)
			_, kept := span.Attributes().Get("fabric.event_id")
			if kept != (event == testScopeID) {
				t.Errorf("%s: event %q kept=%v", kind, event, kept)
			}
		}
	}
	for _, labels := range []string{captureLabelsClear, captureLabelsPseudonymous} {
		cfg := createDefaultConfig()
		cfg.CaptureLabels = labels
		for _, source := range []string{testSourceLabel, "clear-source", "bad source"} {
			span := processOne(t, newTestGuard(t, cfg), "fabric.capture_manifest", map[string]any{"fabric.source_id": source})
			_, kept := span.Attributes().Get("fabric.source_id")
			want := source == testSourceLabel || labels == captureLabelsClear && source == "clear-source"
			if kept != want {
				t.Errorf("manifest %s %q kept=%v", labels, source, kept)
			}
		}
	}
}

func TestExchangeAndRunStartIdentityPlacements(t *testing.T) {
	for _, labels := range []string{captureLabelsPseudonymous, captureLabelsClear} {
		for _, key := range []string{"fabric.agent_id", "fabric.system_id", "fabric.deployment_id", "fabric.release_id", "fabric.environment", "fabric.session_id", "fabric.user_id"} {
			for _, class := range []string{"exchange", "run_start", "run_end", "periodic", "loss", "record"} {
				t.Run(labels+"/"+key+"/"+class, func(t *testing.T) {
					cfg := createDefaultConfig()
					cfg.CaptureLabels = labels
					value := "lbl-0123456789abcdef0123456789abcdef"
					if key == "fabric.session_id" {
						value = "sess-0123456789abcdef0123456789abcdef"
					}
					if key == "fabric.user_id" {
						value = "usr-0123456789abcdef0123456789abcdef"
					}
					for _, text := range []string{value, "operator-label", "private content with spaces"} {
						var attrs map[string]any
						switch class {
						case "exchange":
							attrs = wireExchangeAttrs()
						case "record":
							attrs = recordAttrs()
						case "loss":
							attrs = wireLossAttrs()
						default:
							attrs = heartbeatOfKind(class)
						}
						attrs[key] = text
						span := processOne(t, newTestGuard(t, cfg), "native", attrs)
						_, kept := span.Attributes().Get(key)
						want := (class == "exchange" || class == "run_start") && text == value
						if key != "fabric.session_id" && key != "fabric.user_id" && labels == captureLabelsClear && text == "operator-label" {
							want = class == "exchange" || class == "run_start"
						}
						if kept != want {
							t.Errorf("%q kept=%v, want %v", text, kept, want)
						}
					}
				})
			}
		}
	}
}

func TestRecordStructuredValuesAreRefusedWithoutRewriting(t *testing.T) {
	for _, value := range []any{3.5, []byte("private"), map[string]any{"id": "private"}, []any{testScopeID, 1.5}, []any{[]any{testScopeID}}} {
		td := makeRawSpan("fabric.activity", recordAttrs())
		attrs := firstSpan(td).Attributes()
		if err := attrs.PutEmpty("fabric.content.object_ids").FromRaw(value); err != nil {
			t.Fatal(err)
		}
		g := newTestGuard(t, nil)
		g.applyRecordProfile(attrs)
		if _, kept := attrs.Get("fabric.content.object_ids"); kept {
			t.Errorf("structured value %v survived", value)
		}
		if g.stats.snapshot().NotAllowedRemoved != 1 {
			t.Fatal("refused value was not counted exactly once")
		}
	}
}

func TestCaptureEpochCompatibility(t *testing.T) {
	for _, epoch := range []int64{0, 1, 9223372036854775807} {
		for _, attrs := range []map[string]any{recordAttrs(), wireExchangeAttrs(), wireLossAttrs(), wireHeartbeatAttrs()} {
			attrs["fabric.source.epoch"] = epoch
			span := processOne(t, newTestGuard(t, nil), "native", attrs)
			value, ok := span.Attributes().Get("fabric.source.epoch")
			if !ok || value.Int() != epoch {
				t.Errorf("epoch %d was not preserved", epoch)
			}
		}
	}
}
