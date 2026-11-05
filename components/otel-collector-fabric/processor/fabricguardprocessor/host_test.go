// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	hostFixturesDirectory = "../../../../contracts/capture/v1/fixtures/host/"
	captureManifest       = "../../../../contracts/capture/v1/manifest.json"
	testHostTenant        = "tenant-a"
	testHostSource        = "s-2c6c641009e36ee2e6587ef29bc3a782"
)

func hostGuard(t *testing.T, kind, digests string) *guard {
	t.Helper()
	cfg := createDefaultConfig()
	cfg.Profile = profileProduction
	cfg.SourceKind = kind
	cfg.HostDigests = digests
	cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: testHostTenant, SourceID: testHostSource}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return newTestGuard(t, cfg)
}

func agentGuard(t *testing.T) *guard {
	t.Helper()
	cfg := createDefaultConfig()
	cfg.Profile = profileProduction
	cfg.SourceKind = sourceKindAgent
	cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: testHostTenant, SourceID: testHostSource}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return newTestGuard(t, cfg)
}

func hostRecordAttrs() map[string]any {
	return map[string]any{
		"fabric.tenant_id": testHostTenant, "fabric.source_id": testHostSource,
		"fabric.source.epoch": int64(6917529027641081857), "fabric.source.sequence": int64(4),
		"fabric.event_id": "07dde3b1-c61c-4e0e-a0e8-78bdd8e049e2", "fabric.attempt.uid": "113eb822-5f48-4cee-a789-ff2c3926d026",
		"fabric.capture.input": "records", "fabric.capture.source": "observed",
		"fabric.capture.point":      "host.ebpf@0.11.0",
		"fabric.sensor.event_class": "exec", "fabric.sensor.syscall": "execve",
		"fabric.sensor.result": "success", "fabric.sensor.pid": int64(4121),
	}
}

func hostHeartbeatAttrs() map[string]any {
	return map[string]any{
		"fabric.source_id": testHostSource, "fabric.source.epoch": int64(6917529027641081857),
		"fabric.heartbeat.kind": "periodic", "fabric.heartbeat.last_sequence": int64(4),
		"fabric.capture.manifest_seq": int64(0), "fabric.capture.point": "host.ebpf@0.11.0",
		"fabric.event_id":             "9145cbb4-fd2e-4bbb-a49a-bcfefa8ccd76",
		"fabric.sensor.upstream_lost": int64(0),
	}
}

func hostLossAttrs() map[string]any {
	return map[string]any{
		"fabric.source_id": testHostSource, "fabric.source.epoch": int64(6917529027641081857),
		"fabric.capture.point": "host.ebpf@0.11.0", "fabric.event_id": "5a1f3c2e-7b4d-4e8f-9a0b-1c2d3e4f5a6b",
		"fabric.loss.reason": "span_dropped", "fabric.loss.count": int64(2),
		"fabric.loss.first_sequence": int64(5), "fabric.loss.last_sequence": int64(6),
	}
}

// makeSpans builds one resource and scope holding one span per (name, attrs).
func makeSpans(spans ...any) ptrace.Traces {
	td := ptrace.NewTraces()
	out := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
	for i := 0; i+1 < len(spans); i += 2 {
		span := out.AppendEmpty()
		span.SetName(spans[i].(string))
		if err := span.Attributes().FromRaw(spans[i+1].(map[string]any)); err != nil {
			panic(err)
		}
	}
	return td
}

func allSpans(td ptrace.Traces) []ptrace.Span {
	var out []ptrace.Span
	for ri := 0; ri < td.ResourceSpans().Len(); ri++ {
		scopes := td.ResourceSpans().At(ri).ScopeSpans()
		for si := 0; si < scopes.Len(); si++ {
			for i := 0; i < scopes.At(si).Spans().Len(); i++ {
				out = append(out, scopes.At(si).Spans().At(i))
			}
		}
	}
	return out
}

// assertRefused checks a non-retryable INVALID_ARGUMENT naming code, the
// mapping the OTLP receiver turns into a client error.
func assertRefused(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("batch admitted, want %s", code)
	}
	mapped, ok := status.FromError(err)
	if !consumererror.IsPermanent(err) || !ok || mapped.Code() != codes.InvalidArgument || !strings.Contains(err.Error(), code) {
		t.Fatalf("refusal %v, want permanent InvalidArgument %s", err, code)
	}
}

func clone(attrs map[string]any) map[string]any {
	out := make(map[string]any, len(attrs))
	for key, value := range attrs {
		out[key] = value
	}
	return out
}

func with(attrs map[string]any, changes map[string]any) map[string]any {
	out := clone(attrs)
	for key, value := range changes {
		if value == nil {
			delete(out, key)
		} else {
			out[key] = value
		}
	}
	return out
}

// TestHostFixtures runs every contracts/capture/v1/fixtures/host document
// through its guard: a valid one gives exactly its expected spans, per-key
// strip counts and drops; a refused one fails with the code manifest.json
// names. The Python reference (scripts/contracts/host_records.admit) gives the
// same results from the same inputs.
func TestHostFixtures(t *testing.T) {
	var manifest struct {
		Artifacts []struct {
			Path          string
			Expectation   string
			ExpectedError string `json:"expected_error"`
		}
	}
	decodeJSON(t, captureManifest, &manifest)
	codes := map[string]string{}
	for _, file := range manifest.Artifacts {
		if rel, ok := strings.CutPrefix(file.Path, "fixtures/host/"); ok && file.Expectation == "invalid" {
			codes[rel] = file.ExpectedError
		}
	}
	paths, err := filepath.Glob(hostFixturesDirectory + "*/*.json")
	if err != nil || len(paths) < 20 {
		t.Fatalf("host fixtures: %d, %v", len(paths), err)
	}
	for _, path := range paths {
		rel := strings.TrimPrefix(path, hostFixturesDirectory)
		t.Run(rel, func(t *testing.T) {
			var fixture struct {
				Guard struct {
					SourceKind  string `json:"source_kind"`
					Profile     string
					TenantID    string `json:"tenant_id"`
					SourceID    string `json:"source_id"`
					HostDigests string `json:"host_digests"`
				}
				Batches  []json.RawMessage
				Expected []struct {
					Spans []struct {
						Name       string
						Attributes map[string]any
					}
					Stripped map[string]int
					Dropped  int
				}
			}
			decodeJSON(t, path, &fixture)
			cfg := createDefaultConfig()
			cfg.SourceKind, cfg.Profile = fixture.Guard.SourceKind, fixture.Guard.Profile
			cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: fixture.Guard.TenantID, SourceID: fixture.Guard.SourceID}
			if fixture.Guard.SourceKind != sourceKindAgent {
				cfg.HostDigests = fixture.Guard.HostDigests
			}
			code, refused := codes[rel]
			if err := cfg.Validate(); err != nil {
				if code != "capture.host.source_kind" || !strings.Contains(err.Error(), "source_kind") {
					t.Fatalf("guard configuration refused: %v", err)
				}
				return
			}
			g := newTestGuard(t, cfg)
			for b, body := range fixture.Batches {
				td, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces(body)
				if err != nil {
					t.Fatal(err)
				}
				before := map[string]map[string]any{}
				for _, span := range allSpans(td) {
					before[span.SpanID().String()] = span.Attributes().AsRaw()
				}
				stats := g.stats.snapshot()
				out, err := g.processTraces(context.Background(), td)
				if refused && code != "capture.host.replay" {
					assertRefused(t, err, code)
					return
				}
				if err != nil {
					t.Fatalf("batch %d refused: %v", b, err)
				}
				if refused {
					continue // a replay is admissible batch by batch; the verifier reports it
				}
				want := fixture.Expected[b]
				spans := allSpans(out)
				if len(spans) != len(want.Spans) {
					t.Fatalf("batch %d: %d spans, want %d", b, len(spans), len(want.Spans))
				}
				stripped := map[string]int{}
				for i, span := range spans {
					got := span.Attributes().AsRaw()
					if span.Name() != want.Spans[i].Name || !reflect.DeepEqual(got, raw(t, want.Spans[i].Attributes)) {
						t.Fatalf("batch %d span %d:\n got %s %v\nwant %s %v", b, i, span.Name(), got, want.Spans[i].Name, want.Spans[i].Attributes)
					}
					for key := range before[span.SpanID().String()] {
						if _, kept := got[key]; !kept {
							stripped[key]++
						}
					}
				}
				if !reflect.DeepEqual(stripped, want.Stripped) && (len(stripped) != 0 || len(want.Stripped) != 0) {
					t.Errorf("batch %d stripped %v, want %v", b, stripped, want.Stripped)
				}
				after := g.stats.snapshot()
				if n := after.HostSpanDropped - stats.HostSpanDropped; n != uint64(want.Dropped) {
					t.Errorf("batch %d dropped %d, want %d", b, n, want.Dropped)
				}
				total := 0
				for _, n := range want.Stripped {
					total += n
				}
				if n := (after.HostKeyStripped + after.HostDigestStripped) - (stats.HostKeyStripped + stats.HostDigestStripped); n != uint64(total) {
					t.Errorf("batch %d stripped count %d, want %d", b, n, total)
				}
			}
			if refused && code != "capture.host.replay" {
				t.Fatalf("no batch was refused, want %s", code)
			}
		})
	}
}

// TestHostAdmissionOrder pins spec 053 §6.2.7, one case per step, including
// which step wins when a batch fails two of them.
func TestHostAdmissionOrder(t *testing.T) {
	exchange := wireExchangeAttrs()
	t.Run("1 repeated key wins over every other finding", func(t *testing.T) {
		// A second fabric.event_id in a record that also names a foreign
		// source, next to an exchange (steps 4 and 5 would refuse too).
		first := with(hostRecordAttrs(), map[string]any{"fabric.source_id": "s-8f7a2b26a947d94497736831c32f63ce", placeholder("fabric.event_id"): "x"})
		td := wireDuplicateTraces(t, makeSpans("openai.chat", exchange, "x", first), "fabric.event_id")
		_, err := hostGuard(t, sourceKindEBPF, "").processTraces(context.Background(), td)
		assertRefused(t, err, hostRefusalRepeatedKey)
	})
	t.Run("2 a supplied authentication stamp is removed, not counted", func(t *testing.T) {
		g := hostGuard(t, sourceKindEBPF, "")
		out, err := g.processTraces(context.Background(), makeSpans("x", with(hostRecordAttrs(), map[string]any{sourceAuthenticatedKey: false})))
		if err != nil {
			t.Fatal(err)
		}
		stamp, _ := allSpans(out)[0].Attributes().Get(sourceAuthenticatedKey)
		if !stamp.Bool() || g.stats.snapshot().HostKeyStripped != 0 {
			t.Fatalf("stamp=%v stripped=%d", stamp.AsRaw(), g.stats.snapshot().HostKeyStripped)
		}
	})
	t.Run("3 log records are dropped and counted", func(t *testing.T) {
		g := hostGuard(t, sourceKindAuditd, "")
		ld := makeLogs(map[string]any{"event_class": "host_audit", "audit.event": "capture_loss"}, map[string]any{"event_class": "evidence"})
		out, err := g.processLogs(context.Background(), ld)
		if err != nil || out.LogRecordCount() != 0 || g.stats.snapshot().HostLogDropped != 2 {
			t.Fatalf("err=%v records=%d dropped=%d", err, out.LogRecordCount(), g.stats.snapshot().HostLogDropped)
		}
		dup := wireDuplicateLogs(t, makeLogs(map[string]any{"fabric.source_id": testHostSource, placeholder("fabric.source_id"): testHostSource}), "fabric.source_id")
		if _, err := g.processLogs(context.Background(), dup); err == nil {
			t.Fatal("a repeated key in a logs batch was not refused (step 1 precedes step 3)")
		}
	})
	t.Run("4 a non-host span refuses the whole batch before binding", func(t *testing.T) {
		for name, other := range map[string]map[string]any{
			"exchange":          exchange,
			"run marker":        with(hostHeartbeatAttrs(), map[string]any{"fabric.heartbeat.kind": "run_start"}),
			"seal":              with(hostHeartbeatAttrs(), map[string]any{"fabric.heartbeat.kind": "segment_seal"}),
			"agent record":      with(hostRecordAttrs(), map[string]any{"fabric.capture.point": "exec.subprocess@0.11.0"}),
			"unknown point":     with(hostRecordAttrs(), map[string]any{"fabric.capture.point": "host.etw@1"}),
			"wire input":        with(hostRecordAttrs(), map[string]any{"fabric.capture.input": "wire"}),
			"plain span":        {"fabric.decision_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7"},
			"heartbeat no kind": with(hostHeartbeatAttrs(), map[string]any{"fabric.heartbeat.kind": nil}),
		} {
			t.Run(name, func(t *testing.T) {
				// The first span also names a foreign source (step 5); step 4 wins
				// whatever the span order.
				foreign := with(hostRecordAttrs(), map[string]any{"fabric.source_id": "s-8f7a2b26a947d94497736831c32f63ce"})
				for _, td := range []ptrace.Traces{makeSpans("x", foreign, "y", other), makeSpans("y", other, "x", foreign)} {
					canary := allSpans(td)[0].Attributes().AsRaw()
					_, err := hostGuard(t, sourceKindEBPF, "").processTraces(context.Background(), td)
					assertRefused(t, err, hostRefusalNotHostEvidence)
					if !reflect.DeepEqual(allSpans(td)[0].Attributes().AsRaw(), canary) {
						t.Fatal("a refused batch was partially processed")
					}
				}
			})
		}
	})
	t.Run("5 binding: tenant, source, capture point and manifest rows", func(t *testing.T) {
		manifest := map[string]any{
			"fabric.event_id": "2434aa1d-8f1d-4a58-a380-79712ccbf700", "fabric.source_id": testHostSource,
			"fabric.source.epoch":            int64(6917529027641081857),
			"fabric.manifest.capture_points": []any{"host.ebpf@0.11.0:S:active:0:1:-"},
		}
		for name, td := range map[string]ptrace.Traces{
			"tenant":          makeSpans("x", with(hostRecordAttrs(), map[string]any{"fabric.tenant_id": "tenant-b"})),
			"source":          makeSpans("x", with(hostRecordAttrs(), map[string]any{"fabric.source_id": "s-8f7a2b26a947d94497736831c32f63ce"})),
			"auditd point":    makeSpans("x", with(hostRecordAttrs(), map[string]any{"fabric.capture.point": "host.auditd@0.11.0"})),
			"marker point":    makeSpans("x", with(hostHeartbeatAttrs(), map[string]any{"fabric.capture.point": "host.auditd@0.11.0"})),
			"manifest row":    makeSpans("fabric.capture_manifest", with(manifest, map[string]any{"fabric.manifest.capture_points": []any{"host.ebpf@0.11.0:S:active:0:1:-", "exec.subprocess@0.11.0:H:active:0:1:-"}})),
			"manifest no row": makeSpans("fabric.capture_manifest", with(manifest, map[string]any{"fabric.manifest.capture_points": nil})),
			"resource source": func() ptrace.Traces {
				td := makeSpans("x", hostRecordAttrs())
				td.ResourceSpans().At(0).Resource().Attributes().PutStr("fabric.source_id", "s-8f7a2b26a947d94497736831c32f63ce")
				return td
			}(),
		} {
			t.Run(name, func(t *testing.T) {
				_, err := hostGuard(t, sourceKindEBPF, "").processTraces(context.Background(), td)
				assertRefused(t, err, hostRefusalBinding)
			})
		}
		out, err := hostGuard(t, sourceKindEBPF, "").processTraces(context.Background(), makeSpans("fabric.capture_manifest", manifest))
		if err != nil || len(allSpans(out)) != 1 {
			t.Fatalf("bound manifest: %v", err)
		}
	})
	t.Run("6 keys outside the host placement are stripped; failing identity drops", func(t *testing.T) {
		g := hostGuard(t, sourceKindEBPF, "")
		out, err := g.processTraces(context.Background(), makeSpans(
			"a", with(hostRecordAttrs(), map[string]any{"fabric.run.id": "r-93347307304ecb0a9bb1b51ae90ac326", "fabric.sensor.upstream_lost": int64(1), "gen_ai.request.model": "gpt-4o", "fabric.sensor.errno": "EPERM"}),
			"b", with(hostRecordAttrs(), map[string]any{"fabric.source.sequence": int64(-1)}),
			"c", with(hostRecordAttrs(), map[string]any{"fabric.event_id": nil}),
			"d", with(hostRecordAttrs(), map[string]any{"fabric.sensor.syscall": "connect"}),
			"e", with(hostRecordAttrs(), map[string]any{"fabric.sensor.pid": nil}),
			"f", with(hostHeartbeatAttrs(), map[string]any{"fabric.heartbeat.last_sequence": "4"}),
			"g", with(hostLossAttrs(), map[string]any{"fabric.loss.reason": "queue_full"}),
			"h", with(hostHeartbeatAttrs(), map[string]any{"fabric.sensor.upstream_loss_reason": "ring_buffer_full", "fabric.run.segment_id": "seg-dc036958c70a72cf420903c9385c1051"}),
		))
		if err != nil {
			t.Fatal(err)
		}
		spans := allSpans(out)
		if len(spans) != 2 || g.stats.snapshot().HostSpanDropped != 6 {
			t.Fatalf("admitted %d, dropped %d", len(spans), g.stats.snapshot().HostSpanDropped)
		}
		for _, key := range []string{"fabric.run.id", "fabric.sensor.upstream_lost", "gen_ai.request.model", "fabric.sensor.errno"} {
			if _, kept := spans[0].Attributes().Get(key); kept {
				t.Errorf("record kept %s", key)
			}
		}
		for _, key := range []string{"fabric.sensor.upstream_loss_reason", "fabric.run.segment_id"} {
			if _, kept := spans[1].Attributes().Get(key); kept {
				t.Errorf("heartbeat kept %s", key)
			}
		}
		if spans[0].Name() != "fabric.sensor_event" || spans[1].Name() != "fabric.capture_heartbeat" {
			t.Errorf("names %q %q", spans[0].Name(), spans[1].Name())
		}
		if n := g.stats.snapshot().HostKeyStripped; n != 6 {
			t.Errorf("stripped %d, want 6", n)
		}
	})
	t.Run("7 digests are stripped without the group's permission", func(t *testing.T) {
		digest := map[string]any{"fabric.sensor.exe_sha256": strings.Repeat("ab", 32), "fabric.sensor.path_sha256": "sha256:" + strings.Repeat("ab", 32)}
		g := hostGuard(t, sourceKindEBPF, "")
		span := allSpans(mustProcess(t, g, makeSpans("x", with(hostRecordAttrs(), digest))))[0]
		if _, kept := span.Attributes().Get("fabric.sensor.exe_sha256"); kept {
			t.Fatal("digest kept without permission")
		}
		// the prefixed value fails its check at step 6, before step 7
		if s := g.stats.snapshot(); s.HostDigestStripped != 1 || s.HostKeyStripped != 1 {
			t.Fatalf("digest stripped %d, key stripped %d", s.HostDigestStripped, s.HostKeyStripped)
		}
	})
	t.Run("8 the Node stamps every admitted span", func(t *testing.T) {
		out := mustProcess(t, hostGuard(t, sourceKindEBPF, ""), makeSpans("x", hostRecordAttrs(), "y", hostHeartbeatAttrs(), "z", hostLossAttrs()))
		for _, span := range allSpans(out) {
			if stamp, ok := span.Attributes().Get(sourceAuthenticatedKey); !ok || !stamp.Bool() {
				t.Fatalf("%s not stamped", span.Name())
			}
		}
	})
}

func mustProcess(t *testing.T, g *guard, td ptrace.Traces) ptrace.Traces {
	t.Helper()
	out, err := g.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestHostBatchWithAgentRecordRefused(t *testing.T) {
	for name, agent := range map[string]map[string]any{
		"exec.subprocess record": with(hostRecordAttrs(), map[string]any{"fabric.capture.point": "exec.subprocess@0.11.0"}),
		"sdk record":             with(recordAttrs(), map[string]any{"fabric.source_id": testHostSource}),
		"exchange":               with(wireExchangeAttrs(), map[string]any{"fabric.source_id": testHostSource}),
		"run start":              with(wireHeartbeatAttrs(), map[string]any{"fabric.source_id": testHostSource}),
	} {
		t.Run(name, func(t *testing.T) {
			for _, kind := range []string{sourceKindEBPF, sourceKindAuditd} {
				host := with(hostRecordAttrs(), map[string]any{"fabric.capture.point": kind + "@0.11.0"})
				g := hostGuard(t, kind, "")
				_, err := g.processTraces(context.Background(), makeSpans("x", host, "y", agent))
				assertRefused(t, err, hostRefusalNotHostEvidence)
				if g.stats.snapshot().HostBatchRefused != 1 {
					t.Fatal("refusal not counted")
				}
			}
		})
	}
}

func TestAgentBatchWithSensorKeyRefused(t *testing.T) {
	legacy := createDefaultConfig()
	for name, g := range map[string]*guard{"agent": agentGuard(t), "legacy unbound": newTestGuard(t, legacy), "legacy bound": boundGuard(t)} {
		t.Run(name, func(t *testing.T) {
			for what, td := range map[string]ptrace.Traces{
				"sensor key on a record": makeSpans("x", with(recordAttrs(), map[string]any{"fabric.sensor.pid": int64(7)})),
				"host record":            makeSpans("x", hostRecordAttrs()),
				"kind-S point alone":     makeSpans("x", with(recordAttrs(), map[string]any{"fabric.capture.point": "host.auditd@1"})),
				"sensor key on a resource": func() ptrace.Traces {
					td := makeSpans("x", recordAttrs())
					td.ResourceSpans().At(0).Resource().Attributes().PutStr("fabric.sensor.scope", "agent")
					return td
				}(),
				"sensor key on an event": func() ptrace.Traces {
					td := makeSpans("x", recordAttrs())
					allSpans(td)[0].Events().AppendEmpty().Attributes().PutInt("fabric.sensor.upstream_lost", 1)
					return td
				}(),
				"host heartbeat": makeSpans("x", hostHeartbeatAttrs()),
			} {
				t.Run(what, func(t *testing.T) {
					_, err := g.processTraces(context.Background(), td)
					assertRefused(t, err, hostRefusalSensorOnAgent)
				})
			}
		})
	}
	// A duplicate still wins, so the reason does not depend on key order.
	td := wireDuplicateTraces(t, makeSpans("x", with(recordAttrs(), map[string]any{"fabric.sensor.pid": int64(7), placeholder("fabric.event_id"): testScopeID})), "fabric.event_id")
	_, err := agentGuard(t).processTraces(context.Background(), td)
	if err == nil || !strings.Contains(err.Error(), "duplicate attribute key") {
		t.Fatalf("duplicate did not win: %v", err)
	}
	// Other agent spans keep their admission.
	if _, err := agentGuard(t).processTraces(context.Background(), makeSpans("x", with(recordAttrs(), map[string]any{"fabric.source_id": testHostSource}))); err != nil {
		t.Fatal(err)
	}
}

// TestHostDigestsNeedBothPermissions: a digest reaches the export only when
// the sensor emitted it (its digests: permitted) and the group's guard sets
// host_digests: permitted (spec 053 §6.2.5).
func TestHostDigestsNeedBothPermissions(t *testing.T) {
	digests := map[string]any{
		"fabric.sensor.exe_sha256":  strings.Repeat("0a", 32),
		"fabric.sensor.argv_sha256": strings.Repeat("1b", 32),
		"fabric.sensor.path_sha256": strings.Repeat("2c", 32),
	}
	for _, tc := range []struct {
		name          string
		sensor, guard bool
	}{
		{"neither", false, false}, {"sensor only", true, false}, {"guard only", false, true}, {"both", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := hostRecordAttrs()
			if tc.sensor {
				attrs = with(attrs, digests)
			}
			mode := hostDigestsOmitted
			if tc.guard {
				mode = hostDigestsPermitted
			}
			span := allSpans(mustProcess(t, hostGuard(t, sourceKindEBPF, mode), makeSpans("x", attrs)))[0]
			for key, value := range digests {
				got, kept := span.Attributes().Get(key)
				if kept != (tc.sensor && tc.guard) || kept && got.Str() != value {
					t.Errorf("%s kept=%v", key, kept)
				}
			}
		})
	}
	// The default is omitted.
	span := allSpans(mustProcess(t, hostGuard(t, sourceKindEBPF, ""), makeSpans("x", with(hostRecordAttrs(), digests))))[0]
	if _, kept := span.Attributes().Get("fabric.sensor.exe_sha256"); kept {
		t.Fatal("default host_digests admitted a digest")
	}
}

func TestSensorEventCategory(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name     string
			Hint     string   `json:"name_hint"`
			Keys     []string `json:"attribute_keys"`
			Category string
		} `json:"sensor_cases"`
	}
	decodeJSON(t, vectorsDirectory+"span-category-v1.json", &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("empty sensor category vectors")
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			attrs := pcommon.NewMap()
			for _, key := range tc.Keys {
				attrs.PutStr(key, "")
			}
			if got := activityCategory(tc.Hint, attrs); got != tc.Category {
				t.Fatalf("got %q, want %q", got, tc.Category)
			}
		})
	}
}

func TestSourceKindConfiguration(t *testing.T) {
	base := func() *Config {
		cfg := createDefaultConfig()
		cfg.Profile = profileProduction
		cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: testHostTenant, SourceID: testHostSource}
		return cfg
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		ok     bool
	}{
		{"absent is legacy agent", func(*Config) {}, true},
		{"agent", func(c *Config) { c.SourceKind = sourceKindAgent }, true},
		{"ebpf", func(c *Config) { c.SourceKind = sourceKindEBPF }, true},
		{"auditd permitted", func(c *Config) { c.SourceKind, c.HostDigests = sourceKindAuditd, hostDigestsPermitted }, true},
		{"ebpf omitted", func(c *Config) { c.SourceKind, c.HostDigests = sourceKindEBPF, hostDigestsOmitted }, true},
		{"unknown kind", func(c *Config) { c.SourceKind = "host.etw" }, false},
		{"digests on agent", func(c *Config) { c.SourceKind, c.HostDigests = sourceKindAgent, hostDigestsOmitted }, false},
		{"digests on legacy", func(c *Config) { c.HostDigests = hostDigestsPermitted }, false},
		{"bad digests value", func(c *Config) { c.SourceKind, c.HostDigests = sourceKindEBPF, "yes" }, false},
		{"host on local", func(c *Config) { c.SourceKind, c.Profile = sourceKindEBPF, profileLocal }, false},
		{"host without binding", func(c *Config) { c.SourceKind, c.EvidenceSourceBinding = sourceKindEBPF, nil }, false},
		{"host with a clear source", func(c *Config) { c.SourceKind = sourceKindEBPF; c.EvidenceSourceBinding.SourceID = "node-a/ebpf" }, false},
		{"agent with a clear source", func(c *Config) { c.EvidenceSourceBinding.SourceID = "source-a" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.change(cfg)
			if err := cfg.Validate(); (err == nil) != tc.ok {
				t.Fatalf("Validate()=%v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// TestHostPlacementVectors pins the derived host placement and the host
// rule-A cases of records-span-v1.json on a host instance.
func TestHostPlacementVectors(t *testing.T) {
	var vectors struct {
		Placement []string `json:"host_placement"`
	}
	decodeJSON(t, vectorsDirectory+"records-span-v1.json", &vectors)
	keys := make([]string, 0, len(hostRecordKeys))
	for key := range hostRecordKeys {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !reflect.DeepEqual(keys, vectors.Placement) {
		t.Fatalf("host placement %v, want %v", keys, vectors.Placement)
	}
	// The manifest's host placement is the registry's manifest properties.
	var registry struct {
		Keys []struct {
			Key      string
			Manifest any `json:"manifest_property"`
		}
	}
	decodeJSON(t, coverageRegistry, &registry)
	manifest := map[string]struct{}{}
	for _, row := range registry.Keys {
		if row.Manifest != nil {
			manifest[row.Key] = struct{}{}
		}
	}
	if !reflect.DeepEqual(manifest, manifestSpanKeys) {
		t.Fatal("manifest span keys differ from the registry's manifest properties")
	}
}

// Host processing is idempotent like the rest of the guard: a second pass of
// an admitted batch changes nothing.
func TestHostAdmissionIsIdempotent(t *testing.T) {
	paths, _ := filepath.Glob(hostFixturesDirectory + "valid/*.json")
	for _, path := range paths {
		var fixture struct {
			Guard struct {
				SourceKind  string `json:"source_kind"`
				SourceID    string `json:"source_id"`
				HostDigests string `json:"host_digests"`
			}
			Batches []json.RawMessage
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &fixture); err != nil {
			t.Fatal(err)
		}
		cfg := createDefaultConfig()
		cfg.Profile, cfg.SourceKind, cfg.HostDigests = profileProduction, fixture.Guard.SourceKind, fixture.Guard.HostDigests
		cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: testHostTenant, SourceID: fixture.Guard.SourceID}
		g := newTestGuard(t, cfg)
		for _, batch := range fixture.Batches {
			td, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces(batch)
			if err != nil {
				t.Fatal(err)
			}
			once := mustProcess(t, g, td)
			first, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(once)
			twice := mustProcess(t, g, once)
			second, _ := (&ptrace.JSONMarshaler{}).MarshalTraces(twice)
			if string(first) != string(second) {
				t.Fatalf("%s: second pass changed the batch", filepath.Base(path))
			}
		}
	}
}
