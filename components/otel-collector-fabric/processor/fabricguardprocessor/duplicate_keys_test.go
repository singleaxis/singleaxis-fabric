// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// pcommon.Map.Put* never creates a duplicate key, but an OTLP protobuf
// payload can carry one and pdata keeps every KeyValue on unmarshal. These
// tests build such payloads the way an agent would send them: a placeholder
// key of the same length is written through pdata, then renamed at the wire
// level (a length-preserving byte rewrite keeps the protobuf valid), and the
// bytes are unmarshalled through pdata's protobuf path as the OTLP receiver
// does.

const foreignSource = "s-ffffffffffffffffffffffffffffffff"

// placeholder returns a same-length stand-in for key that no fixture uses.
func placeholder(key string) string { return key[:len(key)-1] + "\x01" }

func wireDuplicateTraces(t *testing.T, td ptrace.Traces, key string) ptrace.Traces {
	t.Helper()
	raw, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(td)
	if err != nil {
		t.Fatal(err)
	}
	raw = renameOnWire(t, raw, key)
	out, err := (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func wireDuplicateLogs(t *testing.T, ld plog.Logs, key string) plog.Logs {
	t.Helper()
	raw, err := (&plog.ProtoMarshaler{}).MarshalLogs(ld)
	if err != nil {
		t.Fatal(err)
	}
	raw = renameOnWire(t, raw, key)
	out, err := (&plog.ProtoUnmarshaler{}).UnmarshalLogs(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func renameOnWire(t *testing.T, raw []byte, key string) []byte {
	t.Helper()
	ph := []byte(placeholder(key))
	if n := bytes.Count(raw, ph); n != 1 {
		t.Fatalf("placeholder for %q occurs %d times on the wire", key, n)
	}
	return bytes.Replace(raw, ph, []byte(key), 1)
}

// countKey counts every occurrence of key, which Get cannot see past.
func countKey(attrs pcommon.Map, key string) int {
	n := 0
	attrs.Range(func(k string, _ pcommon.Value) bool {
		if k == key {
			n++
		}
		return true
	})
	return n
}

func assertDuplicateRefused(t *testing.T, err error) {
	t.Helper()
	if err == nil || !consumererror.IsPermanent(err) || status.Code(err) != codes.InvalidArgument ||
		!strings.HasSuffix(err.Error(), "fabricguard: duplicate attribute key rejected") || strings.Contains(err.Error(), foreignSource) {
		t.Fatalf("duplicate-key batch was not safely refused: %v", err)
	}
	if mapped, ok := status.FromError(err); !ok || mapped.Code() != codes.InvalidArgument {
		t.Fatalf("refusal would not map to an OTLP client error: %v", err)
	}
}

// D2: a span carrying fabric.source_id twice — bound value first, foreign
// value second — was admitted and stamped fabric.source.authenticated=true
// with both keys delivered, so a last-wins consumer read an authenticated
// span from the foreign source.
func TestDuplicateKeysRefuseTraceBatch(t *testing.T) {
	type place func(ptrace.Traces) pcommon.Map
	span := func(td ptrace.Traces) pcommon.Map { return firstSpan(td).Attributes() }
	resource := func(td ptrace.Traces) pcommon.Map { return td.ResourceSpans().At(0).Resource().Attributes() }
	scope := func(td ptrace.Traces) pcommon.Map {
		return td.ResourceSpans().At(0).ScopeSpans().At(0).Scope().Attributes()
	}
	event := func(td ptrace.Traces) pcommon.Map {
		s := firstSpan(td)
		if s.Events().Len() == 0 {
			s.Events().AppendEmpty().SetName("e")
		}
		return s.Events().At(0).Attributes()
	}
	link := func(td ptrace.Traces) pcommon.Map {
		s := firstSpan(td)
		if s.Links().Len() == 0 {
			s.Links().AppendEmpty()
		}
		return s.Links().At(0).Attributes()
	}
	cases := []struct {
		name         string
		where        place
		key          string
		first, again string
	}{
		{"span source bound first", span, "fabric.source_id", testSourceLabel, foreignSource},
		{"span source foreign first", span, "fabric.source_id", foreignSource, testSourceLabel},
		{"span source identical", span, "fabric.source_id", testSourceLabel, testSourceLabel},
		{"span tenant bound first", span, "fabric.tenant_id", "tenant-a", "tenant-b"},
		{"resource source bound first", resource, "fabric.source_id", testSourceLabel, foreignSource},
		{"resource tenant bound first", resource, "fabric.tenant_id", "tenant-a", "tenant-b"},
		{"scope source bound first", scope, "fabric.source_id", testSourceLabel, foreignSource},
		{"scope tenant foreign first", scope, "fabric.tenant_id", "tenant-b", "tenant-a"},
		{"span run id", span, "fabric.run.id", "trace:0af7651916cd43dd8448eb211c80319c", "trace:1af7651916cd43dd8448eb211c80319c"},
		{"span content ref", span, "fabric.content.request_ref", "0f8fad5b-d9cb-469f-a165-70867728950e", "1f8fad5b-d9cb-469f-a165-70867728950e"},
		{"span unlisted fabric key", span, "fabric.zz", "a", "b"},
		{"span authenticated stamp", span, sourceAuthenticatedKey, "true", "true"},
		{"event source", event, "fabric.source_id", testSourceLabel, foreignSource},
		{"link tenant", link, "fabric.tenant_id", "tenant-a", "tenant-b"},
	}
	for _, bound := range []bool{true, false} {
		for _, tc := range cases {
			name := tc.name
			if !bound {
				name = "unbound " + name
			}
			t.Run(name, func(t *testing.T) {
				td := makeTraces(spanFixture{name: "native", attrs: wireExchangeAttrs()})
				attrs := tc.where(td)
				attrs.Remove(tc.key)
				attrs.PutStr(tc.key, tc.first)
				attrs.PutStr(placeholder(tc.key), tc.again)
				td = wireDuplicateTraces(t, td, tc.key)
				if got := countKey(tc.where(td), tc.key); got != 2 {
					t.Fatalf("fixture carries %q %d times, want 2", tc.key, got)
				}
				firstSpan(td).Attributes().PutStr("fabric.prompt", "PRIVATE-CANARY")
				g := newTestGuard(t, nil)
				if bound {
					g = traceBoundGuard(t)
				}
				_, err := g.processTraces(context.Background(), td)
				assertDuplicateRefused(t, err)
				if v, _ := firstSpan(td).Attributes().Get("fabric.prompt"); v.Str() != "PRIVATE-CANARY" {
					t.Fatal("refused batch was partially processed")
				}
				if got := g.stats.snapshot().DuplicateKeyRejected; got != 1 {
					t.Fatalf("duplicate-key refusals counted %d, want 1", got)
				}
			})
		}
	}
}

// The same wire round trip without a duplicate, and with a duplicate
// non-fabric key (which the allowlist validates entry by entry and the
// binding never reads), is admitted and stamped.
func TestDuplicateKeysLegitimateTraceBatchPasses(t *testing.T) {
	for _, dupKey := range []string{"", "http.request.method"} {
		td := makeTraces(spanFixture{name: "native", attrs: wireExchangeAttrs()})
		if dupKey != "" {
			firstSpan(td).Attributes().PutStr(placeholder(dupKey), "GET")
			td = wireDuplicateTraces(t, td, dupKey)
		} else {
			raw, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(td)
			if err != nil {
				t.Fatal(err)
			}
			if td, err = (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(raw); err != nil {
				t.Fatal(err)
			}
		}
		g := traceBoundGuard(t)
		out, err := g.processTraces(context.Background(), td)
		if err != nil {
			t.Fatalf("legitimate batch (dup %q) refused: %v", dupKey, err)
		}
		attrs := firstSpan(out).Attributes()
		if stamp, ok := attrs.Get(sourceAuthenticatedKey); !ok || !stamp.Bool() {
			t.Fatalf("legitimate span not stamped: %v", attrs.AsRaw())
		}
		if countKey(attrs, "fabric.source_id") != 1 || countKey(attrs, sourceAuthenticatedKey) != 1 {
			t.Fatalf("legitimate span keys not unique: %v", attrs.AsRaw())
		}
		if g.stats.snapshot().DuplicateKeyRejected != 0 {
			t.Fatal("legitimate batch counted as a duplicate-key refusal")
		}
	}
}

func TestDuplicateKeysRefuseLogBatch(t *testing.T) {
	record := func(ld plog.Logs) pcommon.Map { return firstRecord(t, ld).Attributes() }
	resource := func(ld plog.Logs) pcommon.Map { return ld.ResourceLogs().At(0).Resource().Attributes() }
	scope := func(ld plog.Logs) pcommon.Map { return ld.ResourceLogs().At(0).ScopeLogs().At(0).Scope().Attributes() }
	cases := []struct {
		name         string
		where        func(plog.Logs) pcommon.Map
		key          string
		first, again string
	}{
		{"record source bound first", record, "source_id", "source-a", "source-b"},
		{"record source foreign first", record, "source_id", "source-b", "source-a"},
		{"record tenant bound first", record, "tenant_id", "tenant-a", "tenant-b"},
		{"record class", record, "event_class", "evidence", "activity"},
		{"record run id", record, "run_id", "run-a", "run-b"},
		{"record content digest", record, "content_sha256", "sha256:" + hex64("a"), "sha256:" + hex64("b")},
		{"record fabric key", record, "fabric.source_id", "source-a", "source-b"},
		{"resource fabric key", resource, "fabric.tenant_id", "tenant-a", "tenant-b"},
		{"scope fabric key", scope, "fabric.source_id", "source-a", "source-b"},
	}
	for _, bound := range []bool{true, false} {
		for _, tc := range cases {
			name := tc.name
			if !bound {
				name = "unbound " + name
			}
			t.Run(name, func(t *testing.T) {
				ld := makeLogs(boundRecord())
				firstRecord(t, ld).SetEventName("agent.evidence.call")
				attrs := tc.where(ld)
				attrs.Remove(tc.key)
				attrs.PutStr(tc.key, tc.first)
				attrs.PutStr(placeholder(tc.key), tc.again)
				ld = wireDuplicateLogs(t, ld, tc.key)
				if got := countKey(tc.where(ld), tc.key); got != 2 {
					t.Fatalf("fixture carries %q %d times, want 2", tc.key, got)
				}
				firstRecord(t, ld).Body().SetStr("PRIVATE-CANARY")
				g := newTestGuard(t, nil)
				if bound {
					g = boundGuard(t)
				}
				_, err := g.processLogs(context.Background(), ld)
				assertDuplicateRefused(t, err)
				if firstRecord(t, ld).Body().Str() != "PRIVATE-CANARY" {
					t.Fatal("refused batch was partially processed")
				}
				if got := g.stats.snapshot().DuplicateKeyRejected; got != 1 {
					t.Fatalf("duplicate-key refusals counted %d, want 1", got)
				}
			})
		}
	}
}

func TestDuplicateKeysLegitimateLogBatchPasses(t *testing.T) {
	ld := makeLogs(boundRecord())
	firstRecord(t, ld).SetEventName("agent.evidence.call")
	raw, err := (&plog.ProtoMarshaler{}).MarshalLogs(ld)
	if err != nil {
		t.Fatal(err)
	}
	if ld, err = (&plog.ProtoUnmarshaler{}).UnmarshalLogs(raw); err != nil {
		t.Fatal(err)
	}
	out, err := boundGuard(t).processLogs(context.Background(), ld)
	if err != nil || recordCount(out) != 1 {
		t.Fatalf("legitimate evidence refused: count=%d err=%v", recordCount(out), err)
	}
}

// The scan of an attribute map with no guarded key must not allocate: it
// runs on every resource, scope, span, event, link and record.
func TestDuplicateKeyScanDoesNotAllocate(t *testing.T) {
	attrs := pcommon.NewMap()
	for _, k := range []string{"http.request.method", "gen_ai.operation.name", "service.name", "url.scheme"} {
		attrs.PutStr(k, "v")
	}
	if n := testing.AllocsPerRun(100, func() { _ = hasDuplicateKey(attrs, isTraceGuardedKey) }); n != 0 {
		t.Fatalf("scan without guarded keys allocated %v times", n)
	}
	small := pcommon.NewMap()
	for k, v := range wireExchangeAttrs() {
		if s, ok := v.(string); ok {
			small.PutStr(k, s)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _ = hasDuplicateKey(small, isTraceGuardedKey) }); n != 0 {
		t.Fatalf("scan of a capture span allocated %v times", n)
	}
}
