// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// Spec 057 §10.4, WP7-14: an emitter that writes the neutral fabric.grant.*,
// fabric.control.*, fabric.hook.*, fabric.extension.* and fabric.mcp.* keys
// itself needs nothing else on the Node. testdata/neutral holds golden OTLP
// inputs (one record of each family on spans, two control records on
// security_context logs, a forged-invariant record, out-of-contract values and
// unrelated attributes); the goldens are what the Node exports for them.

func neutralTraces(t *testing.T) ptrace.Traces {
	t.Helper()
	var unmarshaler ptrace.JSONUnmarshaler
	td, err := unmarshaler.UnmarshalTraces(readFile(t, filepath.Join("testdata", "neutral", "neutral-emitter.traces.otlp.json")))
	if err != nil {
		t.Fatal(err)
	}
	return td
}

func neutralLogs(t *testing.T) plog.Logs {
	t.Helper()
	var unmarshaler plog.JSONUnmarshaler
	ld, err := unmarshaler.UnmarshalLogs(readFile(t, filepath.Join("testdata", "neutral", "neutral-emitter.logs.otlp.json")))
	if err != nil {
		t.Fatal(err)
	}
	return ld
}

func logRecordsOf(ld plog.Logs) []record {
	var out []record
	resourceLogs := ld.ResourceLogs()
	for ri := 0; ri < resourceLogs.Len(); ri++ {
		scopeLogs := resourceLogs.At(ri).ScopeLogs()
		for si := 0; si < scopeLogs.Len(); si++ {
			records := scopeLogs.At(si).LogRecords()
			for i := 0; i < records.Len(); i++ {
				out = append(out, record{Name: records.At(i).EventName(), Attributes: records.At(i).Attributes().AsRaw()})
			}
		}
	}
	return out
}

// The Node without a mapping processor: fabricguard alone admits the neutral
// keys with their closed checks.
func TestNeutralEmitterGoldenRecords(t *testing.T) {
	plain := &mapper{} // no profile, no source keys: a pass-through
	traces := throughNode(t, plain, guardConfig(nil), neutralTraces(t))
	checkGolden(t, "neutral-span-records.json", canonical(t, spanRecords(traces)))
	logs := logsThroughNode(t, plain, guardConfig(nil), neutralLogs(t))
	checkGolden(t, "neutral-log-records.json", canonical(t, logRecordsOf(logs)))

	all := everyString(traces) + everyLogString(logs)
	for _, canary := range []string{
		"jane.doe@example.com", "org-4471", "Refund order 8841", "deny refunds over 500",
		"call_7Hq2mXb41TzK", "my-previous-grant", "token=abc", "Refund Limit For Jane",
		"verified\"", "approve\"", "gen_ai.prompt", "user.email",
	} {
		if strings.Contains(all, canary) {
			t.Errorf("%q left the Node", canary)
		}
	}
}

// B5: a forged invariant never reaches the export, on a span or a log record;
// the record keeps its other admitted facts and no invariant claims anything
// but the constants.
func TestNeutralEmitterForgedInvariantsAreRefused(t *testing.T) {
	plain := &mapper{}
	records := append(spanRecords(throughNode(t, plain, guardConfig(nil), neutralTraces(t))),
		logRecordsOf(logsThroughNode(t, plain, guardConfig(nil), neutralLogs(t)))...)
	forged := 0
	for _, r := range records {
		if v, ok := r.Attributes["fabric.control.enforced_by_fabric"]; ok && v != false {
			t.Errorf("enforced_by_fabric = %v exported", v)
		}
		if v, ok := r.Attributes["fabric.control.authentication"]; ok && v != "unverified_caller_report" {
			t.Errorf("authentication = %v exported", v)
		}
		_, enforced := r.Attributes["fabric.control.enforced_by_fabric"]
		if r.Attributes["fabric.control.kind"] == "approval" && r.Attributes["fabric.control.decision"] == "allow" && !enforced {
			forged++
		}
	}
	if forged != 2 {
		t.Errorf("%d forged records kept without their invariants, want 2 (one span, one log)", forged)
	}
}

// OD-12 on the golden input: with genai_source_keys the pinned semantic-
// convention keys on the neutral record become its gated call, and are never
// exported under their own names.
func TestNeutralEmitterWithGenAISourceKeys(t *testing.T) {
	m := testMapper(t, "", func(cfg *Config) { cfg.GenAISourceKeys = GenAISemconvVersion })
	traces := throughNode(t, m, guardConfig(nil), neutralTraces(t))
	var found bool
	for _, r := range spanRecords(traces) {
		if r.Attributes["fabric.control.kind"] != "permission_check" {
			continue
		}
		found = true
		if got, want := r.Attributes["fabric.control.gated_tool_call_id"], hostrecords.V2("p", "call_7Hq2mXb41TzK", []byte(testIDKey)); got != want {
			t.Errorf("gated_tool_call_id = %v, want %v", got, want)
		}
		if r.Attributes["fabric.control.gated_kind"] != "tool_call" {
			t.Errorf("gated_kind = %v, want tool_call", r.Attributes["fabric.control.gated_kind"])
		}
	}
	if !found {
		t.Fatal("the permission_check record was not exported")
	}
	if text := everyString(traces); strings.Contains(text, "gen_ai.") || strings.Contains(text, "call_7Hq2mXb41TzK") {
		t.Error("a GenAI semantic-convention key or the clear call id left the Node")
	}
}
