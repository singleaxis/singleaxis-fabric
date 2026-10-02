// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap/zaptest"
)

// newTestGuard returns a guard wired with the supplied config, or
// defaults when cfg is nil. Tests mutate pdata in place so the logger
// surface is small.
func newTestGuard(t *testing.T, cfg *Config) *guard {
	t.Helper()
	if cfg == nil {
		cfg = createDefaultConfig()
	}
	return newGuard(cfg, zaptest.NewLogger(t))
}

// makeLogs builds a plog.Logs with a single resource / scope and one
// log record per supplied attribute map. Keys that look like
// "event_class" are stored as strings so the class extraction path
// stays realistic.
func makeLogs(records ...map[string]any) plog.Logs {
	ld := plog.NewLogs()
	sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	for _, attrs := range records {
		lr := sl.LogRecords().AppendEmpty()
		for k, v := range attrs {
			switch val := v.(type) {
			case string:
				lr.Attributes().PutStr(k, val)
			case int:
				lr.Attributes().PutInt(k, int64(val))
			case float64:
				lr.Attributes().PutDouble(k, val)
			case bool:
				lr.Attributes().PutBool(k, val)
			}
		}
	}
	return ld
}

func firstRecord(t *testing.T, ld plog.Logs) plog.LogRecord {
	t.Helper()
	if ld.ResourceLogs().Len() == 0 {
		t.Fatal("no resource logs")
	}
	sl := ld.ResourceLogs().At(0).ScopeLogs()
	if sl.Len() == 0 || sl.At(0).LogRecords().Len() == 0 {
		t.Fatal("no records")
	}
	return sl.At(0).LogRecords().At(0)
}

func recordCount(ld plog.Logs) int {
	n := 0
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		sls := rls.At(i).ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			n += sls.At(j).LogRecords().Len()
		}
	}
	return n
}

func TestEvidenceProjectionClosedMetadata(t *testing.T) {
	base := map[string]any{
		"event_class": "evidence", "schema_version": "agent.evidence.event/v1",
		"record_id": "evt-1", "tenant_id": "tenant-1", "run_id": "run-1",
		"source_id": "source-1", "source_epoch": 1, "source_sequence": 2,
		"operation_id": "op-1", "attempt_id": "try-1", "boundary": "terminal",
		"provenance": "caller_reported", "role": "terminal.stdout", "status": "stored",
		"content_object_id": "obj-1", "content_sha256": "sha256:" + strings.Repeat("a", 64),
		"observed_at": "2026-09-26T10:00:00Z", "raw_output": "CANARY-SECRET",
		"content_ref": "file:///private/CANARY-SECRET",
	}
	ld := makeLogs(base)
	lr := firstRecord(t, ld)
	lr.SetEventName("agent.evidence.content")
	lr.Body().SetStr("CANARY-SECRET")
	resource := ld.ResourceLogs().At(0)
	resource.Resource().Attributes().PutStr("service.name", "CANARY-SECRET")
	resource.ScopeLogs().At(0).Scope().Attributes().PutStr("service.name", "CANARY-SECRET")
	out, err := newTestGuard(t, nil).processLogs(context.Background(), ld)
	if err != nil || recordCount(out) != 1 {
		t.Fatalf("valid projection rejected: count=%d err=%v", recordCount(out), err)
	}
	lr = firstRecord(t, out)
	if lr.EventName() != "agent.evidence.content" || lr.Body().Type() != pcommon.ValueTypeEmpty {
		t.Fatal("name not preserved or body not cleared")
	}
	if out.ResourceLogs().At(0).Resource().Attributes().Len() != 0 || out.ResourceLogs().At(0).ScopeLogs().At(0).Scope().Attributes().Len() != 0 {
		t.Fatal("evidence resource/scope metadata not cleared")
	}
	for _, key := range []string{"raw_output", "content_ref"} {
		if _, ok := lr.Attributes().Get(key); ok {
			t.Fatalf("unsafe key retained: %s", key)
		}
	}
	for _, test := range []struct {
		key   string
		value any
		name  string
	}{
		{"role", "CANARY-SECRET", "agent.evidence.content"},
		{"tenant_id", "tenant/CANARY-SECRET", "agent.evidence.content"},
		{"status", "CANARY-SECRET", "agent.evidence.content"},
		{"content_sha256", "sha256:CANARY-SECRET", "agent.evidence.content"},
		{"role", "terminal.stdout", "CANARY-SECRET"},
	} {
		attrs := make(map[string]any, len(base))
		for key, value := range base {
			attrs[key] = value
		}
		attrs[test.key] = test.value
		bad := makeLogs(attrs)
		firstRecord(t, bad).SetEventName(test.name)
		filtered, err := newTestGuard(t, nil).processLogs(context.Background(), bad)
		if err != nil || recordCount(filtered) != 0 {
			t.Fatalf("invalid %s/%s survived: count=%d err=%v", test.key, test.name, recordCount(filtered), err)
		}
	}
}

func TestAllowlistStripsUnknownAttributes(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := makeLogs(map[string]any{
		"event_class":  "decision_summary",
		"tenant_id":    "t-1",
		"agent_id":     "a-1",
		"cost_usd":     0.01,
		"internal_pii": "ssn-123-45-6789", // NOT in allowlist
		"secret_note":  "do not leak",     // NOT in allowlist
	})

	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if recordCount(out) != 1 {
		t.Fatalf("expected 1 record, got %d", recordCount(out))
	}
	lr := firstRecord(t, out)
	if _, ok := lr.Attributes().Get("internal_pii"); ok {
		t.Error("internal_pii should have been stripped")
	}
	if _, ok := lr.Attributes().Get("secret_note"); ok {
		t.Error("secret_note should have been stripped")
	}
	if v, ok := lr.Attributes().Get("tenant_id"); !ok || v.Str() != "t-1" {
		t.Error("tenant_id should have been preserved")
	}
}

func TestAllowlistDropsUnknownClasses(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := makeLogs(
		map[string]any{"event_class": "decision_summary", "tenant_id": "t-1"},
		map[string]any{"event_class": "not_a_fabric_class", "tenant_id": "t-1"},
		map[string]any{"tenant_id": "t-1"}, // no event_class at all
	)
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if got := recordCount(out); got != 1 {
		t.Fatalf("expected 1 record after dropping unknown classes, got %d", got)
	}
}

func TestAllowlistKeepsUnknownWhenDropDisabled(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.DropUnknownClasses = false
	g := newTestGuard(t, cfg)
	ld := makeLogs(
		map[string]any{"event_class": "decision_summary", "tenant_id": "t-1"},
		map[string]any{"event_class": "mystery", "tenant_id": "t-1", "weird": "x"},
	)
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if got := recordCount(out); got != 2 {
		t.Fatalf("expected 2 records when drop disabled, got %d", got)
	}
	second := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(1)
	if _, ok := second.Attributes().Get("weird"); ok {
		t.Error("unknown-class debug mode must still strip non-envelope attributes")
	}
}

func TestLogsRemoveBodyAndFilterResourceScopeAndSensitiveExtensions(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.ExtraAllowedFields = map[string][]string{
		"activity": {"customer.region", "customer.prompt", "customer.response", "authorization", "authorization_hash"},
	}
	g := newTestGuard(t, cfg)
	ld := makeLogs(map[string]any{
		"event_class": "activity", "event_id": "e-1", "customer.region": "eu",
		"customer.prompt": "raw prompt", "customer.response": "raw response",
		"authorization": "Bearer secret", "authorization_hash": "sha256:still-credential-shaped",
		"gen_ai.output.messages": "raw response",
	})
	rl := ld.ResourceLogs().At(0)
	rl.SetSchemaUrl("https://schemas.invalid/patient/Jane-Doe?secretKey=abc")
	rl.Resource().Attributes().PutStr("service.name", "agent")
	rl.Resource().Attributes().PutStr("host.name", "private-host")
	sl := rl.ScopeLogs().At(0)
	sl.SetSchemaUrl("https://scope.invalid/clientSecret")
	sl.Scope().SetName("patient-Jane-Doe")
	sl.Scope().SetVersion("bearerToken=secret")
	sl.Scope().Attributes().PutStr("otel.scope.version", "1.0")
	sl.Scope().Attributes().PutStr("scope.secret", "private")
	sl.LogRecords().At(0).Body().SetStr("raw patient content")
	sl.LogRecords().At(0).SetSeverityText("ERROR patient=Jane-Doe x-api-key=secret")

	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	record := firstRecord(t, out)
	if record.Body().Type() != pcommon.ValueTypeEmpty {
		t.Error("log body should be cleared")
	}
	if record.SeverityText() != "" {
		t.Error("severity text should be cleared; severity number is the safe channel")
	}
	if rl.SchemaUrl() != "" || sl.SchemaUrl() != "" || sl.Scope().Name() != "" || sl.Scope().Version() != "" {
		t.Error("log resource/scope native text fields should be cleared")
	}
	if _, ok := record.Attributes().Get("customer.region"); !ok {
		t.Error("safe exact extension should survive")
	}
	for _, key := range []string{"customer.prompt", "customer.response", "authorization", "authorization_hash", "gen_ai.output.messages"} {
		if _, ok := record.Attributes().Get(key); ok {
			t.Errorf("sensitive field %q survived", key)
		}
	}
	if _, ok := rl.Resource().Attributes().Get("service.name"); !ok {
		t.Error("safe resource identity should survive")
	}
	if _, ok := rl.Resource().Attributes().Get("host.name"); ok {
		t.Error("unknown resource identity should be removed")
	}
	if _, ok := sl.Scope().Attributes().Get("otel.scope.version"); !ok {
		t.Error("safe producer scope should survive")
	}
	if _, ok := sl.Scope().Attributes().Get("scope.secret"); ok {
		t.Error("secret scope attribute should be removed")
	}
	stats := g.stats.snapshot()
	if stats.LogBodyRemoved != 1 || stats.SensitiveRemoved < 5 {
		t.Fatalf("unexpected removal counters: %+v", stats)
	}
}

func TestAllowlistRemovesOversizedStrings(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.MaxFieldBytes = 64
	g := newTestGuard(t, cfg)
	huge := strings.Repeat("x", 200)
	ld := makeLogs(map[string]any{
		"event_class": "decision_summary",
		"tenant_id":   "t-1",
		"model":       huge,
	})
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	lr := firstRecord(t, out)
	if _, ok := lr.Attributes().Get("model"); ok {
		t.Error("oversized model should have been removed")
	}
}

func TestMaxFieldBytesZeroIsRejected(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.MaxFieldBytes = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("max_field_bytes=0 must be rejected: it silently disables oversized-value removal")
	}
}

func TestLogRecordEventNameIsNormalized(t *testing.T) {
	g := newTestGuard(t, nil)
	marker := "patient Jane Doe SSN 123-45-6789"
	ld := makeLogs(map[string]any{
		"event_class": "decision_summary",
		"tenant_id":   "t-1",
	})
	rec := firstRecord(t, ld)
	rec.SetEventName(marker)

	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if recordCount(out) != 1 {
		t.Fatalf("expected 1 record, got %d", recordCount(out))
	}
	got := firstRecord(t, out).EventName()
	if strings.Contains(got, marker) || got == marker {
		t.Fatalf("caller-controlled event_name %q survived processing", got)
	}
	if got != "fabric.activity" {
		t.Errorf("event_name = %q, want fixed category fabric.activity", got)
	}
	if g.stats.snapshot().NativeTextNormalized < 1 {
		t.Error("event_name normalization should count in nativeTextNormalized")
	}
}

func TestLogRecordEventNameKeepsKnownCategory(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := makeLogs(map[string]any{
		"event_class":      "activity",
		"tenant_id":        "t-1",
		"fabric.tool.name": "ehr_write",
	})
	rec := firstRecord(t, ld)
	rec.SetEventName("fabric.tool_call")

	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if got := firstRecord(t, out).EventName(); got != "fabric.tool_call" {
		t.Errorf("vocabulary event_name = %q, want fabric.tool_call", got)
	}
}

func TestAllowlistDropsRecordsThatBecomeEmpty(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := plog.NewLogs()
	sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Attributes().PutStr("event_class", "decision_summary")
	lr.Attributes().PutStr("junk_a", "x")
	lr.Attributes().PutStr("junk_b", "y")

	// First pass: event_class itself is allowlisted, so the record
	// survives with just that field after junk is stripped.
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	if recordCount(out) != 1 {
		t.Fatalf("first pass should keep record, got %d", recordCount(out))
	}

	// Strip the class attribute and re-run: now the class is unknown
	// (empty) and drop_unknown_classes=true removes the record.
	firstRecord(t, out).Attributes().Remove("event_class")
	out2, err := g.processLogs(context.Background(), out)
	if err != nil {
		t.Fatalf("processLogs 2: %v", err)
	}
	if got := recordCount(out2); got != 0 {
		t.Fatalf("expected 0 after class removal, got %d", got)
	}
}

func TestAllowlistExtraAllowedFields(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.ExtraAllowedFields = map[string][]string{
		"decision_summary": {"tenant_override_id"},
	}
	g := newTestGuard(t, cfg)
	ld := makeLogs(map[string]any{
		"event_class":        "decision_summary",
		"tenant_id":          "t-1",
		"tenant_override_id": "to-42",
		"not_allowed":        "x",
	})
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	lr := firstRecord(t, out)
	if _, ok := lr.Attributes().Get("tenant_override_id"); !ok {
		t.Error("tenant_override_id should be allowed via extras")
	}
	if _, ok := lr.Attributes().Get("not_allowed"); ok {
		t.Error("not_allowed should still be stripped")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"default is valid", func(c *Config) {}, ""},
		{"empty class attr", func(c *Config) { c.EventClassAttribute = "" }, "event_class_attribute"},
		{"negative max bytes", func(c *Config) { c.MaxFieldBytes = -1 }, "max_field_bytes"},
		{"zero max bytes", func(c *Config) { c.MaxFieldBytes = 0 }, "max_field_bytes"},
		{"zero max attributes", func(c *Config) { c.MaxAttributes = 0 }, "max_attributes"},
		{"zero max events", func(c *Config) { c.MaxEventsPerSpan = 0 }, "max_events_per_span"},
		{"zero max links", func(c *Config) { c.MaxLinksPerSpan = 0 }, "max_links_per_span"},
		{"zero max slice elements", func(c *Config) { c.MaxSliceElements = 0 }, "max_slice_elements"},
		{"unknown extras class", func(c *Config) {
			c.ExtraAllowedFields = map[string][]string{"not_a_class": {"x"}}
		}, "unknown event class"},
		{"prefix policies rejected", func(c *Config) { c.TraceAttributePrefixes = []string{"fabric."} }, "no longer supported"},
		{"empty extras key", func(c *Config) {
			c.ExtraAllowedFields = map[string][]string{"": {"x"}}
		}, "empty class key"},
		{"sensitive log extension", func(c *Config) {
			c.ExtraAllowedFields = map[string][]string{"activity": {"customer.prompt"}}
		}, "prohibited sensitive field"},
		{"sensitive trace extension", func(c *Config) {
			c.ExtraAllowedTraceFields = []string{"http.request.header.authorization"}
		}, "prohibited sensitive field"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := createDefaultConfig()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestFactoryTypeAndDefaults(t *testing.T) {
	f := NewFactory()
	if got := f.Type().String(); got != "fabricguard" {
		t.Errorf("factory type = %q, want fabricguard", got)
	}
	cfg, ok := f.CreateDefaultConfig().(*Config)
	if !ok {
		t.Fatalf("default config wrong type: %T", f.CreateDefaultConfig())
	}
	if cfg.EventClassAttribute != "event_class" || cfg.MaxFieldBytes != 8192 || !cfg.DropUnknownClasses ||
		cfg.MaxAttributes != 256 || cfg.MaxEventsPerSpan != 128 || cfg.MaxLinksPerSpan != 64 || cfg.MaxSliceElements != 64 {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestMergeAllowedReturnsBaseWhenNoExtras(t *testing.T) {
	got, ok := mergeAllowed("decision_summary", nil)
	if !ok {
		t.Fatal("decision_summary should be a known class")
	}
	if _, ok := got["tenant_id"]; !ok {
		t.Error("tenant_id should be in built-in allowlist")
	}
}

func TestMergeAllowedUnknownClass(t *testing.T) {
	if _, ok := mergeAllowed("nope", nil); ok {
		t.Error("unknown class should return ok=false")
	}
}

func TestHostLossReasonIsExactAuditMetadata(t *testing.T) {
	audit, ok := mergeAllowed("audit", nil)
	if !ok {
		t.Fatal("audit class missing")
	}
	if _, ok := audit["audit.loss_reason"]; !ok {
		t.Fatal("closed host loss reason must survive audit protection")
	}
	if _, ok := audit["log.record.uid"]; !ok {
		t.Fatal("stable host record identity must survive for deduplication")
	}
	if _, ok := audit["audit.loss_detail"]; ok {
		t.Fatal("arbitrary raw host loss detail must not be exported")
	}
	if sensitiveAttributeKey("audit.loss_reason") {
		t.Fatal("closed loss reason should be safe metadata")
	}
	if sensitiveAttributeKey("log.record.uid") {
		t.Fatal("opaque record identity should be safe metadata")
	}
}

func TestHostAuditValuesRejectCallerControlledText(t *testing.T) {
	g := newTestGuard(t, nil)
	ld := makeLogs(
		map[string]any{
			"event_class":                    "audit",
			"audit.event":                    "capture_loss",
			"audit.loss_reason":              "ring_buffer_full",
			"log.record.uid":                 "host-0123456789abcdef0123456789abcdef",
			"audit.dedupe_key":               "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"process.executable.path_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"file.path_sha256":               "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		map[string]any{
			"event_class":             "audit",
			"audit.event":             "secret=do-not-export",
			"audit.loss_reason":       "secret=do-not-export",
			"log.record.uid":          "host-token-do-not-export",
			"audit.dedupe_key":        "secret=/private/customer/file",
			"process.executable.path": "/private/customer/secret-file",
			"file.path":               "/private/customer/secret-file",
		},
	)
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatalf("processLogs: %v", err)
	}
	first := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if _, ok := first.Attributes().Get("audit.loss_reason"); !ok {
		t.Fatal("closed loss reason was stripped")
	}
	if _, ok := first.Attributes().Get("log.record.uid"); !ok {
		t.Fatal("opaque record id was stripped")
	}
	if _, ok := first.Attributes().Get("audit.dedupe_key"); !ok {
		t.Fatal("hashed dedupe key was stripped")
	}
	if _, ok := first.Attributes().Get("process.executable.path_sha256"); !ok {
		t.Fatal("hashed executable path was stripped")
	}
	if _, ok := first.Attributes().Get("file.path_sha256"); !ok {
		t.Fatal("hashed file path was stripped")
	}
	second := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(1)
	if _, ok := second.Attributes().Get("audit.event"); ok {
		t.Fatal("free-form audit event leaked")
	}
	if _, ok := second.Attributes().Get("audit.loss_reason"); ok {
		t.Fatal("free-form loss reason leaked")
	}
	if _, ok := second.Attributes().Get("log.record.uid"); ok {
		t.Fatal("free-form record id leaked")
	}
	if _, ok := second.Attributes().Get("audit.dedupe_key"); ok {
		t.Fatal("raw dedupe key leaked")
	}
	if _, ok := second.Attributes().Get("process.executable.path"); ok {
		t.Fatal("raw executable path leaked")
	}
	if _, ok := second.Attributes().Get("file.path"); ok {
		t.Fatal("raw file path leaked")
	}
}

func TestBuiltInClassesAreRecorderOnly(t *testing.T) {
	for _, class := range []string{"red_team_result", "escalation", "judge_result", "assurance_finding"} {
		if _, ok := BuiltInAllowedFields[class]; ok {
			t.Errorf("assurance/control class %q must not be enabled by the recorder", class)
		}
	}
	for _, class := range []string{"activity", "audit", "decision_summary"} {
		if _, ok := BuiltInAllowedFields[class]; !ok {
			t.Errorf("observed activity class %q should remain supported", class)
		}
	}
}

func TestSensitiveAttributeKey(t *testing.T) {
	tests := map[string]bool{
		"prompt":                            true,
		"customer.response":                 true,
		"gen_ai.input.messages":             true,
		"tool.arguments":                    true,
		"http.request.header.authorization": true,
		"authorization_hash":                true,
		"x-api-key":                         true,
		"XApiKey":                           true,
		"secretKey":                         true,
		"clientSecret":                      true,
		"bearerToken":                       true,
		"customer.session-token":            true,
		"fabric.tool.arguments_hash":        false,
		"fabric.interaction.payload_hash":   false,
		"gen_ai.response.model":             false,
		"fabric.llm.usage.input_tokens":     false,
	}
	for key, want := range tests {
		if got := sensitiveAttributeKey(key); got != want {
			t.Errorf("sensitiveAttributeKey(%q) = %v, want %v", key, got, want)
		}
	}
}

var _ = pcommon.NewMap // keep pcommon import in case test utilities evolve

func TestDurableAuditIdentityAndLossEvidenceSurviveProtection(t *testing.T) {
	g := newTestGuard(t, nil)
	fields := map[string]any{
		"event_class": "audit", "audit.event": "logfile_checkpoint",
		"fabric.record_id": strings.Repeat("a", 64), "audit.source_id": strings.Repeat("b", 32),
		"audit.source_generation": int(2), "audit.cursor_start": int(0), "audit.cursor_end": int(4096),
		"audit.assembly_complete": false, "audit.input_records": int(3), "audit.filtered_events": int(0),
		"audit.invalid_records": int(1), "audit.oversized_records": int(1), "audit.incomplete_events": int(1),
		"audit.unmatched_events": int(1), "audit.discarded_bytes": int(4096),
	}
	bad := map[string]any{"event_class": "audit"}
	for k := range fields {
		if k != "event_class" {
			bad[k] = "secret=/private/customer/argv"
		}
	}
	ld := makeLogs(fields, bad)
	out, err := g.processLogs(context.Background(), ld)
	if err != nil {
		t.Fatal(err)
	}
	records := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	for k := range fields {
		if _, ok := records.At(0).Attributes().Get(k); !ok {
			t.Errorf("durable evidence stripped: %s", k)
		}
	}
	for k := range bad {
		if k != "event_class" {
			if _, ok := records.At(1).Attributes().Get(k); ok {
				t.Errorf("caller-controlled text leaked: %s", k)
			}
		}
	}
	for _, reason := range []string{"source_rotated", "source_rotation_gap", "source_missing", "source_truncated_or_rewritten"} {
		out, err := g.processLogs(context.Background(), makeLogs(map[string]any{"event_class": "audit", "audit.event": reason}))
		if err != nil {
			t.Fatal(err)
		}
		v, ok := out.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("audit.event")
		if !ok || v.Str() != reason {
			t.Fatalf("loss evidence %q stripped", reason)
		}
	}
}
