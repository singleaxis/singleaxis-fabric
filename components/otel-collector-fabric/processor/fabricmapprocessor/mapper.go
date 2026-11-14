// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

const (
	// mappedName replaces the emitter's span or log name on a mapped record:
	// a caller-chosen name can hold anything. fabricguard gives it its public
	// category.
	mappedName = "fabric.security_context"
	// capturePoint is stamped on every record a profile produced (spec 057 §3
	// rule 7, §6.4).
	capturePoint = "otlp.mapping_profile@1"
	// logClass is fabricguard's log class for security-context records.
	logClass          = "security_context"
	logClassAttribute = "event_class"
	maxSliceItems     = 64
	maxIDBytes        = 4096

	captureInputKey = "fabric.capture.input"
)

// stepKinds: the record kind's step kind (spec 057 §5.1): grant snapshots and
// extension inventories are run annotations.
var stepKinds = map[string]string{"control": "control", "hook": "hook", "grant": "run", "extension": "run"}

// originActors is how a rule's assertion_origin reaches telemetry: the
// record's actor type, for the two origins the actor vocabulary names. The
// others leave the actor unstated (it reads as unknown).
var originActors = map[string]string{"provider": "provider", "service": "external_service"}

type mapStats struct {
	mapped            atomic.Uint64 // records a rule rewrote
	attributesDropped atomic.Uint64 // attributes outside the profile
	valuesUnmapped    atomic.Uint64 // a mapped source whose value was not usable
	sourcesAccepted   atomic.Uint64 // semantic-convention source keys translated
}

type mapper struct {
	profile      *profile
	key          []byte
	genAISources bool
	binding      *SourceBinding
	logger       *zap.Logger
	stats        mapStats
}

func (m *mapper) processTraces(_ context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	resourceSpans := td.ResourceSpans()
	for ri := 0; ri < resourceSpans.Len(); ri++ {
		scopeSpans := resourceSpans.At(ri).ScopeSpans()
		for si := 0; si < scopeSpans.Len(); si++ {
			spans := scopeSpans.At(si).Spans()
			for i := 0; i < spans.Len(); i++ {
				m.mapSpan(spans.At(i))
			}
		}
	}
	return td, nil
}

func (m *mapper) processLogs(_ context.Context, ld plog.Logs) (plog.Logs, error) {
	resourceLogs := ld.ResourceLogs()
	for ri := 0; ri < resourceLogs.Len(); ri++ {
		scopeLogs := resourceLogs.At(ri).ScopeLogs()
		for si := 0; si < scopeLogs.Len(); si++ {
			records := scopeLogs.At(si).LogRecords()
			for i := 0; i < records.Len(); i++ {
				m.mapLog(records.At(i))
			}
		}
	}
	return ld, nil
}

func (m *mapper) mapSpan(span ptrace.Span) {
	attrs := span.Attributes()
	// A Fabric capture record (wire or records input) is never an emitter's
	// record: it passes untouched.
	if _, capture := attrs.Get(captureInputKey); capture {
		return
	}
	if r := m.matchRule(span.Name(), "", attrs); r != nil {
		m.applyRule(r, attrs)
		if m.binding != nil {
			attrs.PutStr("fabric.tenant_id", m.binding.TenantID)
			attrs.PutStr("fabric.source_id", m.binding.SourceID)
		}
		span.SetName(mappedName)
		span.Events().RemoveIf(func(ptrace.SpanEvent) bool { return true })
		span.Links().RemoveIf(func(ptrace.SpanLink) bool { return true })
		span.Status().SetMessage("")
		span.TraceState().FromRaw("")
		return
	}
	m.acceptGenAISources(attrs)
}

func (m *mapper) mapLog(record plog.LogRecord) {
	attrs := record.Attributes()
	if _, capture := attrs.Get(captureInputKey); capture {
		return
	}
	if r := m.matchRule("", record.EventName(), attrs); r != nil {
		m.applyRule(r, attrs)
		attrs.PutStr(logClassAttribute, logClass)
		if m.binding != nil {
			attrs.PutStr("tenant_id", m.binding.TenantID)
			attrs.PutStr("source_id", m.binding.SourceID)
		}
		record.SetEventName(mappedName)
		_ = record.Body().FromRaw(nil)
		record.SetSeverityText("")
		return
	}
	m.acceptGenAISources(attrs)
}

// matchRule returns the first rule whose name and literal attributes match.
func (m *mapper) matchRule(spanName, logName string, attrs pcommon.Map) *rule {
	if m.profile == nil {
		return nil
	}
	for i := range m.profile.rules {
		r := &m.profile.rules[i]
		if spanName != "" && r.Match.SpanName != spanName || logName != "" && r.Match.LogName != logName {
			continue
		}
		if spanName == "" && logName == "" {
			continue
		}
		matched := true
		for key, want := range r.Match.Attributes {
			got, ok := attrs.Get(key)
			if !ok || !literalEquals(want, got) {
				matched = false
				break
			}
		}
		if matched {
			return r
		}
	}
	return nil
}

// literalEquals compares a profile literal with an attribute value: the same
// type and value; an integer literal also equals a double of the same value.
func literalEquals(want literal, got pcommon.Value) bool {
	switch got.Type() {
	case pcommon.ValueTypeStr:
		return want.kind == 's' && want.s == got.Str()
	case pcommon.ValueTypeBool:
		return want.kind == 'b' && want.b == got.Bool()
	case pcommon.ValueTypeInt:
		return want.kind == 'i' && want.i == got.Int() || want.kind == 'f' && want.f == float64(got.Int())
	case pcommon.ValueTypeDouble:
		return (want.kind == 'i' || want.kind == 'f') && want.f == got.Double()
	default:
		return false
	}
}

func putLiteral(attrs pcommon.Map, key string, value literal) {
	switch value.kind {
	case 's':
		attrs.PutStr(key, value.s)
	case 'i':
		attrs.PutInt(key, value.i)
	case 'f':
		attrs.PutDouble(key, value.f)
	case 'b':
		attrs.PutBool(key, value.b)
	}
}

// applyRule replaces attrs by the rule's targets. Drop-by-default: nothing of
// the source record survives unless a mapping names it.
func (m *mapper) applyRule(r *rule, attrs pcommon.Map) {
	out := pcommon.NewMap()
	used := 0
	for i := range r.Map {
		mp := &r.Map[i]
		source, ok := attrs.Get(mp.Source)
		if !ok {
			continue
		}
		used++
		if !m.mapValue(mp, source, out) {
			m.stats.valuesUnmapped.Add(1)
		}
	}
	for _, s := range r.Set {
		putLiteral(out, s.Target, *s.Value)
	}
	// The Node's own statements about the record. Provenance is always
	// reported (spec 057 §3 rule 3); a control record's constants are never
	// taken from the emitter (B5).
	out.PutStr("fabric.capture.source", "reported")
	out.PutStr("fabric.capture.point", capturePoint)
	out.PutStr("fabric.step.kind", stepKinds[r.Record])
	if actor, ok := originActors[r.AssertionOrigin]; ok {
		out.PutStr("fabric.actor.type", actor)
	}
	switch r.Record {
	case "control":
		out.PutStr("fabric.control.authentication", "unverified_caller_report")
		out.PutBool("fabric.control.enforced_by_fabric", false)
	}
	for target, value := range stampedTargets[r.Record] {
		out.PutStr(target, value)
	}
	if dropped := attrs.Len() - used; dropped > 0 {
		m.stats.attributesDropped.Add(uint64(dropped))
	}
	m.stats.mapped.Add(1)
	out.MoveTo(attrs)
}

// mapValue writes one mapping's target; false when the source value cannot
// be used (then the target is omitted, never guessed).
func (m *mapper) mapValue(mp *mapping, source pcommon.Value, out pcommon.Map) bool {
	switch {
	case mp.Values != nil:
		for _, entry := range mp.Values {
			if literalEquals(entry.From, source) {
				putLiteral(out, mp.Target, entry.To)
				return true
			}
		}
		return false
	case mp.prefix != "":
		id, ok := m.pseudonym(mp.prefix, source)
		if ok {
			out.PutStr(mp.Target, id)
		}
		return ok
	}
	switch source.Type() {
	case pcommon.ValueTypeStr, pcommon.ValueTypeInt, pcommon.ValueTypeDouble, pcommon.ValueTypeBool:
		source.CopyTo(out.PutEmpty(mp.Target))
		return true
	case pcommon.ValueTypeSlice:
		items := source.Slice()
		if items.Len() == 0 || items.Len() > maxSliceItems {
			return false
		}
		for i := 0; i < items.Len(); i++ {
			if items.At(i).Type() != pcommon.ValueTypeStr {
				return false
			}
		}
		source.CopyTo(out.PutEmpty(mp.Target))
		return true
	default: // maps and bytes are content channels
		return false
	}
}

// pseudonym is the keyed id of a string or integer source value.
func (m *mapper) pseudonym(prefix string, source pcommon.Value) (string, bool) {
	var clear string
	switch source.Type() {
	case pcommon.ValueTypeStr:
		clear = source.Str()
	case pcommon.ValueTypeInt:
		clear = strconv.FormatInt(source.Int(), 10)
	default:
		return "", false
	}
	if clear == "" || len(clear) > maxIDBytes || len(m.key) == 0 {
		return "", false
	}
	if prefix == labelPrefix {
		return hostrecords.LabelPseudonym(prefix, clear, m.key), true
	}
	id := hostrecords.V2(prefix, clear, m.key)
	return id, id != ""
}

// The OpenTelemetry GenAI semantic conventions, version GenAISemconvVersion,
// define these attributes for facts a neutral record also states. They are
// accepted as sources only: translated into the Fabric key when the record
// does not already state it, then removed (spec 057 §4.5, OD-12).
const (
	genAIToolCallID    = "gen_ai.tool.call.id"
	genAIOperationName = "gen_ai.operation.name"
)

// genAIGatedKinds maps gen_ai.operation.name to fabric.control.gated_kind.
var genAIGatedKinds = map[string]string{
	"execute_tool":     "tool_call",
	"chat":             "model_call",
	"text_completion":  "model_call",
	"generate_content": "model_call",
}

var providerPseudonym = regexp.MustCompile(`^p-[0-9a-f]{32}$`)

// acceptGenAISources translates the pinned source keys on a neutral control
// or hook record. A record of neither family is left exactly as it was.
func (m *mapper) acceptGenAISources(attrs pcommon.Map) {
	if !m.genAISources {
		return
	}
	control, hook := false, false
	attrs.Range(func(key string, _ pcommon.Value) bool {
		control = control || strings.HasPrefix(key, "fabric.control.")
		hook = hook || strings.HasPrefix(key, "fabric.hook.")
		return !control
	})
	var callTarget string
	switch {
	case control:
		callTarget = "fabric.control.gated_tool_call_id"
	case hook:
		callTarget = "fabric.hook.gated_tool_call_id"
	default:
		return
	}
	if source, ok := attrs.Get(genAIToolCallID); ok {
		if _, stated := attrs.Get(callTarget); !stated {
			if source.Type() == pcommon.ValueTypeStr && providerPseudonym.MatchString(source.Str()) {
				attrs.PutStr(callTarget, source.Str()) // already the agents' keyed form
			} else if id, ok := m.pseudonym("p", source); ok {
				attrs.PutStr(callTarget, id)
			}
		}
		attrs.Remove(genAIToolCallID)
		m.stats.sourcesAccepted.Add(1)
	}
	if !control {
		return
	}
	if source, ok := attrs.Get(genAIOperationName); ok {
		if _, stated := attrs.Get("fabric.control.gated_kind"); !stated && source.Type() == pcommon.ValueTypeStr {
			if kind, known := genAIGatedKinds[source.Str()]; known {
				attrs.PutStr("fabric.control.gated_kind", kind)
			}
		}
		attrs.Remove(genAIOperationName)
		m.stats.sourcesAccepted.Add(1)
	}
}
