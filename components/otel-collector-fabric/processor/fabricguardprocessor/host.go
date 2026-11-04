// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"slices"
	"strings"

	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Host admission (spec 053 §6.2.7; spec 056 §7.3.3 (e)). A host instance
// (source_kind host.auditd or host.ebpf) guards one sensor's ingress group: it
// admits only host records and that source's markers, and refuses a batch
// that holds anything else, like a forged identity. The executable reference
// is scripts/contracts/host_records.py (admit); the fixtures in
// contracts/capture/v1/fixtures/host pin both. Nothing here reads, judges or
// answers the monitored workload: a refusal is an OTLP client error to the
// sensor, never a signal back to the agent.

const sensorKeyPrefix = "fabric.sensor."

// Refusal codes (contracts/capture/v1/fixtures/host/README.md). Every one is
// a non-retryable INVALID_ARGUMENT; the error names the code, never a key or
// value.
const (
	hostRefusalRepeatedKey     = "capture.host.repeated_key"      // step 1
	hostRefusalNotHostEvidence = "capture.host.not_host_evidence" // step 4
	hostRefusalBinding         = "capture.host.binding"           // step 5
	hostRefusalSensorOnAgent   = "capture.host.sensor_on_agent"   // agent instance
)

func hostRefusal(code string) error {
	return consumererror.NewPermanent(status.Error(codes.InvalidArgument, "fabricguard: batch refused ("+code+")"))
}

func (g *guard) hostInstance() bool {
	return g.cfg.SourceKind == sourceKindAuditd || g.cfg.SourceKind == sourceKindEBPF
}

// hostClass is a span's class under step 4.
type hostClass uint8

const (
	hostRefused hostClass = iota
	hostRecord
	hostManifest
	hostPeriodic
	hostFinal
	hostLoss
)

var (
	// hostRecordBase: the 053 §6.2.3 keys that are not kind-S registry rows.
	hostRecordBase = []string{
		"fabric.tenant_id", "fabric.source_id", "fabric.source.epoch", "fabric.source.sequence",
		"fabric.event_id", "fabric.attempt.uid", "fabric.capture.input", "fabric.capture.source",
		"fabric.capture.point", "fabric.network.host_id", "fabric.execution.host_id",
		"fabric.execution.sandbox_id", "fabric.execution.image_digest",
	}
	// hostRecordKeys is the host placement of a host record (records-span-v1
	// host_placement): the base keys plus every records key restricted to
	// capture-point kind S. Derived from the generated tables.
	hostRecordKeys = func() map[string]struct{} {
		keys := toSet(hostRecordBase...)
		for key, condition := range recordKeyConditions {
			if slices.Contains(condition["capture_point_kinds"], "S") && slices.Contains(coverageKeyPlacements[key], "record") {
				keys[key] = struct{}{}
			}
		}
		return keys
	}()
	// Identity, capture and sequence keys a span cannot be admitted without:
	// a missing or failing one drops the span (step 6).
	hostRecordIdentity = []string{
		"fabric.tenant_id", "fabric.source_id", "fabric.source.epoch", "fabric.source.sequence",
		"fabric.event_id", "fabric.attempt.uid", "fabric.capture.input", "fabric.capture.source",
		"fabric.capture.point",
	}
	// The remaining required record keys must be supplied; a failing value is
	// stripped like any other key.
	hostRecordSupplied = []string{
		"fabric.sensor.event_class", "fabric.sensor.syscall", "fabric.sensor.result", "fabric.sensor.pid",
	}
	hostDigestKeys   = toSet("fabric.sensor.exe_sha256", "fabric.sensor.argv_sha256", "fabric.sensor.path_sha256")
	hostSyscallClass = map[string]string{
		"execve": "exec", "execveat": "exec", "connect": "connect", "accept": "connect",
		"bind": "connect", "socket": "connect", "openat": "file", "open": "file",
	}
	// hostLegacyMarkerChecks: the spec 047 marker keys (no placement column),
	// closed to what a host source sends. Loss reasons are 053 §6.2.3's.
	hostLegacyMarkerChecks = map[string]func(pcommon.Value) bool{
		"fabric.heartbeat.kind":          oneOf(toSet("periodic", "final")),
		"fabric.heartbeat.last_sequence": intAtLeast(-1),
		"fabric.loss.reason":             oneOf(toSet("disk_full", "internal_error", "span_dropped", "shutdown")),
		"fabric.loss.count":              intAtLeast(1),
		"fabric.loss.first_sequence":     intAtLeast(0),
		"fabric.loss.last_sequence":      intAtLeast(0),
	}
	hostHeartbeatLegacy = []string{"fabric.heartbeat.kind", "fabric.heartbeat.last_sequence"}
	hostLossLegacy      = []string{"fabric.loss.reason", "fabric.loss.count", "fabric.loss.first_sequence", "fabric.loss.last_sequence"}
	hostMarkerBase      = []string{"fabric.source_id", "fabric.source.epoch", "fabric.event_id", "fabric.capture.point"}

	// hostAllowed and hostRequired are each class's host placement and the
	// keys it cannot be admitted without.
	hostAllowed = map[hostClass]map[string]struct{}{
		hostRecord:   hostRecordKeys,
		hostManifest: manifestSpanKeys,
		hostPeriodic: hostMarkerKeys("periodic", hostHeartbeatLegacy),
		hostFinal:    hostMarkerKeys("final", hostHeartbeatLegacy),
		hostLoss:     hostMarkerKeys("loss", hostLossLegacy),
	}
	hostRequired = map[hostClass][]string{
		hostRecord:   hostRecordIdentity,
		hostManifest: {"fabric.event_id", "fabric.source_id", "fabric.source.epoch"},
		hostPeriodic: append(slices.Clone(hostMarkerBase), hostHeartbeatLegacy...),
		hostFinal:    append(slices.Clone(hostMarkerBase), hostHeartbeatLegacy...),
		hostLoss:     append(slices.Clone(hostMarkerBase), hostLossLegacy...),
	}
)

// hostMarkerKeys is a marker's host placement: its registry placement plus
// the spec 047 marker keys.
func hostMarkerKeys(placement string, legacy []string) map[string]struct{} {
	keys := toSet(legacy...)
	for key, placements := range coverageKeyPlacements {
		if slices.Contains(placements, placement) {
			keys[key] = struct{}{}
		}
	}
	return keys
}

// classifyHostSpan is step 4, from unfiltered attributes: a host record
// (records class, capture point of kind S), a manifest, a periodic or final
// heartbeat, a loss marker, or anything else (an exchange, a run marker, a
// seal, a records span of another kind), which refuses the batch.
func classifyHostSpan(span ptrace.Span) hostClass {
	if span.Name() == "fabric.capture_manifest" {
		return hostManifest
	}
	attrs := span.Attributes()
	input, hasInput := attrs.Get("fabric.capture.input")
	if _, exchange := attrs.Get("fabric.wire.exchange_id"); exchange || hasInput && constStr("wire")(input) {
		return hostRefused
	}
	if kind, ok := attrs.Get("fabric.heartbeat.kind"); ok {
		switch {
		case constStr("periodic")(kind):
			return hostPeriodic
		case constStr("final")(kind):
			return hostFinal
		}
		return hostRefused // run_start, run_end, segment_seal or no kind
	}
	if _, ok := attrs.Get("fabric.loss.reason"); ok {
		return hostLoss
	}
	if hasInput && constStr("records")(input) {
		if point, ok := attrs.Get("fabric.capture.point"); ok && capturePointKind(point) == "S" {
			return hostRecord
		}
	}
	return hostRefused
}

// hostSpanBound is step 5 for one span, beyond the tenant and source keys
// checkTraceBatch compares in every container: the capture point id equals
// source_kind, and a manifest's rows name only source_kind.
func (g *guard) hostSpanBound(span ptrace.Span, class hostClass) bool {
	attrs := span.Attributes()
	if point, ok := attrs.Get("fabric.capture.point"); ok {
		if point.Type() != pcommon.ValueTypeStr || pointID(point.Str()) != g.cfg.SourceKind {
			return false
		}
	}
	if class != hostManifest {
		return true
	}
	rows, ok := attrs.Get("fabric.manifest.capture_points")
	if !ok || rows.Type() != pcommon.ValueTypeSlice || rows.Slice().Len() == 0 {
		return false
	}
	for i := 0; i < rows.Slice().Len(); i++ {
		row := rows.Slice().At(i)
		if row.Type() != pcommon.ValueTypeStr || !strings.HasPrefix(row.Str(), g.cfg.SourceKind+"@") {
			return false
		}
	}
	return true
}

// pointID is the id part of "id@version" (the whole value without '@').
func pointID(value string) string {
	id, _, _ := strings.Cut(value, "@")
	return id
}

// processHostTraces applies 053 §6.2.7 in order. Steps 1, 4 and 5 read the
// whole request before anything is mutated, so a refused batch is left as it
// arrived and its reason does not depend on span or key order.
func (g *guard) processHostTraces(td ptrace.Traces) (ptrace.Traces, error) {
	// Step 1: a repeated fabric.* key in any container.
	scan := g.checkTraceBatch(td)
	if scan.duplicate {
		g.stats.duplicateKeyRejected.Add(1)
		return td, g.refuseHost(hostRefusalRepeatedKey)
	}
	// Step 4 over the whole batch, then step 5.
	var classes []hostClass
	bound := !scan.foreign
	resourceSpans := td.ResourceSpans()
	for ri := 0; ri < resourceSpans.Len(); ri++ {
		scopeSpans := resourceSpans.At(ri).ScopeSpans()
		for si := 0; si < scopeSpans.Len(); si++ {
			spans := scopeSpans.At(si).Spans()
			for i := 0; i < spans.Len(); i++ {
				class := classifyHostSpan(spans.At(i))
				if class == hostRefused {
					return td, g.refuseHost(hostRefusalNotHostEvidence)
				}
				bound = bound && g.hostSpanBound(spans.At(i), class)
				classes = append(classes, class)
			}
		}
	}
	if !bound {
		return td, g.refuseHost(hostRefusalBinding)
	}
	// Steps 2 and 6–8, span by span. A host source names itself on its spans;
	// resource and scope carry nothing.
	next := 0
	dropped := 0
	for ri := 0; ri < resourceSpans.Len(); ri++ {
		resourceSpan := resourceSpans.At(ri)
		if resourceSpan.SchemaUrl() != "" {
			resourceSpan.SetSchemaUrl("")
			g.stats.nativeTextNormalized.Add(1)
		}
		clearEntityRefs(resourceSpan.Resource(), g)
		g.removeAll(resourceSpan.Resource().Attributes())
		scopeSpans := resourceSpan.ScopeSpans()
		for si := 0; si < scopeSpans.Len(); si++ {
			scopeSpan := scopeSpans.At(si)
			g.scrubTraceScope(scopeSpan)
			g.removeAll(scopeSpan.Scope().Attributes())
			scopeSpan.Spans().RemoveIf(func(span ptrace.Span) bool {
				class := classes[next]
				next++
				if g.admitHostSpan(span, class) {
					return false
				}
				dropped++
				return true
			})
		}
	}
	if dropped > 0 {
		g.stats.hostSpanDropped.Add(uint64(dropped))
		g.logger.Debug("dropping host spans", zap.String("reason", "host_identity_invalid"), zap.Int("count", dropped))
	}
	return td, nil
}

func (g *guard) refuseHost(code string) error {
	g.stats.hostBatchRefused.Add(1)
	g.logger.Debug("refusing batch", zap.String("reason", code))
	return hostRefusal(code)
}

// admitHostSpan applies steps 2 and 6–8 to one classified span and reports
// whether it is admitted.
func (g *guard) admitHostSpan(span ptrace.Span, class hostClass) bool {
	attrs := span.Attributes()
	// Step 2: never the sender's statement.
	attrs.Remove(sourceAuthenticatedKey)
	// Read before filtering: the conditional rules and the supplied keys
	// look at what the sender sent, not at what survived.
	point := recordPoint(attrs)
	failed := false
	if result, ok := attrs.Get("fabric.sensor.result"); ok {
		failed = constStr("failed")(result)
	}
	lossReported := false
	if lost, ok := attrs.Get("fabric.sensor.upstream_lost"); ok {
		lossReported = !(lost.Type() == pcommon.ValueTypeInt && lost.Int() == 0)
	}
	if class == hostRecord {
		for _, key := range hostRecordSupplied {
			if _, ok := attrs.Get(key); !ok {
				return false
			}
		}
	}
	allowed := hostAllowed[class]
	permitted := g.cfg.HostDigests == hostDigestsPermitted
	// Steps 6 and 7. Strips are counted for admitted spans only; a dropped
	// span is counted once, as dropped.
	var stripped, digests uint64
	attrs.RemoveIf(func(key string, value pcommon.Value) bool {
		keep := false
		if _, listed := allowed[key]; listed {
			keep = g.hostValueAdmitted(class, key, value, point)
		}
		switch {
		case !keep:
		case key == "fabric.sensor.errno":
			keep = failed // only on a failed call
		case key == "fabric.sensor.upstream_loss_reason":
			keep = lossReported // only when a loss is reported
		}
		if !keep {
			stripped++
			return true
		}
		if _, digest := hostDigestKeys[key]; digest && !permitted {
			digests++
			return true
		}
		return false
	})
	// The generic checks (sensitive names, hash shapes, size and count
	// bounds) still apply; on an admissible span they change nothing.
	g.filterAttributesOf(attrs, TraceAllowedFields, "host-span", class == hostRecord)
	if class == hostManifest {
		g.applyManifestProfile(attrs)
	}
	for _, key := range hostRequired[class] {
		if _, ok := attrs.Get(key); !ok {
			return false
		}
	}
	if class == hostRecord {
		syscall, _ := attrs.Get("fabric.sensor.syscall")
		eventClass, ok := attrs.Get("fabric.sensor.event_class")
		if !ok || hostSyscallClass[syscall.Str()] != eventClass.Str() {
			return false // a syscall of another event class, or none
		}
	}
	if removed := span.Events().Len() + span.Links().Len(); removed > 0 {
		span.Events().RemoveIf(func(ptrace.SpanEvent) bool { return true })
		span.Links().RemoveIf(func(ptrace.SpanLink) bool { return true })
		g.stats.notAllowedRemoved.Add(uint64(removed))
	}
	if name := activityCategory(span.Name(), attrs); name != span.Name() {
		span.SetName(name)
		g.stats.nativeTextNormalized.Add(1)
	}
	if span.TraceState().AsRaw() != "" {
		span.TraceState().FromRaw("")
		g.stats.nativeTextNormalized.Add(1)
	}
	if span.Status().Message() != "" {
		span.Status().SetMessage("")
		g.stats.statusMessageRemoved.Add(1)
	}
	// Step 8: the Node's own statement that the span arrived on this group.
	attrs.PutBool(sourceAuthenticatedKey, true)
	g.stats.hostKeyStripped.Add(stripped)
	g.stats.hostDigestStripped.Add(digests)
	return true
}

// hostValueAdmitted closes one listed key's value: rule A for a host record,
// the spec 047 marker checks, the generated coverage checks, and a reused
// manifest key's existing admission.
func (g *guard) hostValueAdmitted(class hostClass, key string, value pcommon.Value, point string) bool {
	if class == hostRecord {
		return g.recordKeyAdmitted(key, value, point)
	}
	if check, legacy := hostLegacyMarkerChecks[key]; legacy {
		return check(value)
	}
	if valid, known := g.validCoverageValue(key, value); known {
		return valid
	}
	// The source keys' registry checks are the generated record ones.
	if valid, known := recordKeyValidators[key]; known {
		return valid(value) && (key != "fabric.source_id" || g.validSourceLabel(value))
	}
	return class == hostManifest
}

// dropHostLogs is step 3: a host group has no logs in production; every log
// record is dropped and counted, and the batch is not refused.
func (g *guard) dropHostLogs(ld plog.Logs) {
	n := ld.LogRecordCount()
	ld.ResourceLogs().RemoveIf(func(plog.ResourceLogs) bool { return true })
	if n > 0 {
		g.stats.hostLogDropped.Add(uint64(n))
		g.logger.Debug("dropping log records", zap.String("reason", "host_group_has_no_logs"), zap.Int("count", n))
	}
}
