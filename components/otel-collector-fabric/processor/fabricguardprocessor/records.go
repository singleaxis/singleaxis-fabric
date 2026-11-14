// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"slices"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Capture-point kinds are pinned to the public registry by TestCapturePointKinds.
// The runtime must not read a repository file or infer a kind from a caller's
// arbitrary point name. Unknown points cannot satisfy a kind restriction.
var capturePointKinds = map[string]string{
	"fabric.self": "F", "install.config": "R",
	"wire.py.httpx": "W", "wire.py.aiohttp": "W", "wire.ts.undici": "W", "wire.ts.node_http": "W",
	"explicit.call_recorder": "R", "explicit.byte_boundary": "R",
	"explicit.final_http": "R", "explicit.subprocess_artifact": "R",
	"sdk.records": "R", "run.scope": "R", "records.control": "R", "records.grant": "R",
	"records.extension": "R", "mcp.wrapper": "R",
	"mcp.client": "H", "exec.subprocess": "H", "exec.audit": "H",
	"db.dbapi": "H", "http.nonmodel": "W", "file.audit": "H",
	"remote.ssh_wrapper": "R", "remote.sandbox": "H", "ui.automation": "H", "rt.websocket": "W",
	"reconstruct.parse": "P", "reconstruct.infer": "I", "host.ebpf": "S",
	"host.ebpf.exit": "S", "host.ebpf.syscall_result": "S", // spec 057 §6.4 manifest rows
	"host.auditd": "S", "feed.independent": "S", "delivery.receipts": "S",
}

func recordConditionHolds(condition map[string][]string, point string) bool {
	id, _, _ := strings.Cut(point, "@")
	if points, restricted := condition["capture_points"]; restricted && !slices.Contains(points, id) {
		return false
	}
	if kinds, restricted := condition["capture_point_kinds"]; restricted {
		kind, known := capturePointKinds[id]
		return known && slices.Contains(kinds, kind)
	}
	return true
}

// applyRecordProfile implements rule A using the same generated checks as the
// emitter. Snapshot the point before filtering so admission is independent of
// OTLP attribute order. This method also supports rule-A vector testing before
// class discrimination (vectors deliberately include foreign marker keys).
func (g *guard) applyRecordProfile(attrs pcommon.Map) {
	point := recordPoint(attrs)
	attrs.RemoveIf(func(key string, value pcommon.Value) bool {
		keep := g.recordKeyAdmitted(key, value, point)
		if !keep {
			g.stats.notAllowedRemoved.Add(1)
		}
		return !keep
	})
}

// recordPoint is the record's capture point when well formed, else "".
func recordPoint(attrs pcommon.Map) string {
	if value, ok := attrs.Get("fabric.capture.point"); ok && capturePointPattern.MatchString(value.Str()) {
		return value.Str()
	}
	return ""
}

// recordKeyAdmitted is rule A for one key of a record whose capture point is
// point; host admission (spec 053 §6.2.7 step 6) applies it too.
func (g *guard) recordKeyAdmitted(key string, value pcommon.Value, point string) bool {
	valid, listed := recordKeyValidators[key]
	if !listed || !placementAllowed(key, onRecord, "") ||
		!recordConditionHolds(recordKeyConditions[key], point) || !recordMetadataShape(value) {
		return false
	}
	switch key {
	case "fabric.capture.input":
		return constStr("records")(value)
	case "fabric.source_id":
		return valid(value) && g.validSourceLabel(value)
	case "fabric.run.id":
		return g.validRunIDLabel(value) && (g.cfg.IdentityMode == identityModeClear || valid(value))
	default:
		return valid(value)
	}
}

// capturePointKind is the registry kind of a capture point value ("id@ver"
// or a bare id); "" for an unknown point or a non-string value.
func capturePointKind(value pcommon.Value) string {
	if value.Type() != pcommon.ValueTypeStr {
		return ""
	}
	id, _, _ := strings.Cut(value.Str(), "@")
	return capturePointKinds[id]
}

// Rule A refuses bytes, maps and nested values instead of rewriting them. A scalar
// double passes the shape check only so its key's validator can decide: a registry
// "number" check (spec 057 D41, E03) admits it, every other validator refuses it.
func recordMetadataShape(value pcommon.Value) bool {
	switch value.Type() {
	case pcommon.ValueTypeStr, pcommon.ValueTypeInt, pcommon.ValueTypeBool, pcommon.ValueTypeDouble:
		return true
	case pcommon.ValueTypeSlice:
		values := value.Slice()
		for i := 0; i < values.Len(); i++ {
			switch values.At(i).Type() {
			case pcommon.ValueTypeStr, pcommon.ValueTypeInt, pcommon.ValueTypeBool:
			default:
				return false
			}
		}
		return true
	default:
		return false
	}
}
