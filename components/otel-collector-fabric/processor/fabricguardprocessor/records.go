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
	"wire.py.httpx": "W", "wire.py.aiohttp": "W", "wire.ts.undici": "W",
	"explicit.call_recorder": "R", "explicit.byte_boundary": "R",
	"explicit.final_http": "R", "explicit.subprocess_artifact": "R",
	"sdk.records": "R", "run.scope": "R", "mcp.wrapper": "R",
	"mcp.client": "H", "exec.subprocess": "H", "exec.audit": "H",
	"db.dbapi": "H", "http.nonmodel": "W", "file.audit": "H",
	"remote.ssh_wrapper": "R", "ui.automation": "H", "rt.websocket": "W",
	"reconstruct.parse": "P", "reconstruct.infer": "I", "host.ebpf": "S",
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
	point := ""
	if value, ok := attrs.Get("fabric.capture.point"); ok && capturePointPattern.MatchString(value.Str()) {
		point = value.Str()
	}
	attrs.RemoveIf(func(key string, value pcommon.Value) bool {
		valid, listed := recordKeyValidators[key]
		keep := listed && placementAllowed(key, onRecord, "") &&
			recordConditionHolds(recordKeyConditions[key], point) && recordMetadataShape(value)
		if keep {
			switch key {
			case "fabric.capture.input":
				keep = constStr("records")(value)
			case "fabric.source_id":
				keep = valid(value) && g.validSourceLabel(value)
			case "fabric.run.id":
				keep = g.validRunIDLabel(value) && (g.cfg.IdentityMode == identityModeClear || valid(value))
			default:
				keep = valid(value)
			}
		}
		if !keep {
			g.stats.notAllowedRemoved.Add(1)
		}
		return !keep
	})
}

// Rule A refuses floats, bytes and nested values instead of rewriting them.
func recordMetadataShape(value pcommon.Value) bool {
	switch value.Type() {
	case pcommon.ValueTypeStr, pcommon.ValueTypeInt, pcommon.ValueTypeBool:
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
