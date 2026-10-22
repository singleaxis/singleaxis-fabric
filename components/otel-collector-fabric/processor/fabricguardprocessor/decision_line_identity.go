// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"regexp"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Decision-line keys that carried caller data in clear up to v0.8.0 (spec 049
// §2.9, §4.2; spec 051 §4.9). From v0.8.1 the SDK maps them in its
// pseudonymous identity mode, and a pseudonymous Node admits only the mapped
// form: a clear value from an old or non-conforming agent is dropped,
// consistently with the identity validators of coverage_keys.go. identity_mode
// clear keeps their pre-v0.8.1 admission (the generic metadata checks still
// apply). These hand-written rules hold until the P2 contracts work package
// (spec 051 WP2-0) moves the keys into the generated registry table with
// dedicated v2 prefixes.

// decisionLineIDKeys are caller ids with no v2 type yet: the SDK emits the
// generic operator label lbl- + 32 hex (a single value or a list).
var decisionLineIDKeys = toSet(
	"fabric.side_effect.idempotency_key",
	"fabric.tool.idempotency_key",
	"fabric.retrieval.source_document_ids",
)

// decisionLineLabelKeys are operator labels: lbl- + 32 hex unless the Node
// admits clear labels (capture_labels clear, or identity_mode clear, under
// which the SDK reproduces the v0.8.0 output).
var decisionLineLabelKeys = toSet(
	"fabric.checkpoint.step_name",
	"fabric.mcp.tools",
)

// mcpToolEntryPattern is one fabric.mcp.tools entry under a pseudonymous
// Node: the tool name's label and the first 12 hex of its definition digest.
var mcpToolEntryPattern = regexp.MustCompile(`^lbl-[0-9a-f]{32}:[0-9a-f]{12}$`)

// validDecisionLineValue closes a decision-line key's value; ok is false when
// the key is not one of them.
func (g *guard) validDecisionLineValue(key string, value pcommon.Value) (valid, ok bool) {
	_, id := decisionLineIDKeys[key]
	_, label := decisionLineLabelKeys[key]
	if !id && !label {
		return false, false
	}
	if g.cfg.IdentityMode == identityModeClear || label && g.clearLabels() {
		return true, true
	}
	element := labelPseudonymPattern
	if key == "fabric.mcp.tools" {
		element = mcpToolEntryPattern
	}
	if key == "fabric.mcp.tools" || key == "fabric.retrieval.source_document_ids" {
		if value.Type() != pcommon.ValueTypeSlice {
			return false, true
		}
		slice := value.Slice()
		for i := 0; i < slice.Len(); i++ {
			if !matches(element)(slice.At(i)) {
				return false, true
			}
		}
		return true, true
	}
	return matches(element)(value), true
}
