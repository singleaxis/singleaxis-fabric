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
	"fabric.request_id",
	"gen_ai.data_source.id",
)

// decisionLineProviderKeys are provider correlation ids (spec 049 §2.9 rule
// 4; N12, C39, C40): the SDK emits the keyed v2 p- + 32 hex form, the same
// function as the wire line. The legacy unkeyed p- + 16 hex form is not
// admitted: an unkeyed hash of an id is not a pseudonym.
var decisionLineProviderKeys = toSet(
	"fabric.side_effect.parent_tool_call_id",
	"gen_ai.response.id",
	"gen_ai.request.previous_response.id",
	"gen_ai.tool.call.id",
	"fabric.tool.call.id",
)

var providerPseudonymPattern = pseudonymPattern("p")

// decisionLineLabelKeys are operator labels: lbl- + 32 hex unless the Node
// admits clear labels (capture_labels clear, or identity_mode clear, under
// which the SDK reproduces the v0.8.0 output).
var decisionLineLabelKeys = toSet(
	"fabric.checkpoint.step_name",
	"fabric.mcp.tools",
	"gen_ai.tool.name",
	"fabric.tool.name",
	"fabric.side_effect.target_system",
	"fabric.side_effect.operation",
	"fabric.side_effect_systems",
)

// decisionLineMintedOrIDKeys carry an id Fabric minted (uuid4, as is) or a
// caller's id (lbl- + 32 hex): side-effect ids and the replay list of them.
var decisionLineMintedOrIDKeys = toSet(
	"fabric.side_effect.side_effect_id",
	"fabric.replay.suppressed_side_effect_ids",
)

var mintedUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// mcpToolEntryPattern is one fabric.mcp.tools entry under a pseudonymous
// Node: the tool name's label and the first 12 hex of its definition digest.
var mcpToolEntryPattern = regexp.MustCompile(`^lbl-[0-9a-f]{32}:[0-9a-f]{12}$`)

// decisionLineMappedOnlyKeys were never admitted clear: the Node admits them
// only in the SDK's mapped form, whatever its identity_mode (v0.8.1 Sol
// review item 7): the memory store id as mst- (pseudonym v2) and tags as
// lists of lbl- operator labels.
var decisionLineMappedOnlyKeys = map[string]func(pcommon.Value) bool{
	"gen_ai.memory.store.id": matches(pseudonymPattern("mst")),
	"fabric.tags":            sliceOf(1, 256, false, matches(labelPseudonymPattern)),
	"fabric.memory.tags":     sliceOf(1, 256, false, matches(labelPseudonymPattern)),
}

// validDecisionLineValue closes a decision-line key's value; ok is false when
// the key is not one of them.
func (g *guard) validDecisionLineValue(key string, value pcommon.Value) (valid, ok bool) {
	if check, mappedOnly := decisionLineMappedOnlyKeys[key]; mappedOnly {
		return check(value), true
	}
	_, id := decisionLineIDKeys[key]
	_, label := decisionLineLabelKeys[key]
	_, provider := decisionLineProviderKeys[key]
	_, minted := decisionLineMintedOrIDKeys[key]
	if !id && !label && !provider && !minted {
		return false, false
	}
	if g.cfg.IdentityMode == identityModeClear || label && g.clearLabels() {
		return true, true
	}
	if provider {
		return matches(providerPseudonymPattern)(value), true
	}
	if minted {
		item := func(v pcommon.Value) bool {
			return matches(mintedUUIDPattern)(v) || matches(labelPseudonymPattern)(v)
		}
		if key == "fabric.replay.suppressed_side_effect_ids" {
			return sliceOf(1, 1024, false, item)(value), true
		}
		return item(value), true
	}
	element := labelPseudonymPattern
	if key == "fabric.mcp.tools" {
		element = mcpToolEntryPattern
	}
	if key == "fabric.mcp.tools" || key == "fabric.retrieval.source_document_ids" ||
		key == "fabric.side_effect_systems" {
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
