// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricmapprocessor

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Spec 057 §10.4, WP7-14: the published emitter contract
// (docs/security-context-otlp.md) lists exactly the keys an emitter may write:
// the mapping-profile targets, the two invariants and the spec 022 hook keys
// the records reuse (E24-E27). A key added to one and not the other fails here.
func TestPublishedEmitterContractListsEveryNeutralKey(t *testing.T) {
	doc := string(readFile(t, filepath.Join(repoRoot(t), "docs", "security-context-otlp.md")))
	row := regexp.MustCompile("(?m)^\\| `(fabric\\.(?:grant|control|hook|extension|mcp)\\.[a-z0-9_.]+)` \\|")
	listed := map[string]bool{}
	for _, match := range row.FindAllStringSubmatch(doc, -1) {
		if listed[match[1]] {
			t.Errorf("%s is listed twice", match[1])
		}
		listed[match[1]] = true
	}
	want := map[string]bool{}
	for key := range targets {
		want[key] = true
	}
	for key := range invariantTargets {
		want[key] = true
	}
	for _, key := range []string{"fabric.hook.name", "fabric.hook.phase", "fabric.hook.modified", "fabric.hook.input_hash", "fabric.hook.output_hash"} {
		want[key] = true
	}
	var missing, extra []string
	for key := range want {
		if !listed[key] {
			missing = append(missing, key)
		}
	}
	for key := range listed {
		if !want[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Errorf("docs/security-context-otlp.md is out of date: missing %v, not a neutral emitter key %v", missing, extra)
	}
	if !strings.Contains(doc, "**"+GenAISemconvVersion+"**") {
		t.Errorf("the doc does not name the pinned GenAI semantic-conventions version %s", GenAISemconvVersion)
	}
}
