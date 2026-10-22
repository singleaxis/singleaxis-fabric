// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestSpanCategoryVectors(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name     string
			Hint     string   `json:"name_hint"`
			Keys     []string `json:"attribute_keys"`
			Category string
		}
	}
	decodeJSON(t, vectorsDirectory+"span-category-v1.json", &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("empty category vectors")
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			attrs := pcommon.NewMap()
			for _, key := range tc.Keys {
				attrs.PutStr(key, "")
			}
			if got := activityCategory(tc.Hint, attrs); got != tc.Category {
				t.Fatalf("got %q, want %q", got, tc.Category)
			}
		})
	}
}

// T3's Go half runs the Python emitter's exact int64 timestamps and attributes
// through the bound Node and independently hashes the resulting record. Do
// not decode JSON numbers through float64: P1 epochs exceed its exact range.
func TestSealParityVectors(t *testing.T) {
	var vectors struct {
		Node struct {
			CaptureLabels string `json:"capture_labels"`
			IdentityMode  string `json:"identity_mode"`
			BoundSource   string `json:"bound_source"`
		}
		Cases []struct {
			Name, Class string
			Emitted     struct {
				Name       string
				StartNS    uint64 `json:"start_ns"`
				EndNS      uint64 `json:"end_ns"`
				Status     string
				Attributes map[string]any
			}
			Export struct {
				Name       string
				Attributes map[string]any
			} `json:"expected_export"`
			Content     []any
			Digest      string
			SealEntries [][]any `json:"seal_entries"`
		}
	}
	decodeJSON(t, vectorsDirectory+"seal-parity-v1.json", &vectors)
	if len(vectors.Cases) == 0 {
		t.Fatal("empty seal parity vectors")
	}
	classes := map[string]bool{}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			cfg := createDefaultConfig()
			cfg.Profile = profileProduction
			cfg.CaptureLabels = vectors.Node.CaptureLabels
			cfg.IdentityMode = vectors.Node.IdentityMode
			cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: "tenant-a", SourceID: vectors.Node.BoundSource}
			g := newTestGuard(t, cfg)
			td := makeRawSpan(tc.Emitted.Name, vectorRaw(t, tc.Emitted.Attributes).(map[string]any))
			span := firstSpan(td)
			span.SetStartTimestamp(pcommon.Timestamp(tc.Emitted.StartNS))
			span.SetEndTimestamp(pcommon.Timestamp(tc.Emitted.EndNS))
			switch tc.Emitted.Status {
			case "unset":
				span.Status().SetCode(ptrace.StatusCodeUnset)
			case "ok":
				span.Status().SetCode(ptrace.StatusCodeOk)
			case "error":
				span.Status().SetCode(ptrace.StatusCodeError)
			default:
				t.Fatalf("unknown status %q", tc.Emitted.Status)
			}
			out, err := g.processTraces(context.Background(), td)
			if err != nil {
				t.Fatal(err)
			}
			span = firstSpan(out)
			want := vectorRaw(t, tc.Export.Attributes)
			if span.Name() != tc.Export.Name || !reflect.DeepEqual(span.Attributes().AsRaw(), want) {
				t.Fatalf("export=%s %v; want %s %v", span.Name(), span.Attributes().AsRaw(), tc.Export.Name, want)
			}
			if uint64(span.StartTimestamp()) != tc.Emitted.StartNS || uint64(span.EndTimestamp()) != tc.Emitted.EndNS {
				t.Fatal("Node changed timestamps")
			}
			if tc.Digest != "" {
				attrs := span.Attributes().AsRaw()
				for key := range receiverOwnedKeys {
					delete(attrs, key)
				}
				status := map[ptrace.StatusCode]string{ptrace.StatusCodeUnset: "unset", ptrace.StatusCodeOk: "ok", ptrace.StatusCodeError: "error"}[span.Status().Code()]
				record := map[string]any{"name": span.Name(), "start_ns": uint64(span.StartTimestamp()), "end_ns": uint64(span.EndTimestamp()),
					"status": status, "attributes": attrs, "content": tc.Content}
				var canonical bytes.Buffer
				encoder := json.NewEncoder(&canonical)
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(record); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(bytes.TrimSuffix(canonical.Bytes(), []byte("\n")))
				if got := "sha256:" + hex.EncodeToString(digest[:]); got != tc.Digest {
					t.Fatalf("record digest=%s, want %s", got, tc.Digest)
				}
			}
			if tc.Class == "loss" {
				attrs := span.Attributes()
				segment, _ := attrs.Get("fabric.run.segment_id")
				if segment.Str() != tc.Emitted.Attributes["fabric.run.segment_id"] {
					t.Fatal("loss lost its segment attribution")
				}
				first, _ := attrs.Get("fabric.loss.first_sequence")
				last, _ := attrs.Get("fabric.loss.last_sequence")
				reason, _ := attrs.Get("fabric.loss.reason")
				entries := make([]any, 0, last.Int()-first.Int()+1)
				for seq := first.Int(); seq <= last.Int(); seq++ {
					entries = append(entries, []any{seq, "loss:" + reason.Str()})
				}
				if !reflect.DeepEqual(entries, vectorRaw(t, anySlice(tc.SealEntries))) {
					t.Fatalf("loss entries=%v, want %v", entries, tc.SealEntries)
				}
			}
			// A second Node must preserve every sealed field and the receiver stamp.
			out, err = g.processTraces(context.Background(), out)
			if err != nil || !reflect.DeepEqual(firstSpan(out).Attributes().AsRaw(), want) || firstSpan(out).Name() != tc.Export.Name {
				t.Fatalf("second Node changed the export: %v", err)
			}
		})
		classes[tc.Class] = true
	}
	for _, class := range []string{"record", "exchange", "loss", "segment_seal"} {
		if !classes[class] {
			t.Errorf("missing class %s", class)
		}
	}
}

func anySlice(entries [][]any) []any {
	result := make([]any, len(entries))
	for i, entry := range entries {
		result[i] = entry
	}
	return result
}
