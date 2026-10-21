// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
)

const (
	rolesRegistry = "../../../../contracts/coverage/v1/registry/content-roles-v1.json"
	vocabRegistry = "../../../../contracts/coverage/v1/registry/vocabularies-v1.json"
	skeletonID    = "2b8f3c9e-4d1a-4b7e-9c2f-7a6d5e4c3b2a"
	partID        = "5c1d2e3f-6a7b-4c8d-9e0f-1a2b3c4d5e6f"
	reviewID      = "8e7d6c5b-4a39-4281-b7c6-d5e4f3a2b1c0"
	testSource    = "s-c5aedfd8a3ee415e277e335bf1517ff4"
	policyDigest  = "sha256:3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f"
)

var capWords = map[string]int64{"64 KiB": 65536, "256 KiB": 262144, "1 MiB": 1 << 20, "4 MiB": 4 << 20, "max_body_bytes": 0}

// The generated table is the registry (spec 049 §4.3: the single role
// source); generate_p0_contracts.py --check also keeps the file fresh.
func TestRoleTableIsTheRegistry(t *testing.T) {
	var table struct {
		SchemaVersion string `json:"schema_version"`
		Revision      int    `json:"registry_revision"`
		Roles         []struct {
			Role       string   `json:"role"`
			Boundary   []string `json:"boundary"`
			Provenance []string `json:"provenance"`
			Media      []string `json:"media_types"`
			Cap        string   `json:"cap"`
		} `json:"roles"`
	}
	decodeFile(t, rolesRegistry, &table)
	if len(table.Roles) != len(roleTable) {
		t.Fatalf("registry lists %d roles, exporter %d", len(table.Roles), len(roleTable))
	}
	if want := table.SchemaVersion + "@" + strings.TrimSpace(jsonText(t, table.Revision)); roleTableVersion != want {
		t.Fatalf("role table version %q, registry %q", roleTableVersion, want)
	}
	for _, row := range table.Roles {
		cap, known := capWords[row.Cap]
		got, ok := roleTable[row.Role]
		if !ok || !known || !reflect.DeepEqual(got, roleRule{boundary: row.Boundary, provenance: row.Provenance, media: row.Media, capBytes: cap}) {
			t.Errorf("role %q differs from the registry: %+v", row.Role, got)
		}
	}
	var vocab struct {
		Reason []struct {
			Value string `json:"value"`
		} `json:"reason"`
	}
	decodeFile(t, vocabRegistry, &vocab)
	if len(vocab.Reason) != len(statusReasons) {
		t.Fatalf("reason vocabulary %d, exporter %d", len(vocab.Reason), len(statusReasons))
	}
	for _, r := range vocab.Reason {
		if !statusReasons[r.Value] {
			t.Errorf("reason %q missing", r.Value)
		}
	}
}

func decodeFile(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// roleAttrs is a valid stored record of role, with the row's first boundary,
// provenance and a concrete media type.
func roleAttrs(role string, body []byte) map[string]any {
	rule := roleTable[role]
	media := rule.media[0]
	switch {
	case media == "*":
		media = "application/octet-stream"
	case strings.HasSuffix(media, "/*"):
		media = strings.TrimSuffix(media, "*") + "x-test"
	}
	attrs := validAttrs(body)
	attrs["role"], attrs["boundary"], attrs["provenance"], attrs["media_type"] = role, rule.boundary[0], rule.provenance[0], media
	if role == "model.exchange.part" {
		attrs["links"] = []any{map[string]any{"relation": "part_of", "object_id": skeletonID, "byte_range": []any{int64(10), int64(10 + len(body))}}}
		attrs["content_encoding"] = "base64"
	}
	return attrs
}

func parsesAs(t *testing.T, attrs map[string]any, body []byte, maxBody int64) string {
	t.Helper()
	lr := makeLogs(t, withBody(attrs, body)).ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	_, reason := parseRecord(lr, maxBody)
	return reason
}

// Spec 049 §4.3 rules 1-4: every role of the table is carried with its own
// boundary, provenance, media and cap; anything else is refused.
func TestEveryRoleIsDrivenByItsRow(t *testing.T) {
	body := []byte(`{"a":1}`)
	for role, rule := range roleTable {
		t.Run(role, func(t *testing.T) {
			if reason := parsesAs(t, roleAttrs(role, body), body, defaultMaxBodyBytes); reason != "" {
				t.Fatalf("valid %s record dropped: %s", role, reason)
			}
			for _, boundary := range []string{"caller", "provider_bound", "tool", "terminal", "sandbox", "remote", "host", "service"} {
				attrs := setAttr(roleAttrs(role, body), "boundary", boundary)
				if got := parsesAs(t, attrs, body, defaultMaxBodyBytes); (got == "") != contains(rule.boundary, boundary) {
					t.Errorf("boundary %s: reason %q", boundary, got)
				}
			}
			for _, provenance := range []string{"native", "protocol", "caller_reported", "inferred"} {
				attrs := setAttr(roleAttrs(role, body), "provenance", provenance)
				if got := parsesAs(t, attrs, body, defaultMaxBodyBytes); (got == "") != contains(rule.provenance, provenance) {
					t.Errorf("provenance %s: reason %q", provenance, got)
				}
			}
			if !contains(rule.media, "*") {
				if got := parsesAs(t, setAttr(roleAttrs(role, body), "media_type", "model/x-unlisted"), body, defaultMaxBodyBytes); got != reasonBadDescriptor {
					t.Errorf("unlisted media type admitted: %q", got)
				}
			}
			// Cap: stored_byte_length one past the row's cap is refused.
			limit := rule.capBytes
			if limit == 0 {
				limit = 4096 // a small configured max_body_bytes
			}
			big := bytes.Repeat([]byte("x"), int(limit)+1)
			if got := parsesAs(t, roleAttrs(role, big), big, 4096); got != reasonBadDescriptor {
				t.Errorf("record over the cap admitted: %q", got)
			}
			fits := bytes.Repeat([]byte("x"), int(limit))
			if got := parsesAs(t, roleAttrs(role, fits), fits, 4096); got != "" {
				t.Errorf("record at the cap dropped: %q", got)
			}
		})
	}
	for _, unknown := range []string{"governed.input", "model.exchange", "Model.exchange.request", "run.secret", ""} {
		if got := parsesAs(t, setAttr(validAttrs(body), "role", unknown), body, defaultMaxBodyBytes); got != reasonBadDescriptor {
			t.Errorf("unknown role %q admitted: %q", unknown, got)
		}
	}
}

// policy adds the policy block of a configured capture policy.
func policy(attrs map[string]any, mode, protection string) map[string]any {
	attrs["privacy_mode"], attrs["protection_status"] = mode, protection
	attrs["policy_id"], attrs["policy_version"], attrs["policy_digest"] = "acme-capture", int64(3), policyDigest
	return attrs
}

func redacted(body []byte, mode, representation, transformation string) map[string]any {
	attrs := policy(validAttrs(body), mode, map[string]string{"redacted": "redacted", "tokenized": "tokenized"}[representation])
	attrs["status"], attrs["representation"], attrs["transformations"] = "redacted", representation, []any{transformation}
	attrs["transformation_id"], attrs["transformation_version"] = "acme-pii-mask", "7"
	delete(attrs, "source_sha256")
	delete(attrs, "source_byte_length")
	return attrs
}

func withheld(mode, reason string) map[string]any {
	attrs := policy(validAttrs(nil), mode, "withheld")
	attrs["status"], attrs["representation"], attrs["status_reason"] = "not_captured", "unavailable", reason
	for _, key := range []string{"stored_byte_length", "stored_sha256", "source_byte_length", "source_sha256"} {
		delete(attrs, key)
	}
	return attrs
}

func splitSkeleton(body []byte, original []byte) map[string]any {
	attrs := validAttrs(body)
	attrs["object_id"], attrs["representation"], attrs["transformations"] = skeletonID, "split", []any{"extract_parts"}
	attrs["source_byte_length"], attrs["source_sha256"] = int64(len(original)), digest(original)
	return attrs
}

func clone(attrs map[string]any) map[string]any {
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	return out
}

// Spec 049 §4.3 rules 5-7, §7.5 and §7.7: the privacy modes, descriptor-only
// withholding, split parts and review copies.
func TestPrivacyModesAndStatuses(t *testing.T) {
	body := []byte("masked [NAME] asked about [DRUG]")
	original := []byte(`{"messages":"...image..."}`)
	part := []byte("iVBORw0KGgo=")
	partAttrs := setAttr(roleAttrs("model.exchange.part", part), "object_id", partID)
	partAttrs["media_type"] = "image/png"
	review := redacted(body, "original_plus_masked", "redacted", "redact")
	review["object_id"], review["links"] = reviewID, []any{map[string]any{"relation": "derived_from", "object_id": testObjectID}}
	accepted := map[string]struct {
		attrs map[string]any
		body  []byte
	}{
		"redact":                         {redacted(body, "redact", "redacted", "redact"), body},
		"masked_only":                    {redacted(body, "masked_only", "redacted", "redact"), body},
		"tokenize":                       {redacted(body, "tokenize", "tokenized", "tokenize"), body},
		"redacted skeleton":              {setAttr(redacted(body, "redact", "redacted", "redact"), "transformations", []any{"extract_parts", "redact"}), body},
		"original_plus_masked original":  {policy(validAttrs(body), "original_plus_masked", "retained"), body},
		"original_plus_masked review":    {review, body},
		"retain_original with policy":    {policy(validAttrs(body), "retain_original", "retained"), body},
		"retained truncated":             {policy(truncatedAttrs(body), "retain_original", "retained"), body},
		"protection_failed redact":       {withheld("redact", "protection_failed"), nil},
		"protection_failed masked_only":  {withheld("masked_only", "protection_failed"), nil},
		"protection_failed opm":          {withheld("original_plus_masked", "protection_failed"), nil},
		"metadata_only":                  {setAttr(withheld("metadata_only", "privacy_policy"), "source_byte_length", int64(512)), nil},
		"omit":                           {withheld("omit", "privacy_policy"), nil},
		"part_cap under retain_original": {setAttr(setAttr(withheld("retain_original", "part_cap"), "source_byte_length", int64(70<<20)), "source_sha256", digest(part)), nil},
		"not_captured without policy":    {setAttr(withheld("retain_original", "body_cap"), "privacy_mode", nil), nil},
		"split skeleton":                 {splitSkeleton(body, original), body},
		"split part":                     {partAttrs, part},
		"redacted part":                  {redactedPart(part), part},
		// Sol P0-A #7: a binary part no part transformation applies to (§7.5).
		"privacy-withheld part redact":      {withheldPart("redact"), nil},
		"privacy-withheld part masked_only": {withheldPart("masked_only"), nil},
		"stream chunk":                      {setAttr(setAttr(validAttrs(body), "stream_id", "st-1"), "chunk_index", int64(4)), body},
		"attempt and workload":              {setAttr(setAttr(setAttr(validAttrs(body), "attempt_id", "att-1"), "workload_id", "wl-1"), "observed_at", "2026-10-19T09:00:00Z"), body},
	}
	for name, tc := range accepted {
		t.Run("accept/"+name, func(t *testing.T) {
			attrs := tc.attrs
			if name == "not_captured without policy" {
				for _, key := range policyFields {
					delete(attrs, key)
				}
			}
			if got := parsesAs(t, clone(attrs), tc.body, defaultMaxBodyBytes); got != "" {
				t.Fatalf("dropped: %s", got)
			}
		})
	}
	rejected := map[string]struct {
		attrs map[string]any
		body  []byte
	}{
		"redacted keeps source digest":      {setAttr(redacted(body, "redact", "redacted", "redact"), "source_sha256", digest(body)), body},
		"redacted keeps source length":      {setAttr(redacted(body, "redact", "redacted", "redact"), "source_byte_length", int64(99)), body},
		"redacted without policy":           {stripPolicy(redacted(body, "redact", "redacted", "redact")), body},
		"redacted wrong transformation":     {setAttr(redacted(body, "redact", "redacted", "redact"), "transformations", []any{"tokenize"}), body},
		"redacted no transformation":        {setAttr(redacted(body, "redact", "redacted", "redact"), "transformations", []any{}), body},
		"tokenized as redact mode":          {redacted(body, "redact", "tokenized", "tokenize"), body},
		"redacted under retain_original":    {redacted(body, "retain_original", "redacted", "redact"), body},
		"review copy without derived_from":  {redacted(body, "original_plus_masked", "redacted", "redact"), body},
		"masked_only stored as original":    {policy(validAttrs(body), "masked_only", "retained"), body},
		"redact stored as original":         {policy(validAttrs(body), "redact", "retained"), body},
		"metadata_only with bytes":          {policy(validAttrs(body), "metadata_only", "retained"), body},
		"protection_failed with digest":     {setAttr(setAttr(withheld("redact", "protection_failed"), "source_sha256", digest(body)), "source_byte_length", int64(len(body))), nil},
		"protection_failed metadata_only":   {withheld("metadata_only", "protection_failed"), nil},
		"withheld with bytes":               {withheld("redact", "protection_failed"), body},
		"withheld with stored digest":       {setAttr(setAttr(withheld("redact", "protection_failed"), "stored_sha256", digest(nil)), "stored_byte_length", int64(0)), nil},
		"not_captured without reason":       {setAttr(withheld("redact", "protection_failed"), "status_reason", nil), nil},
		"not_captured free-text reason":     {setAttr(withheld("redact", "protection_failed"), "status_reason", "the PII detector crashed on Jane"), nil},
		"reason on stored":                  {setAttr(validAttrs(body), "status_reason", "body_cap"), body},
		"omit with length":                  {setAttr(withheld("omit", "privacy_policy"), "source_byte_length", int64(5)), nil},
		"privacy-withheld redact request":   {withheld("redact", "privacy_policy"), nil},
		"privacy-withheld tokenize part":    {withheldPart("tokenize"), nil},
		"privacy-withheld part with digest": {setAttr(withheldPart("redact"), "source_sha256", digest(part)), nil},
		"privacy-withheld part with length": {setAttr(withheldPart("masked_only"), "source_byte_length", int64(len(part))), nil},
		"metadata_only with digest":         {setAttr(setAttr(withheld("metadata_only", "privacy_policy"), "source_sha256", digest(body)), "source_byte_length", int64(len(body))), nil},
		"lost":                              {policy(validAttrs(body), "retain_original", "lost"), body},
		"unsupported":                       {policy(validAttrs(body), "retain_original", "unsupported"), body},
		"partial policy block":              {setAttr(policy(validAttrs(body), "retain_original", "retained"), "policy_digest", nil), body},
		"policy_version zero":               {setAttr(policy(validAttrs(body), "retain_original", "retained"), "policy_version", int64(0)), body},
		"unknown mode":                      {policy(validAttrs(body), "original", "retained"), body},
		"transformation without policy":     {setAttr(setAttr(validAttrs(body), "transformation_id", "x"), "transformation_version", "1"), body},
		"transformation id alone":           {setAttr(redacted(body, "redact", "redacted", "redact"), "transformation_version", nil), body},
		"status pending":                    {setAttr(validAttrs(body), "status", "pending"), body},
		"status dropped":                    {setAttr(validAttrs(body), "status", "dropped"), body},
		"split without extract_parts":       {setAttr(splitSkeleton(body, original), "transformations", []any{}), body},
		"split without source digest":       {setAttr(splitSkeleton(body, original), "source_sha256", nil), body},
		"part without part_of":              {setAttr(clone(partAttrs), "links", nil), part},
		"part_of on a non-part":             {setAttr(validAttrs(body), "links", []any{map[string]any{"relation": "part_of", "object_id": skeletonID}}), body},
		"byte_range wrong length":           {setAttr(clone(partAttrs), "links", []any{map[string]any{"relation": "part_of", "object_id": skeletonID, "byte_range": []any{int64(0), int64(3)}}}), part},
		"byte_range reversed":               {setAttr(clone(partAttrs), "links", []any{map[string]any{"relation": "part_of", "object_id": skeletonID, "byte_range": []any{int64(9), int64(1)}}}), part},
		"byte_range on derived_from":        {setAttr(clone(review), "links", []any{map[string]any{"relation": "derived_from", "object_id": testObjectID, "byte_range": []any{int64(0), int64(1)}}}), body},
		"byte_range on redacted part":       {setAttr(redactedPart(part), "links", []any{map[string]any{"relation": "part_of", "object_id": skeletonID, "byte_range": []any{int64(0), int64(len(part))}}}), part},
		"link to itself":                    {setAttr(clone(review), "links", []any{map[string]any{"relation": "derived_from", "object_id": reviewID}}), body},
		"link unknown relation":             {setAttr(clone(review), "links", []any{map[string]any{"relation": "parent", "object_id": testObjectID}}), body},
		"link extra key":                    {setAttr(clone(review), "links", []any{map[string]any{"relation": "derived_from", "object_id": testObjectID, "note": "x"}}), body},
		"link path object":                  {setAttr(clone(review), "links", []any{map[string]any{"relation": "derived_from", "object_id": "../etc/passwd"}}), body},
		"links empty":                       {setAttr(validAttrs(body), "links", []any{}), body},
		"links not maps":                    {setAttr(validAttrs(body), "links", []any{"derived_from"}), body},
		"chunk without stream":              {setAttr(validAttrs(body), "chunk_index", int64(1)), body},
		"stream without chunk":              {setAttr(validAttrs(body), "stream_id", "st-1"), body},
		"source_authenticated true":         {setAttr(validAttrs(body), "source_authenticated", true), body},
		"source_authenticated false":        {setAttr(validAttrs(body), "source_authenticated", false), body},
	}
	for name, tc := range rejected {
		t.Run("reject/"+name, func(t *testing.T) {
			if got := parsesAs(t, clone(tc.attrs), tc.body, defaultMaxBodyBytes); got != reasonBadDescriptor {
				t.Fatalf("reason %q, want bad_descriptor", got)
			}
		})
	}
}

func redactedPart(part []byte) map[string]any {
	attrs := redacted(part, "redact", "redacted", "redact")
	attrs["object_id"], attrs["role"], attrs["media_type"], attrs["content_encoding"] = partID, "model.exchange.part", "image/png", "base64"
	attrs["links"] = []any{map[string]any{"relation": "part_of", "object_id": skeletonID}}
	return attrs
}

// withheldPart is a binary part withheld by its role's privacy mode: no part
// transformation applies to it (spec 049 §7.5), descriptor only.
func withheldPart(mode string) map[string]any {
	attrs := withheld(mode, "privacy_policy")
	attrs["object_id"], attrs["role"], attrs["media_type"], attrs["content_encoding"] = partID, "model.exchange.part", "image/png", "base64"
	attrs["links"] = []any{map[string]any{"relation": "part_of", "object_id": skeletonID}}
	return attrs
}

func stripPolicy(attrs map[string]any) map[string]any {
	for _, key := range policyFields {
		delete(attrs, key)
	}
	delete(attrs, "transformation_id")
	delete(attrs, "transformation_version")
	return attrs
}

func TestDescriptorJSONForTheNewFields(t *testing.T) {
	part := []byte("iVBORw0KGgo=")
	attrs := setAttr(roleAttrs("model.exchange.part", part), "object_id", partID)
	attrs["media_type"] = "image/png"
	rec := parseDescriptor(mapOf(t, attrs), defaultMaxBodyBytes)
	if rec == nil {
		t.Fatal("part rejected")
	}
	got := string(rec.descriptorJSON("file:///c/tenant-a/evidence/"+partID, true))
	for _, want := range []string{
		`"links": [{"byte_range": [10, 22], "object_id": "` + skeletonID + `", "relation": "part_of"}]`,
		`"source_authenticated": true`,
		`"transformations": []`,
		`"encoding": "binary"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("descriptor lacks %s: %s", want, got)
		}
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("descriptor is not JSON: %v", err)
	}
	// Descriptor-only: no ref, no encoding, no stored fields.
	rec = parseDescriptor(mapOf(t, withheld("redact", "protection_failed")), defaultMaxBodyBytes)
	if rec == nil {
		t.Fatal("withheld record rejected")
	}
	got = string(rec.descriptorJSON("file:///never", false))
	for _, absent := range []string{"ref", "encoding", "stored_sha256", "source_authenticated", "file:///never"} {
		if strings.Contains(got, `"`+absent+`"`) || strings.Contains(got, absent) && absent == "file:///never" {
			t.Errorf("descriptor-only record carries %s: %s", absent, got)
		}
	}
	if !strings.Contains(got, `"status_reason": "protection_failed"`) || !strings.Contains(got, `"transformations": []}`) {
		t.Errorf("descriptor-only record = %s", got)
	}
}

func boundConfig(dir string) *Config {
	cfg := fileConfig(dir)
	cfg.SourceBinding = &SourceBinding{TenantID: testTenant, SourceID: testSource}
	return cfg
}

func boundAttrs(body []byte) map[string]any {
	return setAttr(validAttrs(body), "source_id", testSource)
}

// Spec 049 §7.9 and §4.3 rule 6: a bound exporter writes the receiver-owned
// source_authenticated into the persisted descriptor and drops records of
// another tenant or source; an unbound exporter never writes it.
func TestSourceBindingAndPersistedAuthentication(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	e, logs := observedExporter(t, boundConfig(dir), nil)
	body := []byte("bound body")
	forgedSource := setAttr(setAttr(boundAttrs(body), "source_id", "s-00000000000000000000000000000000"), "object_id", "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a03")
	clearSource := setAttr(setAttr(boundAttrs(body), "source_id", "billing-agent"), "object_id", "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a04")
	withheldRecord := setAttr(setAttr(withheld("redact", "protection_failed"), "source_id", testSource), "object_id", "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a05")
	if err := e.pushLogs(context.Background(), makeLogs(t,
		withBody(boundAttrs(body), body),
		withBody(forgedSource, body),
		withBody(clearSource, body),
		withBody(withheldRecord, nil),
		withBody(setAttr(boundAttrs(body), "source_authenticated", true), body),
	)); err != nil {
		t.Fatal(err)
	}
	assertDropped(t, e, logs, map[string]uint64{reasonSourceUnbound: 2, reasonBadDescriptor: 1})
	meta := readFile(t, shardedMeta(dir, testTenant, testObjectID))
	if !strings.Contains(string(meta), `"source_authenticated": true`) {
		t.Fatalf("bound descriptor lacks source_authenticated: %s", meta)
	}
	for _, id := range []string{"0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a03", "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a04"} {
		if _, err := os.Stat(shardedObject(dir, testTenant, id)); !os.IsNotExist(err) {
			t.Errorf("unbound record %s written", id)
		}
	}
	// Descriptor-only: a descriptor, no body object.
	if _, err := os.Stat(shardedObject(dir, testTenant, "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a05")); !os.IsNotExist(err) {
		t.Error("withheld record wrote a body object")
	}
	withheldMeta := readFile(t, shardedMeta(dir, testTenant, "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a05"))
	if !strings.Contains(string(withheldMeta), `"source_authenticated": true`) || strings.Contains(string(withheldMeta), `"ref"`) {
		t.Errorf("withheld descriptor = %s", withheldMeta)
	}

	unbound := filepath.Join(t.TempDir(), "content")
	e, _ = observedExporter(t, fileConfig(unbound), nil)
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	if meta := readFile(t, shardedMeta(unbound, testTenant, testObjectID)); strings.Contains(string(meta), "source_authenticated") {
		t.Fatalf("unbound exporter wrote source_authenticated: %s", meta)
	}
}

// A full content queue applies backpressure (the request waits, then fails
// at its deadline, so the agent's spool keeps the record); nothing is
// dropped or written while the store is unavailable, and every record is
// stored once it recovers.
func TestQueueFullAndStoreUnavailable(t *testing.T) {
	mem := newMemBackend()
	mem.failFor = func(string) bool { return true } // store unavailable
	cfg := fileConfig("/unused")
	queue := exporterhelper.NewDefaultQueueConfig()
	queue.QueueSize, queue.NumConsumers, queue.BlockOnOverflow = 1, 1, true
	cfg.QueueConfig = configoptional.Some(queue)
	cfg.RetryConfig.InitialInterval = 5 * time.Millisecond
	cfg.RetryConfig.MaxInterval = 10 * time.Millisecond
	f := NewFactory()
	set := exportertest.NewNopSettings(f.Type())
	set.ID = component.MustNewID("fabriccontent")
	exp, err := createLogsWithBackend(t, set, cfg, mem)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exp.Shutdown(context.Background()) }()
	ids := []string{"0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a11", "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a12", "0b8e1c52-1f0a-4d7e-8f3b-5c9a2e7d1a13"}
	body := []byte("queued body")
	var blocked int
	for _, id := range ids {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		if err := exp.ConsumeLogs(ctx, makeLogs(t, withBody(setAttr(validAttrs(body), "object_id", id), body))); err != nil {
			blocked++
			if strings.Contains(err.Error(), "queued body") || strings.Contains(err.Error(), testTenant) {
				t.Fatalf("backpressure error leaks content: %v", err)
			}
		}
		cancel()
	}
	if blocked == 0 {
		t.Fatal("a full queue accepted every record without backpressure")
	}
	mem.mu.Lock()
	written := len(mem.objects)
	mem.mu.Unlock()
	if written != 0 {
		t.Fatalf("objects written while the store was unavailable: %d", written)
	}
	mem.mu.Lock()
	mem.failFor = nil
	mem.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mem.mu.Lock()
		written = len(mem.objects)
		mem.mu.Unlock()
		if written == 2*(len(ids)-blocked) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("accepted records not stored after recovery: %d objects", written)
}

// createLogsWithBackend builds the exporter through exporterhelper exactly as
// the factory does, with an injected backend.
func createLogsWithBackend(t *testing.T, set exporter.Settings, cfg *Config, b backend) (exporter.Logs, error) {
	t.Helper()
	e, err := newContentExporter(cfg, set.TelemetrySettings)
	if err != nil {
		return nil, err
	}
	e.newBackend = func(context.Context) (backend, error) { return b, nil }
	exp, err := exporterhelper.NewLogs(context.Background(), set, cfg, e.pushLogs,
		exporterhelper.WithStart(e.start),
		exporterhelper.WithTimeout(cfg.TimeoutConfig),
		exporterhelper.WithRetry(cfg.RetryConfig),
		exporterhelper.WithQueue(cfg.QueueConfig),
	)
	if err != nil {
		return nil, err
	}
	return exp, exp.Start(context.Background(), componenttest.NewNopHost())
}

// Spec 049 §7.4 rule 3 and §7.5 (agreed with the SDK sender): a part over
// the cap under retain_original is a descriptor-only part_cap record that
// keeps its length, digest and range; a side cut at body_cap under a
// transforming mode is withheld with no lengths.
func TestWithheldPartsAndCutSides(t *testing.T) {
	partCap := policy(validAttrs(nil), "retain_original", "withheld")
	for _, key := range []string{"stored_byte_length", "stored_sha256"} {
		delete(partCap, key)
	}
	partCap["object_id"], partCap["role"], partCap["media_type"], partCap["content_encoding"] = partID, "model.exchange.part", "image/png", "base64"
	partCap["status"], partCap["representation"], partCap["status_reason"] = "not_captured", "unavailable", "part_cap"
	partCap["source_byte_length"], partCap["source_sha256"] = int64(70<<20), digest([]byte("part"))
	partCap["links"] = []any{map[string]any{"relation": "part_of", "object_id": skeletonID, "byte_range": []any{int64(100), int64(100 + 70<<20)}}}
	if got := parsesAs(t, clone(partCap), nil, defaultMaxBodyBytes); got != "" {
		t.Fatalf("part_cap record dropped: %s", got)
	}
	short := clone(partCap)
	short["links"] = []any{map[string]any{"relation": "part_of", "object_id": skeletonID, "byte_range": []any{int64(100), int64(101)}}}
	if got := parsesAs(t, short, nil, defaultMaxBodyBytes); got != reasonBadDescriptor {
		t.Fatalf("range not spanning the withheld part admitted: %q", got)
	}
	for _, mode := range []string{"redact", "tokenize", "masked_only"} {
		cut := withheld(mode, "body_cap")
		if got := parsesAs(t, clone(cut), nil, defaultMaxBodyBytes); got != "" {
			t.Errorf("%s body_cap withholding dropped: %s", mode, got)
		}
		if got := parsesAs(t, setAttr(clone(cut), "source_byte_length", int64(9)), nil, defaultMaxBodyBytes); got != reasonBadDescriptor {
			t.Errorf("%s withholding kept the original's length: %q", mode, got)
		}
	}
}

// The Node's parser and the capture/v1 contract agree on every pinned
// content log record: valid fixtures parse, invalid ones (other than a body
// digest mismatch, which needs the bytes) are bad descriptors.
func TestContentLogRecordFixturesParity(t *testing.T) {
	const family = "../../../../contracts/capture/v1/"
	var manifest struct {
		Artifacts []struct {
			Path          string  `json:"path"`
			Expectation   string  `json:"expectation"`
			ExpectedError *string `json:"expected_error"`
		} `json:"artifacts"`
	}
	decodeFile(t, family+"manifest.json", &manifest)
	seen := 0
	for _, a := range manifest.Artifacts {
		if !strings.Contains(a.Path, "content-log-record") || a.Expectation == "schema" {
			continue
		}
		if a.ExpectedError != nil && *a.ExpectedError == "capture.content.digest" {
			continue
		}
		seen++
		t.Run(a.Path, func(t *testing.T) {
			raw, err := os.ReadFile(family + a.Path)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Attributes map[string]any `json:"attributes"`
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&doc); err != nil {
				t.Fatal(err)
			}
			rec := parseDescriptor(mapOf(t, numbersToInts(t, doc.Attributes).(map[string]any)), defaultMaxBodyBytes)
			if (rec != nil) != (a.Expectation == "valid") {
				t.Fatalf("parser accepted=%v, contract expects %s", rec != nil, a.Expectation)
			}
		})
	}
	if seen < 10 {
		t.Fatalf("only %d content log record fixtures checked", seen)
	}
}

func numbersToInts(t *testing.T, v any) any {
	t.Helper()
	switch x := v.(type) {
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			t.Fatal(err)
		}
		return i
	case map[string]any:
		for k, item := range x {
			x[k] = numbersToInts(t, item)
		}
		return x
	case []any:
		for i, item := range x {
			x[i] = numbersToInts(t, item)
		}
		return x
	}
	return v
}
