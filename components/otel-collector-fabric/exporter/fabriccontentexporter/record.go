// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// Drop reasons. These four strings are the only detail a dropped record ever
// produces in logs or metrics (spec 043 §4).
const (
	reasonBadDescriptor    = "bad_descriptor"
	reasonDigestMismatch   = "digest_mismatch"
	reasonTenantNotAllowed = "tenant_not_allowed"
	reasonConflict         = "conflict"
)

// RE2 has no lookahead, so media_type length (3..128) is checked separately.
var (
	uuid4Pattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	opaqueIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mediaTypePattern   = regexp.MustCompile(`^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$`)
	encodingPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,31}(,[a-z0-9][a-z0-9._+-]{0,31}){0,3}$`)
	capturedAtPattern  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$`)
	roleValues         = map[string]bool{"model.exchange.request": true, "model.exchange.response": true}
	representationVals = map[string]bool{"exact": true, "partial": true, "truncated": true}
	statusValues       = map[string]bool{"stored": true, "truncated": true}
)

func mediaTypeOK(s string) bool {
	return len(s) >= 3 && len(s) <= 128 && mediaTypePattern.MatchString(s)
}

func constant(want string) func(string) bool { return func(s string) bool { return s == want } }

func member(set map[string]bool) func(string) bool { return func(s string) bool { return set[s] } }

// stringFields maps every string attribute to its validator. source_sha256 is
// the only optional key; event_class is checked but never written.
var stringFields = map[string]func(string) bool{
	"event_class":      constant("content"),
	"schema_version":   constant("fabric.content-object/v2"),
	"object_id":        uuid4Pattern.MatchString,
	"tenant_id":        tenantPattern.MatchString,
	"role":             member(roleValues),
	"media_type":       mediaTypeOK,
	"content_encoding": encodingPattern.MatchString,
	"representation":   member(representationVals),
	"provenance":       constant("protocol"),
	"boundary":         constant("provider_bound"),
	"status":           member(statusValues),
	"stored_sha256":    digestPattern.MatchString,
	"source_sha256":    digestPattern.MatchString,
	"source_id":        opaqueIDPattern.MatchString,
	"run_id":           opaqueIDPattern.MatchString,
	"operation_id":     opaqueIDPattern.MatchString,
	"captured_at":      capturedAtPattern.MatchString,
}

var intFields = map[string]bool{
	"stored_byte_length": true, "source_byte_length": true,
	"source_epoch": true, "source_sequence": true,
}

// requiredFieldCount is the closed attribute set minus the optional
// source_sha256: 16 strings + 4 ints + transformations.
var requiredFieldCount = len(stringFields) - 1 + len(intFields) + 1

// contentRecord is a validated content log record.
type contentRecord struct {
	tenant   string
	objectID string
	body     []byte
	strs     map[string]string
	ints     map[string]int64
	truncate bool // transformations == ["truncate"]
}

// parseRecord applies spec 043 §4 steps 1 and 2. It returns the drop reason
// for a record that must not be written.
func parseRecord(lr plog.LogRecord) (*contentRecord, string) {
	if lr.Body().Type() != pcommon.ValueTypeBytes {
		return nil, reasonBadDescriptor
	}
	rec := parseDescriptor(lr.Attributes())
	if rec == nil {
		return nil, reasonBadDescriptor
	}
	rec.body = lr.Body().Bytes().AsRaw()
	sum := sha256.Sum256(rec.body)
	if int64(len(rec.body)) != rec.ints["stored_byte_length"] ||
		rec.strs["stored_sha256"] != "sha256:"+hex.EncodeToString(sum[:]) {
		return nil, reasonDigestMismatch
	}
	return rec, ""
}

// parseDescriptor validates the closed attribute set and its consistency
// rules (step 1); nil means bad_descriptor.
func parseDescriptor(attrs pcommon.Map) *contentRecord {
	rec := &contentRecord{strs: map[string]string{}, ints: map[string]int64{}}
	transformations, ok, seen := -1, true, 0
	attrs.Range(func(key string, value pcommon.Value) bool {
		seen++
		switch {
		case stringFields[key] != nil:
			ok = value.Type() == pcommon.ValueTypeStr && stringFields[key](value.Str())
			rec.strs[key] = value.Str()
		case intFields[key]:
			ok = value.Type() == pcommon.ValueTypeInt && value.Int() >= 0
			rec.ints[key] = value.Int()
		case key == "transformations":
			ok = value.Type() == pcommon.ValueTypeSlice
			if ok {
				transformations, ok = transformationsValue(value.Slice())
			}
		default:
			ok = false // any key outside the closed set
		}
		return ok
	})
	present := len(rec.strs) + len(rec.ints)
	if transformations >= 0 {
		present++
	}
	duplicates := seen != present // OTLP key lists may repeat a key
	if _, has := rec.strs["source_sha256"]; has {
		present--
	}
	if !ok || duplicates || present != requiredFieldCount {
		return nil
	}
	rec.truncate = transformations == 1
	if !consistent(rec) {
		return nil
	}
	rec.tenant, rec.objectID = rec.strs["tenant_id"], rec.strs["object_id"]
	return rec
}

// transformationsValue returns 0 for [] and 1 for ["truncate"].
func transformationsValue(s pcommon.Slice) (int, bool) {
	switch s.Len() {
	case 0:
		return 0, true
	case 1:
		v := s.At(0)
		return 1, v.Type() == pcommon.ValueTypeStr && v.Str() == "truncate"
	default:
		return 0, false
	}
}

// consistent enforces: truncated <=> status truncated <=> ["truncate"] <=>
// no source_sha256 <=> source_byte_length > stored_byte_length; otherwise
// stored, [] and source digest/length equal to the stored ones; partial only
// on a response.
func consistent(rec *contentRecord) bool {
	sourceSHA, hasSourceSHA := rec.strs["source_sha256"]
	stored, source := rec.ints["stored_byte_length"], rec.ints["source_byte_length"]
	if rec.strs["representation"] == "truncated" {
		return rec.strs["status"] == "truncated" && rec.truncate && !hasSourceSHA && source > stored
	}
	if rec.strs["representation"] == "partial" && rec.strs["role"] != "model.exchange.response" {
		return false
	}
	return rec.strs["status"] == "stored" && !rec.truncate && hasSourceSHA &&
		sourceSHA == rec.strs["stored_sha256"] && source == stored
}

// descriptorJSON renders the stored descriptor exactly as Python's
// json.dumps(d, ensure_ascii=False, sort_keys=True) + "\n": the attributes
// minus event_class, plus encoding "binary" and the writer's ref.
func (rec *contentRecord) descriptorJSON(ref string) []byte {
	fields := map[string]string{"encoding": quote("binary"), "ref": quote(ref)}
	for key, value := range rec.strs {
		if key != "event_class" {
			fields[key] = quote(value)
		}
	}
	for key, value := range rec.ints {
		fields[key] = strconv.FormatInt(value, 10)
	}
	fields["transformations"] = "[]"
	if rec.truncate {
		fields["transformations"] = `["truncate"]`
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys) // byte order == Python's code-point order for ASCII keys
	var b strings.Builder
	b.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(quote(key))
		b.WriteString(": ")
		b.WriteString(fields[key])
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

// quote is Python's json string encoder with ensure_ascii=False: only '"',
// '\\' and C0 controls are escaped; everything else (including '&', '<',
// '>', '/' and non-ASCII) is written as is.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteString(hex.EncodeToString([]byte{byte(r)}))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// objectKey and descriptorKey are the SDK store layout relative to the
// backend prefix.
func objectKey(prefix, tenant, objectID string) string {
	return prefix + tenant + "/evidence/" + objectID
}

func descriptorKey(prefix, tenant, objectID string) string {
	return prefix + tenant + "/evidence/meta/" + objectID + ".json"
}
