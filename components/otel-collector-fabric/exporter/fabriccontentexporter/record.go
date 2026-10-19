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

// Drop reasons. These strings are the only detail a dropped record ever
// produces in logs or metrics (spec 048 §4, spec 049 §4.3 and §7.9).
const (
	reasonBadDescriptor    = "bad_descriptor"
	reasonDigestMismatch   = "digest_mismatch"
	reasonTenantNotAllowed = "tenant_not_allowed"
	reasonConflict         = "conflict"
	// reasonSourceUnbound: the record names a tenant or source other than
	// the binding of the ingress it arrived on (spec 049 §7.9).
	reasonSourceUnbound = "source_unbound"
)

// RE2 has no lookahead, so media_type length (3..128) is checked separately.
var (
	uuid4Pattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	opaqueIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mediaTypePattern  = regexp.MustCompile(`^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$`)
	encodingPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,31}(,[a-z0-9][a-z0-9._+-]{0,31}){0,3}$`)
	capturedAtPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$`)

	provenanceValues     = setOf("native", "protocol", "caller_reported", "inferred")
	boundaryValues       = setOf("caller", "provider_bound", "tool", "terminal", "sandbox", "remote", "host", "service")
	representationValues = setOf("exact", "partial", "truncated", "split", "redacted", "tokenized", "unavailable")
	// Spec 049 §4.3 rule 5: stored, truncated, redacted (body = transformed
	// bytes) and descriptor-only not_captured; any other status is rejected.
	statusValues = setOf("stored", "truncated", "redacted", "not_captured")
	// Spec 049 §2.7 / §7.7 modes and the outcomes the content path admits.
	privacyModes       = setOf("retain_original", "redact", "tokenize", "masked_only", "original_plus_masked", "metadata_only", "omit")
	protectionStatuses = setOf("retained", "redacted", "tokenized", "withheld")
	linkRelations      = setOf("part_of", "derived_from")
	// byteStoringModes are the privacy modes that store bytes (spec 049 §2.7).
	byteStoringModes = setOf("retain_original", "redact", "tokenize", "masked_only", "original_plus_masked")
)

// roleRule is one row of the content role table (roles_generated.go).
type roleRule struct {
	boundary   []string
	provenance []string
	media      []string
	capBytes   int64 // 0: the configured max_body_bytes
}

func setOf(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	return set
}

func mediaTypeOK(s string) bool {
	return len(s) >= 3 && len(s) <= 128 && mediaTypePattern.MatchString(s)
}

func constant(want string) func(string) bool { return func(s string) bool { return s == want } }

func member(set map[string]bool) func(string) bool { return func(s string) bool { return set[s] } }

func knownRole(s string) bool { _, ok := roleTable[s]; return ok }

func knownReason(s string) bool { return statusReasons[s] }

// stringFields maps every string attribute to its validator; requiredStrings
// lists those every record carries. event_class is checked but never written.
var stringFields = map[string]func(string) bool{
	"event_class":            constant("content"),
	"schema_version":         constant("fabric.content-object/v2"),
	"object_id":              uuid4Pattern.MatchString,
	"tenant_id":              tenantPattern.MatchString,
	"role":                   knownRole,
	"media_type":             mediaTypeOK,
	"content_encoding":       encodingPattern.MatchString,
	"representation":         member(representationValues),
	"provenance":             member(provenanceValues),
	"boundary":               member(boundaryValues),
	"status":                 member(statusValues),
	"status_reason":          knownReason,
	"stored_sha256":          digestPattern.MatchString,
	"source_sha256":          digestPattern.MatchString,
	"source_id":              opaqueIDPattern.MatchString,
	"run_id":                 opaqueIDPattern.MatchString,
	"operation_id":           opaqueIDPattern.MatchString,
	"captured_at":            capturedAtPattern.MatchString,
	"observed_at":            capturedAtPattern.MatchString,
	"workload_id":            opaqueIDPattern.MatchString,
	"attempt_id":             opaqueIDPattern.MatchString,
	"stream_id":              opaqueIDPattern.MatchString,
	"privacy_mode":           member(privacyModes),
	"policy_id":              opaqueIDPattern.MatchString,
	"policy_digest":          digestPattern.MatchString,
	"protection_status":      member(protectionStatuses),
	"transformation_id":      opaqueIDPattern.MatchString,
	"transformation_version": opaqueIDPattern.MatchString,
}

var requiredStrings = []string{
	"event_class", "schema_version", "object_id", "tenant_id", "role", "media_type",
	"content_encoding", "representation", "provenance", "boundary", "status",
	"source_id", "run_id", "operation_id", "captured_at",
}

// intFields maps every integer attribute to its minimum.
var intFields = map[string]int64{
	"stored_byte_length": 0, "source_byte_length": 0,
	"source_epoch": 0, "source_sequence": 0,
	"policy_version": 1, "chunk_index": 0,
}

var requiredInts = []string{"source_epoch", "source_sequence"}

// policyFields are present together or not at all (content-v2).
var policyFields = []string{"privacy_mode", "policy_id", "policy_version", "policy_digest", "protection_status"}

// link is one closed descriptor link (spec 049 §4.3 rule 7, §7.4-§7.5).
type link struct {
	relation  string
	objectID  string
	byteRange []int64 // nil, or the half-open [start, end)
}

// contentRecord is a validated content log record.
type contentRecord struct {
	tenant          string
	objectID        string
	body            []byte
	strs            map[string]string
	ints            map[string]int64
	transformations []string
	links           []link
	hasLinks        bool
}

// descriptorOnly reports a not_captured record: no body object, no ref.
func (rec *contentRecord) descriptorOnly() bool { return rec.strs["status"] == "not_captured" }

func (rec *contentRecord) has(key string) bool {
	if _, ok := rec.strs[key]; ok {
		return true
	}
	_, ok := rec.ints[key]
	return ok
}

// parseRecord applies the closed descriptor (spec 048 §4 steps 1 and 2,
// widened by spec 049 §4.3) with maxBody as the role table's
// max_body_bytes. It returns the drop reason for a record that must not be
// written.
func parseRecord(lr plog.LogRecord, maxBody int64) (*contentRecord, string) {
	if lr.Body().Type() != pcommon.ValueTypeBytes {
		return nil, reasonBadDescriptor
	}
	rec := parseDescriptor(lr.Attributes(), maxBody)
	if rec == nil {
		return nil, reasonBadDescriptor
	}
	rec.body = lr.Body().Bytes().AsRaw()
	if rec.descriptorOnly() {
		// A descriptor-only record carries no bytes at all.
		if len(rec.body) != 0 {
			return nil, reasonBadDescriptor
		}
		return rec, ""
	}
	sum := sha256.Sum256(rec.body)
	if int64(len(rec.body)) != rec.ints["stored_byte_length"] ||
		rec.strs["stored_sha256"] != "sha256:"+hex.EncodeToString(sum[:]) {
		return nil, reasonDigestMismatch
	}
	return rec, ""
}

// parseDescriptor validates the closed attribute set and its consistency
// rules; nil means bad_descriptor.
func parseDescriptor(attrs pcommon.Map, maxBody int64) *contentRecord {
	rec := &contentRecord{strs: map[string]string{}, ints: map[string]int64{}}
	ok, seen, hasTransformations := true, 0, false
	attrs.Range(func(key string, value pcommon.Value) bool {
		seen++
		if validate := stringFields[key]; validate != nil {
			ok = value.Type() == pcommon.ValueTypeStr && validate(value.Str())
			rec.strs[key] = value.Str()
			return ok
		}
		if minimum, isInt := intFields[key]; isInt {
			ok = value.Type() == pcommon.ValueTypeInt && value.Int() >= minimum
			rec.ints[key] = value.Int()
			return ok
		}
		switch key {
		case "transformations":
			hasTransformations = true
			rec.transformations, ok = stringList(value)
		case "links":
			rec.hasLinks = true
			rec.links, ok = linksValue(value)
		default:
			// Any key outside the closed set, including the receiver-owned
			// source_authenticated (spec 049 §4.3 rule 6): never from an agent.
			ok = false
		}
		return ok
	})
	present := len(rec.strs) + len(rec.ints)
	if hasTransformations {
		present++
	}
	if rec.hasLinks {
		present++
	}
	if !ok || seen != present || !hasTransformations { // OTLP key lists may repeat a key
		return nil
	}
	for _, key := range requiredStrings {
		if _, has := rec.strs[key]; !has {
			return nil
		}
	}
	for _, key := range requiredInts {
		if !rec.has(key) {
			return nil
		}
	}
	if !consistent(rec) || !protectionConsistent(rec) || !linksConsistent(rec) || !roleConsistent(rec, maxBody) {
		return nil
	}
	rec.tenant, rec.objectID = rec.strs["tenant_id"], rec.strs["object_id"]
	return rec
}

func stringList(value pcommon.Value) ([]string, bool) {
	if value.Type() != pcommon.ValueTypeSlice {
		return nil, false
	}
	s := value.Slice()
	out := make([]string, 0, s.Len())
	for i := 0; i < s.Len(); i++ {
		if s.At(i).Type() != pcommon.ValueTypeStr {
			return nil, false
		}
		out = append(out, s.At(i).Str())
	}
	return out, true
}

// linksValue parses links: an array of one or two maps with exactly
// relation, object_id and an optional two-integer byte_range.
func linksValue(value pcommon.Value) ([]link, bool) {
	if value.Type() != pcommon.ValueTypeSlice || value.Slice().Len() == 0 || value.Slice().Len() > 2 {
		return nil, false
	}
	s := value.Slice()
	out := make([]link, 0, s.Len())
	for i := 0; i < s.Len(); i++ {
		if s.At(i).Type() != pcommon.ValueTypeMap {
			return nil, false
		}
		var l link
		ok, seen := true, 0
		s.At(i).Map().Range(func(key string, v pcommon.Value) bool {
			seen++
			switch key {
			case "relation":
				ok = v.Type() == pcommon.ValueTypeStr && linkRelations[v.Str()]
				l.relation = v.Str()
			case "object_id":
				ok = v.Type() == pcommon.ValueTypeStr && uuid4Pattern.MatchString(v.Str())
				l.objectID = v.Str()
			case "byte_range":
				ok = v.Type() == pcommon.ValueTypeSlice && v.Slice().Len() == 2
				for j := 0; ok && j < 2; j++ {
					item := v.Slice().At(j)
					ok = item.Type() == pcommon.ValueTypeInt && item.Int() >= 0
					l.byteRange = append(l.byteRange, item.Int())
				}
				ok = ok && l.byteRange[0] <= l.byteRange[1]
			default:
				ok = false
			}
			return ok
		})
		want := 2
		if l.byteRange != nil {
			want = 3
		}
		if !ok || seen != want || l.relation == "" || l.objectID == "" {
			return nil, false
		}
		out = append(out, l)
	}
	return out, true
}

func transformationsAre(rec *contentRecord, options ...[]string) bool {
	for _, option := range options {
		if len(option) != len(rec.transformations) {
			continue
		}
		match := true
		for i := range option {
			match = match && option[i] == rec.transformations[i]
		}
		if match {
			return true
		}
	}
	return false
}

// consistent enforces the status, representation, transformation and digest
// combinations of spec 048 §3 widened by spec 049 §4.3 and §7.5:
//
//	stored        exact []                 source digest and length equal the stored ones
//	stored        partial []               as exact, model.exchange.response only
//	stored        split [extract_parts]    source digest and length of the original body
//	truncated     truncated [truncate]     no source digest, source length > stored
//	redacted      redacted [redact] | [extract_parts, redact]
//	redacted      tokenized [tokenize] | [extract_parts, tokenize]
//	                                       no source digest or length (no original-body claim)
//	not_captured  unavailable []           no stored digest or length, status_reason required
func consistent(rec *contentRecord) bool {
	sourceSHA, hasSourceSHA := rec.strs["source_sha256"]
	storedSHA, hasStoredSHA := rec.strs["stored_sha256"]
	stored, hasStored := rec.ints["stored_byte_length"]
	source, hasSource := rec.ints["source_byte_length"]
	hasReason := rec.has("status_reason")
	representation := rec.strs["representation"]
	if hasStoredSHA != hasStored || hasSourceSHA && !hasSource || rec.has("stream_id") != rec.has("chunk_index") {
		return false
	}
	switch rec.strs["status"] {
	case "not_captured":
		return representation == "unavailable" && len(rec.transformations) == 0 && !hasStored && hasReason
	case "stored":
		if !hasStored || hasReason || !hasSource {
			return false
		}
		switch representation {
		case "exact", "partial":
			if representation == "partial" && rec.strs["role"] != "model.exchange.response" {
				return false
			}
			return len(rec.transformations) == 0 && hasSourceSHA && sourceSHA == storedSHA && source == stored
		case "split":
			return transformationsAre(rec, []string{"extract_parts"}) && hasSourceSHA
		}
	case "truncated":
		return hasStored && !hasReason && representation == "truncated" &&
			transformationsAre(rec, []string{"truncate"}) && !hasSourceSHA && hasSource && source > stored
	case "redacted":
		if !hasStored || hasReason || hasSourceSHA || hasSource {
			return false
		}
		switch representation {
		case "redacted":
			return transformationsAre(rec, []string{"redact"}, []string{"extract_parts", "redact"})
		case "tokenized":
			return transformationsAre(rec, []string{"tokenize"}, []string{"extract_parts", "tokenize"})
		}
	}
	return false
}

// protectionConsistent applies spec 049 §7.5 and §7.7 to the policy block:
// the configured mode, the recorded protection outcome and the status agree;
// a failed transformation is a withheld descriptor, never bytes; and no
// digest of the original survives where the mode forbids one.
func protectionConsistent(rec *contentRecord) bool {
	count := 0
	for _, key := range policyFields {
		if rec.has(key) {
			count++
		}
	}
	if rec.has("transformation_id") != rec.has("transformation_version") {
		return false
	}
	status, reason := rec.strs["status"], rec.strs["status_reason"]
	if count == 0 {
		// No capture policy recorded (the implicit local default): only
		// unprotected outcomes; a transformation always records its policy.
		return !rec.has("transformation_id") && status != "redacted"
	}
	if count != len(policyFields) {
		return false
	}
	mode, protection := rec.strs["privacy_mode"], rec.strs["protection_status"]
	retainsOriginal := mode == "retain_original" || mode == "original_plus_masked"
	hasSourceSHA, hasSource := rec.has("source_sha256"), rec.has("source_byte_length")
	// content-v2: these modes never record the original's length.
	if hasSource && (mode == "omit" || mode == "redact" || mode == "tokenize" || mode == "masked_only") {
		return false
	}
	switch status {
	case "not_captured":
		if protection != "withheld" {
			return false
		}
		switch reason {
		case "protection_failed":
			return byteStoringModes[mode] && !hasSourceSHA
		case "privacy_policy":
			return (mode == "metadata_only" || mode == "omit") && !hasSourceSHA
		}
		// Any other withholding (part_cap, body_cap, ...) keeps the mode's
		// digest rule: only an original-retaining mode may name a digest.
		return retainsOriginal || !hasSourceSHA
	case "stored", "truncated":
		return protection == "retained" && retainsOriginal
	case "redacted":
		if rec.strs["representation"] == "tokenized" {
			return mode == "tokenize" && protection == "tokenized"
		}
		if protection != "redacted" || mode != "redact" && mode != "masked_only" && mode != "original_plus_masked" {
			return false
		}
		if mode != "original_plus_masked" {
			return true
		}
		// A review copy names the original it masks (spec 049 §7.5).
		for _, l := range rec.links {
			if l.relation == "derived_from" {
				return true
			}
		}
	}
	return false
}

// linksConsistent: part_of only on model.exchange.part (exactly one), at
// most one derived_from, never a link to the record itself, and byte_range
// only on part_of of an untransformed part, spanning exactly its stored
// bytes (spec 049 §7.4-§7.5).
func linksConsistent(rec *contentRecord) bool {
	partOf, derivedFrom := 0, 0
	for _, l := range rec.links {
		if l.objectID == rec.strs["object_id"] {
			return false
		}
		if l.relation == "derived_from" {
			derivedFrom++
			if l.byteRange != nil {
				return false
			}
			continue
		}
		partOf++
		if l.byteRange == nil {
			continue
		}
		if rec.strs["status"] == "redacted" {
			return false
		}
		// The range spans the part: its stored bytes, or for a withheld part
		// (part_cap) the source length it names.
		length, ok := rec.ints["stored_byte_length"]
		if !ok {
			length, ok = rec.ints["source_byte_length"]
		}
		if ok && l.byteRange[1]-l.byteRange[0] != length {
			return false
		}
	}
	isPart := rec.strs["role"] == "model.exchange.part"
	return derivedFrom <= 1 && (isPart && partOf == 1 || !isPart && partOf == 0)
}

// roleConsistent applies the role table row (spec 049 §4.3 rules 2-4).
func roleConsistent(rec *contentRecord, maxBody int64) bool {
	rule := roleTable[rec.strs["role"]]
	if !contains(rule.boundary, rec.strs["boundary"]) || !contains(rule.provenance, rec.strs["provenance"]) ||
		!mediaAllowed(rule.media, rec.strs["media_type"]) {
		return false
	}
	limit := rule.capBytes
	if limit == 0 {
		limit = maxBody
	}
	stored, has := rec.ints["stored_byte_length"]
	return !has || stored <= limit
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// mediaAllowed matches an exact type/subtype, a type/* wildcard or *.
func mediaAllowed(patterns []string, mediaType string) bool {
	for _, p := range patterns {
		if p == "*" || p == mediaType || strings.HasSuffix(p, "/*") && strings.HasPrefix(mediaType, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

// descriptorJSON renders the stored descriptor exactly as Python's
// json.dumps(d, ensure_ascii=False, sort_keys=True) + "\n": the attributes
// minus event_class, plus encoding "binary" and the writer's ref for an
// object with bytes, plus the receiver-owned source_authenticated when the
// record arrived on an ingress bound to its tenant and source (spec 049
// §4.3 rule 6). A descriptor-only record has no encoding and no ref.
func (rec *contentRecord) descriptorJSON(ref string, authenticated bool) []byte {
	fields := map[string]string{}
	if !rec.descriptorOnly() {
		fields["encoding"], fields["ref"] = quote("binary"), quote(ref)
	}
	if authenticated {
		fields["source_authenticated"] = "true"
	}
	for key, value := range rec.strs {
		if key != "event_class" {
			fields[key] = quote(value)
		}
	}
	for key, value := range rec.ints {
		fields[key] = strconv.FormatInt(value, 10)
	}
	items := make([]string, len(rec.transformations))
	for i, t := range rec.transformations {
		items[i] = quote(t)
	}
	fields["transformations"] = "[" + strings.Join(items, ", ") + "]"
	if rec.hasLinks {
		links := make([]string, len(rec.links))
		for i, l := range rec.links {
			var b strings.Builder // keys sorted: byte_range, object_id, relation
			b.WriteByte('{')
			if l.byteRange != nil {
				b.WriteString(`"byte_range": [` + strconv.FormatInt(l.byteRange[0], 10) + ", " + strconv.FormatInt(l.byteRange[1], 10) + "], ")
			}
			b.WriteString(`"object_id": ` + quote(l.objectID) + `, "relation": ` + quote(l.relation) + "}")
			links[i] = b.String()
		}
		fields["links"] = "[" + strings.Join(links, ", ") + "]"
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
