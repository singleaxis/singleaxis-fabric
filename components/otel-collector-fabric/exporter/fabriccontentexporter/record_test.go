// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
)

type golden struct {
	Record struct {
		Attributes map[string]any `json:"attributes"`
	} `json:"content_log_record"`
	Backend struct {
		Kind      string `json:"kind"`
		Directory string `json:"directory"`
		Bucket    string `json:"bucket"`
		Prefix    string `json:"prefix"`
	} `json:"backend"`
	ObjectKey      string `json:"object_key"`
	DescriptorKey  string `json:"descriptor_key"`
	Ref            string `json:"ref"`
	DescriptorJSON string `json:"descriptor_json"`
}

func loadGolden(t *testing.T, name string) golden {
	t.Helper()
	raw, err := os.ReadFile("../../../../contracts/capture/v1/fixtures/golden/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&g); err != nil {
		t.Fatal(err)
	}
	// JSON numbers become int64 attributes, lists become slices.
	for k, v := range g.Record.Attributes {
		if n, ok := v.(json.Number); ok {
			i, err := n.Int64()
			if err != nil {
				t.Fatal(err)
			}
			g.Record.Attributes[k] = i
		}
	}
	return g
}

// The Node's keys, ref and descriptor bytes must equal the contract goldens
// byte for byte: fabric.reconstruct reads exactly this layout.
func TestGoldenDescriptorLayout(t *testing.T) {
	for _, name := range []string{"content-descriptor-file.json", "content-descriptor-s3.json"} {
		t.Run(name, func(t *testing.T) {
			g := loadGolden(t, name)
			rec := parseDescriptor(mapOf(t, g.Record.Attributes))
			if rec == nil {
				t.Fatal("golden attributes rejected")
			}
			var b backend
			var relPrefix string
			switch g.Backend.Kind {
			case "file":
				b = newFileBackend(g.Backend.Directory)
			case "s3":
				b = &s3Backend{cfg: S3Config{Bucket: g.Backend.Bucket, Prefix: g.Backend.Prefix}}
				relPrefix = g.Backend.Prefix
			default:
				t.Fatalf("unknown backend %q", g.Backend.Kind)
			}
			if got := objectKey(relPrefix, rec.tenant, rec.objectID); got != g.ObjectKey {
				t.Errorf("object key = %q, want %q", got, g.ObjectKey)
			}
			if got := descriptorKey(relPrefix, rec.tenant, rec.objectID); got != g.DescriptorKey {
				t.Errorf("descriptor key = %q, want %q", got, g.DescriptorKey)
			}
			full := objectKey(b.prefix(), rec.tenant, rec.objectID)
			if got := b.ref(full); got != g.Ref {
				t.Errorf("ref = %q, want %q", got, g.Ref)
			}
			if got := string(rec.descriptorJSON(b.ref(full))); got != g.DescriptorJSON {
				t.Errorf("descriptor bytes differ:\n got %q\nwant %q", got, g.DescriptorJSON)
			}
		})
	}
}

func TestDescriptorJSONTruncatedAndEscaping(t *testing.T) {
	body := []byte("x")
	rec := parseDescriptor(mapOf(t, truncatedAttrs(body)))
	if rec == nil {
		t.Fatal("valid truncated record rejected")
	}
	got := string(rec.descriptorJSON("file:///c/tenant-a/evidence/x"))
	if !strings.Contains(got, `"transformations": ["truncate"]`) || strings.Contains(got, "source_sha256") {
		t.Errorf("truncated descriptor = %s", got)
	}
	// media_type may contain '&' etc.: no HTML escaping (Python json.dumps).
	attrs := validAttrs(body)
	attrs["media_type"] = "application/a&b+json"
	rec = parseDescriptor(mapOf(t, attrs))
	if rec == nil {
		t.Fatal("media type with & rejected")
	}
	if got := string(rec.descriptorJSON("r")); !strings.Contains(got, `"media_type": "application/a&b+json"`) {
		t.Errorf("media_type escaped: %s", got)
	}
	if got := quote("a\"b\\c\n\x01é"); got != `"a\"b\\c\n\u0001é"` {
		t.Errorf("quote = %s", got)
	}
}

func TestParseRecordAcceptsValidRecords(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[]}`)
	for name, attrs := range map[string]map[string]any{
		"exact request":     validAttrs(body),
		"truncated":         truncatedAttrs(body),
		"partial response":  setAttr(setAttr(validAttrs(body), "role", "model.exchange.response"), "representation", "partial"),
		"empty body":        validAttrs(nil),
		"encoding list":     setAttr(validAttrs(body), "content_encoding", "gzip,br"),
		"z timestamp":       setAttr(validAttrs(body), "captured_at", "2026-10-07T00:00:01Z"),
		"media type 3 char": setAttr(validAttrs(body), "media_type", "a/b"),
	} {
		t.Run(name, func(t *testing.T) {
			b := body
			if name == "empty body" {
				b = nil
			}
			lr := makeLogs(t, withBody(attrs, b)).ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			if _, reason := parseRecord(lr); reason != "" {
				t.Fatalf("valid record dropped: %s", reason)
			}
		})
	}
}

// Every way a record can leave the closed set is bad_descriptor.
func TestParseRecordRejectsBadDescriptors(t *testing.T) {
	body := []byte("hello")
	long := "application/" + strings.Repeat("x", 120)
	cases := map[string]map[string]any{
		"unknown attribute":         setAttr(validAttrs(body), "prompt", "secret"),
		"missing event_class":       setAttr(validAttrs(body), "event_class", nil),
		"event_class activity":      setAttr(validAttrs(body), "event_class", "activity"),
		"missing object_id":         setAttr(validAttrs(body), "object_id", nil),
		"uppercase object_id":       setAttr(validAttrs(body), "object_id", strings.ToUpper(testObjectID)),
		"object_id path":            setAttr(validAttrs(body), "object_id", "../../etc/passwd"),
		"tenant traversal":          setAttr(validAttrs(body), "tenant_id", "../x"),
		"tenant slash":              setAttr(validAttrs(body), "tenant_id", "a/b"),
		"wrong schema":              setAttr(validAttrs(body), "schema_version", "fabric.content-object/v1"),
		"bad role":                  setAttr(validAttrs(body), "role", "governed.input"),
		"media type too long":       setAttr(validAttrs(body), "media_type", long),
		"media type too short":      setAttr(validAttrs(body), "media_type", "a/"),
		"media type upper":          setAttr(validAttrs(body), "media_type", "Application/JSON"),
		"bad encoding":              setAttr(validAttrs(body), "content_encoding", "GZIP"),
		"bad provenance":            setAttr(validAttrs(body), "provenance", "sdk"),
		"bad boundary":              setAttr(validAttrs(body), "boundary", "internal"),
		"int as string":             setAttr(validAttrs(body), "source_sequence", "1"),
		"negative int":              setAttr(validAttrs(body), "source_epoch", int64(-1)),
		"string as int":             setAttr(validAttrs(body), "run_id", int64(7)),
		"bad run id":                setAttr(validAttrs(body), "run_id", "run id with spaces"),
		"bad captured_at":           setAttr(validAttrs(body), "captured_at", "yesterday"),
		"bad digest":                setAttr(validAttrs(body), "stored_sha256", "sha256:XYZ"),
		"transformations string":    setAttr(validAttrs(body), "transformations", "truncate"),
		"transformations other":     setAttr(validAttrs(body), "transformations", []any{"redact"}),
		"transformations two":       setAttr(validAttrs(body), "transformations", []any{"truncate", "truncate"}),
		"partial request":           setAttr(validAttrs(body), "representation", "partial"),
		"stored with truncate":      setAttr(validAttrs(body), "transformations", []any{"truncate"}),
		"source digest differs":     setAttr(validAttrs(body), "source_sha256", digest([]byte("other"))),
		"source length differs":     setAttr(validAttrs(body), "source_byte_length", int64(99)),
		"missing source digest":     setAttr(validAttrs(body), "source_sha256", nil),
		"truncated with source sha": setAttr(truncatedAttrs(body), "source_sha256", digest(body)),
		"truncated not longer":      setAttr(truncatedAttrs(body), "source_byte_length", int64(len(body))),
		"truncated status stored":   setAttr(truncatedAttrs(body), "status", "stored"),
		"truncated no transform":    setAttr(truncatedAttrs(body), "transformations", []any{}),
		"status truncated on exact": setAttr(validAttrs(body), "status", "truncated"),
		"map value":                 setAttr(validAttrs(body), "role", map[string]any{"a": "b"}),
		// Spec 049 §4.3 rule 6: source_authenticated is receiver-owned. The
		// exporter writes it; an agent that supplies it (true or otherwise)
		// is rejected by the closed parser.
		"agent source_authenticated": setAttr(validAttrs(body), "source_authenticated", true),
		"agent source_auth string":   setAttr(validAttrs(body), "source_authenticated", "true"),
	}
	for name, attrs := range cases {
		t.Run(name, func(t *testing.T) {
			lr := makeLogs(t, withBody(attrs, body)).ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			if rec, reason := parseRecord(lr); reason != reasonBadDescriptor {
				t.Fatalf("reason = %q (rec %v), want bad_descriptor", reason, rec != nil)
			}
		})
	}
	t.Run("string body", func(t *testing.T) {
		ld := makeLogs(t, withBody(validAttrs(body), body))
		lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		lr.Body().SetStr("hello")
		if _, reason := parseRecord(lr); reason != reasonBadDescriptor {
			t.Fatalf("reason = %q, want bad_descriptor", reason)
		}
	})
	t.Run("duplicate key", func(t *testing.T) {
		// pcommon.Map never creates duplicates itself; an OTLP key list on
		// the wire can. Inject a second "role" through the JSON encoding.
		raw, err := (&plog.JSONMarshaler{}).MarshalLogs(makeLogs(t, withBody(validAttrs(body), body)))
		if err != nil {
			t.Fatal(err)
		}
		at := strings.Index(string(raw), `"logRecords"`)
		at += strings.Index(string(raw[at:]), `"attributes":[`) + len(`"attributes":[`)
		dup := `{"key":"role","value":{"stringValue":"model.exchange.response"}},`
		raw = []byte(string(raw[:at]) + dup + string(raw[at:]))
		parsed, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs(raw)
		if err != nil {
			t.Fatal(err)
		}
		got := parsed.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
		if got.Attributes().Len() != len(validAttrs(body))+1 {
			t.Skipf("pdata deduplicated keys on unmarshal (len %d)", got.Attributes().Len())
		}
		if _, reason := parseRecord(got); reason != reasonBadDescriptor {
			t.Fatalf("duplicate key accepted: %q", reason)
		}
	})
}

func TestParseRecordDigestMismatch(t *testing.T) {
	body := []byte("hello")
	for name, mutate := range map[string]func(lr plog.LogRecord){
		"body changed":   func(lr plog.LogRecord) { lr.Body().SetEmptyBytes().FromRaw([]byte("hellO")) },
		"body longer":    func(lr plog.LogRecord) { lr.Body().SetEmptyBytes().FromRaw([]byte("hello!")) },
		"length claimed": func(lr plog.LogRecord) { lr.Attributes().PutInt("stored_byte_length", 4) },
	} {
		t.Run(name, func(t *testing.T) {
			attrs := validAttrs(body)
			if name == "length claimed" {
				attrs["source_byte_length"] = int64(4)
			}
			lr := makeLogs(t, withBody(attrs, body)).ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
			mutate(lr)
			if _, reason := parseRecord(lr); reason != reasonDigestMismatch {
				t.Fatalf("reason = %q, want digest_mismatch", reason)
			}
		})
	}
}
