// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumererror"
)

// fakeS3 is a minimal path-style S3 endpoint: conditional PutObject
// (If-None-Match: *), GetObject, and optional failure modes.
type fakeS3 struct {
	mu            sync.Mutex
	objects       map[string][]byte
	headers       map[string]http.Header
	puts          int
	unconditional int
	noConditional bool // respond 501 NotImplemented to conditional writes
	failStatus    int  // respond with this status to every PUT
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}, headers: map[string]http.Header{}}
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch r.Method {
	case http.MethodPut:
		f.puts++
		if r.Header.Get("If-None-Match") != "*" {
			f.unconditional++
		}
		if f.failStatus != 0 {
			s3Error(w, f.failStatus, "ServiceUnavailable")
			return
		}
		if f.noConditional {
			s3Error(w, http.StatusNotImplemented, "NotImplemented")
			return
		}
		body, err := readS3Body(r)
		if err != nil {
			s3Error(w, http.StatusBadRequest, "BadRequest")
			return
		}
		if sum := r.Header.Get("X-Amz-Checksum-Sha256"); sum != "" {
			digest := sha256.Sum256(body)
			if sum != base64.StdEncoding.EncodeToString(digest[:]) {
				s3Error(w, http.StatusBadRequest, "BadDigest")
				return
			}
		}
		if _, exists := f.objects[key]; exists && r.Header.Get("If-None-Match") == "*" {
			s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		f.objects[key] = body
		f.headers[key] = r.Header.Clone()
		w.Header().Set("ETag", `"etag"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		body, ok := f.objects[key]
		if !ok {
			s3Error(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	default:
		s3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func s3Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>m</Message><RequestId>r</RequestId></Error>`, code)
}

// readS3Body decodes an aws-chunked payload if the SDK used one.
func readS3Body(r *http.Request) ([]byte, error) {
	if !strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
		return io.ReadAll(r.Body)
	}
	var out bytes.Buffer
	br := bufio.NewReader(r.Body)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(line, ";", 2)[0]), 16, 64)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return out.Bytes(), nil
		}
		if _, err := io.CopyN(&out, br, size); err != nil {
			return nil, err
		}
		if _, err := br.ReadString('\n'); err != nil {
			return nil, err
		}
	}
}

func s3TestConfig(t *testing.T, endpoint string) *Config {
	t.Helper()
	// Static test credentials through the default chain; no profile, IMDS
	// or shared files are consulted.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDFABRICTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fabric-test-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent/fabric/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/fabric/credentials")
	t.Setenv("AWS_PROFILE", "")
	cfg := createDefaultConfig().(*Config)
	cfg.AllowedTenants = []string{testTenant}
	cfg.Backend = backendS3
	cfg.S3 = S3Config{
		Bucket:       "customer-evidence",
		Prefix:       "fabric/content/",
		Region:       "us-east-1",
		Endpoint:     endpoint,
		UsePathStyle: true,
		SSE:          "aws:kms",
		KMSKeyID:     "arn:aws:kms:us-east-1:111122223333:key/fabric-test",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

const s3BodyKey = "customer-evidence/fabric/content/tenant-a/evidence/" + testObjectID
const s3MetaKey = "customer-evidence/fabric/content/tenant-a/evidence/meta/" + testObjectID + ".json"

func TestS3BackendWritesLayoutWithSSEAndConditionalPut(t *testing.T) {
	fake := newFakeS3()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	e, logs := observedExporter(t, s3TestConfig(t, srv.URL), nil)
	body := []byte(`{"model":"gpt-4o","messages":[]}`)
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	if got := fake.objects[s3BodyKey]; !bytes.Equal(got, body) {
		t.Fatalf("stored body = %q (keys %v)", got, keys(fake.objects))
	}
	var desc map[string]any
	if err := json.Unmarshal(fake.objects[s3MetaKey], &desc); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if want := "s3://customer-evidence/fabric/content/tenant-a/evidence/" + testObjectID; desc["ref"] != want {
		t.Errorf("ref = %v, want %s", desc["ref"], want)
	}
	for _, key := range []string{s3BodyKey, s3MetaKey} {
		h := fake.headers[key]
		if h.Get("If-None-Match") != "*" {
			t.Errorf("%s: PutObject without If-None-Match: *", key)
		}
		if h.Get("X-Amz-Server-Side-Encryption") != "aws:kms" {
			t.Errorf("%s: SSE header = %q", key, h.Get("X-Amz-Server-Side-Encryption"))
		}
		if h.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != "arn:aws:kms:us-east-1:111122223333:key/fabric-test" {
			t.Errorf("%s: KMS key header = %q", key, h.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"))
		}
		if h.Get("X-Amz-Checksum-Sha256") == "" {
			t.Errorf("%s: no SHA-256 checksum sent", key)
		}
	}
	if logs.Len() != 0 {
		t.Errorf("unexpected logs: %d", logs.Len())
	}
}

func TestS3BackendAES256(t *testing.T) {
	fake := newFakeS3()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := s3TestConfig(t, srv.URL)
	cfg.S3.SSE, cfg.S3.KMSKeyID = "AES256", ""
	e, _ := observedExporter(t, cfg, nil)
	body := []byte("b")
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	h := fake.headers[s3BodyKey]
	if h.Get("X-Amz-Server-Side-Encryption") != "AES256" || h.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != "" {
		t.Errorf("SSE headers = %q / %q", h.Get("X-Amz-Server-Side-Encryption"), h.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"))
	}
}

// On 412 the existing object is read back: identical bytes are a successful
// replay; different bytes are a permanent conflict and nothing is overwritten.
func TestS3BackendIfNoneMatchReplayAndConflict(t *testing.T) {
	fake := newFakeS3()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	e, logs := observedExporter(t, s3TestConfig(t, srv.URL), nil)
	body := []byte("original")
	ld := makeLogs(t, withBody(validAttrs(body), body))
	for i := 0; i < 2; i++ {
		if err := e.pushLogs(context.Background(), ld); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	if e.written.Load() != 2 {
		t.Errorf("identical replay not accepted: written = %d", e.written.Load())
	}
	other := []byte("tampered")
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(other), other))); err != nil {
		t.Fatalf("conflict must be permanent, got %v", err)
	}
	if got := fake.objects[s3BodyKey]; !bytes.Equal(got, body) {
		t.Fatalf("object overwritten: %q", got)
	}
	if fake.unconditional != 0 {
		t.Errorf("%d unconditional PUTs sent", fake.unconditional)
	}
	assertDropped(t, e, logs, map[string]uint64{reasonConflict: 1})
}

// A store without conditional-write support is retryable, never an
// unconditional overwrite; server errors are retryable and content-free.
func TestS3BackendFailuresAreRetryable(t *testing.T) {
	for name, configure := range map[string]func(*fakeS3){
		"conditional writes unsupported": func(f *fakeS3) { f.noConditional = true },
		"service unavailable":            func(f *fakeS3) { f.failStatus = http.StatusServiceUnavailable },
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeS3()
			configure(fake)
			srv := httptest.NewServer(fake)
			defer srv.Close()
			e, logs := observedExporter(t, s3TestConfig(t, srv.URL), nil)
			body := []byte("body")
			err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body)))
			if err == nil || consumererror.IsPermanent(err) {
				t.Fatalf("want retryable error, got %v", err)
			}
			if len(fake.objects) != 0 || fake.unconditional != 0 {
				t.Fatalf("objects written: %d, unconditional PUTs: %d", len(fake.objects), fake.unconditional)
			}
			for _, secret := range []string{srv.URL, "127.0.0.1", "customer-evidence", testTenant, testObjectID, "fabric-test"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error text leaks %q: %s", secret, err.Error())
				}
			}
			if logs.Len() != 0 {
				t.Errorf("retryable failure logged as a drop")
			}
		})
	}
}

func TestS3BackendRequiresRegion(t *testing.T) {
	cfg := s3TestConfig(t, "http://127.0.0.1:1")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	cfg.S3.Region = ""
	if _, err := newS3Backend(context.Background(), cfg.S3); err == nil {
		t.Fatal("backend started without a region")
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
