// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// Spec 043 H1 on the S3 path. The AWS SDK's default client follows 307/308
// (limitedRedirect); a PutObject was refused only because its body is not
// replayable. A GetObject has no body, so after a 412 the replay comparison
// followed a 307 to another host and compared against whatever that host
// served: a redirect could turn an unverified write into a "successful
// replay". The backend now never follows a redirect on any request.
func TestS3BackendNeverFollowsRedirects(t *testing.T) {
	data := []byte("exact-LLM-content")
	for _, tc := range []struct {
		code        int
		redirectPut bool
	}{{301, false}, {302, false}, {307, false}, {308, false}, {307, true}, {308, true}} {
		code := tc.code
		name := http.StatusText(code) + "/replay-read"
		if tc.redirectPut {
			name = http.StatusText(code) + "/put"
		}
		t.Run(name, func(t *testing.T) {
			var targetCalls, sourceGets atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("ETag", `"x"`)
				_, _ = w.Write(data) // the redirect target "has" the same bytes
			}))
			defer target.Close()
			location := strings.Replace(target.URL, "127.0.0.1", "localhost", 1) + "/elsewhere"
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if r.Method == http.MethodPut && !tc.redirectPut {
					s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed")
					return
				}
				sourceGets.Add(1) // any request answered with the redirect
				w.Header().Set("Location", location)
				w.WriteHeader(code)
			}))
			defer source.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw})
			cfg := S3Config{Bucket: "customer-evidence", Region: "us-east-1", Endpoint: source.URL, Prefix: "fabric/content/", SSE: "AES256", UsePathStyle: true}
			b, err := newS3Backend(context.Background(), cfg,
				awsconfig.WithCustomCABundle(strings.NewReader(string(ca))),
				awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIDFABRICTEST", "fabric-test-secret", "")),
				awsconfig.WithRetryMaxAttempts(1))
			if err != nil {
				t.Fatal(err)
			}
			err = b.put(context.Background(), "fabric/content/tenant-a/evidence/object", data)
			if err == nil {
				t.Fatalf("HTTP %d redirect was accepted as a successful write", code)
			}
			if !isRetryableStoreError(err) {
				t.Fatalf("HTTP %d: want a retryable store error, got %T %v", code, err, err)
			}
			// The TLS store was really reached (a handshake failure would
			// also be a retryable error and prove nothing).
			if sourceGets.Load() == 0 {
				t.Fatal("the replay read never reached the store")
			}
			if n := targetCalls.Load(); n != 0 {
				t.Fatalf("HTTP %d: redirect target contacted %d time(s)", code, n)
			}
		})
	}
}

func isRetryableStoreError(err error) bool {
	_, ok := err.(*storeError)
	return ok
}
