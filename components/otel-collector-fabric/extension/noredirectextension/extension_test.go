// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package noredirectextension

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configmiddleware"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/extension/extensiontest"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

const probeSecret = "Bearer NOREDIRECT_PROBE_SECRET"

// target records what a redirect target received.
type target struct {
	mu     sync.Mutex
	calls  int
	body   string
	auth   string
	server *httptest.Server
}

func newTarget(t *testing.T) *target {
	tg := &target{}
	tg.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		tg.mu.Lock()
		tg.calls++
		tg.body = string(b)
		tg.auth = r.Header.Get("Authorization")
		tg.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>login</html>"))
	}))
	t.Cleanup(tg.server.Close)
	return tg
}

func (tg *target) snapshot() (int, string, string) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.calls, tg.body, tg.auth
}

// redirectingSource is an HTTPS destination that answers every request with
// status code and a Location on the plaintext target. It returns the server
// and a CA file trusting it.
func redirectingSource(t *testing.T, code int, location string) (*httptest.Server, string) {
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Location", location)
		w.WriteHeader(code)
		_, _ = w.Write([]byte("redirecting"))
	}))
	t.Cleanup(source.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return source, ca
}

type extensionHost struct {
	component.Host
	extensions map[component.ID]component.Component
}

func (h extensionHost) GetExtensions() map[component.ID]component.Component { return h.extensions }

// exportOnce builds the pinned upstream OTLP/HTTP exporter (queue and retry
// disabled so the export outcome is returned directly), optionally with the
// noredirect middleware, and exports one span to endpoint.
func exportOnce(t *testing.T, endpoint, caFile string, withMiddleware bool) error {
	t.Helper()
	ctx := context.Background()
	factory := otlphttpexporter.NewFactory()
	cfg := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
	cfg.ClientConfig.Endpoint = endpoint
	cfg.ClientConfig.Compression = ""
	cfg.ClientConfig.TLS.CAFile = caFile
	cfg.ClientConfig.Headers = configopaque.MapList{{Name: "Authorization", Value: probeSecret}}
	cfg.QueueConfig = configoptional.None[exporterhelper.QueueBatchConfig]()
	cfg.RetryConfig.Enabled = false

	extID := component.MustNewID(typeStr)
	host := extensionHost{Host: componenttest.NewNopHost(), extensions: map[component.ID]component.Component{}}
	if withMiddleware {
		cfg.ClientConfig.Middlewares = []configmiddleware.Config{{ID: extID}}
		ext, err := NewFactory().Create(ctx, extensiontest.NewNopSettings(component.MustNewType(typeStr)), NewFactory().CreateDefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		host.extensions[extID] = ext
	}

	exp, err := factory.CreateTraces(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.Start(ctx, host); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

	td := ptrace.NewTraces()
	td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty().SetName("exact-metadata")
	return exp.ConsumeTraces(ctx, td)
}

// Sol deployment review of 03484d5 #1: HTTPS -> 307 -> plaintext HTTP must
// never re-send the body or the Authorization header, and a 302 to an HTML
// login page must never count as a successful export. The failure must be
// retryable (not permanent), so the persistent queue keeps the data.
func TestOTLPHTTPExporterRefusesRedirects(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			tg := newTarget(t)
			location := strings.Replace(tg.server.URL, "127.0.0.1", "localhost", 1) + "/v1/traces?token=LOCATION_SECRET"
			source, ca := redirectingSource(t, code, location)

			err := exportOnce(t, source.URL, ca, true)
			if err == nil {
				t.Fatalf("HTTP %d redirect reported as a successful export", code)
			}
			if consumererror.IsPermanent(err) {
				t.Fatalf("HTTP %d redirect is a permanent (dropping) failure, want retryable: %v", code, err)
			}
			var refused *RedirectRefusedError
			if !errors.As(err, &refused) || refused.StatusCode != code {
				t.Fatalf("error is not a refused redirect for %d: %v", code, err)
			}
			if strings.Contains(err.Error(), "LOCATION_SECRET") || strings.Contains(err.Error(), "NOREDIRECT_PROBE_SECRET") {
				t.Fatalf("error echoes the Location or a credential: %v", err)
			}
			if calls, body, auth := tg.snapshot(); calls != 0 {
				t.Fatalf("redirect target was contacted %d time(s) (body %d bytes, auth set %v)", calls, len(body), auth != "")
			}
		})
	}
}

// Control: the pinned upstream exporter without the middleware follows the
// redirect, re-sends the credential and acknowledges an HTML page. This is
// the defect the middleware closes; if it ever stops reproducing, the
// upstream behaviour changed and the gate requirement can be revisited.
func TestUpstreamExporterFollowsRedirectsWithoutMiddleware(t *testing.T) {
	tg := newTarget(t)
	source, ca := redirectingSource(t, http.StatusTemporaryRedirect, strings.Replace(tg.server.URL, "127.0.0.1", "localhost", 1)+"/v1/traces")
	err := exportOnce(t, source.URL, ca, false)
	calls, body, auth := tg.snapshot()
	if err != nil || calls != 1 || auth != probeSecret || body == "" {
		t.Skipf("upstream no longer follows redirects (err=%v calls=%d); control not reproduced", err, calls)
	}
}

// Non-redirect responses pass through untouched: success stays success and a
// 503 stays the exporter's own retryable status failure.
func TestNonRedirectResponsesPassThrough(t *testing.T) {
	for _, tc := range []struct {
		code    int
		success bool
	}{{http.StatusOK, true}, {http.StatusServiceUnavailable, false}, {http.StatusBadRequest, false}} {
		t.Run(http.StatusText(tc.code), func(t *testing.T) {
			var got string
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("Authorization")
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/x-protobuf")
				w.WriteHeader(tc.code)
			}))
			t.Cleanup(source.Close)
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			err := exportOnce(t, source.URL, ca, true)
			if (err == nil) != tc.success {
				t.Fatalf("HTTP %d: export error %v, want success=%v", tc.code, err, tc.success)
			}
			var refused *RedirectRefusedError
			if errors.As(err, &refused) {
				t.Fatalf("HTTP %d reported as a redirect", tc.code)
			}
			if got != probeSecret {
				t.Fatalf("configured header did not reach the destination")
			}
		})
	}
}

type stubTransport struct {
	resp *http.Response
	err  error
}

func (s stubTransport) RoundTrip(*http.Request) (*http.Response, error) { return s.resp, s.err }

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

// The refused redirect's body is closed and the error carries the status
// code only.
func TestRoundTripperClosesRedirectBody(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader("<html>BODY_SECRET</html>")}
	rt := Wrap(stubTransport{resp: &http.Response{StatusCode: 302, Body: body, Header: http.Header{"Location": {"http://x/?t=LOCATION_SECRET"}}}})
	req := httptest.NewRequest(http.MethodPost, "https://example.invalid/v1/traces", strings.NewReader("x"))
	resp, err := rt.RoundTrip(req)
	if resp != nil || err == nil {
		t.Fatalf("redirect passed through: resp=%v err=%v", resp, err)
	}
	if !body.closed {
		t.Fatal("redirect response body not closed")
	}
	for _, leak := range []string{"BODY_SECRET", "LOCATION_SECRET", "example.invalid"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error echoes %s: %v", leak, err)
		}
	}
	transportErr := errors.New("dial failed")
	if _, err := Wrap(stubTransport{err: transportErr}).RoundTrip(req); !errors.Is(err, transportErr) {
		t.Fatalf("transport error not passed through: %v", err)
	}
}

func TestFactory(t *testing.T) {
	f := NewFactory()
	if f.Type().String() != typeStr {
		t.Fatalf("type %q", f.Type())
	}
	ext, err := f.Create(context.Background(), extensiontest.NewNopSettings(f.Type()), f.CreateDefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := ext.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if err := ext.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
