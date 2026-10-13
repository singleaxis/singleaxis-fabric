// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package noredirectextension

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionmiddleware"
)

// typeStr is the component type referenced in collector configs:
// `extensions.noredirect` and `middlewares: [{id: noredirect}]`.
const typeStr = "noredirect"

// drainLimit bounds how much of a refused redirect's body is read so the
// connection can be reused; the bytes are discarded, never logged.
const drainLimit = 4096

// Config has no options: refusing redirects is not tunable.
type Config struct{}

// NewFactory returns the noredirect extension factory.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		component.MustNewType(typeStr),
		func() component.Config { return &Config{} },
		func(context.Context, extension.Settings, component.Config) (extension.Extension, error) {
			return noRedirect{}, nil
		},
		component.StabilityLevelAlpha,
	)
}

type noRedirect struct{}

var (
	_ extension.Extension            = noRedirect{}
	_ extensionmiddleware.HTTPClient = noRedirect{}
	_ http.RoundTripper              = (*roundTripper)(nil)
)

func (noRedirect) Start(context.Context, component.Host) error { return nil }
func (noRedirect) Shutdown(context.Context) error              { return nil }

// GetHTTPRoundTripper wraps the client transport. confighttp applies
// middlewares inside authentication, header and compression wrappers, so this
// round tripper sees the raw transport response first.
func (noRedirect) GetHTTPRoundTripper(context.Context) (extensionmiddleware.WrapHTTPRoundTripperFunc, error) {
	return func(_ context.Context, next http.RoundTripper) (http.RoundTripper, error) {
		return Wrap(next), nil
	}, nil
}

// Wrap returns a RoundTripper that refuses every 3xx response from next.
func Wrap(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &roundTripper{next: next}
}

type roundTripper struct{ next http.RoundTripper }

// RoundTrip performs the request and converts a 3xx response into a
// *RedirectRefusedError. Returning an error (not a response) is what stops
// net/http.Client from following the Location; the OTLP/HTTP exporter then
// reports a transport failure, which exporterhelper retries.
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.next.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return resp, nil
	}
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
		_ = resp.Body.Close()
	}
	return nil, &RedirectRefusedError{StatusCode: resp.StatusCode}
}

// RedirectRefusedError reports a refused redirect by status code only: the
// Location, headers and body are never included.
type RedirectRefusedError struct{ StatusCode int }

func (e *RedirectRefusedError) Error() string {
	return fmt.Sprintf("destination answered with a redirect (HTTP %d); Fabric never follows redirects, the export will be retried", e.StatusCode)
}
