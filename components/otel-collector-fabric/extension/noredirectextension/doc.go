// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package noredirectextension is the Fabric Node's HTTP client middleware
// that refuses redirects (spec 043 H1, Sol deployment review of 03484d5).
//
// The pinned upstream OTLP/HTTP exporter builds a net/http client that
// follows redirects: an HTTPS destination answering 307 to a plaintext URL
// gets the request body and the Authorization header re-sent there, and a 302
// to an HTML login page is acknowledged as a successful export. Listed in an
// exporter's `middlewares`, this extension sits directly around the
// transport and turns every 3xx response into a transport error before the
// client can follow it: the response body is closed, nothing is re-sent, and
// the exporter treats the failure as retryable (the persistent queue keeps
// the data). fabric-gate refuses an OTLP/HTTP exporter that does not list it.
package noredirectextension
