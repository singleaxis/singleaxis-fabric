// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package noredirectextension is the Fabric Node's destination response
// policy: the HTTP client middleware every OTLP/HTTP exporter lists
// (fabric-gate refuses one that does not).
//
// Redirects (spec 048 H1). The pinned upstream OTLP/HTTP exporter builds a
// net/http client that follows redirects: an HTTPS destination answering 307
// to a plaintext URL gets the request body and the Authorization header
// re-sent there, and a 302 to an HTML login page is acknowledged as a
// successful export. This middleware sits directly around the transport and
// turns every 3xx response into a transport error before the client can
// follow it: the response body is closed, nothing is re-sent, and the
// exporter treats the failure as retryable (the persistent queue keeps the
// data).
//
// Rejections. The same exporter retries only 429, 502, 503 and 504 and drops
// every other status as permanent, including 401, 403, 404 and 500, for
// batches the Node had already acknowledged to the source: a destination
// answering 403 for 40 seconds removed whole agent runs without a trace. The
// middleware therefore holds every credential, availability and
// configuration failure for retry (policy.go), and lets a genuinely
// permanent rejection (400, 409, 413, 422) through only after it has
// written a destination_rejected loss record for every source position in
// the batch to a durable loss outbox (loss.go, outbox.go). The outbox
// delivers those records to the destination once it accepts an export
// again, so `python -m fabric.reconstruct` reports the affected runs as lost
// rather than not at all. Without a configured outbox, or when a loss cannot
// be recorded, the rejection is held too: the Node never drops acknowledged
// data without a record.
//
// The component type stays `noredirect` so existing configurations keep
// working; `loss_outbox.directory` enables giving up on permanent
// rejections.
package noredirectextension
