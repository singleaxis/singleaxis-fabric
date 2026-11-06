// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package noredirectextension

import "fmt"

// responseClass is what the Fabric Node does with one destination response.
//
// The pinned upstream OTLP/HTTP exporter retries only 429, 502, 503 and 504
// and drops every other non-2xx response as permanent, including 401, 403,
// 404 and 500, although those batches were already acknowledged to the
// source. It has no per-status retry option, so this middleware decides
// before the exporter sees the response:
//
//   - classSuccess: 2xx, passed through.
//   - classUpstreamRetry: 429, 502, 503, 504, passed through; the exporter
//     already retries them and honours Retry-After on 429 and 503.
//   - classRedirect: 3xx, refused and retried (spec 048 H1).
//   - classHold: every response that says nothing about the bytes of this
//     batch, so the same bytes can be accepted once the operator or the
//     destination fixes the cause. Fabric converts it into a transport error,
//     which the exporter retries with backoff (max_elapsed_time 0: forever);
//     the batch stays in the persistent queue and a full queue back-pressures
//     the source's spool. This covers credentials and authorization (401,
//     403, 407), a missing or moved endpoint (404, 405, 410, 421), a
//     destination that is not ready or misconfigured (406, 408, 411, 412,
//     414-418, 423-426, 428, 431, 451), every 5xx other than the upstream
//     set (500, 501, 505-599), and any status this table does not name: an
//     unrecognised status cannot be shown to be about the bytes, so it never
//     discards acknowledged data on a guess.
//   - classPermanent: the destination refused these bytes and would refuse
//     them again: 400 (malformed or invalid), 409 (conflicts with what the
//     destination holds), 413 (too large) and 422 (unprocessable). Retrying
//     such a batch forever would block a queue consumer behind it, so Fabric
//     gives up on it, but only after a loss record naming its positions is
//     durably in the loss outbox (see recordLoss). When no outbox is
//     configured, or the loss cannot be recorded, the response is held
//     instead: data is never dropped without a record.
type responseClass int

const (
	classSuccess responseClass = iota
	classUpstreamRetry
	classRedirect
	classHold
	classPermanent
)

// classify maps an HTTP status code to the Node's delivery decision.
func classify(code int) responseClass {
	switch {
	case code >= 200 && code <= 299:
		return classSuccess
	case code >= 300 && code <= 399:
		return classRedirect
	}
	switch code {
	case 429, 502, 503, 504:
		return classUpstreamRetry
	case 400, 409, 413, 422:
		return classPermanent
	}
	return classHold
}

// HeldResponseError reports a destination response that Fabric keeps queued
// and retries. Only the status code is reported: the response body, headers
// and the request are never included.
type HeldResponseError struct {
	StatusCode int
	// Unrecorded is set when the status is a permanent rejection that Fabric
	// could not account for with a loss record (no loss outbox, a body it
	// could not read, or a full outbox); Reason says which, without data.
	Unrecorded bool
	Reason     string
}

func (e *HeldResponseError) Error() string {
	if e.Unrecorded {
		return fmt.Sprintf("destination rejected the batch (HTTP %d) but Fabric could not record its loss (%s); the batch stays queued and is retried", e.StatusCode, e.Reason)
	}
	return fmt.Sprintf("destination answered HTTP %d; Fabric treats it as a credential, availability or configuration failure, keeps the batch queued and retries", e.StatusCode)
}
