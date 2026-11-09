// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Diagnostics go to the emitter's own log only; nothing here reaches a
// monitored process.

const diagMessageMax = 240

var (
	// A bearer credential, and any long opaque run (a token, key or digest):
	// never printed, whatever echoed it.
	bearerPattern = regexp.MustCompile(`(?i)bearer\s+\S+`)
	opaquePattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
)

// sanitizeDiagnostic makes an error text safe for one log line: credentials
// and long opaque runs are replaced, control characters dropped, the length
// bounded.
func sanitizeDiagnostic(msg string) string {
	msg = bearerPattern.ReplaceAllString(msg, "Bearer [redacted]")
	msg = opaquePattern.ReplaceAllString(msg, "[redacted]")
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, msg)
	if len(msg) > diagMessageMax {
		cut := diagMessageMax
		for cut > 0 && !utf8Start(msg[cut]) {
			cut--
		}
		msg = msg[:cut] + "..."
	}
	return msg
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// exportHint names the likely fix for a gRPC status code.
func exportHint(code codes.Code) string {
	switch code {
	case codes.Unavailable, codes.DeadlineExceeded:
		return "the Node's ingress port is not reachable: check the endpoint, the Node's Service and pods, and any NetworkPolicy between this pod and the Node (the chart's deny-default policy needs the host sensor egress rule)"
	case codes.Unauthenticated:
		return "the Node refused the credential: check that EMIT_BEARER_TOKEN_FILE holds this node's group token and that the Node's group Secret has the same bytes"
	case codes.PermissionDenied, codes.InvalidArgument:
		return "the Node refused the batch: check that EMIT_TENANT_ID and this sensor's source id match the group's tenantId and sourceId"
	case codes.Unimplemented:
		return "the endpoint does not serve OTLP traces: check that EMIT_ENDPOINT names the Node's group port"
	}
	return ""
}

// describeExportError is the log text of a failed OTLP export: the gRPC
// status code, its message (sanitized) and, where known, the likely fix.
func describeExportError(err error) string {
	code := codes.Unknown
	msg := err.Error()
	if st, ok := status.FromError(err); ok {
		code, msg = st.Code(), st.Message()
	} else if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	out := fmt.Sprintf("grpc_code=%s grpc_message=%q", code, sanitizeDiagnostic(msg))
	if hint := exportHint(code); hint != "" {
		out += " hint=" + fmt.Sprintf("%q", hint)
	}
	return out
}

// describeError is the log text of any other failure (the pod watch):
// sanitized, one line.
func describeError(err error) string {
	return fmt.Sprintf("error=%q", sanitizeDiagnostic(err.Error()))
}

// retryLog logs a repeating failure once, then at most once per interval
// with the number of repeats, and immediately when the text changes.
type retryLog struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	printf   func(format string, args ...any)
	last     string
	lastAt   time.Time
	repeated int
}

func newRetryLog(interval time.Duration) *retryLog {
	return &retryLog{interval: interval, now: time.Now, printf: log.Printf}
}

func (r *retryLog) log(prefix, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if detail == r.last && now.Sub(r.lastAt) < r.interval {
		r.repeated++
		return
	}
	if detail == r.last && r.repeated > 0 {
		r.printf("%s %s repeated=%d", prefix, detail, r.repeated)
	} else {
		r.printf("%s %s", prefix, detail)
	}
	r.last, r.lastAt, r.repeated = detail, now, 0
}

// reset forgets the last failure after a success, so the next failure is
// logged at once.
func (r *retryLog) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last, r.repeated = "", 0
}
