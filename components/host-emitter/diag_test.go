// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestExportFailureNamesCodeAndFix: a failed export logs the gRPC status
// code, its message and the likely fix, not the Go type (*status.Error) the
// emitter logged before. A NetworkPolicy drop shows as Unavailable.
func TestExportFailureNamesCodeAndFix(t *testing.T) {
	cfg := productionConfig(t, t.TempDir())
	src := openTestSource(t, cfg)
	defer src.Close(false)
	blocked := status.Error(codes.Unavailable, `connection error: desc = "transport: Error while dialing: dial tcp 10.96.14.2:4417: i/o timeout"`)
	prod := newProduction(src, &fakeSender{results: []error{blocked}})
	if err := prod.heartbeat(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	ok, err := prod.sendPending(context.Background())
	log.SetOutput(os.Stderr)
	if err != nil || ok {
		t.Fatalf("sendPending = %v, %v; want a retry", ok, err)
	}
	line := buf.String()
	for _, want := range []string{"grpc_code=Unavailable", "dial tcp 10.96.14.2:4417: i/o timeout", "NetworkPolicy"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log %q lacks %q", line, want)
		}
	}
	if strings.Contains(line, "*status.Error") {
		t.Fatalf("log still names the Go type: %q", line)
	}
}

func TestDescribeExportErrorCodes(t *testing.T) {
	for code, hint := range map[codes.Code]string{
		codes.Unauthenticated:  "EMIT_BEARER_TOKEN_FILE",
		codes.PermissionDenied: "sourceId",
		codes.DeadlineExceeded: "NetworkPolicy",
		codes.Unimplemented:    "group port",
	} {
		got := describeExportError(status.Error(code, "refused"))
		if !strings.Contains(got, "grpc_code="+code.String()) || !strings.Contains(got, hint) {
			t.Fatalf("%s: %q", code, got)
		}
	}
	if got := describeExportError(fmt.Errorf("wrapped: %w", context.DeadlineExceeded)); !strings.Contains(got, "grpc_code=DeadlineExceeded") {
		t.Fatalf("deadline: %q", got)
	}
}

// TestDiagnosticsNeverPrintSecrets: whatever a status message echoes, a
// bearer credential or a long opaque run (a token or key) is redacted, and
// the text is one bounded line.
func TestDiagnosticsNeverPrintSecrets(t *testing.T) {
	token := strings.Repeat("7f", 32)
	msg := "unauthenticated: header Authorization: Bearer " + token + "\nsecond line; key=" + strings.Repeat("Q", 44) + strings.Repeat(" padding", 60)
	got := describeExportError(status.Error(codes.Unauthenticated, msg))
	if strings.Contains(got, token) || strings.Contains(got, strings.Repeat("Q", 44)) {
		t.Fatalf("a secret reached the log: %q", got)
	}
	if strings.Contains(got, "\n") || strings.Contains(got, `\n`) {
		t.Fatalf("not one line: %q", got)
	}
	if len(sanitizeDiagnostic(msg)) > diagMessageMax+3 {
		t.Fatal("message not bounded")
	}
	if !strings.Contains(got, "Bearer [redacted]") {
		t.Fatalf("redaction not visible: %q", got)
	}
}

// TestRetryLogCollapsesRepeats: the same failure once a second is logged
// once per interval with its repeat count; a new failure at once.
func TestRetryLogCollapsesRepeats(t *testing.T) {
	var lines []string
	clock := time.Unix(0, 0)
	r := newRetryLog(30 * time.Second)
	r.now = func() time.Time { return clock }
	r.printf = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	for i := 0; i < 30; i++ {
		r.log("p", "a")
		clock = clock.Add(time.Second)
	}
	r.log("p", "a")
	r.log("p", "b")
	if len(lines) != 3 || lines[0] != "p a" || lines[1] != "p a repeated=29" || lines[2] != "p b" {
		t.Fatalf("lines = %q", lines)
	}
	r.reset()
	r.log("p", "b")
	if len(lines) != 4 {
		t.Fatalf("a failure after a success was not logged at once: %q", lines)
	}
}
