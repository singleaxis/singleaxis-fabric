// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"context"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// deploy/compose/verify-prod.sh fills this fixture with the Node's bound
// tenant and source; a production guard must admit and stamp that probe and
// refuse the same probe naming another source (spec 049 §7.9).
func TestVerifyProdProbeMatchesProductionBinding(t *testing.T) {
	raw, err := os.ReadFile("../../../../deploy/compose/fixtures/bound-span.json")
	if err != nil {
		t.Fatal(err)
	}
	const tenant, source = "acme-prod", "s-0123456789abcdef0123456789abcdef"
	cfg := createDefaultConfig()
	cfg.Profile = profileProduction
	cfg.EvidenceSourceBinding = &EvidenceSourceBinding{TenantID: tenant, SourceID: source}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	probe := func(source string) (ptrace.Traces, error) {
		text := strings.NewReplacer("__FABRIC_TENANT_ID__", tenant, "__FABRIC_SOURCE_ID__", source).Replace(string(raw))
		td, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return newTestGuard(t, cfg).processTraces(context.Background(), td)
	}
	out, err := probe(source)
	if err != nil || out.SpanCount() != 1 {
		t.Fatalf("bound probe not admitted: spans=%d err=%v", out.SpanCount(), err)
	}
	stamp, ok := out.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().Get(sourceAuthenticatedKey)
	if !ok || stamp.Type() != pcommon.ValueTypeBool || !stamp.Bool() {
		t.Fatal("bound probe not stamped source-authenticated")
	}
	if _, err := probe("verify-prod-forged-source"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("forged-source probe not refused: %v", err)
	}
}
