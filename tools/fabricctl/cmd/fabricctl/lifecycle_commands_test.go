//go:build legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlanHelpExplainsNonMutatingArtifactResolution(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--help"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, expected := range []string{"without contacting or changing a cluster", "--image-locks", "immutable reviewed digests"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("help missing %q: %s", expected, stdout.String())
		}
	}
}

func TestPlanRejectsIncompleteFlagsBeforeExecution(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--bundle", "example"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "requires --bundle") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestInstallHelpExplainsApprovalReceiptAndDryRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"install", "--help"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, expected := range []string{"mutation-ready", "--approval FILE", "--receipt FILE", "--dry-run"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("help missing %q: %s", expected, stdout.String())
		}
	}
}

func TestInstallRejectsMissingPinnedInputsBeforeDiscovery(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"install", "--bundle", "example"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "requires the bundle") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestStatusHelpStatesReadOnlyAndDeliveryLimit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--help"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, expected := range []string{"without mutation", "--receipt FILE", "does not claim telemetry delivery"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("help missing %q: %s", expected, stdout.String())
		}
	}
}

func TestSupportHelpStatesLocalAllowlistAndExclusions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"support", "--help"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, expected := range []string{"never upload", "--output-dir DIR", "credentials", "cluster logs"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("help missing %q: %s", expected, stdout.String())
		}
	}
}

func TestVerifyHelpDoesNotConflateReadinessAndDelivery(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "--help"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, expected := range []string{"without overclaiming delivery", "metadata-only synthetic trace", "destination acknowledgement"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("help missing %q: %s", expected, stdout.String())
		}
	}
}

func TestConnectHelpExplainsOptionalWorkloadIdentityPairing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"connect", "--help"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, expected := range []string{"Optionally pair", "customer-hosted", "ephemeral device flow", "Static access tokens are never written"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("help missing %q: %s", expected, stdout.String())
		}
	}
}
