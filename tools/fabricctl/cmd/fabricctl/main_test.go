//go:build legacy

// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, buildDate
	defer func() { version, commit, buildDate = oldVersion, oldCommit, oldDate }()
	version, commit, buildDate = "1.2.3", "abc123", "2026-08-25"
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if got := stdout.String(); got != "fabricctl 1.2.3 (commit abc123, built 2026-08-25)\n" {
		t.Fatalf("version output = %q", got)
	}
}

func TestInvalidDoctorOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"doctor", "--output", "xml"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "must be human or json") {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"frobnicate"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "frobnicate"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRepeatableValuesPreserveOrder(t *testing.T) {
	var values stringList
	for _, value := range []string{"profile.yaml", "tenant.yaml", "region.yaml"} {
		if err := values.Set(value); err != nil {
			t.Fatal(err)
		}
	}
	if got := values.String(); got != "profile.yaml,tenant.yaml,region.yaml" {
		t.Fatalf("values order = %q", got)
	}
}
