// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestTranslateExecHashesArgv(t *testing.T) {
	argv := []byte("/tmp/agent-tool\x00--token\x00supersecret")
	e := &event{
		Type: evExec, TsNs: 1726000000000000000, Pid: 42, Ppid: 10,
		Comm: "agent-tool", Filename: "/tmp/agent-tool", Argv: argv,
	}
	lr := translate(e)
	attrs := lr.Attributes()
	if v, _ := attrs.Get("audit.syscall"); v.Str() != "execve" {
		t.Fatalf("syscall = %v", v.Str())
	}
	sum := sha256.Sum256(argv)
	if v, _ := attrs.Get("process.command_args_sha256"); v.Str() != hex.EncodeToString(sum[:]) {
		t.Fatalf("argv hash = %v", v.Str())
	}
	// Raw argv must never appear in any attribute.
	for k, v := range attrs.AsRaw() {
		if s, ok := v.(string); ok && strings.Contains(s, "supersecret") {
			t.Fatalf("raw argv leaked in %s=%q", k, s)
		}
	}
	if v, _ := attrs.Get("process.executable.path"); v.Str() != "/tmp/agent-tool" {
		t.Fatalf("exe = %v", v.Str())
	}
	if v, _ := attrs.Get("audit.result"); v.Str() != "success" {
		t.Fatalf("result = %v", v.Str())
	}
}

func TestTranslateConnectDecodesAddr(t *testing.T) {
	var addr [16]byte
	copy(addr[:4], []byte{10, 0, 0, 5})
	e := &event{
		Type: evConnect, TsNs: 1, Pid: 42, Ppid: 10,
		Comm: "curl", Family: 2, Port: 443, Addr: addr,
	}
	lr := translate(e)
	attrs := lr.Attributes()
	if v, _ := attrs.Get("network.peer.address"); v.Str() != "10.0.0.5" {
		t.Fatalf("peer = %v", v.Str())
	}
	if v, _ := attrs.Get("network.peer.port"); v.Int() != 443 {
		t.Fatalf("port = %v", v.Int())
	}
	if v, _ := attrs.Get("audit.source"); v.Str() != "ebpf" {
		t.Fatalf("source = %v", v.Str())
	}
}

func TestTranslateIPv6Connect(t *testing.T) {
	var addr [16]byte
	addr[15] = 1 // ::1
	e := &event{Type: evConnect, Family: 10, Port: 22, Addr: addr, Comm: "ssh"}
	lr := translate(e)
	if v, _ := lr.Attributes().Get("network.peer.address"); v.Str() != "::1" {
		t.Fatalf("v6 peer = %v", v.Str())
	}
}

func TestTranslateOpenatPath(t *testing.T) {
	e := &event{Type: evOpenat, Comm: "cat", Filename: "/etc/shadow"}
	lr := translate(e)
	if v, _ := lr.Attributes().Get("file.path"); v.Str() != "/etc/shadow" {
		t.Fatalf("path = %v", v.Str())
	}
}

func TestConfigRequiresScopeOrOptIn(t *testing.T) {
	cfg := &Config{Endpoint: "x:4317"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty cgroup_path without all_host accepted — silent host-wide watch")
	}
	cfg.AllHost = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("all_host opt-in rejected: %v", err)
	}
	cfg.AllHost = false
	cfg.CgroupPath = "/sys/fs/cgroup/x"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cgroup scope rejected: %v", err)
	}
}

func TestDedupeAndBucket(t *testing.T) {
	d := newDeduper(time.Second)
	k := "1|a|b|443|x"
	if ok, _ := d.add(k, time.Now()); !ok {
		t.Fatal("first event should emit")
	}
	if ok, _ := d.add(k, time.Now()); ok {
		t.Fatal("repeat inside window emitted")
	}
	got := d.sweep(time.Now().Add(2 * time.Second))
	if got[k] != 2 {
		t.Fatalf("collapsed count = %d, want 2", got[k])
	}
	b := newTokenBucket(2)
	if !b.allow(time.Now()) || !b.allow(time.Now()) {
		t.Fatal("bucket should allow up to rate")
	}
	if b.allow(time.Now()) {
		t.Fatal("bucket should deny past rate")
	}
}

func TestTimestampIsWallClock(t *testing.T) {
	// bpf_ktime_get_ns is boot-relative; translate must add the computed
	// boot epoch offset so records carry wall time, not 1970-era stamps.
	e := &event{Type: evExec, TsNs: 10 * 1e9, Comm: "x"}
	lr := translate(e)
	want := time.Unix(0, bootEpochOffsetNs+int64(e.TsNs))
	if !lr.Timestamp().AsTime().Equal(want) {
		t.Fatalf("timestamp = %v, want boot-offset %v", lr.Timestamp().AsTime(), want)
	}
	// And the offset must be nonzero on any real machine (boot epoch != 1970).
	if bootEpochOffsetNs == 0 {
		t.Fatal("boot epoch offset never initialized")
	}
}

func TestCollapsedRecordShape(t *testing.T) {
	lr := collapsedRecord("k", 5)
	attrs := lr.Attributes()
	if v, _ := attrs.Get("audit.event"); v.Str() != "dedupe_collapsed" {
		t.Fatalf("event = %v", v.Str())
	}
	if v, _ := attrs.Get("fabric.event_count"); v.Int() != 5 {
		t.Fatalf("count = %v", v.Int())
	}
}
