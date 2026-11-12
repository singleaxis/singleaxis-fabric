// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// Spec 057 OD-13 (WP7-11): syscall results, failed execs, process exits and
// watched-path labels, translated in the emitter's user space.

func testWatch(t *testing.T) *hostrecords.WatchTable {
	t.Helper()
	table, err := hostrecords.NewWatchTable([]hostrecords.WatchedPath{
		{Path: "/etc/agent/acl.json", Match: "exact", Label: "agent-acl", Class: "permission_config"},
		{Path: "/home/a/.agent/skills", Match: "prefix", Label: "skills-dir", Class: "extension_dir"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func TestHostEventSyscallResults(t *testing.T) {
	watch := testWatch(t)
	for name, tc := range map[string]struct {
		e             event
		result, errno string
	}{
		"exec success":          {event{Type: evExec, Pid: 7, Result: resultSuccess}, "success", ""},
		"exec failed EACCES":    {event{Type: evExec, Pid: 7, Result: resultFailed, Errno: 13}, "failed", "EACCES"},
		"connect without pairs": {event{Type: evConnect, Pid: 7}, "unknown", ""},
		"connect ok":            {event{Type: evConnect, Pid: 7, Result: resultSuccess}, "success", ""},
		"connect EPERM":         {event{Type: evConnect, Pid: 7, Result: resultFailed, Errno: 1}, "failed", "EPERM"},
		"connect refused":       {event{Type: evConnect, Pid: 7, Result: resultFailed, Errno: 111}, "failed", "ECONNREFUSED"},
		"open ENOENT":           {event{Type: evOpenat, Pid: 7, Filename: "/x", Result: resultFailed, Errno: 2}, "failed", "ENOENT"},
		"open other errno":      {event{Type: evOpenat, Pid: 7, Filename: "/x", Result: resultFailed, Errno: 40}, "failed", "40"},
		"open without pairs":    {event{Type: evOpenat, Pid: 7, Filename: "/x"}, "unknown", ""},
	} {
		ev, ok := hostEvent(&tc.e, watch)
		if !ok || ev.Result != tc.result || ev.Errno != tc.errno {
			t.Errorf("%s: result %q errno %q", name, ev.Result, ev.Errno)
		}
	}
}

func TestHostEventExit(t *testing.T) {
	code, _ := hostEvent(&event{Type: evExit, Pid: 7, ExitCode: 2}, nil)
	if code.Class != "exit" || code.Syscall != "" || code.Result != "unknown" || code.ExitCode == nil || *code.ExitCode != 2 || code.Signal != nil {
		t.Fatalf("exit code: %+v", code)
	}
	zero, _ := hostEvent(&event{Type: evExit, Pid: 7}, nil)
	if zero.ExitCode == nil || *zero.ExitCode != 0 {
		t.Fatal("exit 0 must stay distinct from unknown")
	}
	killed, _ := hostEvent(&event{Type: evExit, Pid: 7, ExitSignal: 31}, nil)
	if killed.Signal == nil || *killed.Signal != 31 || killed.ExitCode != nil {
		t.Fatalf("killed: %+v", killed)
	}
}

func TestHostEventWatchedPaths(t *testing.T) {
	watch := testWatch(t)
	for path, want := range map[string]string{
		"/etc/agent/acl.json":            "agent-acl",
		"/home/a/.agent/skills/x/SKILL":  "skills-dir",
		"/etc/agent/acl.json.swp":        "",
		"agent/acl.json":                 "",
		"/home/a/.agent/skillsets/other": "",
	} {
		ev, _ := hostEvent(&event{Type: evOpenat, Pid: 7, Filename: path, Result: resultSuccess}, watch)
		label := ""
		if ev.Watch != nil {
			label = ev.Watch.Label
		}
		if label != want {
			t.Errorf("%s: label %q, want %q", path, label, want)
		}
	}
	// An incomplete path is never labelled; an exec of a watched path is not an open.
	if ev, _ := hostEvent(&event{Type: evOpenat, Pid: 7, Filename: "/etc/agent/acl.json", FilenameIncomplete: true}, watch); ev.Watch != nil {
		t.Error("an incomplete path was labelled")
	}
	if ev, _ := hostEvent(&event{Type: evExec, Pid: 7, Filename: "/etc/agent/acl.json"}, watch); ev.Watch != nil {
		t.Error("an exec was labelled")
	}
	// Without a list, opens are unchanged.
	ev, _ := hostEvent(&event{Type: evOpenat, Pid: 7, Filename: "/etc/agent/acl.json"}, nil)
	if ev.Watch != nil || ev.Result != "unknown" {
		t.Errorf("unwatched open changed: %+v", ev)
	}
}

// TestWatchedOpenStagedWithoutPath: through the library, a watched open
// carries the label, the class and the keyed id; no staged byte holds the path.
func TestWatchedOpenStagedWithoutPath(t *testing.T) {
	cfg := productionConfig(t, t.TempDir())
	cfg.FileAccess = true
	src := openTestSource(t, cfg)
	defer func() { _, _ = src.Close(false) }()
	ev, _ := hostEvent(&event{Type: evOpenat, Pid: 7, Filename: "/etc/agent/acl.json", Result: resultFailed, Errno: 13, Scope: scopeAgent}, testWatch(t))
	ev.TimeUnixNano = 1
	b, err := src.Stage([]hostrecords.Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	attrs := b.Traces().ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().AsRaw()
	if attrs["fabric.sensor.watch_label"] != "agent-acl" || attrs["fabric.sensor.watch_class"] != "permission_config" ||
		!strings.HasPrefix(attrs["fabric.sensor.watch_id"].(string), "pth-") || attrs["fabric.sensor.errno"] != "EACCES" {
		t.Fatalf("watched open: %v", attrs)
	}
	for k, v := range attrs {
		if s, ok := v.(string); ok && strings.Contains(s, "/etc/agent") {
			t.Fatalf("%s holds the path", k)
		}
	}
}

func TestLocalAuditResult(t *testing.T) {
	for name, tc := range map[string]struct {
		e    event
		want string
	}{
		"connect refused": {event{Type: evConnect, Result: resultFailed, Errno: 111}, "failed:ECONNREFUSED"},
		"open denied":     {event{Type: evOpenat, Filename: "/x", Result: resultFailed, Errno: 13}, "failed:EACCES"},
		"open ok":         {event{Type: evOpenat, Filename: "/x", Result: resultSuccess}, "success"},
		"exec failed":     {event{Type: evExec, Result: resultFailed, Errno: 2}, "failed:ENOENT"},
		"exec":            {event{Type: evExec}, "success"},
		"connect unknown": {event{Type: evConnect}, ""},
	} {
		lr := translate(&tc.e)
		got := ""
		if v, ok := lr.Attributes().Get("audit.result"); ok {
			got = v.Str()
		}
		if got != tc.want {
			t.Errorf("%s: audit.result %q, want %q", name, got, tc.want)
		}
	}
	a := event{Type: evOpenat, Filename: "/x", Result: resultFailed, Errno: 13}
	b := a
	b.Result, b.Errno = resultSuccess, 0
	c := event{Type: evOpenat, Filename: "/x"}
	if dedupeKey(&a) == dedupeKey(&b) {
		t.Error("a refused and an allowed open fold into one")
	}
	if dedupeKey(&c) != sha256String("3||/x|0|00000000000000000000000000000000") {
		t.Error("the dedupe key of an event without a result changed")
	}
}

func TestSensorClassConfig(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "watched.json")
	if err := os.WriteFile(list, []byte(`{"security_context": {"watched_paths": [{"path": "/etc/agent/acl.json", "match": "exact", "label": "agent-acl", "class": "permission_config"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EMIT_SYSCALL_RESULTS", "true")
	t.Setenv("EMIT_EXIT", "true")
	t.Setenv("EMIT_WATCHED_PATHS_FILE", list)
	cfg := &Config{}
	cfg.loadSensorClassConfig()
	if !cfg.SyscallResults || !cfg.ProcessExit || cfg.watch.Len() != 1 || len(cfg.loadErrs) != 0 {
		t.Fatalf("sensor class settings not read: %+v", cfg)
	}
	for name, env := range map[string][2]string{
		"mistyped switch": {"EMIT_EXIT", "on"},
		"missing file":    {"EMIT_WATCHED_PATHS_FILE", filepath.Join(dir, "absent.json")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			c := &Config{}
			c.loadSensorClassConfig()
			if len(c.loadErrs) == 0 || !strings.Contains(c.loadErrs[0].Error(), env[0]) {
				t.Fatalf("errors %v", c.loadErrs)
			}
		})
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`[{"path": "relative", "match": "exact", "label": "a", "class": "other"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EMIT_WATCHED_PATHS_FILE", bad)
	c := &Config{}
	c.loadSensorClassConfig()
	if len(c.loadErrs) == 0 || !strings.Contains(c.loadErrs[0].Error(), "absolute path") || strings.Contains(c.loadErrs[0].Error(), "relative") {
		t.Fatalf("bad entry: %v", c.loadErrs)
	}

	// Validation: exits and labels are production-mode host-record keys;
	// labels label opens.
	local := &Config{Endpoint: "x:4317", AllHost: true, SpoolDir: "/tmp/spool", SpoolMaxBytes: 1, Exec: true, ProcessExit: true}
	if err := local.Validate(); err == nil || !strings.Contains(err.Error(), "EMIT_PRODUCTION") {
		t.Fatalf("EMIT_EXIT in local mode: %v", err)
	}
	local.ProcessExit, local.SyscallResults = false, true
	if err := local.Validate(); err != nil {
		t.Fatalf("syscall results in local mode: %v", err)
	}
	prod := productionConfig(t, dir)
	prod.WatchedPathsFile, prod.watch = list, testWatch(t)
	if err := prod.Validate(); err == nil || !strings.Contains(err.Error(), "EMIT_FILE_ACCESS") {
		t.Fatalf("watched paths without file access: %v", err)
	}
	prod.FileAccess, prod.ProcessExit, prod.SyscallResults = true, true, true
	if err := prod.Validate(); err != nil {
		t.Fatalf("full production sensor classes: %v", err)
	}
	if got := strings.Join(prod.eventClasses(), ","); got != "exec,connect,file,exit" {
		t.Fatalf("event classes %s", got)
	}
}
