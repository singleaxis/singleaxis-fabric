// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestWatchTableMatch(t *testing.T) {
	table, err := NewWatchTable([]WatchedPath{
		{Path: "/etc/agent/acl.json", Match: "exact", Label: "agent-acl", Class: "permission_config"},
		{Path: "/home/a/.agent/skills/", Match: "prefix", Label: "skills-dir", Class: "extension_dir"},
		{Path: "/home/a/.agent", Match: "prefix", Label: "agent-home", Class: "other"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"/etc/agent/acl.json":           "agent-acl",
		"/etc/agent/acl.json.bak":       "", // exact means exact
		"/etc/agent":                    "",
		"/home/a/.agent/skills":         "skills-dir", // the directory itself
		"/home/a/.agent/skills/x/y.md":  "skills-dir", // the deepest prefix wins
		"/home/a/.agent/config.toml":    "agent-home",
		"/home/a/.agentx/config.toml":   "", // a prefix is a directory, never a string prefix
		"etc/agent/acl.json":            "", // relative: never labelled
		"/home/a/.agent/../b/acl.json":  "agent-home",
		"":                              "",
		"/home/a/.agent/skills/../keys": "skills-dir", // matched as passed, never normalised
	} {
		got := table.Match(path)
		label := ""
		if got != nil {
			label = got.Label
		}
		if label != want {
			t.Errorf("Match(%q) = %q, want %q", path, label, want)
		}
	}
	var none *WatchTable
	if none.Match("/etc/agent/acl.json") != nil || none.Len() != 0 {
		t.Error("a nil table matched")
	}
	root, err := NewWatchTable([]WatchedPath{{Path: "/", Match: "prefix", Label: "all", Class: "other"}})
	if err != nil || root.Match("/x/y") == nil {
		t.Errorf("a root prefix matches everything absolute: %v", err)
	}
}

func TestWatchTableRefusals(t *testing.T) {
	ok := WatchedPath{Path: "/etc/a", Match: "exact", Label: "a", Class: "other"}
	with := func(f func(*WatchedPath)) []WatchedPath {
		e := ok
		f(&e)
		return []WatchedPath{e}
	}
	many := make([]WatchedPath, MaxWatchedPaths+1)
	for i := range many {
		many[i] = WatchedPath{Path: fmt.Sprintf("/etc/a%d", i), Match: "exact", Label: "a", Class: "other"}
	}
	for name, tc := range map[string]struct {
		entries []WatchedPath
		hint    string
	}{
		"relative path":   {with(func(e *WatchedPath) { e.Path = "etc/a" }), "absolute path"},
		"control byte":    {with(func(e *WatchedPath) { e.Path = "/etc/\n" }), "printable ASCII"},
		"too long":        {with(func(e *WatchedPath) { e.Path = "/" + strings.Repeat("a", 4096) }), "4096"},
		"bad label":       {with(func(e *WatchedPath) { e.Label = "-a" }), "label must match"},
		"bad class":       {with(func(e *WatchedPath) { e.Class = "secrets" }), "class must be one of"},
		"bad match":       {with(func(e *WatchedPath) { e.Match = "glob" }), "match must be exact or prefix"},
		"duplicate":       {[]WatchedPath{ok, ok}, "same path as an earlier entry"},
		"duplicate slash": {[]WatchedPath{{Path: "/d", Match: "prefix", Label: "a", Class: "other"}, {Path: "/d/", Match: "prefix", Label: "b", Class: "other"}}, "same path"},
		"over limit":      {many, "at most 256"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewWatchTable(tc.entries)
			if err == nil || !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("error %v, want one naming %q", err, tc.hint)
			}
			for _, e := range tc.entries[:1] {
				if len(e.Path) > 1 && strings.Contains(err.Error(), e.Path) {
					t.Error("the error names the path")
				}
			}
		})
	}
}

func TestParseWatchedPaths(t *testing.T) {
	list := `[{"path": "/etc/agent/acl.json", "match": "exact", "label": "agent-acl", "class": "permission_config"}]`
	policy := `{"schema_version": "x", "security_context": {"watched_paths": ` + list + `}}`
	for name, doc := range map[string]string{"list": list, "policy": policy} {
		entries, err := ParseWatchedPaths([]byte(doc))
		if err != nil || len(entries) != 1 || entries[0].Label != "agent-acl" {
			t.Errorf("%s: %v %v", name, entries, err)
		}
	}
	for name, doc := range map[string]string{
		"empty":         " ",
		"not json":      "{",
		"no section":    `{"schema_version": "x"}`,
		"unknown field": `[{"path": "/a", "match": "exact", "label": "a", "class": "other", "glob": true}]`,
	} {
		if _, err := ParseWatchedPaths([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestExitAndWatchedRecords: an exit names no syscall and carries exactly one
// of exit code and signal; a watched open carries the label, class and keyed
// id, never the path; an unwatched open is unchanged.
func TestExitAndWatchedRecords(t *testing.T) {
	cfg := testConfig(t.TempDir())
	cfg.Classes = append(cfg.Classes, "exit")
	s := mustOpen(t, cfg)
	defer crash(t, s)
	code, sig := int64(3), int64(9)
	exit := Event{TimeUnixNano: 1, Class: "exit", Result: "unknown", Pid: 7, ExitCode: &code}
	for name, bad := range map[string]Event{
		"syscall":      func() Event { e := exit; e.Syscall = "execve"; return e }(),
		"result":       func() Event { e := exit; e.Result = "success"; return e }(),
		"both":         func() Event { e := exit; e.Signal = &sig; return e }(),
		"neither":      func() Event { e := exit; e.ExitCode = nil; return e }(),
		"exec no call": {TimeUnixNano: 1, Class: "exec", Result: "success", Pid: 7},
	} {
		if _, err := s.Stage([]Event{bad}); err == nil {
			t.Errorf("%s: staged", name)
		}
	}
	killed := exit
	killed.ExitCode, killed.Signal = nil, &sig
	watch := &WatchedPath{Path: "/etc/agent/acl.json", Match: "exact", Label: "agent-acl", Class: "permission_config"}
	opened := Event{TimeUnixNano: 2, Class: "file", Syscall: "openat", Result: "success", Pid: 7, Watch: watch}
	plain := Event{TimeUnixNano: 3, Class: "file", Syscall: "openat", Result: "success", Pid: 7}
	b, err := s.Stage([]Event{exit, killed, opened, plain})
	if err != nil {
		t.Fatal(err)
	}
	spans := batchSpans(t, b)
	if _, ok := spans[0].attrs["fabric.sensor.syscall"]; ok || spans[0].attrs["fabric.sensor.exit_code"] != int64(3) {
		t.Errorf("exit: %v", spans[0].attrs)
	}
	if _, ok := spans[1].attrs["fabric.sensor.exit_code"]; ok || spans[1].attrs["fabric.sensor.signal"] != int64(9) {
		t.Errorf("killed: %v", spans[1].attrs)
	}
	if spans[2].attrs["fabric.sensor.watch_label"] != "agent-acl" || spans[2].attrs["fabric.sensor.watch_class"] != "permission_config" ||
		spans[2].attrs["fabric.sensor.watch_id"] != V2("pth", watch.Path, cfg.IDKey) {
		t.Errorf("watched: %v", spans[2].attrs)
	}
	raw, _ := json.Marshal(spans[2].attrs)
	if strings.Contains(string(raw), "/etc/agent") {
		t.Error("the watched path reached the record")
	}
	for key := range spans[3].attrs {
		if strings.HasPrefix(key, "fabric.sensor.watch_") {
			t.Errorf("unwatched open carries %s", key)
		}
	}
}
