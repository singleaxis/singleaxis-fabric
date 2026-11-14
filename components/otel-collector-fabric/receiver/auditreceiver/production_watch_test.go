// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// watchedOpenLines are three refused or allowed opens: a watched file by its
// quoted name, a file under a watched directory by its hex name (auditd
// writes a name with a space as hex), and an unwatched file.
var watchedOpenLines = strings.Join([]string{
	`type=SYSCALL msg=audit(1791331201.218:501): arch=c000003e syscall=257 success=no exit=-13 ppid=4100 pid=4121 auid=1000 comm="agent" exe="/usr/bin/agent" key="fabric"`,
	`type=PATH msg=audit(1791331201.218:501): item=0 name="/etc/agent/acl.json" inode=1 nametype=NORMAL`,
	`type=EOE msg=audit(1791331201.218:501):`,
	`type=SYSCALL msg=audit(1791331201.219:502): arch=c000003e syscall=257 success=yes exit=3 ppid=4100 pid=4121 auid=1000 comm="agent" exe="/usr/bin/agent" key="fabric"`,
	`type=PATH msg=audit(1791331201.219:502): item=0 name=` + strings.ToUpper(hex.EncodeToString([]byte("/opt/agent/plugins/my plugin.json"))) + ` inode=2 nametype=NORMAL`,
	`type=EOE msg=audit(1791331201.219:502):`,
	`type=SYSCALL msg=audit(1791331201.220:503): arch=c000003e syscall=257 success=yes exit=3 ppid=4100 pid=4121 auid=1000 comm="agent" exe="/usr/bin/agent" key="fabric"`,
	`type=PATH msg=audit(1791331201.220:503): item=0 name="/etc/hostname" inode=3 nametype=NORMAL`,
	`type=EOE msg=audit(1791331201.220:503):`,
}, "\n")

const watchedPathsJSON = `{"security_context": {"watched_paths": [
  {"path": "/etc/agent/acl.json", "match": "exact", "label": "agent-acl", "class": "permission_config"},
  {"path": "/opt/agent/plugins/", "match": "prefix", "label": "plugins", "class": "extension_dir"}
]}}`

// TestWatchedOpensAreLabelled (spec 057 §4.3, WP7-11 auditd parity): the
// receiver labels the opens of watched paths exactly as the eBPF emitter
// does: label, class and the entry's keyed pth- id, never the path; an
// unwatched open carries none of them and keeps its result and errno.
func TestWatchedOpensAreLabelled(t *testing.T) {
	cfg := productionConfig(t, "netlink")
	cfg.FileAccess = true
	cfg.Production.WatchedPathsFile = filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(cfg.Production.WatchedPathsFile, []byte(watchedPathsJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	sink := &traceSink{}
	r := newProductionTestReceiver(t, cfg, sink)
	lines := startNetlinkForTest(t, r, newFakeNetlink())
	feed(lines, watchedOpenLines)
	waitUntil(t, "three file records", 5*time.Second, func() bool {
		return len(sink.acceptedSpans(recordSpanName)) == 3
	})
	shutdown(t, r)
	records := sink.acceptedSpans(recordSpanName)
	key := []byte(testIDKey)
	want := []struct{ label, class, id, result, errno string }{
		{"agent-acl", "permission_config", hostrecords.V2("pth", "/etc/agent/acl.json", key), "failed", "EACCES"},
		{"plugins", "extension_dir", hostrecords.V2("pth", "/opt/agent/plugins/", key), "success", ""},
		{"", "", "", "success", ""},
	}
	for i, span := range records {
		w := want[i]
		got := [...]string{str(span, "fabric.sensor.watch_label"), str(span, "fabric.sensor.watch_class"),
			str(span, "fabric.sensor.watch_id"), str(span, "fabric.sensor.result"), str(span, "fabric.sensor.errno")}
		if got != [...]string{w.label, w.class, w.id, w.result, w.errno} {
			t.Errorf("record %d: %v, want %+v", i, got, w)
		}
		for _, v := range span.Attributes().AsRaw() {
			if s, ok := v.(string); ok && (strings.Contains(s, "/etc/") || strings.Contains(s, "/opt/") || strings.Contains(s, "my plugin")) {
				t.Errorf("record %d carries a path in clear: %q", i, s)
			}
		}
	}
	if !strings.HasPrefix(want[0].id, "pth-") {
		t.Fatalf("no pth- id under the test key: %q", want[0].id)
	}
}

func TestWatchedPathsConfigErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"local mode": {func(c *Config) {
			c.Mode, c.Production = modeLocal, ProductionConfig{WatchedPathsFile: "/etc/fabric/watched.json"}
		}, "require mode: production"},
		"relative":       {func(c *Config) { c.Production.WatchedPathsFile = "watched.json" }, "absolute, clean path"},
		"no file access": {func(c *Config) { c.FileAccess = false }, "set file_access: true"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := productionConfig(t, "netlink")
			cfg.FileAccess = true
			cfg.Production.WatchedPathsFile = "/etc/fabric/watched.json"
			tc.mutate(cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
	dir := t.TempDir()
	n := 0
	write := func(body string) string {
		n++
		p := filepath.Join(dir, "w"+string(rune('0'+n))+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, tc := range map[string]struct{ path, want string }{
		"missing":       {filepath.Join(dir, "absent.json"), "cannot be opened"},
		"not a list":    {write(`{"other": 1}`), "without security_context.watched_paths"},
		"bad entry":     {write(`[{"path": "relative", "match": "exact", "label": "a", "class": "other"}]`), "watched_paths[0].path"},
		"unknown field": {write(`[{"path": "/a", "match": "exact", "label": "a", "class": "other", "x": 1}]`), "exactly path, match, label and class"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readWatchedPaths(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "production.watched_paths_file") {
				t.Fatalf("readWatchedPaths = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "relative\"") {
				t.Fatal("the error names a listed path")
			}
		})
	}
}

func TestAuditPathName(t *testing.T) {
	for raw, want := range map[string]string{
		"/etc/a":   "/etc/a",
		"2F612062": "/a b",
		"(null)":   "",
		"":         "",
		"rel/a":    "",
		"7A":       "z",
	} {
		if got := auditPathName(raw); got != want {
			t.Errorf("auditPathName(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestCreatedWatchedFileIsLabelled: an open that creates a file logs its
// directory first (nametype=PARENT) and the file next (CREATE); the record
// is labelled, and digested, by the file, so writing a new permission file
// is labelled like opening an existing one.
func TestCreatedWatchedFileIsLabelled(t *testing.T) {
	cfg := productionConfig(t, "netlink")
	cfg.FileAccess = true
	cfg.Production.Digests = "permitted"
	cfg.Production.WatchedPathsFile = filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(cfg.Production.WatchedPathsFile, []byte(watchedPathsJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	sink := &traceSink{}
	r := newProductionTestReceiver(t, cfg, sink)
	lines := startNetlinkForTest(t, r, newFakeNetlink())
	feed(lines, strings.Join([]string{
		`type=SYSCALL msg=audit(1791331201.230:510): arch=c000003e syscall=257 success=yes exit=3 ppid=4100 pid=4121 auid=1000 comm="agent" exe="/usr/bin/agent" key="fabric"`,
		`type=PATH msg=audit(1791331201.230:510): item=0 name="/etc/agent/" inode=9 nametype=PARENT`,
		`type=PATH msg=audit(1791331201.230:510): item=1 name="/etc/agent/acl.json" inode=10 nametype=CREATE`,
		`type=EOE msg=audit(1791331201.230:510):`,
	}, "\n"))
	waitUntil(t, "one file record", 5*time.Second, func() bool {
		return len(sink.acceptedSpans(recordSpanName)) == 1
	})
	shutdown(t, r)
	span := sink.acceptedSpans(recordSpanName)[0]
	if got := str(span, "fabric.sensor.watch_label"); got != "agent-acl" {
		t.Errorf("created watched file: label %q, want agent-acl", got)
	}
	if got := str(span, "fabric.sensor.path_sha256"); got != sha256Hex("/etc/agent/acl.json") {
		t.Errorf("path digest %q is not the created file's", got)
	}
}
