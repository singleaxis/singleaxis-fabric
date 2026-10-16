// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/component/componenttest"
)

// Sol F3 (privacy): a restored or reused content-queue volume with broad
// permissions (directory 0755, database 0644) stayed readable by other local
// users; file_storage applies directory_permissions only when it creates the
// directory. start tightens it before the queue opens the database.
func TestStartTightensAnExistingContentQueue(t *testing.T) {
	root := t.TempDir()
	queue := filepath.Join(root, "content-queue")
	nested := filepath.Join(queue, "compaction")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(queue, "exporter_fabriccontent__logs")
	temp := filepath.Join(nested, "tempdb123")
	for _, file := range []string{db, temp} {
		if err := os.WriteFile(file, []byte("queued bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for path, mode := range map[string]os.FileMode{queue: 0o755, nested: 0o2775, db: 0o644, temp: 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	cfg := fileConfig(filepath.Join(root, "content"))
	cfg.QueueDirectory = queue
	e, err := newContentExporter(cfg, componenttest.NewNopTelemetrySettings())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{queue: 0o700, nested: 0o700, db: 0o600, temp: 0o600} {
		if got := perm(t, path); got != want {
			t.Errorf("%s: mode %o, want %o", filepath.Base(path), got, want)
		}
	}
}

func TestStartRefusesALinkOrNonDirectoryQueue(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	queue := filepath.Join(root, "content-queue")
	if err := os.Mkdir(queue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(queue, "exporter_fabriccontent__logs")); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(root, "linked-queue")
	if err := os.Symlink(queue, linkedRoot); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{"link inside": queue, "linked root": linkedRoot, "file root": outside} {
		err := privateQueueDir(dir)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), root) {
			t.Errorf("%s: error carries a path: %v", name, err)
		}
	}
	if got := perm(t, outside); got != 0o644 {
		t.Errorf("a symlink target was changed: %o", got)
	}
}

func TestMissingQueueDirectoryIsLeftToFileStorage(t *testing.T) {
	if err := privateQueueDir(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatal(err)
	}
	if err := privateQueueDir(""); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentQueueRequiresQueueDirectory(t *testing.T) {
	base := map[string]any{
		"allowed_tenants": []any{"tenant-a"},
		"backend":         "file",
		"file":            map[string]any{"directory": "/var/lib/fabric-node/content"},
		"sending_queue":   map[string]any{"enabled": true, "storage": "file_storage/fabric_content"},
	}
	if _, err := unmarshal(t, base); err == nil || !strings.Contains(err.Error(), "queue_directory is required") {
		t.Fatalf("persistent queue without queue_directory: %v", err)
	}
	for _, bad := range []string{"relative/queue", "/var/lib/q/", "/", "/var/lib/../q"} {
		raw := map[string]any{}
		for k, v := range base {
			raw[k] = v
		}
		raw["queue_directory"] = bad
		if _, err := unmarshal(t, raw); err == nil || !strings.Contains(err.Error(), "queue_directory must be") {
			t.Errorf("queue_directory %q: %v", bad, err)
		}
	}
	memory := map[string]any{
		"allowed_tenants": []any{"tenant-a"},
		"backend":         "file",
		"file":            map[string]any{"directory": "/var/lib/fabric-node/content"},
	}
	if _, err := unmarshal(t, memory); err != nil {
		t.Fatalf("in-memory queue: %v", err)
	}
}
