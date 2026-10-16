// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func nlink(t *testing.T, path string) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return uint64(st.Nlink)
}

func temps(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && isTempName(entry.Name()) {
			found = append(found, path)
		}
		return nil
	})
	return found
}

// crashAfterLink leaves the state of a put that crashed right after link(2)
// published the object, before its temp was removed.
func crashAfterLink(t *testing.T, b *fileBackend, key string, body []byte) string {
	t.Helper()
	if err := b.privateDirs(filepath.Dir(key)); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(filepath.Dir(key), "."+filepath.Base(key)+".123.tmp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(tmp, key); err != nil {
		t.Fatal(err)
	}
	return tmp
}

func TestFileBackend_PutLeavesOneLinkAndNoTemp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	b := newFileBackend(dir)
	key := filepath.ToSlash(filepath.Join(dir, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000001"))
	if err := b.put(context.Background(), key, []byte("exact wire body")); err != nil {
		t.Fatal(err)
	}
	if n := nlink(t, key); n != 1 {
		t.Errorf("nlink = %d, want 1", n)
	}
	if left := temps(t, dir); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

// m4: a replay of the record after a crash between link(2) and the temp's
// removal heals the object (readers refuse nlink != 1).
func TestFileBackend_ReplayHealsACrashAfterLink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	b := newFileBackend(dir)
	key := filepath.ToSlash(filepath.Join(dir, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000001"))
	body := []byte("exact wire body")
	tmp := crashAfterLink(t, b, key, body)
	if err := b.put(context.Background(), key, body); err != nil {
		t.Fatalf("replay put: %v", err)
	}
	if n := nlink(t, key); n != 1 {
		t.Errorf("nlink after replay = %d, want 1", n)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("stale temp still present after replay")
	}
	got, err := os.ReadFile(key)
	if err != nil || string(got) != string(body) {
		t.Errorf("object bytes changed: %q, %v", got, err)
	}
}

// m4: when the record is never replayed (an in-memory queue lost it in the
// crash), the next start sweeps the stale temps, healing the object too.
func TestFileBackend_StartSweepsStaleTemps(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	b := newFileBackend(dir)
	key := filepath.ToSlash(filepath.Join(dir, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000001"))
	crashAfterLink(t, b, key, []byte("exact wire body"))
	orphan := filepath.Join(dir, "acme", "evidence", "meta", ".x.json.456.tmp")
	if err := b.privateDirs(filepath.Dir(orphan)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphan, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), ".keep.tmp")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(dir, "acme", "link")); err != nil {
		t.Fatal(err)
	}
	startFileBackend(dir)
	if left := temps(t, dir); len(left) != 0 {
		t.Errorf("temp files left after start: %v", left)
	}
	if n := nlink(t, key); n != 1 {
		t.Errorf("nlink after start = %d, want 1", n)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("the sweep followed a symlink out of the content root")
	}
}

func TestFileBackend_StartWithoutDirectoryIsANoop(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	startFileBackend(dir)
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("start created the content root")
	}
}
