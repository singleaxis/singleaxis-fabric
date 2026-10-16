// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unreadableParent makes base mode 0300 (write and search, no read): the
// backend can create the content root inside it but can never open it to
// fsync it, so the root's entry is never provably durable. Real permissions,
// no injection.
func unreadableParent(t *testing.T, base string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	if err := os.Chmod(base, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o700) })
	if err := syncDirectory(base); err == nil {
		t.Skip("this filesystem lets an unreadable directory be fsync'd")
	}
}

func markerPresent(t *testing.T, root string) bool {
	t.Helper()
	ok, err := hasRootMarker(root)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// Sol K #2: the first backend creates the content root inside a parent it
// cannot fsync and refuses the put. A restart has lost the in-memory record
// of that creation; it must still refuse (Start and puts) for as long as the
// parent fsync fails, and accept only once a walk truly completes. Once that
// walk is on record, a later refusal of the same parent is the boundary.
func TestFileBackend_RestartNeverLaundersAnUnfinishedRootBarrier(t *testing.T) {
	base := t.TempDir()
	unreadableParent(t, base)
	root := filepath.Join(base, "content")
	key := filepath.ToSlash(filepath.Join(root, "tenant", "evidence", "0b1c2d3e-0000-4000-8000-000000000020"))
	body := []byte("exact content")
	if err := newFileBackend(root).put(context.Background(), key, body); err == nil {
		t.Fatal("first put: want a refusal while the new root's parent cannot be fsync'd")
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatalf("the content root was not created: %v", err)
	}
	for attempt := range 2 { // restarts while the parent still refuses
		_, err := startFileBackend(root, "")
		var se *storeError
		if err == nil || !errors.As(err, &se) || strings.Contains(err.Error(), base) {
			t.Fatalf("restart %d: want a retryable storeError without the path, got %v", attempt, err)
		}
		if err := newFileBackend(root).put(context.Background(), key, body); err == nil {
			t.Fatalf("restart %d: a fresh backend acknowledged before the root barrier completed", attempt)
		}
	}
	if markerPresent(t, root) {
		t.Fatal("a refused walk was recorded as complete")
	}
	if _, err := os.Lstat(filepath.FromSlash(key)); err == nil {
		t.Fatal("an object was published below an undurable root")
	}
	// The operator fixes the parent: the walk completes and is recorded.
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := startFileBackend(root, "")
	if err != nil {
		t.Fatalf("start once the parent can be fsync'd: %v", err)
	}
	if !markerPresent(t, root) {
		t.Fatal("a completed walk was not recorded")
	}
	if err := b.put(context.Background(), key, body); err != nil {
		t.Fatal(err)
	}
	// Recorded: the same refusal later is the operator's boundary.
	unreadableParent(t, base)
	b, err = startFileBackend(root, "")
	if err != nil {
		t.Fatalf("restart with a recorded walk: %v", err)
	}
	other := filepath.ToSlash(filepath.Join(root, "tenant", "evidence", "0b1c2d3e-0000-4000-8000-000000000021"))
	if err := b.put(context.Background(), other, body); err != nil {
		t.Fatal(err)
	}
}

// Recreating the content root drops the record with it: the new root's
// barrier must complete again.
func TestFileBackend_RecreatedRootLosesTheRecord(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "content")
	if _, err := startFileBackend(root, ""); err != nil {
		t.Fatal(err)
	}
	key := filepath.ToSlash(filepath.Join(root, "tenant", "evidence", "0b1c2d3e-0000-4000-8000-000000000022"))
	if err := newFileBackend(root).put(context.Background(), key, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !markerPresent(t, root) {
		t.Fatal("not recorded")
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	unreadableParent(t, base)
	if _, err := startFileBackend(root, ""); err == nil {
		t.Fatal("a recreated root inherited the old root's record")
	}
}

// A configured durable boundary is treated like a mount point: the walk
// fsyncs it and below, never above. An operator who provisioned the root
// inside a parent the Node cannot open names the root itself.
func TestFileBackend_ConfiguredDurableBoundary(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "content")
	if err := os.Mkdir(root, 0o700); err != nil { // provisioned by the operator
		t.Fatal(err)
	}
	unreadableParent(t, base)
	if _, err := startFileBackend(root, ""); err == nil {
		t.Fatal("without a boundary the unreadable parent must refuse")
	}
	// The boundary is the unreadable parent: it is still fsync'd, and refuses.
	if _, err := startFileBackend(root, base); err == nil {
		t.Fatal("a boundary is fsync'd itself; an unreadable one must refuse")
	}
	fail := false
	synced := syncLog(t, "", &fail)
	b, err := startFileBackend(root, root)
	if err != nil {
		t.Fatalf("start with the root as the boundary: %v", err)
	}
	for _, d := range *synced {
		if d != root && !strings.HasPrefix(d, root+string(filepath.Separator)) {
			t.Fatalf("the walk fsync'd %s above the configured boundary", d)
		}
	}
	key := filepath.ToSlash(filepath.Join(root, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000023"))
	if err := b.put(context.Background(), key, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !markerPresent(t, root) {
		t.Fatal("the completed walk was not recorded")
	}
}

// The chain stops at the boundary: an ancestor boundary is fsync'd (it holds
// the next entry down), its parent never.
func TestRootAncestorsStopAtTheBoundary(t *testing.T) {
	got := rootAncestors("/a/b/c/content", "/a/b")
	want := []string{"/a/b/c", "/a/b"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rootAncestors = %v, want %v", got, want)
	}
	if got := rootAncestors("/a/b/c/content", "/a/b/c/content"); len(got) != 0 {
		t.Fatalf("a root boundary leaves nothing to walk, got %v", got)
	}
}

// The marker name is never followed: a planted symlink, or a directory, is a
// layout error, and is never taken as a record.
func TestFileBackend_RootMarkerIsNeverFollowed(t *testing.T) {
	for _, plant := range []string{"symlink", "dir"} {
		t.Run(plant, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, rootMarkerName)
			var err error
			if plant == "symlink" {
				err = os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), path)
			} else {
				err = os.Mkdir(path, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = startFileBackend(root, "")
			var se *storeError
			if err == nil || !errors.As(err, &se) {
				t.Fatalf("want a retryable layout error, got %v", err)
			}
		})
	}
}

// The marker is private and is never mistaken for a temp file.
func TestFileBackend_RootMarkerIsPrivateAndSurvivesTheSweep(t *testing.T) {
	root := t.TempDir()
	if _, err := startFileBackend(root, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(root, rootMarkerName))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("marker = %v, %v; want a regular 0600 file", info, err)
	}
	if isTempName(rootMarkerName) {
		t.Fatal("the sweep would remove the marker")
	}
	if _, err := startFileBackend(root, ""); err != nil {
		t.Fatal(err)
	}
	if !markerPresent(t, root) {
		t.Fatal("the marker did not survive a restart")
	}
}
