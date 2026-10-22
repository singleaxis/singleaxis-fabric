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

// physicalTempDir is t.TempDir() spelled physically (on macOS the temp root
// sits below the /var -> /private/var symlink): the root barrier walks
// physical directories, so tests that compare the fsync'd directories with
// their own paths spell those paths physically.
func physicalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

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
	base := physicalTempDir(t)
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
		_, err := startFileBackend(root, "", nil)
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
	b, err := startFileBackend(root, "", nil)
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
	b, err = startFileBackend(root, "", nil)
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
	base := physicalTempDir(t)
	root := filepath.Join(base, "content")
	if _, err := startFileBackend(root, "", nil); err != nil {
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
	if _, err := startFileBackend(root, "", nil); err == nil {
		t.Fatal("a recreated root inherited the old root's record")
	}
}

// A configured durable boundary is treated like a mount point: the walk
// fsyncs it and below, never above. An operator who provisioned the root
// inside a parent the Node cannot open names the root itself.
func TestFileBackend_ConfiguredDurableBoundary(t *testing.T) {
	base := physicalTempDir(t)
	root := filepath.Join(base, "content")
	if err := os.Mkdir(root, 0o700); err != nil { // provisioned by the operator
		t.Fatal(err)
	}
	unreadableParent(t, base)
	if _, err := startFileBackend(root, "", nil); err == nil {
		t.Fatal("without a boundary the unreadable parent must refuse")
	}
	// The boundary is the unreadable parent: it is still fsync'd, and refuses.
	if _, err := startFileBackend(root, base, nil); err == nil {
		t.Fatal("a boundary is fsync'd itself; an unreadable one must refuse")
	}
	fail := false
	synced := syncLog(t, "", &fail)
	b, err := startFileBackend(root, root, nil)
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
			root := physicalTempDir(t)
			path := filepath.Join(root, rootMarkerName)
			var err error
			if plant == "symlink" {
				err = os.Symlink(filepath.Join(physicalTempDir(t), "elsewhere"), path)
			} else {
				err = os.Mkdir(path, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = startFileBackend(root, "", nil)
			var se *storeError
			if err == nil || !errors.As(err, &se) {
				t.Fatalf("want a retryable layout error, got %v", err)
			}
		})
	}
}

// The marker is private and is never mistaken for a temp file.
func TestFileBackend_RootMarkerIsPrivateAndSurvivesTheSweep(t *testing.T) {
	root := physicalTempDir(t)
	if _, err := startFileBackend(root, "", nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(root, rootMarkerName))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("marker = %v, %v; want a regular 0600 file", info, err)
	}
	if isTempName(rootMarkerName) {
		t.Fatal("the sweep would remove the marker")
	}
	if _, err := startFileBackend(root, "", nil); err != nil {
		t.Fatal(err)
	}
	if !markerPresent(t, root) {
		t.Fatal("the marker did not survive a restart")
	}
}

// symlinkedRoot builds base/physical/a with base/alias -> base/physical/a
// and returns (physical, the content root spelled through the alias).
func symlinkedRoot(t *testing.T) (string, string) {
	t.Helper()
	base := physicalTempDir(t)
	physical := filepath.Join(base, "physical")
	target := filepath.Join(physical, "a")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	return physical, filepath.Join(alias, "content")
}

// Sol M1 #2: the content root is configured through a symlinked ancestor
// (alias -> physical/a) whose physical parent cannot be fsync'd. The walk
// used to follow the configured spelling's lexical parents (alias's parent,
// ...), skip physical, and record a completed walk. It must refuse (puts and
// Start, no marker, no object) until the physical parent's fsync truly
// succeeds, and then fsync that physical parent.
func TestFileBackend_SymlinkedAncestorWalksThePhysicalParent(t *testing.T) {
	physical, root := symlinkedRoot(t)
	if err := (FileConfig{Directory: root}).validate(); err != nil {
		t.Fatalf("a symlinked ancestor is a valid configuration: %v", err)
	}
	unreadableParent(t, physical)
	key := filepath.ToSlash(filepath.Join(root, "tenant", "evidence", "0b1c2d3e-0000-4000-8000-000000000030"))
	body := []byte("exact content")
	if err := newFileBackend(root).put(context.Background(), key, body); err == nil {
		t.Fatal("put through the alias acknowledged while the physical parent cannot be fsync'd")
	}
	for attempt := range 2 {
		if _, err := startFileBackend(root, "", nil); err == nil {
			t.Fatalf("restart %d: Start accepted an unfinished physical barrier", attempt)
		}
		if err := newFileBackend(root).put(context.Background(), key, body); err == nil {
			t.Fatalf("restart %d: put acknowledged before the physical barrier completed", attempt)
		}
	}
	if markerPresent(t, root) {
		t.Fatal("a walk that skipped the physical parent was recorded as complete")
	}
	if _, err := os.Lstat(filepath.FromSlash(key)); err == nil {
		t.Fatal("an object was published below an undurable root")
	}
	if err := os.Chmod(physical, 0o700); err != nil {
		t.Fatal(err)
	}
	fail := false
	synced := syncLog(t, "", &fail)
	b, err := startFileBackend(root, "", nil)
	if err != nil {
		t.Fatalf("start once the physical parent can be fsync'd: %v", err)
	}
	if countOf(*synced, physical) != 1 {
		t.Fatalf("the walk did not fsync the physical parent %s: %v", physical, *synced)
	}
	if !markerPresent(t, root) {
		t.Fatal("a completed walk was not recorded")
	}
	if err := b.put(context.Background(), key, body); err != nil {
		t.Fatal(err)
	}
}

// A marker written by the earlier, lexical walk (v1) is not a record: a
// fresh physical walk must complete before a refused fsync is treated as the
// boundary, and then the marker is rewritten in the current version.
func TestFileBackend_StaleMarkerRequiresAFreshPhysicalWalk(t *testing.T) {
	physical, root := symlinkedRoot(t)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, rootMarkerName)
	if err := os.WriteFile(marker, []byte("fabric content root barrier v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if markerPresent(t, root) {
		t.Fatal("a v1 marker was taken as a record of a physical walk")
	}
	unreadableParent(t, physical)
	if _, err := startFileBackend(root, "", nil); err == nil {
		t.Fatal("a v1 marker let Start treat the refused physical parent as the boundary")
	}
	key := filepath.ToSlash(filepath.Join(root, "tenant", "evidence", "0b1c2d3e-0000-4000-8000-000000000031"))
	if err := newFileBackend(root).put(context.Background(), key, []byte("x")); err == nil {
		t.Fatal("a v1 marker let a put acknowledge before a physical walk completed")
	}
	if err := os.Chmod(physical, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := startFileBackend(root, "", nil); err != nil {
		t.Fatalf("start once the physical parent can be fsync'd: %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != string(rootMarkerContent) {
		t.Fatalf("marker = %q, %v; want the current version", got, err)
	}
	// Now recorded: the same refusal is the boundary.
	unreadableParent(t, physical)
	if _, err := startFileBackend(root, "", nil); err != nil {
		t.Fatalf("restart with a current record: %v", err)
	}
}

// A durable boundary that is a lexical, but not a physical, ancestor of the
// content root fails Start with a configuration error naming no path; one
// spelled through the same alias, or physically, is accepted.
func TestFileBackend_BoundaryMustBeAPhysicalAncestor(t *testing.T) {
	physical, root := symlinkedRoot(t)
	alias := filepath.Dir(root)
	base := filepath.Dir(physical)
	_, err := startFileBackend(root, base, nil) // an ancestor of both spellings
	if err != nil {
		t.Fatalf("base is a physical ancestor too: %v", err)
	}
	if err := (FileConfig{Directory: root, DurableBoundary: alias}).validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := startFileBackend(root, alias, nil); err != nil {
		t.Fatalf("the alias resolves to the root's physical parent: %v", err)
	}
	if _, err := startFileBackend(root, filepath.Join(physical, "a"), nil); err != nil {
		t.Fatalf("the physical spelling of the root's parent: %v", err)
	}
	// elsewhere/link -> physical/a: lexically below elsewhere, physically not.
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(physical, "a"), filepath.Join(elsewhere, "link")); err != nil {
		t.Fatal(err)
	}
	viaLink := filepath.Join(elsewhere, "link", "content")
	if err := (FileConfig{Directory: viaLink, DurableBoundary: elsewhere}).validate(); err != nil {
		t.Fatal(err)
	}
	_, err = startFileBackend(viaLink, elsewhere, nil)
	if err == nil || !strings.Contains(err.Error(), "durable_boundary") || strings.Contains(err.Error(), base) {
		t.Fatalf("want a path-free durable_boundary configuration error, got %v", err)
	}
}

func TestPhysicalPathResolvesTheDeepestExistingAncestor(t *testing.T) {
	physical, root := symlinkedRoot(t)
	got, err := physicalPath(filepath.Join(root, "not", "yet"))
	want := filepath.Join(physical, "a", "content", "not", "yet")
	if err != nil || got != want {
		t.Fatalf("physicalPath = %q, %v; want %q", got, err, want)
	}
	if got := rootAncestors(filepath.Join(physical, "a", "content"), ""); len(got) == 0 || got[1] != physical {
		t.Fatalf("the physical chain does not hold the physical parent: %v", got)
	}
}
