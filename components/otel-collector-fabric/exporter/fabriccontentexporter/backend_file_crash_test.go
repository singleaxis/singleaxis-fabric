// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if _, err := startFileBackend(dir); err != nil {
		t.Fatal(err)
	}
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
	if _, err := startFileBackend(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("start created the content root")
	}
}

// countDirSyncs replaces syncDir for the test: it counts fsyncs of dir and
// fails them with EIO while *fail is set.
func countDirSyncs(t *testing.T, dir string, fail *bool) *int {
	t.Helper()
	calls := 0
	original := syncDir
	syncDir = func(d string) error {
		if d == dir {
			calls++
			if *fail {
				return syscall.EIO
			}
		}
		return original(d)
	}
	t.Cleanup(func() { syncDir = original })
	return &calls
}

// Sol F2: a put that published the object and dropped its temp but failed
// its directory fsync leaves a visible single-link object. The replay must
// fsync the directory before it reports success (the queue then retires
// the record), and must keep failing while that fsync fails.
func TestFileBackend_ReplayAfterFailedDirFsyncSyncsTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	b := newFileBackend(dir)
	key := filepath.ToSlash(filepath.Join(dir, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000001"))
	parent := filepath.Dir(filepath.FromSlash(key))
	if err := b.privateDirs(parent); err != nil {
		t.Fatal(err)
	}
	body := []byte("exact wire body")
	fail := true
	calls := countDirSyncs(t, parent, &fail)
	if err := b.put(context.Background(), key, body); err == nil {
		t.Fatal("first put: want the injected directory fsync failure")
	}
	if n := nlink(t, key); n != 1 {
		t.Fatalf("object after failed fsync: nlink = %d, want 1 (published, temp dropped)", n)
	}
	*calls = 0
	if err := b.put(context.Background(), key, body); err == nil {
		t.Fatal("replay while the directory fsync still fails must not succeed")
	}
	fail, *calls = false, 0
	if err := b.put(context.Background(), key, body); err != nil {
		t.Fatalf("replay put: %v", err)
	}
	if *calls == 0 {
		t.Fatal("replay accepted the object without fsyncing its directory")
	}
}

// The concurrent-writer path: link(2) finds the target another writer
// published (identical bytes) after this put's existence check. It must also
// fsync the directory before accepting.
func TestFileBackend_ConcurrentExistingTargetSyncsTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	b := newFileBackend(dir)
	key := filepath.ToSlash(filepath.Join(dir, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000002"))
	parent := filepath.Dir(filepath.FromSlash(key))
	body := []byte("exact wire body")
	originalLink := linkFile
	t.Cleanup(func() { linkFile = originalLink })
	linkFile = func(oldname, newname string) error {
		// The other writer wins between the existence check and link(2),
		// publishing the same bytes without (yet) fsyncing the directory.
		if err := os.WriteFile(newname, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return originalLink(oldname, newname)
	}
	fail := true
	if err := b.privateDirs(parent); err != nil {
		t.Fatal(err)
	}
	calls := countDirSyncs(t, parent, &fail)
	if err := b.put(context.Background(), key, body); err == nil {
		t.Fatal("concurrent replay accepted without a successful directory fsync")
	}
	fail, *calls = false, 0
	if err := os.Remove(filepath.FromSlash(key)); err != nil {
		t.Fatal(err)
	}
	if err := b.put(context.Background(), key, body); err != nil {
		t.Fatalf("concurrent replay: %v", err)
	}
	if *calls == 0 {
		t.Fatal("concurrent replay accepted the object without fsyncing its directory")
	}
	if left := temps(t, dir); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

// syncLog replaces syncDir for the test: it records every successful
// directory fsync and fails the fsyncs of dir with EIO while *fail is set.
func syncLog(t *testing.T, dir string, fail *bool) *[]string {
	t.Helper()
	var synced []string
	original := syncDir
	syncDir = func(d string) error {
		if d == dir && *fail {
			return syscall.EIO
		}
		if err := original(d); err != nil {
			return err
		}
		synced = append(synced, d)
		return nil
	}
	t.Cleanup(func() { syncDir = original })
	return &synced
}

// within keeps, in order, the entries of list at or below dir.
func within(list []string, dir string) []string {
	var kept []string
	for _, s := range list {
		if s == dir || strings.HasPrefix(s, dir+string(filepath.Separator)) {
			kept = append(kept, s)
		}
	}
	return kept
}

func countOf(list []string, item string) int {
	n := 0
	for _, s := range list {
		if s == item {
			n++
		}
	}
	return n
}

// Sol G #2: a put creates <root>/acme, then its fsync of <root> fails. The
// retry sees <root>/acme present; it must still fsync <root> (the barrier
// for the tenant directory's entry) before it acknowledges, and must keep
// failing while that fsync fails.
func TestFileBackend_RetryAfterFailedParentFsyncSyncsTheParent(t *testing.T) {
	root := t.TempDir()
	b := newFileBackend(root)
	key := filepath.ToSlash(filepath.Join(root, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000003"))
	body := []byte("exact wire body")
	fail := true
	synced := syncLog(t, root, &fail)
	if err := b.put(context.Background(), key, body); err == nil {
		t.Fatal("first put: want the injected fsync failure of the content root")
	}
	if _, err := os.Lstat(filepath.Join(root, "acme")); err != nil {
		t.Fatalf("the tenant directory was not created before the failed fsync: %v", err)
	}
	if err := b.put(context.Background(), key, body); err == nil {
		t.Fatal("retry while the parent fsync still fails must not succeed")
	}
	fail, *synced = false, nil
	if err := b.put(context.Background(), key, body); err != nil {
		t.Fatalf("retry put: %v", err)
	}
	if countOf(*synced, root) == 0 {
		t.Fatalf("retry acknowledged without fsyncing the content root; synced %v", *synced)
	}
	// Once durable, later puts in the same directories do not repeat it.
	*synced = nil
	other := filepath.ToSlash(filepath.Join(root, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000004"))
	if err := b.put(context.Background(), other, body); err != nil {
		t.Fatal(err)
	}
	if countOf(*synced, root) != 0 {
		t.Errorf("an already durable chain was fsync'd again: %v", *synced)
	}
}

// Sol G #2 for the root: ensureRoot creates the content root with missing
// ancestors. When the fsync that makes the topmost created ancestor durable
// fails, a retry (the root now exists) must still complete every barrier,
// top-down, before it acknowledges.
func TestFileBackend_RetryCompletesTheBarriersOfCreatedRootAncestors(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "a", "b", "content")
	b := newFileBackend(root)
	key := filepath.ToSlash(filepath.Join(root, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000005"))
	body := []byte("exact wire body")
	fail := true
	synced := syncLog(t, base, &fail)
	if err := b.put(context.Background(), key, body); err == nil {
		t.Fatal("first put: want the injected fsync failure of the ancestor's parent")
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatalf("the content root was not created: %v", err)
	}
	fail, *synced = false, nil
	if err := b.put(context.Background(), key, body); err != nil {
		t.Fatalf("retry put: %v", err)
	}
	want := []string{base, filepath.Join(base, "a"), filepath.Join(base, "a", "b"), root}
	below := within(*synced, base) // the walk also fsyncs base's own ancestors first
	got := below[:min(len(below), len(want))]
	if len(got) != len(want) {
		t.Fatalf("retry synced %v, want the chain %v first", *synced, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("retry synced %v, want the chain %v first", *synced, want)
		}
	}
}

// A fresh backend over a tree an earlier process (or another writer)
// created re-establishes each directory's barrier once before its first
// acknowledgement: their creator may have failed its fsync.
func TestFileBackend_FreshBackendSyncsAnExistingChainOnce(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "acme", "evidence")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	b := newFileBackend(root)
	fail := false
	synced := syncLog(t, "", &fail)
	key := filepath.ToSlash(filepath.Join(parent, "0b1c2d3e-0000-4000-8000-000000000006"))
	if err := b.put(context.Background(), key, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if countOf(*synced, root) != 1 || countOf(*synced, filepath.Join(root, "acme")) != 1 {
		t.Fatalf("existing chain not made durable once: %v", *synced)
	}
}

// Sol H #3: an earlier process created <base>/a/b/content and failed the
// fsync of <base> that makes "a" durable, then restarted. The fresh backend
// knows nothing of that pending barrier and the chain already exists; it must
// still fsync <base> (and every ancestor below the boundary) before its first
// acknowledgement.
func TestFileBackend_RestartCompletesTheRootChainBarrierBeforeAcknowledging(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "a", "b", "content")
	key := filepath.ToSlash(filepath.Join(root, "tenant", "evidence", "0b1c2d3e-0000-4000-8000-000000000010"))
	body := []byte("exact content")
	fail := true
	synced := syncLog(t, base, &fail)
	if err := newFileBackend(root).put(context.Background(), key, body); err == nil {
		t.Fatal("first put: want the injected fsync failure of <base>")
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatal(err)
	}
	// Process restart: a new backend; the fsync now works (no power loss yet).
	fail, *synced = false, nil
	if err := newFileBackend(root).put(context.Background(), key, body); err != nil {
		t.Fatalf("fresh backend put: %v", err)
	}
	chain := []string{base, filepath.Join(base, "a"), filepath.Join(base, "a", "b")}
	got := within(*synced, base)
	if len(got) < len(chain) {
		t.Fatalf("fresh backend acknowledged before the root chain barrier; synced %v", *synced)
	}
	for i, want := range chain {
		if got[i] != want {
			t.Fatalf("fresh backend synced %v, want the chain %v first", got, chain)
		}
	}
}

// The same restart through Start: an existing root re-establishes the chain
// at Start, a non-boundary failure fails Start retryably, and the next Start
// completes the barrier before any put.
func TestFileBackend_StartReestablishesTheRootChainBarrier(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "a", "content")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fail := true
	synced := syncLog(t, base, &fail)
	_, err := startFileBackend(root)
	var se *storeError
	if err == nil || !errors.As(err, &se) || strings.Contains(err.Error(), base) {
		t.Fatalf("start with a failing ancestor fsync: want a retryable storeError without the path, got %v", err)
	}
	fail, *synced = false, nil
	b, err := startFileBackend(root)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if countOf(*synced, base) != 1 || countOf(*synced, filepath.Join(base, "a")) != 1 {
		t.Fatalf("start did not fsync the root's ancestors: %v", *synced)
	}
	*synced = nil
	key := filepath.ToSlash(filepath.Join(root, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000011"))
	if err := b.put(context.Background(), key, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if countOf(*synced, base) != 0 {
		t.Errorf("a completed root barrier was walked again: %v", *synced)
	}
}

// An ancestor that refuses fsync with EACCES, EPERM or EROFS is the durable
// boundary: the walk accepts it, provided this backend did not create a
// directory inside it; anything else (EIO) fails.
func TestFileBackend_RootBarrierBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		created bool
		ok      bool
	}{
		{"eacces existing", syscall.EACCES, false, true},
		{"eperm existing", syscall.EPERM, false, true},
		{"erofs existing", &storeError{op: "dir open", err: &os.PathError{Op: "open", Err: syscall.EROFS}}, false, true},
		{"eio existing", syscall.EIO, false, false},
		{"eacces created", syscall.EACCES, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "content")
			if !tc.created {
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			original := syncDir
			t.Cleanup(func() { syncDir = original })
			var above []string
			syncDir = func(d string) error {
				if d == base {
					return tc.err
				}
				if strings.HasPrefix(base, d+string(filepath.Separator)) || d == "/" {
					above = append(above, d)
				}
				return original(d)
			}
			key := filepath.ToSlash(filepath.Join(root, "acme", "evidence", "0b1c2d3e-0000-4000-8000-000000000012"))
			err := newFileBackend(root).put(context.Background(), key, []byte("x"))
			if (err == nil) != tc.ok {
				t.Fatalf("put = %v, want ok=%v", err, tc.ok)
			}
			if len(above) == 0 {
				t.Errorf("ancestors above the boundary were not attempted")
			}
		})
	}
}

// A mount point ends the chain: its own entry lives on another filesystem.
func TestFileBackend_RootBarrierStopsAtTheFilesystemRoot(t *testing.T) {
	base := t.TempDir()
	mount := filepath.Join(base, "mnt")
	root := filepath.Join(mount, "content")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	original := sameFilesystem
	t.Cleanup(func() { sameFilesystem = original })
	sameFilesystem = func(dir, parent string) bool { return dir != mount }
	fail := false
	synced := syncLog(t, "", &fail)
	if _, err := startFileBackend(root); err != nil {
		t.Fatal(err)
	}
	if countOf(*synced, mount) != 1 || countOf(*synced, base) != 0 {
		t.Fatalf("want the chain to stop at the mount point; synced %v", *synced)
	}
}
