// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// backend writes one object without ever overwriting: an existing object
// with identical bytes is success (replay), different bytes are errConflict,
// and every other failure is a retryable *storeError.
type backend interface {
	// prefix is prepended to the SDK layout keys.
	prefix() string
	// ref is the descriptor ref of the object stored at key.
	ref(key string) string
	put(ctx context.Context, key string, data []byte) error
}

var errConflict = errors.New("fabriccontent: object exists with different bytes")

// storeError is a retryable backend failure. Its message is fixed per
// operation and never contains a path, key, bucket, URL or the underlying
// error text, because exporterhelper logs it on every retry.
type storeError struct {
	op     string
	status int
	err    error // the cause, for errors.Is; never part of the message
}

func (e *storeError) Unwrap() error { return e.err }

func (e *storeError) Error() string {
	if e.status > 0 {
		return "fabriccontent: " + e.op + " failed (status " + strconv.Itoa(e.status) + ")"
	}
	return "fabriccontent: " + e.op + " failed"
}

// fileBackend stores objects below an absolute directory with the SDK's
// local layout: files 0600, directories 0700, written to a temp file,
// fsync'd, then put into place with an atomic no-replace primitive and the
// directory fsync'd. The primitive is link(2), which never replaces an
// existing name; on a filesystem without hard links it is an atomic
// no-replace rename (renameat2 RENAME_NOREPLACE on Linux, renamex_np
// RENAME_EXCL on macOS). When neither works the write fails retryably:
// there is no check-then-rename fallback, because two exporter processes
// sharing the directory could both see the name free and overwrite an
// accepted object (Sol data-exposure #5).
//
// Every directory below the content root, and every directory this backend
// created for the root itself, is durable in its parent only after that
// parent has been fsync'd successfully. That state is tracked per directory
// and set only after the fsync succeeds, so a put that created a directory
// but failed its parent's fsync does not leave the next attempt (which sees
// the directory already present) free to acknowledge an object whose
// directory entry may still be lost on power failure (Sol G #2). A fresh
// process re-establishes the barrier once per directory below the root,
// covering directories an earlier process or another writer created.
//
// The content root and its ancestors get the same treatment (Sol H #3): a
// fresh backend, at Start when the root already exists and in any case
// before its first acknowledgement, fsyncs every ancestor of the root up to
// the durable boundary, whether or not those directories already exist. An
// earlier process may have created them and failed (or crashed before) the
// parent fsync that made them durable. The boundary is the first of:
//
//   - the filesystem root ("/"), or the root of the filesystem holding the
//     content root (a mount point's own entry lives on another filesystem
//     and cannot be lost with this one);
//   - the configured file.durable_boundary (the content root or one of its
//     ancestors), treated exactly like a mount point: the operator vouches
//     for its own entry and everything above it, and the walk fsyncs it and
//     the directories below it.
//
// Once a walk has fsync'd every directory up to that boundary, the backend
// records it on disk (Sol K #2): a private marker file, rootMarkerName, is
// created inside the content root, fsync'd, and the root fsync'd. The
// marker lives inside the root, so removing or recreating the root (or any
// ancestor) removes it too. Only while that marker is present may a later
// walk treat an ancestor whose fsync is refused with EACCES, EPERM or EROFS
// (a directory it cannot open, or a read-only filesystem) as the boundary:
// a previous process proved those entries durable. Without the marker, a
// refused fsync fails Start, or the put, retryably — a restart never turns
// an unfinished barrier into a boundary just because the knowledge of what
// the earlier process created was lost with it. A directory this backend
// created inside a refusing ancestor is never accepted on that basis either.
//
// Any other failure (EIO, ENOSPC, ...) fails Start, or the put, retryably;
// the whole chain is retried until one walk completes.
type fileBackend struct {
	dir string
	// boundary is the configured durable boundary ("" for none): the content
	// root or one of its ancestors, treated like a mount point.
	boundary string

	mu sync.Mutex
	// durable holds directories whose entry in their parent is known to be
	// fsync'd. Bounded by maxDurableDirs: forgetting entries only costs a
	// repeated (harmless) parent fsync.
	durable map[string]bool
	// rootDurable is set once a walk of the root's ancestor chain (see
	// rootBarrier) has completed in this process, and cleared whenever the
	// root has to be created again.
	rootDurable bool
	// created holds the directories ensureRoot created (the content root
	// and any missing ancestors) until a rootBarrier walk completes: their
	// parents may not be treated as the durable boundary.
	created map[string]bool
}

// maxDurableDirs bounds the durable set (three directories per tenant).
const maxDurableDirs = 4096

// linkFile and renameNoReplace are the no-replace primitives; tests replace
// them to simulate filesystems without hard links or without either.
var (
	linkFile        = os.Link
	renameNoReplace = platformRenameNoReplace
)

// rootMarkerName is the file, inside the content root, whose presence
// records that a root barrier walk once completed without relying on a
// refused fsync (see fileBackend). It is never an object: the SDK layout
// keys all live below <root>/<tenant>/.
const rootMarkerName = ".fabric-root-barrier"

// rootMarkerContent is the marker's fixed content; only its presence counts.
var rootMarkerContent = []byte("fabric content root barrier v1\n")

func newFileBackend(dir string) *fileBackend {
	return &fileBackend{dir: dir, durable: map[string]bool{}, created: map[string]bool{}}
}

// startFileBackend is newFileBackend plus a sweep of the temp files an
// earlier process left behind (see sweepStaleTemps) and, when the content
// root already exists, the root barrier (see rootBarrier): a failure other
// than reaching the durable boundary fails Start with a retryable error.
// A missing root is created, and its barrier completed, by the first put.
func startFileBackend(dir, boundary string) (*fileBackend, error) {
	b := newFileBackend(dir)
	b.boundary = boundary
	b.sweepStaleTemps()
	if info, err := os.Lstat(dir); err == nil && info.IsDir() {
		if err := b.ensureRoot(); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// isTempName reports whether name is one of put's temp files
// ("." + object name + "." + random + ".tmp").
func isTempName(name string) bool {
	return strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp")
}

// sweepStaleTemps removes put's temp files below the content root, best
// effort, and fsyncs each directory it changed. A crash between link(2) and
// the temp's removal leaves the object with a second link (nlink 2), which
// readers (LocalFilesystemContentStore) refuse; a crash before link(2) leaves
// an orphan temp. Neither is ever an object, so removing them is always safe,
// also while another exporter writes there (its link then fails and is
// retried). Symlinks are never followed.
func (b *fileBackend) sweepStaleTemps() {
	if info, err := os.Lstat(b.dir); err != nil || !info.IsDir() {
		return
	}
	changed := map[string]bool{}
	_ = filepath.WalkDir(b.dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: skipped, never fatal
		}
		if entry.Type().IsRegular() && isTempName(entry.Name()) {
			if os.Remove(path) == nil {
				changed[filepath.Dir(path)] = true
			}
		}
		return nil
	})
	for dir := range changed {
		_ = syncDir(dir)
	}
}

// healStaleTemps removes the temp files of the object at target when it has
// more than one link (a crash after link(2) in an earlier put), then fsyncs
// the directory. Called whenever a put finds the object already stored (a
// replay, or a concurrent writer that published it first). The directory
// fsync is unconditional: the earlier put may have published the object and
// dropped its temp but failed (or crashed) before its own directory fsync,
// so a visible, single-link object is not yet durable, and success here is
// what lets the delivery queue retire the record (Sol F2).
func healStaleTemps(target string) error {
	info, err := os.Lstat(target)
	if err != nil {
		return &storeError{op: "file read"}
	}
	parent := filepath.Dir(target)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink <= 1 {
		return syncDir(parent)
	}
	prefix := "." + filepath.Base(target) + "."
	entries, err := os.ReadDir(parent)
	if err != nil {
		return &storeError{op: "dir read"}
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasPrefix(name, prefix) && isTempName(name) {
			if err := os.Remove(filepath.Join(parent, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return &storeError{op: "file temp remove"}
			}
		}
	}
	return syncDir(parent)
}

func (b *fileBackend) prefix() string { return b.dir + "/" }

func (b *fileBackend) ref(key string) string { return "file://" + key }

func (b *fileBackend) put(_ context.Context, key string, data []byte) error {
	if !strings.HasPrefix(key, b.prefix()) {
		return &storeError{op: "file layout"}
	}
	target := filepath.FromSlash(key)
	parent := filepath.Dir(target)
	if err := b.privateDirs(parent); err != nil {
		return err
	}
	if done, err := existing(target, data); done || err != nil {
		if err == nil { // a replay: heal a second link a crash after link(2) left
			return healStaleTemps(target)
		}
		return err
	}
	tmp, err := os.CreateTemp(parent, "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return &storeError{op: "file create"}
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := writeSynced(tmp, data); err != nil {
		return err
	}
	err = linkFile(tmpName, target)
	if err != nil && !errors.Is(err, os.ErrExist) {
		// No hard links here: the only other acceptable primitive is an
		// atomic rename that refuses an existing target.
		err = renameNoReplace(tmpName, target)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return &storeError{op: "file no-replace"}
		}
	}
	if err != nil { // the target exists: replay or conflict
		done, err := existing(target, data)
		if err == nil && !done {
			return &storeError{op: "file link"} // vanished: retry
		}
		if err != nil {
			return err
		}
		// Identical bytes another writer published: it may not have
		// fsync'd the directory yet, so do that before accepting.
		return healStaleTemps(target)
	}
	// Drop the temp's name before the directory fsync, so the object is
	// durable with exactly one link (readers refuse nlink != 1). After a
	// rename the temp is already gone.
	if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &storeError{op: "file temp remove"}
	}
	return syncDir(parent)
}

// privateDirs walks from the content root down to dir, top-down so that no
// component is ever resolved through a symlink: a missing directory is
// created 0700, an existing one must be a real directory and is tightened to
// 0700, as the SDK's local store does. The content root itself may be
// created with its missing parents. Before it returns, every directory on
// the chain has a durable entry in its parent (see makeDurable): created or
// not, on this attempt or an earlier one.
func (b *fileBackend) privateDirs(dir string) error {
	rel, err := filepath.Rel(b.dir, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return &storeError{op: "file layout"}
	}
	if err := b.ensureRoot(); err != nil {
		return err
	}
	current := b.dir
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "." || part == "" {
			continue
		}
		next := filepath.Join(current, part)
		created, err := privateDir(next)
		if err != nil {
			return err
		}
		if created { // removed and recreated since it was last made durable
			b.forget(next)
		}
		if err := b.makeDurable(next); err != nil {
			return err
		}
		current = next
	}
	return nil
}

// makeDurable fsyncs dir's parent unless dir's entry there is already known
// durable, and records it only after that fsync succeeds.
func (b *fileBackend) makeDurable(dir string) error {
	b.mu.Lock()
	known := b.durable[dir]
	b.mu.Unlock()
	if known {
		return nil
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return err
	}
	b.mu.Lock()
	if len(b.durable) >= maxDurableDirs {
		b.durable = map[string]bool{}
	}
	b.durable[dir] = true
	b.mu.Unlock()
	return nil
}

func (b *fileBackend) forget(dir string) {
	b.mu.Lock()
	delete(b.durable, dir)
	b.mu.Unlock()
}

// ensureRoot creates the content root (0700, with missing parents) or checks
// that it is a real directory, then completes the root barrier unless a walk
// already completed in this process. Until one does, every put fails, so a
// failed fsync is never skipped because the root now exists, and a fresh
// process never trusts barriers an earlier one may not have completed.
func (b *fileBackend) ensureRoot() error {
	if _, err := os.Lstat(b.dir); errors.Is(err, os.ErrNotExist) {
		var missing []string // the root, then its missing parents
		for d := b.dir; ; {
			if _, err := os.Lstat(d); !errors.Is(err, os.ErrNotExist) {
				break
			}
			missing = append(missing, d)
			up := filepath.Dir(d)
			if up == d {
				break
			}
			d = up
		}
		if err := os.MkdirAll(b.dir, 0o700); err != nil {
			return &storeError{op: "file mkdir", err: err}
		}
		b.mu.Lock()
		b.rootDurable = false
		for _, d := range missing {
			b.created[d] = true
		}
		b.mu.Unlock()
	}
	if _, err := privateDir(b.dir); err != nil {
		return err
	}
	b.mu.Lock()
	done := b.rootDurable
	b.mu.Unlock()
	if done {
		return nil
	}
	return b.rootBarrier()
}

// rootBarrier fsyncs, top-down, every ancestor of the content root up to
// the durable boundary (see fileBackend), making the root's entry and each
// ancestor's entry durable. The root's own entries are made durable by the
// barriers of the directories below it (makeDurable).
func (b *fileBackend) rootBarrier() error {
	chain := rootAncestors(b.dir, b.boundary) // bottom-up
	marked, err := hasRootMarker(b.dir)
	if err != nil {
		return err
	}
	b.mu.Lock()
	created := make(map[string]bool, len(b.created))
	for d := range b.created {
		created[filepath.Dir(d)] = true // parents holding a created entry
	}
	b.mu.Unlock()
	for i := len(chain) - 1; i >= 0; i-- {
		parent := chain[i]
		err := syncDir(parent)
		if err == nil {
			continue
		}
		if !marked || !beyondBoundary(err) || created[parent] {
			var se *storeError
			if errors.As(err, &se) {
				return err
			}
			return &storeError{op: "dir fsync", err: err}
		}
		// A completed walk is on record (the marker): this ancestor, and
		// everything above it, was made durable then. Directories below it
		// must still succeed.
	}
	if !marked {
		// Every directory up to the boundary was fsync'd: record it.
		if err := writeRootMarker(b.dir); err != nil {
			return err
		}
	}
	b.mu.Lock()
	b.rootDurable = true
	b.created = map[string]bool{}
	b.mu.Unlock()
	return nil
}

// hasRootMarker reports whether the content root holds the barrier marker
// as a regular file. Anything else at that name (a symlink, a directory) is
// a layout error, never followed.
func hasRootMarker(root string) (bool, error) {
	info, err := os.Lstat(filepath.Join(root, rootMarkerName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, &storeError{op: "file read"}
	}
	if !info.Mode().IsRegular() {
		return false, &storeError{op: "file layout"}
	}
	return true, nil
}

// writeRootMarker creates the barrier marker (0600, O_EXCL and O_NOFOLLOW:
// never through a planted link), fsyncs it, then fsyncs the content root so
// its entry is durable before any later walk relies on it.
func writeRootMarker(root string) error {
	path := filepath.Join(root, rootMarkerName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	switch {
	case errors.Is(err, os.ErrExist): // another writer recorded it first
		if ok, err := hasRootMarker(root); err != nil || !ok {
			return &storeError{op: "file layout"}
		}
	case err != nil:
		return &storeError{op: "file create", err: err}
	default:
		if err := writeSynced(f, rootMarkerContent); err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	return syncDir(root)
}

// beyondBoundary reports whether a directory fsync failed because this
// process may not open or sync that directory: the durable boundary.
func beyondBoundary(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EROFS)
}

// rootAncestors lists, bottom-up, the parents whose fsync makes the content
// root's entry and its ancestors' entries durable, stopping at "/", at the
// root of the content root's filesystem, or at the configured boundary
// (whose own entry, like a mount point's, the walk does not sync).
func rootAncestors(root, boundary string) []string {
	var chain []string
	for d := root; ; {
		if d == boundary {
			return chain
		}
		parent := filepath.Dir(d)
		if parent == d || !sameFilesystem(d, parent) {
			return chain
		}
		chain = append(chain, parent)
		d = parent
	}
}

// sameFilesystem reports whether dir and its parent are on one filesystem
// (dir is not a mount point). Unknown is "same": the fsync decides. Tests
// replace it to simulate a mount point.
var sameFilesystem = func(dir, parent string) bool {
	a, errA := os.Stat(dir)
	p, errP := os.Stat(parent)
	if errA != nil || errP != nil {
		return true
	}
	sa, okA := a.Sys().(*syscall.Stat_t)
	sp, okP := p.Sys().(*syscall.Stat_t)
	return !okA || !okP || sa.Dev == sp.Dev
}

// privateDir creates path 0700 when it is missing (created reports that),
// or checks that it is a real directory and tightens it to 0700. It never
// fsyncs: the caller makes the directory's entry durable (makeDurable,
// rootBarrier).
func privateDir(path string) (created bool, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return false, &storeError{op: "file mkdir"}
		}
		created = true
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() {
		// A symlink or file in the layout is never followed.
		return created, &storeError{op: "file layout"}
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(path, 0o700); err != nil {
			return created, &storeError{op: "file chmod"}
		}
	}
	return created, nil
}

// existing reports whether path already exists. An existing object holding
// exactly data is success (done, nil); different bytes are errConflict; a
// read failure other than "does not exist" is retryable.
func existing(path string, data []byte) (bool, error) {
	// O_NOFOLLOW: a symlink planted at an object path is a read error,
	// never a comparison against a file outside the content root.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, &storeError{op: "file read"}
	}
	defer func() { _ = f.Close() }()
	current, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if err != nil {
		return true, &storeError{op: "file read"}
	}
	if !bytes.Equal(current, data) {
		return true, errConflict
	}
	return true, nil
}

func writeSynced(f *os.File, data []byte) error {
	defer func() { _ = f.Close() }()
	if err := f.Chmod(0o600); err != nil {
		return &storeError{op: "file chmod"}
	}
	if _, err := f.Write(data); err != nil {
		return &storeError{op: "file write"}
	}
	if err := f.Sync(); err != nil {
		return &storeError{op: "file fsync"}
	}
	if err := f.Close(); err != nil {
		return &storeError{op: "file close"}
	}
	return nil
}

// syncDir fsyncs a directory; tests replace it to inject failures.
var syncDir = syncDirectory

func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return &storeError{op: "dir open", err: err}
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return &storeError{op: "dir fsync", err: err}
	}
	return nil
}
