// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"bytes"
	"context"
	"errors"
	"io"
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
}

func (e *storeError) Error() string {
	if e.status > 0 {
		return "fabriccontent: " + e.op + " failed (status " + strconv.Itoa(e.status) + ")"
	}
	return "fabriccontent: " + e.op + " failed"
}

// fileBackend stores objects below an absolute directory with the SDK's
// local layout: files 0600, directories 0700, written to a temp file,
// fsync'd, then hard-linked into place (link never replaces an existing
// object) and the directory fsync'd.
type fileBackend struct {
	dir string
	mu  sync.Mutex // serializes the no-hard-link fallback only
}

func newFileBackend(dir string) *fileBackend { return &fileBackend{dir: dir} }

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
	if err := os.Link(tmpName, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			done, err := existing(target, data)
			if err == nil && !done {
				return &storeError{op: "file link"} // vanished: retry
			}
			return err
		}
		if err := b.renameNoReplace(tmpName, target, data); err != nil {
			return err
		}
	}
	return syncDir(parent)
}

// renameNoReplace is the fallback for filesystems without hard links: a
// check-then-rename serialized within this process.
func (b *fileBackend) renameNoReplace(tmpName, target string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if done, err := existing(target, data); done || err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return &storeError{op: "file rename"}
	}
	return nil
}

// privateDirs walks from the content root down to dir, top-down so that no
// component is ever resolved through a symlink: a missing directory is
// created 0700 (and its parent fsync'd), an existing one must be a real
// directory and is tightened to 0700, as the SDK's local store does. The
// content root itself may be created with its missing parents.
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
		if err := privateDir(next); err != nil {
			return err
		}
		current = next
	}
	return nil
}

// ensureRoot creates the content root (0700, with missing parents) or checks
// that it is a real directory.
func (b *fileBackend) ensureRoot() error {
	if _, err := os.Lstat(b.dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(b.dir, 0o700); err != nil {
			return &storeError{op: "file mkdir"}
		}
		if err := syncDir(filepath.Dir(b.dir)); err != nil {
			return err
		}
	}
	return privateDir(b.dir)
}

func privateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return &storeError{op: "file mkdir"}
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() {
		// A symlink or file in the layout is never followed.
		return &storeError{op: "file layout"}
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(path, 0o700); err != nil {
			return &storeError{op: "file chmod"}
		}
	}
	return nil
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

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return &storeError{op: "dir open"}
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return &storeError{op: "dir fsync"}
	}
	return nil
}
