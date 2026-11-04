// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package hostrecords

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// prepareStateDir creates the state directory (0700) if it is missing,
// refuses one that is not a directory, not exactly 0700 or not owned by this
// process's effective user, and takes its exclusive lock, so a second sensor
// process on the same directory is refused while this one runs.
func prepareStateDir(dir string) (io.Closer, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("hostrecords: StateDir cannot be created (its parent must exist)")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, errors.New("hostrecords: StateDir is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		return nil, errors.New("hostrecords: StateDir must have mode 0700")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return nil, errors.New("hostrecords: StateDir must be owned by the sensor's user")
	}
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, errors.New("hostrecords: StateDir lock cannot be opened")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("hostrecords: StateDir is in use by another source")
	}
	return f, nil
}
