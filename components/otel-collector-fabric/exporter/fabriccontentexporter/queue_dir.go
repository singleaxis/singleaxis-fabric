// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// privateQueueDir validates and tightens the persistent content queue's
// directory before the queue opens it: every directory 0700 and every file
// without group or other bits, as the content store itself is. A symlink or
// special file anywhere in it, or a root that is not a real directory, fails
// start: the queue would otherwise follow it. A missing directory is left
// to file_storage, which creates it with directory_permissions ("0700" in
// every shipped configuration). Errors carry no path.
func privateQueueDir(dir string) error {
	if dir == "" {
		return nil
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() {
		return errors.New("fabriccontent: queue_directory is not a directory")
	}
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return errors.New("fabriccontent: queue directory not readable")
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("fabriccontent: queue directory not readable")
		}
		mode := info.Mode()
		switch {
		case mode.IsDir():
			if mode.Perm() != 0o700 {
				if err := os.Chmod(path, 0o700); err != nil {
					return errors.New("fabriccontent: queue directory cannot be made private (0700)")
				}
			}
		case mode.IsRegular():
			if mode.Perm()&0o077 != 0 {
				if err := os.Chmod(path, mode.Perm()&^0o077); err != nil {
					return errors.New("fabriccontent: queue file cannot be made private (0600)")
				}
			}
		default: // a symlink, device, FIFO or socket is never followed or opened
			return errors.New("fabriccontent: queue directory holds a symlink or special file")
		}
		return nil
	})
}
