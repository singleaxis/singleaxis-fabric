// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import "golang.org/x/sys/unix"

// platformRenameNoReplace renames from to to atomically, failing with EEXIST
// when to exists (renameat2 RENAME_NOREPLACE). Filesystems or kernels that
// cannot honour the flag return EINVAL or ENOSYS, which the caller treats as
// a retryable failure.
func platformRenameNoReplace(from, to string) error {
	return unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
}

func renameNoReplaceSupported() bool { return true }
