// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import "golang.org/x/sys/unix"

// platformRenameNoReplace renames from to to atomically, failing with EEXIST
// when to exists (renamex_np RENAME_EXCL). A volume that cannot honour the
// flag returns ENOTSUP, which the caller treats as a retryable failure.
func platformRenameNoReplace(from, to string) error {
	return unix.RenamexNp(from, to, unix.RENAME_EXCL)
}

func renameNoReplaceSupported() bool { return true }
