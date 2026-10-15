// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package fabriccontentexporter

import "errors"

// platformRenameNoReplace has no atomic no-replace rename on this platform;
// without hard links the file backend fails retryably.
func platformRenameNoReplace(string, string) error {
	return errors.New("no atomic no-replace rename on this platform")
}

func renameNoReplaceSupported() bool { return false }
