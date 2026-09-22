// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// cgroupIDFromPath resolves a cgroup v2 path (e.g. the agent container's
// cgroup dir under /sys/fs/cgroup) to the kernel cgroup id that
// bpf_get_current_cgroup_id() returns — which is the cgroupfs inode.
func cgroupIDFromPath(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat cgroup path %s: %w", path, err)
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		return 0, fmt.Errorf("cgroup path %s is not a directory", path)
	}
	return st.Ino, nil
}
