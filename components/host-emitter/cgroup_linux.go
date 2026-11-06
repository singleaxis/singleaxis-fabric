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

// suspendedNs is CLOCK_BOOTTIME - CLOCK_MONOTONIC in ns (time spent
// suspended), read with no file access.
func suspendedNs() (int64, bool) {
	var boot, mono unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil || unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono) != nil {
		return 0, false
	}
	return boot.Nano() - mono.Nano(), true
}
