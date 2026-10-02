// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//go:build linux

package auditreceiver

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func logfileIdentity(fi os.FileInfo) (string, error) {
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("audit receiver: missing file identity")
	}
	return fmt.Sprintf("%d:%d", s.Dev, s.Ino), nil
}
func lockState(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }

// Nonblocking open prevents FIFOs/devices substituted at the configured or
// rotated paths from trapping shutdown before the regular-file check.
func openLogHandle(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
