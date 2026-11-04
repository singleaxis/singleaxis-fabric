// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"

	"golang.org/x/sys/unix"
)

// sliceChanges signals when a directory is created in any of dirs (the
// kubepods QoS slices), so a pod slice is installed as a root moments after
// the kubelet creates it. Directories missing at start are covered by the
// periodic resync only. The returned channel never closes.
func sliceChanges(ctx context.Context, dirs []string) <-chan struct{} {
	out := make(chan struct{}, 1)
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return out
	}
	watched := 0
	for _, d := range dirs {
		if _, err := unix.InotifyAddWatch(fd, d, unix.IN_CREATE|unix.IN_ONLYDIR); err == nil {
			watched++
		}
	}
	if watched == 0 {
		unix.Close(fd)
		return out
	}
	go func() {
		defer unix.Close(fd)
		buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for ctx.Err() == nil {
			n, err := unix.Poll(fds, 1000)
			if err == unix.EINTR || n == 0 {
				continue
			}
			if err != nil {
				return
			}
			if _, err := unix.Read(fd, buf); err != nil && err != unix.EAGAIN && err != unix.EINTR {
				return
			}
			select {
			case out <- struct{}{}:
			default:
			}
		}
	}()
	return out
}
