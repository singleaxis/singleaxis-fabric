// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestSyscallNumbersFollowTheClasses: the raw sys_enter program dispatches by
// syscall number, so each enabled class carries this architecture's number
// plus one (0 is never a match), a disabled class 0, and execve is held only
// with syscall results on (a successful exec is sched_process_exec).
func TestSyscallNumbersFollowTheClasses(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want map[uint32]uint64
	}{
		{"defaults: exec and connect", Config{Exec: true, Connect: true},
			map[uint32]uint64{cfgNrConnect: unix.SYS_CONNECT + 1, cfgNrOpenat: 0, cfgNrExecve: 0}},
		{"file access only", Config{FileAccess: true},
			map[uint32]uint64{cfgNrConnect: 0, cfgNrOpenat: unix.SYS_OPENAT + 1, cfgNrExecve: 0}},
		{"results on", Config{Exec: true, Connect: true, FileAccess: true, SyscallResults: true},
			map[uint32]uint64{cfgNrConnect: unix.SYS_CONNECT + 1, cfgNrOpenat: unix.SYS_OPENAT + 1, cfgNrExecve: unix.SYS_EXECVE + 1}},
		{"results on, exec off", Config{Connect: true, SyscallResults: true},
			map[uint32]uint64{cfgNrConnect: unix.SYS_CONNECT + 1, cfgNrOpenat: 0, cfgNrExecve: 0}},
		{"nothing", Config{},
			map[uint32]uint64{cfgNrConnect: 0, cfgNrOpenat: 0, cfgNrExecve: 0}},
	}
	for _, c := range cases {
		got := syscallNumbers(&c.cfg)
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("%s: slot %d = %d, want %d", c.name, k, got[k], v)
			}
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: %d slots, want %d", c.name, len(got), len(c.want))
		}
	}
}
