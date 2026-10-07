// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

//go:generate sh bpf/gen.sh

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// event mirrors struct event in bpf/emit.bpf.c — same field order and sizes.
type rawEvent struct {
	CgroupID           uint64
	TsNs               uint64
	Pid                uint32
	Ppid               uint32
	Type               uint32
	Family             uint32
	Port               uint32
	Addr               [16]byte
	ArgvLen            uint32
	ArgvIncomplete     uint32
	FilenameIncomplete uint32
	Comm               [16]byte
	Filename           [240]byte
	Argv               [384]byte
}

// bpfRuntime owns the loaded objects and attached links.
type bpfRuntime struct {
	objs   emitObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// loadBPF loads the CO-RE objects, applies the cgroup filter, and attaches
// the enabled tracepoints. It fails closed: any missing capability or
// verifier rejection is a startup error, never partial-silent operation.
func loadBPF(cfg *Config) (*bpfRuntime, error) {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}); err != nil {
		return nil, fmt.Errorf("memlock rlimit: %w", err)
	}
	var objs emitObjects
	if err := loadEmitObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects (needs CAP_BPF/CAP_PERFMON or privileged + kernel BTF): %w", err)
	}
	rt := &bpfRuntime{objs: objs}

	// Cgroup scope: resolve the configured path to a cgroup id and pin it in
	// the config map. 0 = unfiltered (explicit all_host opt-in).
	cgID := uint64(0)
	if cfg.CgroupPath != "" {
		id, err := cgroupIDFromPath(cfg.CgroupPath)
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("cgroup_filter %q: %w", cfg.CgroupPath, err)
		}
		cgID = id
	}
	key := uint32(0)
	if err := objs.Cfg.Put(key, cgID); err != nil {
		objs.Close()
		return nil, fmt.Errorf("write cgroup filter: %w", err)
	}

	attach := func(group, name string, prog *ebpf.Program) error {
		l, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			return fmt.Errorf("attach %s/%s: %w", group, name, err)
		}
		rt.links = append(rt.links, l)
		return nil
	}
	if cfg.Exec {
		if err := attach("sched", "sched_process_exec", objs.TpExec); err != nil {
			rt.close()
			return nil, err
		}
	}
	if cfg.Connect {
		if err := attach("syscalls", "sys_enter_connect", objs.TpConnect); err != nil {
			rt.close()
			return nil, err
		}
	}
	if cfg.FileAccess {
		if err := attach("syscalls", "sys_enter_openat", objs.TpOpenat); err != nil {
			rt.close()
			return nil, err
		}
	}
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		rt.close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	rt.reader = rd
	return rt, nil
}

// next reads one raw event from the ringbuf and converts it to the
// platform-neutral event shape.
func (rt *bpfRuntime) next() (*event, error) {
	rec, err := rt.reader.Read()
	if err != nil {
		return nil, err
	}
	var e rawEvent
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
		return nil, err
	}
	return rawToEvent(&e), nil
}

func (rt *bpfRuntime) lossCount() (uint64, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, err
	}
	counts := make([]uint64, cpus)
	key := uint32(0)
	if err := rt.objs.Losses.Lookup(&key, &counts); err != nil {
		return 0, err
	}
	var total uint64
	for _, count := range counts {
		total += count
	}
	return total, nil
}

// rawToEvent converts the fixed-layout kernel record to the neutral event.
func rawToEvent(r *rawEvent) *event {
	return &event{
		Type:               r.Type,
		TsNs:               r.TsNs,
		Pid:                r.Pid,
		Ppid:               r.Ppid,
		Comm:               cstr(r.Comm[:]),
		Filename:           cstr(r.Filename[:]),
		Argv:               r.Argv[:min(int(r.ArgvLen), len(r.Argv))],
		ArgvIncomplete:     r.ArgvIncomplete != 0,
		FilenameIncomplete: r.FilenameIncomplete != 0,
		Family:             r.Family,
		Port:               r.Port,
		Addr:               r.Addr,
		CgroupID:           r.CgroupID,
	}
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (rt *bpfRuntime) close() {
	if rt.reader != nil {
		rt.reader.Close()
	}
	for _, l := range rt.links {
		l.Close()
	}
	rt.objs.Close()
}
