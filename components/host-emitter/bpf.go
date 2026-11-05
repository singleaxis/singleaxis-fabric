// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

//go:generate sh bpf/gen.sh

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	StartBoottime      uint64
	Pid                uint32
	Ppid               uint32
	NsPid              uint32
	NsPpid             uint32
	PidNS              uint32
	Scope              uint32
	Type               uint32
	Family             uint32
	Port               uint32
	Addr               [16]byte
	ArgvLen            uint32
	ArgvIncomplete     uint32
	FilenameIncomplete uint32
	CgroupNames        uint32
	Reserved           uint32
	Comm               [16]byte
	Filename           [240]byte
	Argv               [384]byte
	CgroupName         [128]byte
	CgroupParent       [128]byte
}

// BPF map keys and values shared with bpf/emit.bpf.c.
const (
	cfgLocalCgroup  = 0
	cfgMode         = 1
	cfgDefaultScope = 2
)

// bpfRuntime owns the loaded objects and attached links.
type bpfRuntime struct {
	objs   emitObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// loadBPF loads the CO-RE objects, applies the cgroup filter (local mode) or
// the static scope roots (production mode), and attaches the enabled
// tracepoints. It fails closed: any missing capability or verifier rejection
// is a startup error, never partial-silent operation.
func loadBPF(cfg *Config) (*bpfRuntime, error) {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}); err != nil {
		return nil, fmt.Errorf("memlock rlimit: %w", err)
	}
	var objs emitObjects
	if err := loadEmitObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects (needs CAP_BPF/CAP_PERFMON or privileged + kernel BTF): %w", err)
	}
	rt := &bpfRuntime{objs: objs}

	if cfg.Production {
		if err := rt.applyProductionScope(cfg); err != nil {
			objs.Close()
			return nil, err
		}
	} else {
		// Cgroup scope: resolve the configured path to a cgroup id and pin it
		// in the config map. 0 = unfiltered (explicit all_host opt-in).
		cgID := uint64(0)
		if cfg.CgroupPath != "" {
			id, err := cgroupIDFromPath(cfg.CgroupPath)
			if err != nil {
				objs.Close()
				return nil, fmt.Errorf("cgroup_filter %q: %w", cfg.CgroupPath, err)
			}
			cgID = id
		}
		if err := objs.Cfg.Put(uint32(cfgLocalCgroup), cgID); err != nil {
			objs.Close()
			return nil, fmt.Errorf("write cgroup filter: %w", err)
		}
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

// applyProductionScope installs the static agent and sandbox roots before
// any tracepoint is attached, then switches the program to root-based scope.
func (rt *bpfRuntime) applyProductionScope(cfg *Config) error {
	for _, root := range cfg.staticRoots() {
		id, err := cgroupIDFromPath(root.path)
		if err != nil {
			return fmt.Errorf("scope root %q: %w", root.path, err)
		}
		if err := rt.setRoot(id, root.scope); err != nil {
			return err
		}
	}
	defaultScope := uint64(scopeNone)
	if cfg.AllHost {
		defaultScope = scopeAgent
	}
	if err := rt.objs.Cfg.Put(uint32(cfgDefaultScope), defaultScope); err != nil {
		return fmt.Errorf("write default scope: %w", err)
	}
	if err := rt.objs.Cfg.Put(uint32(cfgMode), uint64(1)); err != nil {
		return fmt.Errorf("write production mode: %w", err)
	}
	return nil
}

// setRoot and deleteRoot implement rootTable for the pod scope watcher.
func (rt *bpfRuntime) setRoot(cgroupID uint64, scope uint32) error {
	if err := rt.objs.Roots.Put(cgroupID, scope); err != nil {
		return fmt.Errorf("install scope root: %w", err)
	}
	return nil
}

func (rt *bpfRuntime) deleteRoot(cgroupID uint64) error {
	if err := rt.objs.Roots.Delete(cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove scope root: %w", err)
	}
	return nil
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
		StartBoottime:      r.StartBoottime,
		NsPid:              r.NsPid,
		NsPpid:             r.NsPpid,
		PidNS:              r.PidNS,
		Scope:              r.Scope,
		CgroupNamesRead:    r.CgroupNames != 0,
		CgroupName:         cstr(r.CgroupName[:]),
		CgroupParentName:   cstr(r.CgroupParent[:]),
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

// stop detaches the programs, so nothing new enters the ring, and flushes
// the reader: next returns every record still in the ring, then ErrFlushed.
func (rt *bpfRuntime) stop() error {
	for _, l := range rt.links {
		l.Close()
	}
	rt.links = nil
	return rt.reader.Flush()
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
