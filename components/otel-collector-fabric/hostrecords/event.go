// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Event holds exactly the 053 §6.2.3 values (amended) of one translated host
// event, before keying. Optional values are pointers or empty strings. The
// JSON field names are the Go field names (the replay command's events file).
type Event struct {
	TimeUnixNano   uint64     // wall-clock nanoseconds; start = end of the span
	Class          string     // exec, connect, file
	Syscall        string     // execve, execveat, connect, accept, bind, socket, openat, open
	Result         string     // success, failed, unknown
	Errno          string     // an errno name; kept only when Result is failed; unknown names are "other"
	Pid            int64      // init-namespace tgid, >= 1
	Ppid           *int64     // init-namespace tgid of the real parent
	NsPid          *int64     // eBPF: the group leader's number in its own pid namespace
	NsPpid         *int64     // eBPF: the parent's tgid in the child's namespace, 0 outside it
	PidNS          *uint64    // eBPF: the inode of the namespace NsPid is numbered in
	ProcessStartNs *int64     // eBPF: the group leader's start_boottime, boot-relative ns
	BootTimeS      *int64     // CLOCK_REALTIME - CLOCK_BOOTTIME at sensor start, seconds
	CgroupID       *uint64    // the event's cgroup id
	Scope          string     // eBPF: agent or sandbox
	ContainerID    string     // 64 lowercase hex, from SandboxIDs; keyed as sbx- v2 of container:<id>
	PodUID         string     // lowercase UUID, from SandboxIDs; keyed as sbx- v2 of k8s-pod:<uid>
	PeerFamily     string     // connect only: ipv4, ipv6, unix, other
	Peer           netip.Addr // connect only; keyed as hst- v2 of PeerText, never emitted clear
	PeerPort       *int64     // 0..65535
	AuditSerial    *uint64    // auditd only, exact
	Incomplete     string     // path, args, path_and_args
	ExeSHA256      string     // bare 64 hex (a "sha256:" prefix is removed); only when digests are permitted
	ArgvSHA256     string
	PathSHA256     string
}

var syscallClass = map[string]string{
	"execve": "exec", "execveat": "exec",
	"connect": "connect", "accept": "connect", "bind": "connect", "socket": "connect",
	"openat": "file", "open": "file",
}

// errnoNames is the registry's closed enum (auditreceiver's names) without
// "other".
var errnoNames = map[string]bool{
	"EPERM": true, "ENOENT": true, "EIO": true, "EAGAIN": true, "EACCES": true,
	"EINVAL": true, "ECONNREFUSED": true, "ETIMEDOUT": true, "EHOSTUNREACH": true,
	"ENETUNREACH": true,
}

var (
	errEventTime    = errors.New("hostrecords: event without a timestamp")
	errEventClass   = errors.New("hostrecords: event class not enabled or not exec, connect or file")
	errEventSyscall = errors.New("hostrecords: syscall is not one of the event class")
	errEventResult  = errors.New("hostrecords: result must be success, failed or unknown")
	errEventPid     = errors.New("hostrecords: pid must be at least 1")
)

// check refuses an event whose required values are wrong; nothing of such a
// batch is staged and no position is allocated.
func (e *Event) check(classes map[string]bool) error {
	switch {
	case e.TimeUnixNano == 0:
		return errEventTime
	case !classes[e.Class]:
		return errEventClass
	case syscallClass[e.Syscall] != e.Class:
		return errEventSyscall
	case e.Result != "success" && e.Result != "failed" && e.Result != "unknown":
		return errEventResult
	case e.Pid < 1:
		return errEventPid
	}
	return nil
}

func digest(value string) string {
	value = strings.TrimPrefix(value, "sha256:")
	if hex64.MatchString(value) {
		return value
	}
	return ""
}

func putOptionalInt(m pcommon.Map, key string, v *int64, minimum, maximum int64) {
	if v != nil && *v >= minimum && *v <= maximum {
		m.PutInt(key, *v)
	}
}

func putOptionalUint(m pcommon.Map, key string, v *uint64) {
	if v != nil {
		m.PutStr(key, strconv.FormatUint(*v, 10))
	}
}

func putEnum(m pcommon.Map, key, v string, values ...string) {
	for _, allowed := range values {
		if v == allowed {
			m.PutStr(key, v)
			return
		}
	}
}

const maxInt64 = int64(^uint64(0) >> 1)

// recordAttributes writes the host record's sensor keys (053 §6.2.3) after
// the identity keys. Invalid optional values are omitted, never emitted.
func (s *Source) recordAttributes(m pcommon.Map, e *Event) {
	m.PutStr("fabric.sensor.event_class", e.Class)
	m.PutStr("fabric.sensor.syscall", e.Syscall)
	m.PutStr("fabric.sensor.result", e.Result)
	if e.Result == "failed" && e.Errno != "" {
		if errnoNames[e.Errno] {
			m.PutStr("fabric.sensor.errno", e.Errno)
		} else {
			m.PutStr("fabric.sensor.errno", "other")
		}
	}
	m.PutInt("fabric.sensor.pid", e.Pid)
	putOptionalInt(m, "fabric.sensor.ppid", e.Ppid, 0, maxInt64)
	putOptionalInt(m, "fabric.sensor.ns_pid", e.NsPid, 1, maxInt64)
	putOptionalInt(m, "fabric.sensor.ns_ppid", e.NsPpid, 0, maxInt64)
	putOptionalUint(m, "fabric.sensor.pid_ns", e.PidNS)
	putOptionalInt(m, "fabric.sensor.process_start_ns", e.ProcessStartNs, 0, maxInt64)
	putOptionalInt(m, "fabric.sensor.boot_time_s", e.BootTimeS, 0, maxInt64)
	putOptionalUint(m, "fabric.sensor.cgroup_id", e.CgroupID)
	putEnum(m, "fabric.sensor.scope", e.Scope, "agent", "sandbox")
	if e.Class == "connect" {
		putEnum(m, "fabric.sensor.peer_family", e.PeerFamily, "ipv4", "ipv6", "unix", "other")
	}
	putOptionalInt(m, "fabric.sensor.peer_port", e.PeerPort, 0, 65535)
	if text := PeerText(e.Peer); text != "" {
		if id := V2("hst", text, s.cfg.IDKey); id != "" {
			m.PutStr("fabric.network.host_id", id)
		}
	}
	if hex64.MatchString(e.ContainerID) {
		m.PutStr("fabric.execution.sandbox_id", V2("sbx", "container:"+e.ContainerID, s.cfg.IDKey))
	}
	if lowerUUID.MatchString(e.PodUID) {
		m.PutStr("fabric.sensor.pod_id", V2("sbx", "k8s-pod:"+e.PodUID, s.cfg.IDKey))
	}
	putOptionalUint(m, "fabric.sensor.audit_serial", e.AuditSerial)
	putEnum(m, "fabric.sensor.incomplete", e.Incomplete, "path", "args", "path_and_args")
	if s.cfg.Digests {
		for _, d := range [...]struct{ key, value string }{
			{"fabric.sensor.exe_sha256", e.ExeSHA256},
			{"fabric.sensor.argv_sha256", e.ArgvSHA256},
			{"fabric.sensor.path_sha256", e.PathSHA256},
		} {
			if v := digest(d.value); v != "" {
				m.PutStr(d.key, v)
			}
		}
	}
	m.PutStr("fabric.execution.host_id", s.hostID)
}

// eventError names the event of a refused batch by index, never by value.
func eventError(index int, err error) error {
	return fmt.Errorf("event %d: %w", index, err)
}
