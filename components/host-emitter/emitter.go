// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package main implements fabric-host-emitter (spec 031): a passive
// CO-RE eBPF DaemonSet that observes exec/connect/openat inside a configured
// cgroup scope and OTLP-exports them as event_class=audit log records
// (local mode), or as host records on traces through the host-records
// library (production mode, spec 053 §6.2.9, spec 056 §7.3.3 (c)).
//
// The emitter only observes. It attaches no LSM hooks, drops no packets,
// and never blocks the workload — it is read-only by construction.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"golang.org/x/sys/unix"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// Config for the emitter (env-driven; see main.go).
type Config struct {
	// Endpoint is the OTLP/gRPC logs destination — normally the Fabric
	// Node's 4317 receiver.
	Endpoint string
	// BearerTokenFile optionally carries the ingress token for the node's
	// bearertokenauth extension.
	BearerTokenFile string
	// Insecure permits plaintext OTLP only for explicitly configured local
	// development. It is incompatible with bearer-token authentication.
	Insecure    bool
	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string
	// CgroupPath scopes observation to one cgroup (e.g. the agent container's
	// cgroup). Empty with AllHost=false is rejected; the sensor must never
	// silently watch the whole host.
	CgroupPath string
	// AllHost is the explicit opt-in to unfiltered host-wide observation.
	AllHost bool

	Exec       bool
	Connect    bool
	FileAccess bool

	// Spec 057 OD-13 (WP7-11), both off by default (B8). SyscallResults
	// pairs connect, openat and execve with their sys_exit, filling result
	// and errno and recording failed execs (EMIT_SYSCALL_RESULTS);
	// ProcessExit records process exits with exit code or signal
	// (EMIT_EXIT, production mode). WatchedPathsFile names the customer's
	// watched_paths list (EMIT_WATCHED_PATHS_FILE, production mode, file
	// access on): opens of a listed path carry its label, class and keyed id.
	SyscallResults   bool
	ProcessExit      bool
	WatchedPathsFile string
	watch            *hostrecords.WatchTable

	MaxEventsPerSec float64
	DedupeWindow    time.Duration
	SpoolDir        string
	SpoolMaxBytes   int64

	// ClockStepMin is the smallest CLOCK_REALTIME offset change that is a
	// step (EMIT_CLOCK_STEP_MIN); ClockSettle is how long the offset stays
	// stable after a step before the declared uncertainty narrows back
	// (EMIT_CLOCK_SETTLE). See clock.go.
	ClockStepMin time.Duration
	ClockSettle  time.Duration

	// EndpointFile names a file holding one line host:port, an alternative
	// to Endpoint (spec 056 §7.3.3 (c), (n)).
	EndpointFile string

	// Production selects host records as traces (spec 053 §6.2.9); the
	// fields below apply to it only (config_production.go).
	Production         bool
	TenantID           string
	SourceLabel        string
	HostLabel          string
	IDKeyFile          string
	StateKeyFile       string
	StateDir           string
	AgentCgroupRoots   []string
	SandboxCgroupRoots []string
	AgentPodSelector   string
	NodeName           string
	Digests            string
	HeartbeatInterval  time.Duration
	// CgroupRoot is the cgroup v2 mount the pod watcher resolves pod
	// slices under (/sys/fs/cgroup).
	CgroupRoot string

	// endpointSet records whether EMIT_ENDPOINT was given explicitly.
	endpointSet bool
	loadErrs    []error
}

// Validate enforces the safety invariants before any BPF is loaded.
func (c *Config) Validate() error {
	if len(c.loadErrs) != 0 {
		return c.loadErrs[0]
	}
	if c.endpointSet && c.EndpointFile != "" {
		return fmt.Errorf("EMIT_ENDPOINT and EMIT_ENDPOINT_FILE are exclusive; set one")
	}
	if c.Production {
		if err := c.validateProduction(); err != nil {
			return err
		}
	} else if c.Endpoint == "" && c.EndpointFile == "" {
		return fmt.Errorf("endpoint is required")
	}
	if !c.Production && c.CgroupPath == "" && !c.AllHost {
		return fmt.Errorf("cgroup_path or explicit all_host=true is required — refusing to silently watch the entire host")
	}
	if math.IsNaN(c.MaxEventsPerSec) || math.IsInf(c.MaxEventsPerSec, 0) || c.MaxEventsPerSec < 0 {
		return fmt.Errorf("max_events_per_sec must be finite and >= 0")
	}
	if c.DedupeWindow < 0 {
		return fmt.Errorf("dedupe_window must be >= 0")
	}
	if !c.Exec && !c.Connect && !c.FileAccess && !c.ProcessExit {
		return fmt.Errorf("at least one host observation event type must be enabled")
	}
	if c.SyscallResults && !c.Exec && !c.Connect && !c.FileAccess {
		return fmt.Errorf("EMIT_SYSCALL_RESULTS=true pairs execve, connect and openat with their result, but none is enabled: set EMIT_EXEC, EMIT_CONNECT or EMIT_FILE_ACCESS to true, or unset EMIT_SYSCALL_RESULTS")
	}
	if c.ProcessExit && !c.Production {
		return fmt.Errorf("EMIT_EXIT=true needs EMIT_PRODUCTION=true: local audit-class records have no exit class; turn production mode on or leave EMIT_EXIT unset")
	}
	if c.WatchedPathsFile != "" {
		if !c.Production {
			return fmt.Errorf("EMIT_WATCHED_PATHS_FILE needs EMIT_PRODUCTION=true: watched-path labels are host-record keys; turn production mode on or unset it")
		}
		if !c.FileAccess {
			return fmt.Errorf("EMIT_WATCHED_PATHS_FILE labels file opens: set EMIT_FILE_ACCESS=true (scoped to the agent's cgroup), or unset it")
		}
		if c.watch == nil {
			return fmt.Errorf("EMIT_WATCHED_PATHS_FILE was not loaded")
		}
	}
	if !c.Production && (c.SpoolDir == "" || c.SpoolMaxBytes <= 0) {
		return fmt.Errorf("spool_dir and positive spool_max_bytes are required")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("tls_cert_file and tls_key_file must be configured together")
	}
	if c.Insecure && (c.TLSCAFile != "" || c.TLSCertFile != "" || c.TLSKeyFile != "") {
		return fmt.Errorf("insecure transport cannot be combined with TLS files")
	}
	if c.Insecure && c.BearerTokenFile != "" {
		return fmt.Errorf("bearer token cannot be sent over insecure transport")
	}
	return nil
}

// Event type codes shared with bpf/emit.bpf.c.
const (
	evExec    = 1
	evConnect = 2
	evOpenat  = 3
	evExit    = 4 // spec 057 OD-13: a process exit (production mode)
)

// Syscall results shared with bpf/emit.bpf.c (spec 057 OD-13).
const (
	resultUnknown = 0
	resultSuccess = 1
	resultFailed  = 2
)

// event is the platform-neutral event the translator consumes. TsNs is
// kernel monotonic time (bpf_ktime_get_ns) — converted to wall time at
// emit via sensorClock (clock.go).
type event struct {
	Type               uint32
	TsNs               uint64
	Pid                uint32
	Ppid               uint32
	Comm               string
	Filename           string
	Argv               []byte
	ArgvIncomplete     bool
	FilenameIncomplete bool
	Family             uint32
	Port               uint32
	Addr               [16]byte
	CgroupID           uint64

	// Production fields (053 §6.2.3 revisions 3 and 4). StartBoottime is the
	// group leader's start_boottime; NsPid, NsPpid and PidNS are the pids in
	// the process's own pid namespace and that namespace's inode; Scope is the
	// admitting root's scope; the cgroup names are the kernfs names of the
	// event's cgroup and its parent (sandbox-scope events only).
	StartBoottime    uint64
	NsPid            uint32
	NsPpid           uint32
	PidNS            uint32
	Scope            uint32
	CgroupNamesRead  bool
	CgroupName       string
	CgroupParentName string

	// Spec 057 OD-13: the paired syscall's result (result*), its positive
	// errno when failed, and a process exit's code or terminating signal
	// (ExitSignal 0: a normal exit with ExitCode).
	Result     uint32
	Errno      int32
	ExitCode   int32
	ExitSignal uint32
}

// errnoName renders the errnos the auditd receiver names (its errno.go) and
// the rest as numbers, for audit.result (local mode) and Event.Errno (the
// library keeps the closed names and reads any other as "other").
func errnoName(n int32) string {
	switch n {
	case 1:
		return "EPERM"
	case 2:
		return "ENOENT"
	case 5:
		return "EIO"
	case 11:
		return "EAGAIN"
	case 13:
		return "EACCES"
	case 22:
		return "EINVAL"
	case 111:
		return "ECONNREFUSED"
	case 110:
		return "ETIMEDOUT"
	case 113:
		return "EHOSTUNREACH"
	case 101:
		return "ENETUNREACH"
	}
	return strconv.Itoa(int(n))
}

// auditResult is the local audit.result of a paired syscall, as the auditd
// receiver writes it; "" when the outcome was not observed.
func auditResult(e *event) string {
	switch e.Result {
	case resultSuccess:
		return "success"
	case resultFailed:
		return "failed:" + errnoName(e.Errno)
	}
	return ""
}

// monotonicNs is CLOCK_MONOTONIC (bpf_ktime_get_ns's clock) in ns.
func monotonicNs() int64 {
	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return time.Now().UnixNano() // never on Linux; keeps wall time sane
	}
	return mono.Nano()
}

// translate converts one kernel event into the shared audit-class log
// record — the same schema the auditreceiver emits, so downstream consumers
// see one shape regardless of the collection mechanism. argv is hashed here,
// never exported raw.
func translate(e *event) plog.LogRecord {
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(
		time.Unix(0, sensorClock.wallNs(e.TsNs))))
	attrs := lr.Attributes()
	attrs.PutStr("event_class", "audit")
	attrs.PutStr("audit.source", "ebpf")
	attrs.PutInt("process.pid", int64(e.Pid))
	attrs.PutInt("process.parent_pid", int64(e.Ppid))
	if e.Comm != "" {
		attrs.PutStr("process.executable.name", e.Comm)
	}
	switch e.Type {
	case evExec:
		attrs.PutStr("audit.syscall", "execve")
		// sched_process_exec fires post-exec (result success); a failed exec
		// comes from its sys_exit (spec 057 OD-13), and a held execve whose
		// return was never seen carries no result, as connect and openat.
		if r := auditResult(e); r != "" {
			attrs.PutStr("audit.result", r)
		}
		pathIncomplete := e.FilenameIncomplete || len(e.Filename) >= 239
		if e.Filename != "" && !pathIncomplete {
			attrs.PutStr("process.executable.path_sha256", sha256String(e.Filename))
		}
		if pathIncomplete && e.ArgvIncomplete {
			attrs.PutStr("audit.event", "path_and_command_args_incomplete")
		} else if pathIncomplete {
			attrs.PutStr("audit.event", "path_incomplete")
		} else if e.ArgvIncomplete {
			attrs.PutStr("audit.event", "command_args_incomplete")
		}
		if !e.ArgvIncomplete && len(e.Argv) > 0 {
			sum := sha256.Sum256(e.Argv)
			attrs.PutStr("process.command_args_sha256", hex.EncodeToString(sum[:]))
		}
	case evConnect:
		attrs.PutStr("audit.syscall", "connect")
		if r := auditResult(e); r != "" {
			attrs.PutStr("audit.result", r)
		}
		if host := addrString(e.Family, e.Addr); host != "" {
			attrs.PutStr("network.peer.address", host)
			attrs.PutInt("network.peer.port", int64(e.Port))
		}
	case evOpenat:
		attrs.PutStr("audit.syscall", "openat")
		if r := auditResult(e); r != "" {
			attrs.PutStr("audit.result", r)
		}
		if e.FilenameIncomplete || len(e.Filename) >= 239 {
			attrs.PutStr("audit.event", "path_incomplete")
		} else if e.Filename != "" {
			attrs.PutStr("file.path_sha256", sha256String(e.Filename))
		}
	}
	if e.CgroupID != 0 {
		attrs.PutInt("audit.cgroup_id", int64(e.CgroupID))
	}
	return lr
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func addrString(fam uint32, addr [16]byte) string {
	switch fam {
	case 2:
		return net.IP(addr[:4]).String()
	case 10:
		return net.IP(addr[:]).String()
	}
	return ""
}

// dedupeKey identifies an event for window-collapse. A result other than
// unknown is part of it: a refused and an allowed open are never folded.
func dedupeKey(e *event) string {
	raw := fmt.Sprintf("%d|%s|%s|%d|%x", e.Type, e.Comm, e.Filename, e.Port, e.Addr)
	if e.Result != resultUnknown {
		raw += fmt.Sprintf("|%d|%d", e.Result, e.Errno)
	}
	return sha256String(raw)
}
