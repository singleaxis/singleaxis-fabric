// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package main implements fabric-host-emitter (spec 031): a passive
// CO-RE eBPF DaemonSet that observes exec/connect/openat inside a configured
// cgroup scope and OTLP-exports them as event_class=audit log records.
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
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"golang.org/x/sys/unix"
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

	MaxEventsPerSec float64
	DedupeWindow    time.Duration
	SpoolDir        string
	SpoolMaxBytes   int64
}

// Validate enforces the safety invariants before any BPF is loaded.
func (c *Config) Validate() error {
	if c.Endpoint == "" {
		return fmt.Errorf("endpoint is required")
	}
	if c.CgroupPath == "" && !c.AllHost {
		return fmt.Errorf("cgroup_path or explicit all_host=true is required — refusing to silently watch the entire host")
	}
	if math.IsNaN(c.MaxEventsPerSec) || math.IsInf(c.MaxEventsPerSec, 0) || c.MaxEventsPerSec < 0 {
		return fmt.Errorf("max_events_per_sec must be finite and >= 0")
	}
	if c.DedupeWindow < 0 {
		return fmt.Errorf("dedupe_window must be >= 0")
	}
	if !c.Exec && !c.Connect && !c.FileAccess {
		return fmt.Errorf("at least one host observation event type must be enabled")
	}
	if c.SpoolDir == "" || c.SpoolMaxBytes <= 0 {
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
)

// event is the platform-neutral event the translator consumes. TsNs is
// kernel monotonic time (bpf_ktime_get_ns) — converted to wall time at
// emit via bootEpochOffset.
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
}

// bootEpochOffsetNs converts kernel monotonic ns to wall-clock ns. Computed
// once at startup: offset = wallNow - monoNow. Without it every record would
// be stamped near 1970 (boot-relative), destroying time correlation.
var bootEpochOffsetNs int64

func init() {
	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err == nil {
		bootEpochOffsetNs = time.Now().UnixNano() - mono.Nano()
	}
}

// translate converts one kernel event into the shared audit-class log
// record — the same schema the auditreceiver emits, so downstream consumers
// see one shape regardless of the collection mechanism. argv is hashed here,
// never exported raw.
func translate(e *event) plog.LogRecord {
	lr := plog.NewLogRecord()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(
		time.Unix(0, bootEpochOffsetNs+int64(e.TsNs))))
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
		attrs.PutStr("audit.result", "success") // sched_process_exec fires post-exec
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
		if host := addrString(e.Family, e.Addr); host != "" {
			attrs.PutStr("network.peer.address", host)
			attrs.PutInt("network.peer.port", int64(e.Port))
		}
	case evOpenat:
		attrs.PutStr("audit.syscall", "openat")
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

// dedupeKey identifies an event for window-collapse.
func dedupeKey(e *event) string {
	raw := fmt.Sprintf("%d|%s|%s|%d|%x", e.Type, e.Comm, e.Filename, e.Port, e.Addr)
	return sha256String(raw)
}
