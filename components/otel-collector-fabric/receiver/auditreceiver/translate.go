// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// eventClass is the log-record class attribute consumed by fabricguard.
const (
	eventClassAttr = "event_class"
	eventClassVal  = "audit"
)

// translate converts an assembled audit event into one log record, or returns
// false when the event carries no syscall the config enabled. Raw argv is
// reduced to a SHA-256 here — collection-side minimization, so secret-bearing
// command lines never leave the host boundary.
func (r *auditReceiver) translate(ev *auditEvent) (plog.LogRecord, string, bool) {
	sys := ev.find(recSyscall)
	if sys == nil {
		return plog.LogRecord{}, "", false
	}
	nr, _ := strconv.Atoi(sys.fields["syscall"])
	name := syscallNames[[2]int{archIndex(sys.fields["arch"]), nr}]
	if name == "" {
		return plog.LogRecord{}, "", false
	}
	class := syscallClass(name)
	if !r.cfg.classEnabled(class) {
		return plog.LogRecord{}, "", false
	}
	if r.cfg.RuleKey != "" && sys.fields["key"] != r.cfg.RuleKey {
		return plog.LogRecord{}, "", false
	}

	rec := plog.NewLogRecord()
	rec.SetTimestamp(pcommon.NewTimestampFromTime(
		timeFromEpoch(ev.sec, ev.msec)))
	attrs := rec.Attributes()
	attrs.PutStr(eventClassAttr, eventClassVal)
	attrs.PutStr("audit.syscall", name)
	attrs.PutStr("audit.source", r.cfg.Source)
	// Audit serials are uint64. A signed OTLP integer would wrap above MaxInt64
	// and break source correlation, so preserve the exact decimal value.
	attrs.PutStr("audit.serial", strconv.FormatUint(ev.serial, 10))

	if s := sys.fields["success"]; s != "" {
		if s == "yes" {
			attrs.PutStr("audit.result", "success")
		} else {
			res := "failed"
			if e := sys.fields["exit"]; e != "" {
				if eno, err := strconv.Atoi(e); err == nil {
					res = "failed:" + errnoName(-eno)
				}
			}
			attrs.PutStr("audit.result", res)
		}
	}
	putInt(attrs, "process.pid", sys.fields["pid"])
	putInt(attrs, "process.parent_pid", sys.fields["ppid"])
	if v := sys.fields["comm"]; v != "" {
		attrs.PutStr("process.executable.name", v)
	}
	if v := sys.fields["exe"]; v != "" {
		sum := sha256.Sum256([]byte(v))
		attrs.PutStr("process.executable.path_sha256", hex.EncodeToString(sum[:]))
	}
	if v := sys.fields["auid"]; v != "" && v != "4294967295" { // unset auid sentinel
		attrs.PutStr("process.owner", v)
	}

	switch class {
	case "exec":
		// Argv evidence: hash only. EXECVE carries a0..aN; PROCTITLE carries
		// the raw cmdline hex. We hash whichever is present and never export
		// the arguments themselves.
		if ex := ev.find(recExecve); ex != nil {
			if hash := argvHash(ex); hash != "" {
				attrs.PutStr("process.command_args_sha256", hash)
			} else {
				attrs.PutStr("audit.event", "command_args_incomplete")
			}
		} else if pt := ev.find(recProctitle); pt != nil {
			if raw, err := decodeProctitle(pt.fields["proctitle"]); err == nil {
				sum := sha256.Sum256(raw)
				attrs.PutStr("process.command_args_sha256", hex.EncodeToString(sum[:]))
			}
		}
	case "connect":
		if sa := ev.find(recSockaddr); sa != nil {
			if host, port, ok := decodeSockaddr(sa.fields["saddr"]); ok {
				attrs.PutStr("network.peer.address", host)
				attrs.PutInt("network.peer.port", int64(port))
			}
		}
	case "file":
		if p := ev.find(recPath); p != nil {
			if fp := p.fields["name"]; fp != "" {
				sum := sha256.Sum256([]byte(fp))
				attrs.PutStr("file.path_sha256", hex.EncodeToString(sum[:]))
			}
		}
	}
	return rec, dedupeKey(name, sys, ev), true
}

// syscallClass buckets a syscall name into a config class.
func syscallClass(name string) string {
	switch name {
	case "execve", "execveat":
		return "exec"
	case "connect", "accept", "bind", "socket":
		return "connect"
	case "openat", "open":
		return "file"
	}
	return ""
}

func (c *Config) classEnabled(class string) bool {
	switch class {
	case "exec":
		return c.Exec
	case "connect":
		return c.Connect
	case "file":
		return c.FileAccess
	}
	return false
}

// argvHash joins a0..aN EXECVE tokens and hashes them. The raw tokens —
// whether quoted strings or hex — are hashed verbatim; decoding is
// unnecessary because the value is evidence, not readability.
func argvHash(ex *auditRecord) string {
	var sb strings.Builder
	argc, err := strconv.Atoi(ex.fields["argc"])
	// Reject malformed or sparse argv inventories before allocating or looping.
	// Audit input is untrusted and may advertise an arbitrarily large argc.
	if err != nil || argc < 0 || argc > len(ex.fields) {
		return ""
	}
	for i := 0; i < argc; i++ {
		if _, ok := ex.fields["a"+strconv.Itoa(i)]; !ok {
			return ""
		}
	}
	for i := 0; i < argc; i++ {
		if i > 0 {
			sb.WriteByte(0)
		}
		sb.WriteString(ex.fields["a"+strconv.Itoa(i)])
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// dedupeKey is a digest of syscall + actor + target. The value is exported in
// collapse summaries, so raw file paths or other target strings must never
// appear in it. Serial and pid are excluded so repeats still fold.
func dedupeKey(name string, sys *auditRecord, ev *auditEvent) string {
	var sb strings.Builder
	sb.WriteString(name)
	sb.WriteByte('|')
	sb.WriteString(sys.fields["exe"])
	sb.WriteByte('|')
	sb.WriteString(sys.fields["comm"])
	sb.WriteByte('|')
	if sa := ev.find(recSockaddr); sa != nil {
		sb.WriteString(sa.fields["saddr"])
	}
	if p := ev.find(recPath); p != nil {
		sb.WriteString(p.fields["name"])
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

func putInt(attrs pcommon.Map, key, s string) {
	if s == "" {
		return
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		attrs.PutInt(key, v)
	}
}

func timeFromEpoch(sec, msec int64) time.Time {
	return time.Unix(sec, msec*int64(time.Millisecond))
}

func pcommonNow() pcommon.Timestamp {
	return pcommon.NewTimestampFromTime(time.Now())
}
