// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// audit record type numbers (linux/audit.h userspace constants).
const (
	recSyscall  = 1300
	recExecve   = 1302
	recCWD      = 1303
	recPath     = 1304
	recProctitle = 1307
	recSockaddr = 1309
	recEOE      = 1320
)

// auditRecord is one parsed `type=NAME msg=audit(sec.msec:serial): k=v ...`
// line. fields preserves raw (unquoted or still-hex) values; decoding is the
// translator's job so the parser stays allocation-light.
type auditRecord struct {
	typ     int
	typName string
	serial  uint64
	sec     int64
	msec    int64
	fields  map[string]string
}

// parseRecord parses one audit text line. Returns nil for lines that are not
// audit data records (headers, junk).
func parseRecord(line string) *auditRecord {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "type=") {
		return nil
	}
	rec := &auditRecord{fields: make(map[string]string, 16)}
	// type=<NAME|num>
	rest := line[len("type="):]
	i := strings.IndexByte(rest, ' ')
	var typTok string
	if i < 0 {
		typTok, rest = rest, ""
	} else {
		typTok, rest = rest[:i], rest[i+1:]
	}
	if n, err := strconv.Atoi(typTok); err == nil {
		rec.typ = n
	} else {
		rec.typName = typTok
		rec.typ = typeNameToNum(typTok)
	}
	// msg=audit(sec.msec:serial):
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "msg=audit(") {
		return nil
	}
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return nil
	}
	hdr := rest[len("msg=audit("):end]
	colon := strings.LastIndexByte(hdr, ':')
	if colon < 0 {
		return nil
	}
	if s, err := strconv.ParseUint(hdr[colon+1:], 10, 64); err == nil {
		rec.serial = s
	}
	if dot := strings.IndexByte(hdr[:colon], '.'); dot >= 0 {
		rec.sec, _ = strconv.ParseInt(hdr[:dot], 10, 64)
		rec.msec, _ = strconv.ParseInt(hdr[dot+1:colon], 10, 64)
	}
	rest = strings.TrimSpace(rest[end+1:])
	rest = strings.TrimPrefix(rest, ":")
	parseFields(rest, rec.fields)
	return rec
}

// parseFields walks `k=v` pairs where v may be bare, "quoted", or hex.
func parseFields(s string, out map[string]string) {
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			return
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return
		}
		key := s[:eq]
		s = s[eq+1:]
		var val string
		if strings.HasPrefix(s, "\"") {
			s = s[1:]
			if j := strings.IndexByte(s, '"'); j >= 0 {
				val, s = s[:j], s[j+1:]
			} else {
				val, s = s, ""
			}
		} else {
			if j := strings.IndexByte(s, ' '); j >= 0 {
				val, s = s[:j], s[j:]
			} else {
				val, s = s, ""
			}
		}
		out[key] = val
	}
}

func typeNameToNum(name string) int {
	switch name {
	case "SYSCALL":
		return recSyscall
	case "EXECVE":
		return recExecve
	case "CWD":
		return recCWD
	case "PATH":
		return recPath
	case "PROCTITLE":
		return recProctitle
	case "SOCKADDR":
		return recSockaddr
	case "EOE":
		return recEOE
	}
	return -1
}

// decodeProctitle decodes the hex-encoded PROCTITLE blob into the raw argv
// bytes (NUL-separated). Only used for hashing — never exported raw.
func decodeProctitle(hexstr string) ([]byte, error) {
	return hex.DecodeString(hexstr)
}

// decodeSockaddr decodes the hex `saddr` field. Supports AF_INET (0200) and
// AF_INET6 (0A00). Returns host, port, ok.
func decodeSockaddr(hexstr string) (string, int, bool) {
	b, err := hex.DecodeString(hexstr)
	if err != nil || len(b) < 4 {
		return "", 0, false
	}
	family := int(b[0]) | int(b[1])<<8
	switch family {
	case 2: // AF_INET
		if len(b) < 8 {
			return "", 0, false
		}
		port := int(b[2])<<8 | int(b[3])
		return fmt.Sprintf("%d.%d.%d.%d", b[4], b[5], b[6], b[7]), port, true
	case 10: // AF_INET6
		if len(b) < 24 {
			return "", 0, false
		}
		port := int(b[2])<<8 | int(b[3])
		var sb strings.Builder
		sb.WriteString("[")
		for i := 8; i < 24; i += 2 {
			if i > 8 {
				sb.WriteString(":")
			}
			fmt.Fprintf(&sb, "%02x%02x", b[i], b[i+1])
		}
		sb.WriteString("]")
		return sb.String(), port, true
	}
	return "", 0, false
}

// syscall names for the classes we emit, keyed by "arch/nr".
var syscallNames = map[[2]int]string{
	// x86_64
	{0, 59}: "execve", {0, 322}: "execveat", {0, 42}: "connect",
	{0, 43}: "accept", {0, 49}: "bind", {0, 41}: "socket",
	{0, 257}: "openat", {0, 2}: "open",
	// arm64 (arch index 1) — audit arch=c00000b7
	{1, 221}: "execve", {1, 281}: "execveat", {1, 203}: "connect",
	{1, 202}: "accept", {1, 200}: "bind", {1, 198}: "socket",
	{1, 56}: "openat",
}

// archIndex maps the audit `arch` hex field to our syscall table index.
func archIndex(arch string) int {
	switch arch {
	case "c00000b7": // arm64
		return 1
	default: // c000003e x86_64 and others default to the x86 table
		return 0
	}
}
