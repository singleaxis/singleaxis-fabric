// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strconv"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

// hostOutcome is what became of one assembled audit event in production mode.
type hostOutcome int

const (
	hostRecord hostOutcome = iota
	// hostFiltered: the configuration excludes the event (class, ABI, key).
	hostFiltered
	// hostUnmatched: records without their SYSCALL record (an event split by a
	// batch or time bound); the event itself was already counted.
	hostUnmatched
	// hostUntranslatable: an observed event that cannot become a valid host
	// record (no timestamp or pid). It gets no position and is upstream loss.
	hostUntranslatable
)

// hostEvent translates an assembled audit event into the library's event
// (053 §6.2.3). Only values the host record schema names leave this function:
// the executable name, owner, raw peer address, argv and paths never do; the
// peer address is handed to the library, which keys it, and digests are
// computed only under digests: permitted.
func (r *auditReceiver) hostEvent(ev *auditEvent) (hostrecords.Event, hostOutcome) {
	if ev.find(recSyscall) == nil {
		return hostrecords.Event{}, hostUnmatched
	}
	sys, name, class, ok := r.selectEvent(ev)
	if !ok {
		return hostrecords.Event{}, hostFiltered
	}
	at := timeFromEpoch(ev.sec, ev.msec).UnixNano()
	pid, err := strconv.ParseInt(sys.fields["pid"], 10, 64)
	if at <= 0 || err != nil || pid < 1 {
		return hostrecords.Event{}, hostUntranslatable
	}
	serial := ev.serial
	out := hostrecords.Event{
		TimeUnixNano: uint64(at),
		Class:        class,
		Syscall:      name,
		Result:       "unknown",
		Pid:          pid,
		AuditSerial:  &serial,
	}
	if ppid, err := strconv.ParseInt(sys.fields["ppid"], 10, 64); err == nil && ppid >= 0 {
		out.Ppid = &ppid
	}
	switch sys.fields["success"] {
	case "yes":
		out.Result = "success"
	case "no":
		out.Result = "failed"
		if eno, err := strconv.Atoi(sys.fields["exit"]); err == nil {
			// errnoName renders names outside the closed enum as numbers; the
			// library maps every other value to "other".
			out.Errno = errnoName(-eno)
		}
	}
	digests := r.cfg.Production.Digests == "permitted"
	exe := sys.fields["exe"]
	if digests && exe != "" {
		out.ExeSHA256 = sha256Hex(exe)
	}
	var pathMissing, argsMissing bool
	switch class {
	case "exec":
		pathMissing = exe == ""
		argv := ""
		if ex := ev.find(recExecve); ex != nil {
			argv = argvHash(ex)
		} else if pt := ev.find(recProctitle); pt != nil {
			if raw, err := decodeProctitle(pt.fields["proctitle"]); err == nil {
				sum := sha256.Sum256(raw)
				argv = hex.EncodeToString(sum[:])
			}
		}
		argsMissing = argv == ""
		if digests {
			out.ArgvSHA256 = argv
		}
	case "connect":
		// Only connect and accept carry a peer; bind's address is local and
		// socket has none.
		if name == "connect" || name == "accept" {
			if sa := ev.find(recSockaddr); sa != nil {
				out.PeerFamily, out.Peer, out.PeerPort = decodePeer(sa.fields["saddr"])
			}
		}
	case "file":
		fp := ""
		if p := ev.find(recPath); p != nil {
			fp = p.fields["name"]
		}
		pathMissing = fp == ""
		if digests && fp != "" {
			out.PathSHA256 = sha256Hex(fp)
		}
	}
	switch {
	case pathMissing && argsMissing:
		out.Incomplete = "path_and_args"
	case pathMissing:
		out.Incomplete = "path"
	case argsMissing:
		out.Incomplete = "args"
	}
	return out, hostRecord
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// decodePeer reads the family, address and port of a SOCKADDR saddr value.
// An address the receiver cannot read gives family "other" without address.
func decodePeer(hexstr string) (string, netip.Addr, *int64) {
	b, err := hex.DecodeString(hexstr)
	if err != nil || len(b) < 2 {
		return "", netip.Addr{}, nil
	}
	port := func() *int64 { p := int64(b[2])<<8 | int64(b[3]); return &p }
	switch int(b[0]) | int(b[1])<<8 {
	case 1: // AF_UNIX
		return "unix", netip.Addr{}, nil
	case 2: // AF_INET
		if len(b) < 8 {
			return "ipv4", netip.Addr{}, nil
		}
		return "ipv4", netip.AddrFrom4([4]byte(b[4:8])), port()
	case 10: // AF_INET6
		if len(b) < 24 {
			return "ipv6", netip.Addr{}, nil
		}
		return "ipv6", netip.AddrFrom16([16]byte(b[8:24])), port()
	}
	return "other", netip.Addr{}, nil
}
