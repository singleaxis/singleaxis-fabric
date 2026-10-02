// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package auditreceiver

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"syscall"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	nlAudit          = 9 // NETLINK_AUDIT
	nlgrpReadlog     = 1 // AUDIT_NLGRP_READLOG — read-only multicast listeners
	auditGet         = 1000
	auditSet         = 1001
	auditAddRule     = 1011
	auditFilterExit  = 4 // always,exit
	auditAlways      = 2
	auditFieldArch   = 4 // AUDIT_ARCH field nr for arch pinning
	auditArchX8664   = 0xC000003E
	auditArchAARCH64 = 0xC00000B7
)

// auditStatus mirrors struct audit_status for AUDIT_GET/SET. Only the fields
// we touch are named; the kernel accepts the fixed-size buffer form.
type auditStatus struct {
	Mask      uint32
	Enabled   uint32
	Failure   uint32
	PID       uint32
	RateLimit uint32
}

// auditRuleData mirrors struct audit_rule_data for AUDIT_ADD_RULE.
const auditRuleFieldsMax = 64

type auditRuleData struct {
	Flags      uint32
	Action     uint32
	FieldCount uint32
	Mask       [auditRuleFieldsMax]uint32
	Fields     [auditRuleFieldsMax]uint32
	Values     [auditRuleFieldsMax]uint32
	FieldFlags [auditRuleFieldsMax]uint32
	Buflen     uint32
}

// auditConn is a bound NETLINK_AUDIT socket joined to the readlog group.
type auditConn struct {
	fd  int
	seq uint32
}

// openAuditNetlink binds the audit netlink socket and joins the multicast
// readlog group so auditd's events fan out to us read-only.
func openAuditNetlink(bufBytes int) (*auditConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, nlAudit)
	if err != nil {
		return nil, fmt.Errorf("audit netlink socket: %w (needs CAP_AUDIT_READ)", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufBytes); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("audit netlink rcvbuf: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("audit netlink bind: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, nlgrpReadlog); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("audit multicast join: %w (needs CAP_AUDIT_READ, kernel >= 3.16)", err)
	}
	return &auditConn{fd: fd}, nil
}

func (c *auditConn) read(buf []byte) (int, error) {
	n, _, flags, _, err := unix.Recvmsg(c.fd, buf, nil, 0)
	if err == nil && flags&unix.MSG_TRUNC != 0 {
		return 0, fmt.Errorf("truncated audit netlink datagram")
	}
	return n, err
}

func (c *auditConn) close() error { return unix.Close(c.fd) }

// marshalNlmsg serializes a netlink message header + payload (nlmsghdr is
// {len u32, type u16, flags u16, seq u32, pid u32} little-endian).
func marshalNlmsg(msgType uint16, payload []byte) []byte {
	buf := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[4:], msgType)
	binary.LittleEndian.PutUint16(buf[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	copy(buf[unix.NLMSG_HDRLEN:], payload)
	return buf
}

// auditReply validates the response envelope before reading any status bytes.
// Unrelated sequence numbers are ignored, never interpreted as acknowledgements.
func auditReply(data []byte, seq uint32, want uint16) ([]byte, bool, error) {
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, false, err
	}
	for _, msg := range msgs {
		if msg.Header.Seq != seq {
			continue
		}
		if msg.Header.Type == unix.NLMSG_ERROR {
			if len(msg.Data) < 4 {
				return nil, false, fmt.Errorf("short audit error")
			}
			code := int32(binary.NativeEndian.Uint32(msg.Data))
			if code != 0 {
				return nil, false, fmt.Errorf("audit request rejected: errno %d", -code)
			}
			if want != unix.NLMSG_ERROR {
				continue
			}
			return msg.Data, true, nil
		}
		if msg.Header.Type != want {
			return nil, false, fmt.Errorf("unexpected audit response type %d", msg.Header.Type)
		}
		return msg.Data, true, nil
	}
	return nil, false, nil
}

func (c *auditConn) requestAudit(msgType uint16, payload []byte, want uint16) ([]byte, error) {
	c.seq++
	buf := marshalNlmsg(msgType, payload)
	binary.NativeEndian.PutUint32(buf[8:12], c.seq)
	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	for attempts := 0; attempts < 8; attempts++ {
		resp := make([]byte, 8192)
		n, _, flags, from, err := unix.Recvmsg(c.fd, resp, nil, 0)
		if err != nil {
			return nil, err
		}
		peer, ok := from.(*unix.SockaddrNetlink)
		if !ok || peer.Pid != 0 {
			return nil, fmt.Errorf("audit response is not from kernel")
		}
		if flags&unix.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("truncated audit response")
		}
		data, matched, err := auditReply(resp[:n], c.seq, want)
		if err != nil {
			return nil, err
		}
		if matched {
			return data, nil
		}
	}
	return nil, fmt.Errorf("audit response limit exceeded")
}

func (c *auditConn) sendAudit(msgType uint16, payload []byte) error {
	_, err := c.requestAudit(msgType, payload, unix.NLMSG_ERROR)
	return err
}

func (c *auditConn) auditControlPID() (uint32, error) {
	data, err := c.requestAudit(auditGet, nil, auditGet)
	if err != nil {
		return 0, err
	}
	if len(data) < 16 {
		return 0, fmt.Errorf("short audit status")
	}
	return binary.NativeEndian.Uint32(data[12:16]), nil
}

// manageRules enables audit and installs always,exit rules for the enabled
// syscall classes, tagged with the configured rule key so the receiver can
// filter to its own events. Skipped when a daemon already holds control.
func (c *auditConn) manageRules(cfg *Config, logger logLike) error {
	// Control requests use a separate socket with no multicast subscription.
	// A finite receive timeout and message limit bound startup under missing ACKs.
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, nlAudit)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		return err
	}
	c = &auditConn{fd: fd}
	arch, nrs, err := ruleSyscalls(cfg, runtime.GOARCH)
	if err != nil {
		return err
	}
	pid, err := c.auditControlPID()
	if err != nil {
		return fmt.Errorf("audit status query: %w", err)
	}
	if pid != 0 {
		logger.Warn("auditd already owns the audit control socket; skipping manage_rules", zap.Uint32("pid", pid))
		return nil
	}
	st := auditStatus{Mask: 1, Enabled: 1} // AUDIT_STATUS_ENABLED
	if err := c.sendAudit(auditSet, marshalStatus(st)); err != nil {
		return fmt.Errorf("enable audit: %w (needs CAP_AUDIT_CONTROL)", err)
	}
	for _, nr := range nrs {
		if err := c.addRule(arch, nr, cfg.RuleKey); err != nil {
			return fmt.Errorf("audit rule syscall=%d: %w", nr, err)
		}
	}
	logger.Info("audit rules installed", zap.Int("count", len(nrs)), zap.String("key", cfg.RuleKey))
	return nil
}

// ruleSyscalls selects only the native supported ABI. Compatibility ABIs are
// intentionally excluded until their translation tables are supported.
func ruleSyscalls(cfg *Config, goarch string) (uint32, []int, error) {
	var arch uint32
	var exec, connect, file []int
	switch goarch {
	case "amd64":
		arch, exec, connect, file = auditArchX8664, []int{59, 322}, []int{42, 43, 49}, []int{257, 2}
	case "arm64":
		arch, exec, connect, file = auditArchAARCH64, []int{221, 281}, []int{203, 202, 200}, []int{56}
	default:
		return 0, nil, fmt.Errorf("audit rule management unsupported architecture %q", goarch)
	}
	var nrs []int
	if cfg.Exec {
		nrs = append(nrs, exec...)
	}
	if cfg.Connect {
		nrs = append(nrs, connect...)
	}
	if cfg.FileAccess {
		nrs = append(nrs, file...)
	}
	return arch, nrs, nil
}

func (c *auditConn) addRule(arch uint32, syscallNr int, key string) error {
	payload, err := syscallRulePayload(arch, syscallNr, key)
	if err != nil {
		return err
	}
	return c.sendAudit(auditAddRule, payload)
}

func syscallRulePayload(arch uint32, syscallNr int, key string) ([]byte, error) {
	if arch != auditArchX8664 && arch != auditArchAARCH64 {
		return nil, fmt.Errorf("unsupported audit architecture %#x", arch)
	}
	if syscallNr < 0 || syscallNr >= 64*32 {
		return nil, fmt.Errorf("invalid audit syscall %d", syscallNr)
	}
	const auditEqual = 0x40000000
	const auditFilterKey = 210
	rule := auditRuleData{Flags: auditFilterExit, Action: auditAlways, FieldCount: 2}
	rule.Mask[syscallNr/32] = 1 << (uint(syscallNr) % 32)
	rule.Fields[0], rule.Values[0], rule.FieldFlags[0] = auditFieldArch, arch, auditEqual
	rule.Fields[1], rule.Values[1], rule.FieldFlags[1] = auditFilterKey, uint32(len(key)), auditEqual
	rule.Buflen = uint32(len(key))
	return append(marshalRule(rule), []byte(key)...), nil
}

func marshalStatus(st auditStatus) []byte {
	b := make([]byte, 48)
	put := func(off int, v uint32) {
		b[off] = byte(v)
		b[off+1] = byte(v >> 8)
		b[off+2] = byte(v >> 16)
		b[off+3] = byte(v >> 24)
	}
	put(0, st.Mask)
	put(4, st.Enabled)
	return b
}

func marshalRule(r auditRuleData) []byte {
	b := make([]byte, 4*4+auditRuleFieldsMax*16)
	put := func(off int, v uint32) {
		b[off] = byte(v)
		b[off+1] = byte(v >> 8)
		b[off+2] = byte(v >> 16)
		b[off+3] = byte(v >> 24)
	}
	put(0, r.Flags)
	put(4, r.Action)
	put(8, r.FieldCount)
	for i := 0; i < auditRuleFieldsMax; i++ {
		put(12+i*4, r.Mask[i])
	}
	for i := 0; i < auditRuleFieldsMax; i++ {
		put(12+256+i*4, r.Fields[i])
		put(12+256+256+i*4, r.Values[i])
		put(12+256+256+256+i*4, r.FieldFlags[i])
	}
	put(12+256*4, r.Buflen)
	return b
}

// decodeAuditNetlink converts framed kernel audit payloads to logfile syntax.
// Audit netlink payloads omit type= and msg=; record type is nlmsg_type.
// Reject an entire malformed datagram rather than accepting a partial prefix.
func decodeAuditNetlink(data []byte) ([]string, error) {
	var lines []string
	for len(data) > 0 {
		if len(data) < unix.NLMSG_HDRLEN {
			return nil, fmt.Errorf("short netlink header")
		}
		size := int(binary.NativeEndian.Uint32(data[:4]))
		typ := binary.NativeEndian.Uint16(data[4:6])
		if size < unix.NLMSG_HDRLEN || size > len(data) {
			return nil, fmt.Errorf("invalid netlink length")
		}
		if typ == unix.NLMSG_ERROR || typ == unix.NLMSG_OVERRUN {
			return nil, fmt.Errorf("audit netlink error or overrun")
		}
		if typ >= 1300 && typ < 1400 {
			payload := strings.TrimRight(string(data[unix.NLMSG_HDRLEN:size]), "\x00")
			if strings.ContainsAny(payload, "\x00\r\n") || !strings.HasPrefix(payload, "audit(") {
				return nil, fmt.Errorf("invalid audit payload")
			}
			lines = append(lines, fmt.Sprintf("type=%d msg=%s", typ, payload))
		}
		aligned := (size + 3) &^ 3
		if size == len(data) {
			break
		}
		if aligned > len(data) {
			return nil, fmt.Errorf("truncated netlink alignment")
		}
		data = data[aligned:]
	}
	return lines, nil
}
