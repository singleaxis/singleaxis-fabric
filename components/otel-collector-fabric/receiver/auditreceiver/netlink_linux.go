// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package auditreceiver

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
	"go.uber.org/zap"
)

const (
	nlAudit        = 9 // NETLINK_AUDIT
	nlgrpReadlog   = 1 // AUDIT_NLGRP_READLOG — read-only multicast listeners
	auditGet       = 1000
	auditSet       = 1001
	auditAddRule   = 1011
	auditFilterExit = 2 // always,exit
	auditAlways    = 1
	auditFieldArch = 4  // AUDIT_ARCH field nr for arch pinning
	auditArchX8664 = 0xC000003E
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
	fd int
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
	n, _, err := unix.Recvfrom(c.fd, buf, 0)
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

// sendAudit sends a netlink request and waits for the kernel ACK.
func (c *auditConn) sendAudit(msgType uint16, payload []byte) error {
	buf := marshalNlmsg(msgType, payload)
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(c.fd, buf, 0, sa); err != nil {
		return err
	}
	// Read ACK — NLMSG_ERROR with error==0 means success.
	resp := make([]byte, 8192)
	n, _, err := unix.Recvfrom(c.fd, resp, 0)
	if err != nil {
		return err
	}
	if n < unix.NLMSG_HDRLEN+4 {
		return fmt.Errorf("short audit ack")
	}
	// nlmsgerr.error is a negative errno int32 at payload offset 0.
	errno := int32(resp[unix.NLMSG_HDRLEN]) | int32(resp[unix.NLMSG_HDRLEN+1])<<8 |
		int32(resp[unix.NLMSG_HDRLEN+2])<<16 | int32(resp[unix.NLMSG_HDRLEN+3])<<24
	if errno != 0 {
		return fmt.Errorf("audit request %d rejected: errno %d", msgType, -errno)
	}
	return nil
}

// auditControlPID returns the PID of the daemon holding the audit control
// socket (0 = none), so manage_rules never fights a live auditd.
func (c *auditConn) auditControlPID() (uint32, error) {
	buf := make([]byte, unix.NLMSG_HDRLEN)
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[4:], auditGet)
	binary.LittleEndian.PutUint16(buf[6:], unix.NLM_F_REQUEST)
	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}
	resp := make([]byte, 8192)
	n, _, err := unix.Recvfrom(c.fd, resp, 0)
	if err != nil {
		return 0, err
	}
	if n < unix.NLMSG_HDRLEN+16 {
		return 0, fmt.Errorf("short audit status")
	}
	// audit_status.pid is at payload offset 12 (mask, enabled, failure, pid).
	p := resp[unix.NLMSG_HDRLEN:]
	pid := uint32(p[12]) | uint32(p[13])<<8 | uint32(p[14])<<16 | uint32(p[15])<<24
	return pid, nil
}

// manageRules enables audit and installs always,exit rules for the enabled
// syscall classes, tagged with the configured rule key so the receiver can
// filter to its own events. Skipped when a daemon already holds control.
func (c *auditConn) manageRules(cfg *Config, logger logLike) error {
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
	var nrs []int
	if cfg.Exec {
		nrs = append(nrs, 59, 221, 322, 281) // execve/execveat both arches
	}
	if cfg.Connect {
		nrs = append(nrs, 42, 203, 43, 202, 49, 200) // connect/accept/bind
	}
	if cfg.FileAccess {
		nrs = append(nrs, 257, 56, 2) // openat/open
	}
	for _, nr := range nrs {
		if err := c.addRule(nr, cfg.RuleKey); err != nil {
			return fmt.Errorf("audit rule syscall=%d: %w", nr, err)
		}
	}
	logger.Info("audit rules installed", zap.Int("count", len(nrs)), zap.String("key", cfg.RuleKey))
	return nil
}

// addRule adds an always,exit syscall rule filtered to the rule key. Both
// arch variants are added defensively; unknown nrs for the running arch are
// simply never hit.
func (c *auditConn) addRule(syscallNr int, key string) error {
	rule := auditRuleData{
		Flags:  auditFilterExit,
		Action: auditAlways,
	}
	if syscallNr >= 0 && syscallNr < 64*32 {
		rule.Mask[syscallNr/32] |= 1 << (uint(syscallNr) % 32)
	}
	// Pin the rule key as an AUDIT_FILTERKEY field so emitted records carry
	// key="fabric". AUDIT_FILTERKEY = 210 (value field carries the string).
	const auditFilterKey = 210
	kb := []byte(key)
	i := rule.FieldCount
	rule.Fields[i] = auditFilterKey
	rule.Values[i] = uint32(len(kb))
	rule.FieldFlags[i] = 0
	rule.FieldCount++
	rule.Buflen = uint32(len(kb))

	payload := marshalRule(rule)
	payload = append(payload, kb...)
	return c.sendAudit(auditAddRule, payload)
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
		put(16+i*4, r.Mask[i])
	}
	for i := 0; i < auditRuleFieldsMax; i++ {
		put(16+256+i*4, r.Fields[i])
		put(16+256+256+i*4, r.Values[i])
		put(16+256+256+256+i*4, r.FieldFlags[i])
	}
	put(16+256*4, r.Buflen)
	return b
}
