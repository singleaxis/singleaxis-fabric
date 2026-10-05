// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package auditreceiver

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestNativeAuditRules(t *testing.T) {
	cfg := &Config{Exec: true, Connect: true, FileAccess: true}
	for _, tc := range []struct {
		goarch string
		arch   uint32
		nrs    []int
	}{
		{"amd64", auditArchX8664, []int{59, 322, 42, 43, 49, 257, 2}},
		{"arm64", auditArchAARCH64, []int{221, 281, 203, 202, 200, 56}},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			arch, nrs, err := ruleSyscalls(cfg, tc.goarch)
			if err != nil || arch != tc.arch || !reflect.DeepEqual(nrs, tc.nrs) {
				t.Fatalf("rules: %x %v %v", arch, nrs, err)
			}
			for _, nr := range nrs {
				p, err := syscallRulePayload(arch, nr, "fabric")
				if err != nil {
					t.Fatal(err)
				}
				// Linux struct audit_rule_data: three header words, four 64-word
				// arrays, then buflen and the variable string buffer (no padding).
				if len(p) != 1040+6 {
					t.Fatalf("payload length=%d", len(p))
				}
				word := func(off int) uint32 { return binary.LittleEndian.Uint32(p[off:]) }
				if word(0) != 4 || word(4) != 2 || word(8) != 2 || word(12+nr/32*4) != 1<<(uint(nr)%32) {
					t.Fatal("bad count/mask")
				}
				if word(268) != 4 || word(524) != arch || word(780) != 0x40000000 {
					t.Fatal("missing architecture equality filter")
				}
				if word(272) != 210 || word(528) != 6 || word(784) != 0x40000000 || word(1036) != 6 || string(p[1040:]) != "fabric" {
					t.Fatal("bad key filter/layout")
				}
			}
		})
	}
	if _, _, err := ruleSyscalls(cfg, "386"); err == nil {
		t.Fatal("unsupported ABI accepted")
	}
	if _, err := syscallRulePayload(auditArchX8664, 2048, "fabric"); err == nil {
		t.Fatal("invalid syscall accepted")
	}
	if _, err := syscallRulePayload(0, 59, "fabric"); err == nil {
		t.Fatal("unknown arch accepted")
	}
}

func TestUnknownAuditABIIsNotX86(t *testing.T) {
	for _, arch := range []string{"", "40000003", "40000028", "bogus"} {
		if _, ok := syscallNames[[2]int{archIndex(arch), 59}]; ok {
			t.Fatalf("unknown arch %q interpreted as x86_64", arch)
		}
	}
}

func TestDecodeAuditNetlink(t *testing.T) {
	frame := func(typ uint16, payload string) []byte {
		size := 16 + len(payload)
		b := make([]byte, (size+3)&^3)
		binary.NativeEndian.PutUint32(b, uint32(size))
		binary.NativeEndian.PutUint16(b[4:], typ)
		copy(b[16:], payload)
		return b
	}
	first := frame(1300, "audit(1700000000.123:42): arch=c000003e syscall=59 key=\"fabric\"\x00")
	second := frame(1320, "audit(1700000000.123:42):")
	lines, err := decodeAuditNetlink(append(first, second...))
	if err != nil || len(lines) != 2 {
		t.Fatalf("decode: %v %v", lines, err)
	}
	for _, line := range lines {
		if rec := parseRecord(line); rec == nil || rec.serial != 42 {
			t.Fatalf("unparseable record %q", line)
		}
	}
	badLength := append([]byte(nil), first...)
	binary.NativeEndian.PutUint32(badLength, uint32(len(badLength)+100))
	for _, bad := range [][]byte{first[:10], badLength, frame(2, "error"), frame(4, "overrun"), frame(1300, "audit(1.1:1):\nforged"), append(first, 1)} {
		if got, err := decodeAuditNetlink(bad); err == nil || got != nil {
			t.Fatalf("accepted malformed datagram: %v %v", got, err)
		}
	}
}

func TestAuditControlReplyDemultiplexing(t *testing.T) {
	frame := func(typ uint16, seq uint32, payload []byte) []byte {
		b := marshalNlmsg(typ, payload)
		binary.NativeEndian.PutUint32(b[8:], seq)
		return b
	}
	ack := frame(2, 7, make([]byte, 4))
	if _, ok, err := auditReply(ack, 7, 2); err != nil || !ok {
		t.Fatalf("valid ack: %v %v", ok, err)
	}
	if _, ok, err := auditReply(ack, 8, 2); err != nil || ok {
		t.Fatal("unrelated sequence accepted")
	}
	if _, ok, err := auditReply(ack, 7, auditGet); err != nil || ok {
		t.Fatal("ACK treated as status")
	}
	if _, _, err := auditReply(frame(1300, 7, make([]byte, 4)), 7, 2); err == nil {
		t.Fatal("audit event treated as ACK")
	}
	if _, _, err := auditReply(frame(2, 7, []byte{1}), 7, 2); err == nil {
		t.Fatal("short error accepted")
	}
	negative := make([]byte, 4)
	binary.NativeEndian.PutUint32(negative, ^uint32(0))
	if _, _, err := auditReply(frame(2, 7, negative), 7, 2); err == nil {
		t.Fatal("kernel error accepted")
	}
	status := make([]byte, 16)
	binary.NativeEndian.PutUint32(status[12:], 1234)
	got, ok, err := auditReply(frame(auditGet, 7, status), 7, auditGet)
	if err != nil || !ok || binary.NativeEndian.Uint32(got[12:]) != 1234 {
		t.Fatal("status not returned")
	}
}
