// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"net/netip"
	"strconv"
	"strings"
)

// PeerText is the canonical text of a peer address (spec 053 §6.2.3
// fabric.network.host_id, vector peer-address-v1.json): IPv4 dotted decimal;
// an IPv4-mapped IPv6 address (::ffff:0:0/96) as its IPv4 text; any other IPv6
// address in RFC 5952 §4 form. It returns "" for the zero Addr and for an
// address with a zone. The IPv6 text is built here, not by netip, so it never
// depends on a library's formatting of embedded IPv4.
func PeerText(addr netip.Addr) string {
	if !addr.IsValid() || addr.Zone() != "" {
		return ""
	}
	if addr.Is4() || addr.Is4In6() {
		return addr.Unmap().String()
	}
	return rfc5952(addr.As16())
}

// rfc5952 renders 16 bytes as RFC 5952 §4 text: lower-case hex, no leading
// zeros, the longest run of two or more zero groups compressed to "::" (the
// first such run on a tie), a single zero group never compressed.
func rfc5952(b [16]byte) string {
	var groups [8]uint16
	for i := range groups {
		groups[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	bestStart, bestLen := -1, 0
	for i := 0; i < len(groups); {
		if groups[i] != 0 {
			i++
			continue
		}
		j := i
		for j < len(groups) && groups[j] == 0 {
			j++
		}
		if j-i >= 2 && j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	hexOf := func(gs []uint16) string {
		parts := make([]string, len(gs))
		for i, g := range gs {
			parts[i] = strconv.FormatUint(uint64(g), 16)
		}
		return strings.Join(parts, ":")
	}
	if bestStart < 0 {
		return hexOf(groups[:])
	}
	return hexOf(groups[:bestStart]) + "::" + hexOf(groups[bestStart+bestLen:])
}
