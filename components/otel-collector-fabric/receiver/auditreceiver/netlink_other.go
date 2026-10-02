// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package auditreceiver

import "fmt"

// auditConn is unavailable off Linux; the stub keeps the package portable so
// `go build`/`go test` work on developer machines.
type auditConn struct{}

func openAuditNetlink(bufBytes int) (*auditConn, error) {
	return nil, fmt.Errorf("audit netlink source requires Linux (NETLINK_AUDIT)")
}

func (c *auditConn) read(buf []byte) (int, error) { return 0, fmt.Errorf("unsupported") }
func (c *auditConn) close() error                 { return nil }
func (c *auditConn) manageRules(cfg *Config, logger logLike) error {
	return fmt.Errorf("manage_rules requires Linux (CAP_AUDIT_CONTROL)")
}

func decodeAuditNetlink([]byte) ([]string, error) {
	return nil, fmt.Errorf("audit netlink requires Linux")
}
