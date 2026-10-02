// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"fmt"
	"math"
	"path/filepath"
	"time"

	"go.opentelemetry.io/collector/component"
)

// Config for the auditd host connector receiver.
type Config struct {
	// Source is "netlink" (audit multicast, CAP_AUDIT_READ) or "logfile"
	// (tail the audit.log path). Default netlink.
	Source string `mapstructure:"source"`
	// LogPath is the audit log file when source=logfile.
	LogPath string `mapstructure:"log_path"`
	// StateDirectory is a dedicated persistent local directory, required for logfile.
	StateDirectory string `mapstructure:"state_directory"`
	// These bounds include one replay batch; no unbounded in-memory retry queue is used.
	MaxStateBytes   int64 `mapstructure:"max_state_bytes"`
	MaxBatchBytes   int   `mapstructure:"max_batch_bytes"`
	MaxRecordBytes  int   `mapstructure:"max_record_bytes"`
	MaxBatchRecords int   `mapstructure:"max_batch_records"`

	// Syscall classes to emit. exec/connect default on; file_access is high
	// volume and defaults off.
	Exec       bool `mapstructure:"exec"`
	Connect    bool `mapstructure:"connect"`
	FileAccess bool `mapstructure:"file_access"`

	// ManageRules lets the receiver enable audit and install its own rules
	// via the control socket when no auditd daemon holds it
	// (CAP_AUDIT_CONTROL). First writer wins; never overrides a live daemon.
	ManageRules bool `mapstructure:"manage_rules"`
	// RuleKey filters events to those carrying this audit rule key (the -k
	// tag). Rules installed by ManageRules carry it automatically; an empty
	// value consumes every audit event (use with care on busy hosts).
	RuleKey string `mapstructure:"rule_key"`

	// MaxEventsPerSec drops/counts excess netlink events; logfile mode paces
	// whole accepted batches instead. Zero means unlimited.
	MaxEventsPerSec float64 `mapstructure:"max_events_per_sec"`
	// DedupeWindow collapses netlink repeats. Durable logfile mode preserves
	// separate records and ignores this window; deduplication uses stable IDs.
	DedupeWindow time.Duration `mapstructure:"dedupe_window"`
	// AssemblyTimeout is how long a serial-grouped event waits for its
	// trailing records (EOE) before being flushed incomplete.
	AssemblyTimeout time.Duration `mapstructure:"assembly_timeout"`
	// HashFilePaths must remain true when file_access is enabled. Paths can
	// contain sensitive names and are never emitted raw.
	HashFilePaths bool `mapstructure:"hash_file_paths"`
	// ReadBufferBytes sizes the netlink buffer. Durable logfile uses bounded 4 KiB reads.
	ReadBufferBytes int `mapstructure:"read_buffer_bytes"`
}

func createDefaultConfig() component.Config {
	return &Config{
		Source:          "netlink",
		MaxStateBytes:   16 << 20,
		MaxBatchBytes:   4 << 20,
		MaxRecordBytes:  1 << 20,
		MaxBatchRecords: 4096,
		LogPath:         "/var/log/audit/audit.log",
		Exec:            true,
		Connect:         true,
		FileAccess:      false,
		RuleKey:         "fabric",
		MaxEventsPerSec: 200,
		DedupeWindow:    time.Second,
		AssemblyTimeout: 500 * time.Millisecond,
		HashFilePaths:   true,
		ReadBufferBytes: 1 << 20,
	}
}

// Validate checks the configuration is coherent before Start.
func (c *Config) Validate() error {
	switch c.Source {
	case "netlink":
	case "logfile":
		if !filepath.IsAbs(c.StateDirectory) {
			return fmt.Errorf("audit receiver: absolute state_directory is required when source=logfile; migrate to a dedicated persistent volume")
		}
		if c.MaxRecordBytes < 4096 || c.MaxRecordBytes > 16<<20 || c.MaxBatchBytes < c.MaxRecordBytes || c.MaxBatchBytes > 64<<20 || c.MaxBatchRecords < 1 || c.MaxBatchRecords > 65536 || c.MaxStateBytes < int64(c.MaxBatchBytes)*2 || c.MaxStateBytes > 256<<20 {
			return fmt.Errorf("audit receiver: invalid durable logfile bounds (record 4 KiB–16 MiB, batch >= record and <=64 MiB, state >=2*batch and <=256 MiB, records 1–65536)")
		}
		if c.LogPath == "" {
			return fmt.Errorf("audit receiver: log_path is required when source=logfile")
		}
	default:
		return fmt.Errorf("audit receiver: source must be netlink or logfile, got %q", c.Source)
	}
	if c.MaxEventsPerSec < 0 || math.IsNaN(c.MaxEventsPerSec) || math.IsInf(c.MaxEventsPerSec, 0) {
		return fmt.Errorf("audit receiver: max_events_per_sec must be >= 0")
	}
	if c.FileAccess && !c.HashFilePaths {
		return fmt.Errorf("audit receiver: hash_file_paths must be true when file_access is enabled")
	}
	if c.DedupeWindow < 0 {
		return fmt.Errorf("audit receiver: dedupe_window must be >= 0")
	}
	if c.AssemblyTimeout <= 0 {
		return fmt.Errorf("audit receiver: assembly_timeout must be > 0")
	}
	if c.ReadBufferBytes < 4096 {
		return fmt.Errorf("audit receiver: read_buffer_bytes must be >= 4096")
	}
	return nil
}
