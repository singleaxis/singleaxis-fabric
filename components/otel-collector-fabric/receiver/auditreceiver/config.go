// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
)

// Config for the auditd host connector receiver.
type Config struct {
	// Mode is "local" (default: audit-class log records, unchanged) or
	// "production" (host records as traces through the host-records library,
	// spec 053 §6.2.8). Production runs only in a customer-deployed sensor
	// collector, never in the Node.
	Mode string `mapstructure:"mode"`
	// Production holds the production-mode source settings (spec 056
	// §7.3.3 (d)); every value is refused in local mode.
	Production ProductionConfig `mapstructure:"production"`

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

// ProductionConfig is the `production:` block of the receiver (spec 056
// §7.3.3 (d)). Key and state files are read at Start, never logged.
type ProductionConfig struct {
	TenantID string `mapstructure:"tenant_id"`
	// SourceLabel is the clear source label (default form <node>/auditd); the
	// source id is its s- label pseudonym under the id key.
	SourceLabel string `mapstructure:"source_label"`
	// HostLabel is the agents' FABRIC_HOST_LABEL value on this host.
	HostLabel string `mapstructure:"host_label"`
	// IDKeyFile holds the agents' FABRIC_WIRE_ID_KEY exactly
	// (hostrecords.ReadIDKeyFile, id-key-file-v1).
	IDKeyFile string `mapstructure:"id_key_file"`
	// StateKeyFile holds the 32-byte AES-256 key that seals the staging,
	// epoch state and logfile cursor.
	StateKeyFile string `mapstructure:"state_key_file"`
	// StateDir is a dedicated 0700 directory owned by the sensor.
	StateDir string `mapstructure:"state_dir"`
	// Digests is the sensor policy for executable, argv and path digests:
	// "omitted" (default) or "permitted". The group's fabricguard instance
	// must also permit them (053 §6.2.5).
	Digests           string        `mapstructure:"digests"`
	HeartbeatInterval time.Duration `mapstructure:"heartbeat_interval"`
	// WatchedPathsFile is the customer's watched_paths list (spec 057 §4.3,
	// WP7-11 auditd parity): a JSON list, or a deployment policy in JSON
	// whose security_context holds it, read once at Start. A file record of
	// a listed path carries the entry's label, class and keyed pth- id; the
	// path never leaves the receiver. Needs file_access.
	WatchedPathsFile string `mapstructure:"watched_paths_file"`
}

const (
	modeLocal      = "local"
	modeProduction = "production"
)

func createDefaultConfig() component.Config {
	return &Config{
		Mode:            modeLocal,
		Production:      ProductionConfig{Digests: "omitted", HeartbeatInterval: 10 * time.Second},
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
	production := c.Mode == modeProduction
	switch c.Mode {
	case modeLocal, "":
		if err := c.Production.validateUnset(); err != nil {
			return err
		}
	case modeProduction:
		if err := c.Production.validate(); err != nil {
			return err
		}
		if c.StateDirectory != "" {
			return fmt.Errorf("audit receiver: state_directory is the local-mode state; production keeps its state in production.state_dir")
		}
		if c.Production.WatchedPathsFile != "" {
			if !filepath.IsAbs(c.Production.WatchedPathsFile) || filepath.Clean(c.Production.WatchedPathsFile) != c.Production.WatchedPathsFile {
				return fmt.Errorf("audit receiver: production.watched_paths_file must be an absolute, clean path")
			}
			if !c.FileAccess {
				return fmt.Errorf("audit receiver: production.watched_paths_file labels file opens: set file_access: true (with audit rules scoped to the agent), or remove production.watched_paths_file")
			}
		}
	default:
		return fmt.Errorf("audit receiver: mode must be local or production, got %q", c.Mode)
	}
	switch c.Source {
	case "netlink":
	case "logfile":
		if !production && !filepath.IsAbs(c.StateDirectory) {
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

// validateUnset refuses production settings outside production mode, so a
// configuration never looks like a production source while it is not one.
func (p *ProductionConfig) validateUnset() error {
	if p.TenantID != "" || p.SourceLabel != "" || p.HostLabel != "" || p.IDKeyFile != "" || p.StateKeyFile != "" || p.StateDir != "" || p.WatchedPathsFile != "" || (p.Digests != "" && p.Digests != "omitted") {
		return fmt.Errorf("audit receiver: production settings require mode: production")
	}
	return nil
}

func (p *ProductionConfig) validate() error {
	for _, v := range []struct{ name, value string }{
		{"tenant_id", p.TenantID}, {"source_label", p.SourceLabel}, {"host_label", p.HostLabel},
	} {
		if v.value == "" || strings.TrimSpace(v.value) != v.value || len(v.value) > 256 {
			return fmt.Errorf("audit receiver: production.%s is required (non-empty, no surrounding space, at most 256 bytes)", v.name)
		}
	}
	for _, v := range []struct{ name, value string }{
		{"id_key_file", p.IDKeyFile}, {"state_key_file", p.StateKeyFile}, {"state_dir", p.StateDir},
	} {
		if !filepath.IsAbs(v.value) || filepath.Clean(v.value) != v.value {
			return fmt.Errorf("audit receiver: production.%s must be an absolute, clean path", v.name)
		}
	}
	if p.Digests != "omitted" && p.Digests != "permitted" {
		return fmt.Errorf("audit receiver: production.digests must be omitted or permitted, got %q", p.Digests)
	}
	if p.HeartbeatInterval < time.Second || p.HeartbeatInterval > time.Minute {
		return fmt.Errorf("audit receiver: production.heartbeat_interval must be between 1s and 60s")
	}
	return nil
}
