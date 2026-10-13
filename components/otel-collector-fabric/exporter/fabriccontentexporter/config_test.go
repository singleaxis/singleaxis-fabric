// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/xconfmap"
)

func unmarshal(t *testing.T, raw map[string]any) (*Config, error) {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	if err := confmap.NewFromStringMap(raw).Unmarshal(cfg); err != nil {
		return nil, err
	}
	return cfg, xconfmap.Validate(cfg)
}

// The defaults are the durable recommendation: bounded request queue with
// backpressure, retry forever, no batching of 64 MiB bodies.
func TestDefaultConfigIsDurable(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	if !cfg.QueueConfig.HasValue() {
		t.Fatal("sending_queue disabled by default")
	}
	q := cfg.QueueConfig.Get()
	if !q.BlockOnOverflow || q.QueueSize != 64 || q.NumConsumers != 4 || q.Batch.HasValue() {
		t.Errorf("queue defaults = %+v", *q)
	}
	if !cfg.RetryConfig.Enabled || cfg.RetryConfig.MaxElapsedTime != 0 {
		t.Errorf("retry defaults = %+v", cfg.RetryConfig)
	}
	if cfg.TimeoutConfig.Timeout != 60*time.Second || cfg.S3.Prefix != "fabric/content/" {
		t.Errorf("timeout/prefix defaults = %v / %q", cfg.TimeoutConfig.Timeout, cfg.S3.Prefix)
	}
}

// The shipped content queue configuration unmarshals into a persistent,
// blocking queue and unbounded retry.
func TestQueueDurabilityConfig(t *testing.T) {
	cfg, err := unmarshal(t, map[string]any{
		"allowed_tenants": []any{"tenant-a"},
		"backend":         "file",
		"file":            map[string]any{"directory": "/var/lib/fabric-node/content"},
		"timeout":         "120s",
		"sending_queue": map[string]any{
			"enabled":           true,
			"storage":           "file_storage/fabric_content",
			"block_on_overflow": true,
			"queue_size":        32,
			"num_consumers":     2,
		},
		"retry_on_failure": map[string]any{"enabled": true, "max_elapsed_time": "0s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	q := cfg.QueueConfig.Get()
	if q.StorageID == nil || q.StorageID.String() != "file_storage/fabric_content" {
		t.Fatalf("storage = %v", q.StorageID)
	}
	if !q.BlockOnOverflow || q.QueueSize != 32 || q.NumConsumers != 2 {
		t.Errorf("queue = %+v", *q)
	}
	if cfg.RetryConfig.MaxElapsedTime != 0 || !cfg.RetryConfig.Enabled {
		t.Errorf("retry = %+v", cfg.RetryConfig)
	}
	if cfg.TimeoutConfig.Timeout != 120*time.Second {
		t.Errorf("timeout = %v", cfg.TimeoutConfig.Timeout)
	}
}

func TestConfigValidation(t *testing.T) {
	file := func() map[string]any {
		return map[string]any{
			"allowed_tenants": []any{"tenant-a"},
			"backend":         "file",
			"file":            map[string]any{"directory": "/var/lib/fabric-node/content"},
		}
	}
	s3 := func(extra map[string]any) map[string]any {
		m := map[string]any{"bucket": "customer-evidence"}
		for k, v := range extra {
			m[k] = v
		}
		return map[string]any{"allowed_tenants": []any{"tenant-a"}, "backend": "s3", "s3": m}
	}
	with := func(m map[string]any, k string, v any) map[string]any { m[k] = v; return m }
	valid := map[string]map[string]any{
		"file":           file(),
		"s3 minimal":     s3(nil),
		"s3 minio":       s3(map[string]any{"endpoint": "http://minio:9000", "use_path_style": true, "sse": "AES256", "region": "us-east-1"}),
		"s3 kms":         s3(map[string]any{"sse": "aws:kms", "kms_key_id": "alias/fabric"}),
		"s3 kms default": s3(map[string]any{"sse": "aws:kms"}),
		"s3 prefix":      s3(map[string]any{"prefix": "a/b/"}),
		"two tenants":    with(file(), "allowed_tenants", []any{"tenant-a", "t.b_c-1"}),
	}
	for name, raw := range valid {
		t.Run("valid/"+name, func(t *testing.T) {
			if _, err := unmarshal(t, raw); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	invalid := map[string]map[string]any{
		"no tenants":          with(file(), "allowed_tenants", []any{}),
		"bad tenant":          with(file(), "allowed_tenants", []any{"../etc"}),
		"no backend":          with(file(), "backend", ""),
		"unknown backend":     with(file(), "backend", "gcs"),
		"relative dir":        with(file(), "file", map[string]any{"directory": "content"}),
		"trailing slash":      with(file(), "file", map[string]any{"directory": "/var/lib/content/"}),
		"unclean dir":         with(file(), "file", map[string]any{"directory": "/var/lib/../content"}),
		"root dir":            with(file(), "file", map[string]any{"directory": "/"}),
		"no dir":              with(file(), "file", map[string]any{}),
		"no bucket":           s3(map[string]any{"bucket": ""}),
		"bad bucket":          s3(map[string]any{"bucket": "Bad_Bucket"}),
		"prefix no slash":     s3(map[string]any{"prefix": "fabric"}),
		"prefix leading":      s3(map[string]any{"prefix": "/fabric/"}),
		"prefix dotdot":       s3(map[string]any{"prefix": "a/../b/"}),
		"prefix empty seg":    s3(map[string]any{"prefix": "a//"}),
		"prefix empty":        s3(map[string]any{"prefix": ""}),
		"endpoint userinfo":   s3(map[string]any{"endpoint": "https://user:secret@minio:9000"}),
		"endpoint query":      s3(map[string]any{"endpoint": "https://minio:9000?x=secret"}),
		"endpoint fragment":   s3(map[string]any{"endpoint": "https://minio:9000#secret"}),
		"endpoint path":       s3(map[string]any{"endpoint": "https://minio:9000/bucket"}),
		"endpoint scheme":     s3(map[string]any{"endpoint": "ftp://minio"}),
		"endpoint no host":    s3(map[string]any{"endpoint": "https://"}),
		"bad sse":             s3(map[string]any{"sse": "aws:kms:dsse"}),
		"kms without aws:kms": s3(map[string]any{"sse": "AES256", "kms_key_id": "alias/x"}),
		"kms without sse":     s3(map[string]any{"kms_key_id": "alias/x"}),
	}
	for name, raw := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			_, err := unmarshal(t, raw)
			if err == nil {
				t.Fatal("accepted")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("validation error echoes a secret: %v", err)
			}
		})
	}
}
