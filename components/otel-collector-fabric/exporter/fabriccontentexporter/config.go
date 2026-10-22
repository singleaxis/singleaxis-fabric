// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
)

const (
	backendFile = "file"
	backendS3   = "s3"

	defaultS3Prefix = "fabric/content/"
)

var (
	tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// FileConfig selects the directory backend.
type FileConfig struct {
	// Directory is the absolute content root; objects are written below
	// <directory>/<tenant>/evidence/.
	Directory string `mapstructure:"directory"`
	// DurableBoundary optionally names the content root or one of its
	// ancestors as a provisioned durable boundary: the operator vouches that
	// its own directory entry and every entry above it are durable (as for
	// a mount point). The exporter then fsyncs it and the directories below
	// it, never above. Needed only when an ancestor of the root cannot be
	// fsync'd by the Node (EACCES/EPERM/EROFS) and no earlier walk was
	// recorded; a root that is (or sits directly in) a volume mount point
	// needs none.
	DurableBoundary string `mapstructure:"durable_boundary"`
	// EncryptionKeyFile names the Node-side customer key (spec 049 §7.8): a
	// mounted Secret holding 32 raw bytes or their base64. When set, every
	// object and descriptor is written in the AES-256-GCM envelope; the key is
	// never a configuration literal. Required in the production profile.
	EncryptionKeyFile string `mapstructure:"encryption_key_file"`
}

// S3Config selects the S3 (or S3-compatible) backend. Credentials come from
// the AWS default chain (environment, shared config, IRSA web identity,
// container and instance roles); none are configured here.
type S3Config struct {
	Bucket       string `mapstructure:"bucket"`
	Prefix       string `mapstructure:"prefix"`
	Region       string `mapstructure:"region"`
	Endpoint     string `mapstructure:"endpoint"`
	UsePathStyle bool   `mapstructure:"use_path_style"`
	// SSE is required: AES256 (SSE-S3) or aws:kms. Content is never written
	// without requested server-side encryption, whatever the launch path.
	SSE      string `mapstructure:"sse"`
	KMSKeyID string `mapstructure:"kms_key_id"`
}

// Config is the fabriccontent exporter configuration (spec 048 §4).
type Config struct {
	// AllowedTenants names the tenant ids this Node writes. Exactly one is
	// allowed unless AllowMultipleTenants is set: the tenant comes from the
	// record, so every listed tenant is writable by every authenticated agent.
	AllowedTenants []string `mapstructure:"allowed_tenants"`
	// AllowMultipleTenants permits more than one allowed tenant. It trusts
	// every authenticated agent to name its tenant; use one Node per tenant
	// otherwise.
	AllowMultipleTenants bool       `mapstructure:"allow_multiple_tenants"`
	Backend              string     `mapstructure:"backend"`
	File                 FileConfig `mapstructure:"file"`
	S3                   S3Config   `mapstructure:"s3"`
	// QueueDirectory is the directory of the file_storage extension that
	// backs this exporter's sending queue (required with a persistent queue).
	// Queued records are raw model bytes: before the queue opens it, start
	// refuses symlinks and special files in it and tightens it to
	// directories 0700 and files 0600, because file_storage creates new
	// directories with directory_permissions only and never tightens an
	// existing directory or database (a restored or reused volume).
	QueueDirectory string `mapstructure:"queue_directory"`

	// SourceBinding is the tenant and source of the ingress feeding this
	// exporter (spec 049 §7.9): a record naming another tenant or source is
	// dropped (source_unbound); every written descriptor carries the
	// receiver-owned source_authenticated: true. fabric-gate checks that the
	// content pipeline's only receiver is the bound, authenticated ingress.
	SourceBinding *SourceBinding `mapstructure:"source_binding"`
	// Profile is "local" (default) or "production". The production profile
	// requires source_binding, the encrypted persistent queue (sending_queue
	// storage on a fabricenvelope extension) and, for the file backend,
	// encryption_key_file (spec 049 §7.3, §7.8, §7.9).
	Profile string `mapstructure:"profile"`
	// MaxBodyBytes is the role table's max_body_bytes (spec 049 §4.3 rule 4):
	// default 32 MiB, never above 63 MiB (one record fits the 64 MiB request).
	MaxBodyBytes int64 `mapstructure:"max_body_bytes"`

	TimeoutConfig exporterhelper.TimeoutConfig                             `mapstructure:",squash"`
	QueueConfig   configoptional.Optional[exporterhelper.QueueBatchConfig] `mapstructure:"sending_queue"`
	RetryConfig   configretry.BackOffConfig                                `mapstructure:"retry_on_failure"`
}

// SourceBinding names the tenant and source an ingress is bound to, as the
// records carry them (the source id in its wire form, s-<32 hex> under the
// SDK's default pseudonymous labels).
type SourceBinding struct {
	TenantID string `mapstructure:"tenant_id"`
	SourceID string `mapstructure:"source_id"`
}

const (
	profileLocal      = "local"
	profileProduction = "production"

	defaultMaxBodyBytes = 32 << 20
	// nodeMaxBodyBytes is 63 MiB: one record must fit the Node's 64 MiB
	// request bound (spec 049 §7.4).
	nodeMaxBodyBytes = 63 << 20

	// envelopeStorageType is the queue storage extension that encrypts the
	// persistent queue (extension/fabricenvelopeextension).
	envelopeStorageType = "fabricenvelope"
)

var _ component.Config = (*Config)(nil)

func createDefaultConfig() component.Config {
	queue := exporterhelper.NewDefaultQueueConfig()
	// One request carries at most one 64 MiB body: bound the queue by
	// requests, apply backpressure instead of dropping when it is full.
	queue.QueueSize = 64
	queue.NumConsumers = 4
	queue.BlockOnOverflow = true
	retry := configretry.NewDefaultBackOffConfig()
	// Content is evidence: retry until the store accepts it.
	retry.MaxElapsedTime = 0
	return &Config{
		Profile:       profileLocal,
		MaxBodyBytes:  defaultMaxBodyBytes,
		S3:            S3Config{Prefix: defaultS3Prefix},
		TimeoutConfig: exporterhelper.TimeoutConfig{Timeout: 60 * time.Second},
		QueueConfig:   configoptional.Some(queue),
		RetryConfig:   retry,
	}
}

// Validate refuses incomplete or unsafe configurations. Messages name the
// offending field, never an endpoint or credential value.
func (c *Config) Validate() error {
	if len(c.AllowedTenants) == 0 {
		return errors.New("allowed_tenants must list at least one tenant id")
	}
	seen := map[string]bool{}
	for i, tenant := range c.AllowedTenants {
		if !tenantPattern.MatchString(tenant) {
			return fmt.Errorf("allowed_tenants[%d] is not a valid tenant id", i)
		}
		if seen[tenant] {
			return fmt.Errorf("allowed_tenants[%d] repeats an earlier tenant id", i)
		}
		seen[tenant] = true
	}
	if len(c.AllowedTenants) > 1 && !c.AllowMultipleTenants {
		// The record names its tenant and agents share one ingress identity
		// model: with several tenants any authenticated agent could write
		// under another tenant's prefix (Codex r2 #1).
		return errors.New("allowed_tenants lists more than one tenant; run one Node per tenant, or set allow_multiple_tenants: true to trust every authenticated agent to name its tenant")
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > nodeMaxBodyBytes {
		return errors.New("max_body_bytes must be between 1 and 66060288 (63 MiB)")
	}
	if b := c.SourceBinding; b != nil {
		if !tenantPattern.MatchString(b.TenantID) || !opaqueIDPattern.MatchString(b.SourceID) {
			return errors.New("source_binding requires a valid tenant_id and source_id")
		}
		if c.AllowMultipleTenants || len(c.AllowedTenants) != 1 || c.AllowedTenants[0] != b.TenantID {
			return errors.New("source_binding requires allowed_tenants to be exactly the bound tenant")
		}
	}
	switch c.Profile {
	case profileLocal:
	case profileProduction:
		if c.SourceBinding == nil {
			return errors.New("the production profile rejects unauthenticated sources; it requires source_binding")
		}
		queue := c.QueueConfig.Get()
		if !c.QueueConfig.HasValue() || queue.StorageID == nil || queue.StorageID.Type().String() != envelopeStorageType {
			return errors.New("the production profile requires the persistent sending_queue on a fabricenvelope storage extension (encrypted at rest)")
		}
		if c.Backend == backendFile && c.File.EncryptionKeyFile == "" {
			return errors.New("the production profile requires file.encryption_key_file for the file backend")
		}
	default:
		return errors.New("profile must be local or production")
	}
	if queue := c.QueueConfig.Get(); c.QueueConfig.HasValue() && queue.StorageID != nil && c.QueueDirectory == "" {
		return errors.New("queue_directory is required with a persistent sending_queue (the storage extension's directory)")
	}
	if dir := c.QueueDirectory; dir != "" && (!filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == string(filepath.Separator)) {
		return errors.New("queue_directory must be an absolute, clean path other than / with no trailing slash")
	}
	switch c.Backend {
	case backendFile:
		return c.File.validate()
	case backendS3:
		return c.S3.validate()
	case "":
		return errors.New("backend is required (file or s3)")
	default:
		return errors.New("backend must be file or s3")
	}
}

func (f FileConfig) validate() error {
	dir := f.Directory
	if dir == "" {
		return errors.New("file.directory is required for the file backend")
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == string(filepath.Separator) {
		return errors.New("file.directory must be an absolute, clean path other than / with no trailing slash")
	}
	if k := f.EncryptionKeyFile; k != "" && (!filepath.IsAbs(k) || filepath.Clean(k) != k) {
		return errors.New("file.encryption_key_file must be an absolute, clean path")
	}
	if b := f.DurableBoundary; b != "" {
		if !filepath.IsAbs(b) || filepath.Clean(b) != b {
			return errors.New("file.durable_boundary must be an absolute, clean path with no trailing slash")
		}
		if b != dir && !strings.HasPrefix(dir, strings.TrimSuffix(b, string(filepath.Separator))+string(filepath.Separator)) {
			return errors.New("file.durable_boundary must be file.directory or one of its ancestors")
		}
	}
	return nil
}

func (s S3Config) validate() error {
	if !bucketPattern.MatchString(s.Bucket) {
		return errors.New("s3.bucket is required and must be a valid bucket name")
	}
	if err := validPrefix(s.Prefix); err != nil {
		return err
	}
	if s.Endpoint != "" {
		if err := validEndpoint(s.Endpoint); err != nil {
			return err
		}
	}
	switch s.SSE {
	case "AES256":
		if s.KMSKeyID != "" {
			return errors.New("s3.kms_key_id requires s3.sse: aws:kms")
		}
	case "aws:kms":
	case "":
		return errors.New("s3.sse is required (AES256 or aws:kms): content is never written without server-side encryption")
	default:
		return errors.New("s3.sse must be AES256 or aws:kms")
	}
	return nil
}

func validPrefix(prefix string) error {
	if prefix == "" || !strings.HasSuffix(prefix, "/") || strings.HasPrefix(prefix, "/") {
		return errors.New("s3.prefix must be non-empty, end with / and not start with /")
	}
	for _, segment := range strings.Split(strings.TrimSuffix(prefix, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("s3.prefix must not contain empty, . or .. segments")
		}
	}
	return nil
}

func validEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	// The URL is never echoed: it may be operator-sensitive topology.
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("s3.endpoint must be an http(s) URL with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(endpoint, "#") {
		return errors.New("s3.endpoint must not contain user info, a query or a fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("s3.endpoint must not contain a path")
	}
	return nil
}
