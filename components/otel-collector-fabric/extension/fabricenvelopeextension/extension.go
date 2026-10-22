// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricenvelopeextension

import (
	"context"
	"errors"
	"path/filepath"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensioncapabilities"
	"go.opentelemetry.io/collector/extension/xextension/storage"
)

// typeStr is the component type referenced in collector configs:
// `extensions.fabricenvelope/<name>` and `sending_queue.storage`.
const typeStr = "fabricenvelope"

// Config names the wrapped storage extension and the key file.
type Config struct {
	// Storage is the storage extension that persists the sealed values
	// (file_storage/<name> in every shipped configuration).
	Storage component.ID `mapstructure:"storage"`
	// KeyFile is the absolute path of the customer key (a mounted Secret):
	// 32 raw bytes or their standard base64. There is no inline key option.
	KeyFile string `mapstructure:"key_file"`
}

// Validate refuses a missing storage reference or key file. Messages never
// carry the path.
func (c *Config) Validate() error {
	if c.Storage.Type().String() == "" {
		return errors.New("fabricenvelope: storage must name the storage extension to wrap")
	}
	if c.Storage.Type().String() == typeStr {
		return errors.New("fabricenvelope: storage must not be another fabricenvelope extension")
	}
	if c.KeyFile == "" || !filepath.IsAbs(c.KeyFile) || filepath.Clean(c.KeyFile) != c.KeyFile {
		return errors.New("fabricenvelope: key_file must be an absolute, clean path to the key file")
	}
	return nil
}

// NewFactory returns the fabricenvelope storage extension factory.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		component.MustNewType(typeStr),
		func() component.Config { return &Config{} },
		func(_ context.Context, _ extension.Settings, cfg component.Config) (extension.Extension, error) {
			c, ok := cfg.(*Config)
			if !ok {
				return nil, errors.New("fabricenvelope: unexpected configuration type")
			}
			if err := c.Validate(); err != nil {
				return nil, err
			}
			return &envelopeStorage{cfg: c}, nil
		},
		component.StabilityLevelAlpha,
	)
}

type envelopeStorage struct {
	cfg    *Config
	sealer *sealer
	inner  storage.Extension
}

var (
	_ storage.Extension               = (*envelopeStorage)(nil)
	_ extensioncapabilities.Dependent = (*envelopeStorage)(nil)
	_ storage.Client                  = (*envelopeClient)(nil)
)

// Dependencies makes the collector start the wrapped storage first.
func (e *envelopeStorage) Dependencies() []component.ID { return []component.ID{e.cfg.Storage} }

// Start loads the key and resolves the wrapped storage extension. A missing
// or malformed key fails start: the queue never opens unencrypted.
func (e *envelopeStorage) Start(_ context.Context, host component.Host) error {
	key, err := loadKey(e.cfg.KeyFile)
	if err != nil {
		return err
	}
	s, err := newSealer(key, queueMagic, queueSchema)
	clear(key)
	if err != nil {
		return err
	}
	ext, ok := host.GetExtensions()[e.cfg.Storage]
	if !ok {
		return errors.New("fabricenvelope: the wrapped storage extension is not configured")
	}
	inner, ok := ext.(storage.Extension)
	if !ok {
		return errors.New("fabricenvelope: the wrapped extension is not a storage extension")
	}
	e.sealer, e.inner = s, inner
	return nil
}

func (e *envelopeStorage) Shutdown(context.Context) error { return nil }

// GetClient wraps the inner storage client of the same component and name.
func (e *envelopeStorage) GetClient(ctx context.Context, kind component.Kind, id component.ID, name string) (storage.Client, error) {
	if e.inner == nil || e.sealer == nil {
		return nil, errors.New("fabricenvelope: not started")
	}
	inner, err := e.inner.GetClient(ctx, kind, id, name)
	if err != nil {
		return nil, err
	}
	return &envelopeClient{inner: inner, sealer: e.sealer, scope: []string{kind.String(), id.String(), name}}, nil
}

// envelopeClient seals every value before the wrapped client persists it and
// opens every value it returns. The AAD binds a value to its client scope and
// key, so a value moved to another key or queue fails authentication.
type envelopeClient struct {
	inner  storage.Client
	sealer *sealer
	scope  []string
}

func (c *envelopeClient) aadScope(key string) []string {
	return append(append([]string(nil), c.scope...), key)
}

func (c *envelopeClient) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := c.inner.Get(ctx, key)
	if err != nil || value == nil {
		return value, err
	}
	return c.sealer.open(value, c.aadScope(key)...)
}

func (c *envelopeClient) Set(ctx context.Context, key string, value []byte) error {
	sealed, err := c.sealer.seal(value, c.aadScope(key)...)
	if err != nil {
		return err
	}
	return c.inner.Set(ctx, key, sealed)
}

func (c *envelopeClient) Delete(ctx context.Context, key string) error {
	return c.inner.Delete(ctx, key)
}

// Batch seals Set values into copies (the caller's operations keep their
// plaintext), runs the wrapped batch, then opens every Get result in place.
// One value that fails authentication fails the batch.
func (c *envelopeClient) Batch(ctx context.Context, ops ...*storage.Operation) error {
	inner := make([]*storage.Operation, len(ops))
	for i, op := range ops {
		copied := &storage.Operation{Key: op.Key, Type: op.Type}
		if op.Type == storage.Set {
			sealed, err := c.sealer.seal(op.Value, c.aadScope(op.Key)...)
			if err != nil {
				return err
			}
			copied.Value = sealed
		}
		inner[i] = copied
	}
	if err := c.inner.Batch(ctx, inner...); err != nil {
		return err
	}
	var failed error
	for i, op := range ops {
		if op.Type != storage.Get {
			continue
		}
		op.Value = nil
		if inner[i].Value == nil {
			continue
		}
		plaintext, err := c.sealer.open(inner[i].Value, c.aadScope(op.Key)...)
		if err != nil {
			failed = err
			continue
		}
		op.Value = plaintext
	}
	return failed
}

func (c *envelopeClient) Close(ctx context.Context) error { return c.inner.Close(ctx) }
