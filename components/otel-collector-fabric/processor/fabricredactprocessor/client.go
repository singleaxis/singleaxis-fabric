// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricredactprocessor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// RedactionResult mirrors the Bridge's presidio.RedactionResult — the
// two processors share the same wire contract with the sidecar.
type RedactionResult struct {
	Value       string
	Hashed      bool
	PIICategory string
}

// Client is the surface the processor calls per string attribute.
// Split as an interface so tests can swap a fake in without standing
// up a real Unix socket sidecar.
type Client interface {
	Redact(ctx context.Context, path, value string) (RedactionResult, error)
	Close() error
}

type udsClient struct {
	http    *http.Client
	baseURL string
}

// NewUDSClient builds an HTTP-over-UDS client pointed at the sidecar
// at `socket`. The socket path is not probed here; errors surface on
// the first Redact call.
func NewUDSClient(socket string, timeout time.Duration) (Client, error) {
	if socket == "" {
		return nil, errors.New("fabricredact: socket is empty")
	}
	if timeout <= 0 {
		return nil, errors.New("fabricredact: timeout must be positive")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 500 * time.Millisecond,
	}
	return &udsClient{
		http:    &http.Client{Transport: transport, Timeout: timeout},
		baseURL: "http://presidio.sock",
	}, nil
}

type redactRequest struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

type redactResponse struct {
	Value       string `json:"value"`
	Hashed      bool   `json:"hashed"`
	PIICategory string `json:"pii_category"`
}

func (c *udsClient) Redact(ctx context.Context, path, value string) (RedactionResult, error) {
	body, err := json.Marshal(redactRequest{Path: path, Value: value})
	if err != nil {
		return RedactionResult{}, fmt.Errorf("fabricredact: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/redact", bytes.NewReader(body))
	if err != nil {
		return RedactionResult{}, fmt.Errorf("fabricredact: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return RedactionResult{}, fmt.Errorf("fabricredact: do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return RedactionResult{}, fmt.Errorf("fabricredact: status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	var decoded redactResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&decoded); err != nil {
		return RedactionResult{}, fmt.Errorf("fabricredact: decode: %w", err)
	}
	return RedactionResult{
		Value:       decoded.Value,
		Hashed:      decoded.Hashed,
		PIICategory: decoded.PIICategory,
	}, nil
}

func (c *udsClient) Close() error {
	if c == nil || c.http == nil {
		return nil
	}
	c.http.CloseIdleConnections()
	return nil
}
