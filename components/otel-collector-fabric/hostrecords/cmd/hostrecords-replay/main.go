// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Command hostrecords-replay replays a host source from an events file
// through the host-records library to a Node group's OTLP/HTTP endpoint (spec
// 056 §7.3.3 (m)). It is test-only: built by tests and CI with `go run`,
// never by an image or a release.
//
//	go run ./cmd/hostrecords-replay \
//	    --config CONFIG.json --id-key-file F --state-key-file F --state-dir DIR \
//	    --events EVENTS.jsonl --endpoint https://HOST:PORT/v1/traces \
//	    --token-file F --ca-file F [--heartbeats N]
//
// It opens a source, stages the events in batches of 512, stages N
// heartbeats (default 1) and the final marker, posts each pending batch as
// OTLP/HTTP protobuf with the bearer token, acknowledges it on a full
// success, exits nonzero on any refusal, and prints only counts.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
)

const (
	stageBatch    = 512
	maxEventLine  = 1 << 20
	maxTokenBytes = 4096
	maxResponse   = 1 << 20
)

// Exit codes: 0 every batch acknowledged; 1 a refusal or a failed post;
// 2 a usage, configuration or input error.
const (
	exitRefused = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	config, idKeyFile, stateKeyFile, stateDir, events, endpoint, tokenFile, caFile string
	heartbeats                                                                     int
}

func parse(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("hostrecords-replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.config, "config", "", "hostrecords.Config without keys (JSON)")
	fs.StringVar(&o.idKeyFile, "id-key-file", "", "the id key file (id-key-file-v1)")
	fs.StringVar(&o.stateKeyFile, "state-key-file", "", "the 32-byte state key file")
	fs.StringVar(&o.stateDir, "state-dir", "", "the source's state directory (0700)")
	fs.StringVar(&o.events, "events", "", "one hostrecords.Event per line (JSON)")
	fs.StringVar(&o.endpoint, "endpoint", "", "https://HOST:PORT/v1/traces of the source's group")
	fs.StringVar(&o.tokenFile, "token-file", "", "the group's bearer token file")
	fs.StringVar(&o.caFile, "ca-file", "", "the CA bundle that signs the Node's certificate")
	fs.IntVar(&o.heartbeats, "heartbeats", 1, "heartbeats staged after the events")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, errors.New("unexpected arguments")
	}
	for name, v := range map[string]string{
		"--config": o.config, "--id-key-file": o.idKeyFile, "--state-key-file": o.stateKeyFile,
		"--state-dir": o.stateDir, "--events": o.events, "--endpoint": o.endpoint,
		"--token-file": o.tokenFile, "--ca-file": o.caFile,
	} {
		if v == "" {
			return o, fmt.Errorf("%s is required", name)
		}
	}
	if o.heartbeats < 0 {
		return o, errors.New("--heartbeats must be at least 0")
	}
	u, err := url.Parse(o.endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return o, errors.New("--endpoint must be an https URL")
	}
	return o, nil
}

// readConfig reads the keyless configuration; key material comes only from
// the key files.
func readConfig(path string) (hostrecords.Config, error) {
	var cfg hostrecords.Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, errors.New("--config is not readable")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, errors.New("--config is not a hostrecords.Config")
	}
	if len(cfg.IDKey) != 0 || len(cfg.StateKey) != 0 || cfg.StateDir != "" {
		return cfg, errors.New("--config must not hold keys or a state directory")
	}
	return cfg, nil
}

func readEvents(path string) ([]hostrecords.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("--events is not readable")
	}
	defer func() { _ = f.Close() }()
	var events []hostrecords.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxEventLine)
	for line := 1; scanner.Scan(); line++ {
		text := bytes.TrimSpace(scanner.Bytes())
		if len(text) == 0 {
			continue
		}
		var e hostrecords.Event
		dec := json.NewDecoder(bytes.NewReader(text))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("--events line %d is not a hostrecords.Event", line)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("--events could not be read")
	}
	return events, nil
}

func client(caFile string) (*http.Client, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("--ca-file is not readable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("--ca-file holds no certificate")
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			Proxy:           nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func readToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxTokenBytes {
		return "", errors.New("--token-file is not readable")
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("--token-file holds no single token")
	}
	return token, nil
}

// post sends one batch and reports whether the Node accepted it in full.
func post(ctx context.Context, c *http.Client, endpoint, token string, b *hostrecords.Batch) (bool, error) {
	body, err := ptraceotlp.NewExportRequestFromTraces(b.Traces()).MarshalProto()
	if err != nil {
		return false, errors.New("a batch could not be encoded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, errors.New("the request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return false, errors.New("the endpoint could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return false, errors.New("the response could not be read")
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("the endpoint answered HTTP %d", resp.StatusCode)
	}
	out := ptraceotlp.NewExportResponse()
	if len(data) > 0 {
		if err := out.UnmarshalProto(data); err != nil {
			return false, errors.New("the response is not an OTLP export response")
		}
	}
	if out.PartialSuccess().RejectedSpans() != 0 {
		return false, fmt.Errorf("the Node rejected %d spans", out.PartialSuccess().RejectedSpans())
	}
	return true, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fail := func(code int, err error) int {
		_, _ = fmt.Fprintln(stderr, "hostrecords-replay:", err)
		return code
	}
	o, err := parse(args, stderr)
	if err != nil {
		return fail(exitUsage, err)
	}
	cfg, err := readConfig(o.config)
	if err != nil {
		return fail(exitUsage, err)
	}
	if cfg.IDKey, err = hostrecords.ReadIDKeyFile(o.idKeyFile); err != nil {
		return fail(exitUsage, err)
	}
	if cfg.StateKey, err = hostrecords.ReadStateKeyFile(o.stateKeyFile); err != nil {
		return fail(exitUsage, err)
	}
	cfg.StateDir = o.stateDir
	events, err := readEvents(o.events)
	if err != nil {
		return fail(exitUsage, err)
	}
	token, err := readToken(o.tokenFile)
	if err != nil {
		return fail(exitUsage, err)
	}
	c, err := client(o.caFile)
	if err != nil {
		return fail(exitUsage, err)
	}
	src, err := hostrecords.Open(cfg)
	if err != nil {
		return fail(exitUsage, err)
	}
	closed := false
	defer func() {
		if !closed {
			_, _ = src.Close(false)
		}
	}()
	staged := 0
	for start := 0; start < len(events); start += stageBatch {
		end := min(start+stageBatch, len(events))
		if _, err := src.Stage(events[start:end]); err != nil {
			return fail(exitUsage, err)
		}
		staged += end - start
	}
	for range o.heartbeats {
		if _, err := src.Heartbeat(); err != nil {
			return fail(exitRefused, err)
		}
	}
	closed = true
	if _, err := src.Close(true); err != nil {
		return fail(exitRefused, err)
	}
	pending, err := src.Pending()
	if err != nil {
		return fail(exitRefused, err)
	}
	batches, spans := 0, 0
	for _, b := range pending {
		ok, err := post(ctx, c, o.endpoint, token, b)
		if err != nil || !ok {
			_, _ = fmt.Fprintf(stdout, "records=%d batches_acknowledged=%d spans_acknowledged=%d batches_refused=1\n",
				staged, batches, spans)
			return fail(exitRefused, err)
		}
		if err := src.Acknowledge(b); err != nil {
			return fail(exitRefused, err)
		}
		batches++
		spans += b.Traces().SpanCount()
	}
	_, _ = fmt.Fprintf(stdout, "records=%d batches_acknowledged=%d spans_acknowledged=%d batches_refused=0\n",
		staged, batches, spans)
	return 0
}
