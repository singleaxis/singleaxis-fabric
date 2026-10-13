// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// s3Backend writes with PutObject If-None-Match: * and, on 412, reads the
// existing object back and compares bytes. A store that does not support
// conditional writes fails retryably; it never gets an unconditional write.
type s3Backend struct {
	client *s3.Client
	cfg    S3Config
}

// newS3Backend builds the client from the AWS default credential chain
// (environment, shared config, IRSA web identity, ECS/EC2 roles). The
// returned error never carries SDK text: it can name profiles or paths.
func newS3Backend(ctx context.Context, cfg S3Config, extra ...func(*awsconfig.LoadOptions) error) (*s3Backend, error) {
	opts := append([]func(*awsconfig.LoadOptions) error{}, extra...)
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, errors.New("fabriccontent: cannot load the AWS configuration")
	}
	if awsCfg.Region == "" {
		return nil, errors.New("fabriccontent: s3.region is not set and no AWS region is configured")
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.HTTPClient = noRedirectClient(awsCfg.HTTPClient)
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.UsePathStyle
		// Send one explicit SHA-256 checksum per object instead of the SDK's
		// default aws-chunked CRC trailer, which several S3-compatible
		// stores reject.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &s3Backend{client: client, cfg: cfg}, nil
}

// noRedirectClient returns an HTTP client that never follows a redirect
// (spec 043 H1). The SDK's default client follows 307/308; a GetObject (the
// replay comparison) has no body to stop it, so a redirect could make the
// comparison read another host's bytes. With ErrUseLastResponse the 3xx is
// returned to the SDK, which reports it as a failed operation (retried). The
// transport is the configured one (custom CA bundle, proxy, timeouts).
func noRedirectClient(configured aws.HTTPClient) *http.Client {
	var transport http.RoundTripper
	if bc, ok := configured.(*awshttp.BuildableClient); ok {
		transport = bc.GetTransport()
	} else {
		transport = awshttp.NewBuildableClient().GetTransport()
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (b *s3Backend) prefix() string { return b.cfg.Prefix }

func (b *s3Backend) ref(key string) string { return "s3://" + b.cfg.Bucket + "/" + key }

func (b *s3Backend) put(ctx context.Context, key string, data []byte) error {
	sum := sha256.Sum256(data)
	in := &s3.PutObjectInput{
		Bucket:         aws.String(b.cfg.Bucket),
		Key:            aws.String(key),
		Body:           bytes.NewReader(data),
		ContentLength:  aws.Int64(int64(len(data))),
		IfNoneMatch:    aws.String("*"),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])),
	}
	if b.cfg.SSE != "" {
		in.ServerSideEncryption = types.ServerSideEncryption(b.cfg.SSE)
	}
	if b.cfg.KMSKeyID != "" {
		in.SSEKMSKeyId = aws.String(b.cfg.KMSKeyID)
	}
	_, err := b.client.PutObject(ctx, in)
	if err == nil {
		return nil
	}
	status, code := classify(err)
	if status != http.StatusPreconditionFailed && code != "PreconditionFailed" {
		// 409 ConditionalRequestConflict, 501 NotImplemented (no
		// conditional-write support), throttling, 5xx, network: retry.
		return &storeError{op: "s3 put", status: status}
	}
	return b.compareExisting(ctx, key, data)
}

func (b *s3Backend) compareExisting(ctx context.Context, key string, data []byte) error {
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.cfg.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		status, _ := classify(err)
		return &storeError{op: "s3 get", status: status}
	}
	defer func() { _ = out.Body.Close() }()
	current, err := io.ReadAll(io.LimitReader(out.Body, int64(len(data))+1))
	if err != nil {
		return &storeError{op: "s3 get"}
	}
	if !bytes.Equal(current, data) {
		return errConflict
	}
	return nil
}

// classify extracts the HTTP status and API error code, never the message.
func classify(err error) (int, string) {
	status, code := 0, ""
	var withStatus interface{ HTTPStatusCode() int }
	if errors.As(err, &withStatus) {
		status = withStatus.HTTPStatusCode()
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		code = api.ErrorCode()
	}
	return status, code
}
