// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package initializer

import (
	"fmt"

	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorder"
	"github.com/singleaxis/singleaxis-fabric/tools/fabricctl/internal/recorderinit"
)

// runRecorder delegates the default initialization to the release recorder
// wizard so both journeys share one prompt, validation, and atomic write
// implementation. The parsed resource is re-read from the committed artifact
// so the result reflects exactly what was written.
func runRecorder(options Options) (*Result, error) {
	prepared, err := recorderinit.Run(recorderinit.Options{
		Input:       options.Input,
		Output:      options.Output,
		OutputDir:   options.OutputDir,
		Interactive: options.Interactive,
		Generator:   recorderinit.Generator(options.Generator),
	})
	if err != nil {
		return nil, err
	}
	parsed, err := recorder.ParseFile(prepared.RecorderPath)
	if err != nil {
		return nil, fmt.Errorf("validate written recorder configuration: %w", err)
	}
	return &Result{
		Recorder:        &parsed,
		RecorderPath:    prepared.RecorderPath,
		InitReceiptPath: prepared.InitReceiptPath,
		RecorderDigest:  prepared.RecorderDigest,
	}, nil
}
