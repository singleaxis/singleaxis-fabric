// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package auditreceiver

import (
	"fmt"
	"os"
)

func logfileIdentity(os.FileInfo) (string, error) {
	return "", fmt.Errorf("audit receiver: durable logfile source requires Linux")
}
func lockState(*os.File) error {
	return fmt.Errorf("audit receiver: durable logfile source requires Linux")
}

func openLogHandle(string) (*os.File, error) {
	return nil, fmt.Errorf("audit receiver: durable logfile source requires Linux")
}
