// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package hostrecords

import (
	"errors"
	"io"
)

// prepareStateDir refuses: host sensors run on Linux (and the replay on
// darwin); no other platform has the owner and lock checks.
func prepareStateDir(string) (io.Closer, error) {
	return nil, errors.New("hostrecords: the state directory needs a unix platform")
}
