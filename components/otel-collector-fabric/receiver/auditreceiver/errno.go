// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import "strconv"

// errnoName renders the handful of errnos worth naming in audit.result;
// anything else stays numeric.
func errnoName(n int) string {
	switch n {
	case 1:
		return "EPERM"
	case 2:
		return "ENOENT"
	case 5:
		return "EIO"
	case 11:
		return "EAGAIN"
	case 13:
		return "EACCES"
	case 22:
		return "EINVAL"
	case 111:
		return "ECONNREFUSED"
	case 110:
		return "ETIMEDOUT"
	case 113:
		return "EHOSTUNREACH"
	case 101:
		return "ENETUNREACH"
	}
	return strconv.Itoa(n)
}
