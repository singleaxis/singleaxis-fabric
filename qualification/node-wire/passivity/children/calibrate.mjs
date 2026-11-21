// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The calibration workload in a fresh process (spec 055 §9.2 "calibration").
import { calibrate } from "../lib/common.mjs";

console.log(JSON.stringify({ ns: calibrate() }));
