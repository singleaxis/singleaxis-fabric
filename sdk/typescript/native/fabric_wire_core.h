/*
 * Copyright 2026 AI5Labs Research OPC Private Limited
 * SPDX-License-Identifier: Apache-2.0
 *
 * fabric_wire_core.h: the plain-C primitives behind the Node-API addon (spec 055 §4.4).
 *
 * fabric_wire.c converts JavaScript arguments and calls these; the C unit tests in
 * native/test/ call them directly, without Node. Every function returns a value >= 0 on
 * success or one of the fixed negative codes of fabric_wire_abi.h, and never blocks.
 */
#ifndef FABRIC_WIRE_CORE_H
#define FABRIC_WIRE_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "fabric_wire_abi.h"

/* Initializes process-global state once (pthread_once): handle tables, the detached
 * environment ring and the pthread_atfork child handler. Safe to call repeatedly. */
void fw_init(void);

/* The fixed code for an errno value (the mapping of §4.4; tests check it). */
int32_t fw_errno_code(int err);

/* Nonzero in a child created by fork() without exec. */
int fw_forked(void);

int32_t fw_open_dir(const char *path, size_t path_len);
int32_t fw_open_file(int32_t dir, const char *name, size_t name_len, int create);
int32_t fw_flock(int32_t h, int32_t op);
int32_t fw_record_lock(int32_t h, int64_t offset, int64_t length, int32_t op);
int32_t fw_pread(int32_t h, void *dst, size_t length, int64_t offset);
int32_t fw_pwrite(int32_t h, const void *src, size_t length, int64_t offset);
int32_t fw_fsync(int32_t h);
int32_t fw_allocate(int32_t h, int64_t length);
int32_t fw_map_shared(int32_t h, int64_t length);
int32_t fw_store64(int32_t m, int64_t offset, int64_t value);
int64_t fw_load64(int32_t m, int64_t offset);
int32_t fw_retire(int32_t m);
int32_t fw_close(int32_t h);

/* Claims a live environment id (1 .. 2^31 - 1); LIMIT when 1,024 are live. */
int32_t fw_env_attach_id(void);
/* The environment cleanup hook's whole body: append the id to the ring, nothing else. */
void fw_env_detached(uint32_t id);
/* Moves up to n detached ids into dst; the count, or OVERFLOW once after ids were dropped. */
int32_t fw_take_detached(uint32_t *dst, size_t n);

#ifdef FABRIC_WIRE_FAULTS
/* Test builds only: the ABI version a fault build reports (FABRIC_WIRE_TEST_FAULT=abi=N). */
int32_t fw_test_abi_version(void);
#endif

#endif /* FABRIC_WIRE_CORE_H */
