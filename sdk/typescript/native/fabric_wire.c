/*
 * Copyright 2026 AI5Labs Research OPC Private Limited
 * SPDX-License-Identifier: Apache-2.0
 *
 * fabric_wire.c: the Node-API binding of Fabric's native lock module (spec 055 §4.4).
 *
 * C against Node-API version 8, no node-addon-api. Module initialization runs once per
 * environment (main thread and each Worker); process-global state is initialized once
 * with pthread_once in fabric_wire_core.c. The exports object carries exactly the
 * functions FABRIC_WIRE_FUNCTIONS lists. Every function is synchronous and never throws:
 * a wrong argument type returns FABRIC_WIRE_BAD_ARGUMENT, and no message string, path or
 * errno text crosses the ABI.
 *
 * This file holds no napi_ref, creates no thread-safe function, async work or finalizer
 * on a JavaScript object, and never calls into JavaScript. The one environment cleanup
 * hook (envAttach) only appends the environment id to the process-global ring.
 */
#include "fabric_wire_abi.h"

/* Node-API 8 exactly (the header's FABRIC_WIRE_NAPI_VERSION); Node 24 provides 10. */
#define NAPI_VERSION 8
#if NAPI_VERSION != FABRIC_WIRE_NAPI_VERSION
#error "NAPI_VERSION must equal FABRIC_WIRE_NAPI_VERSION"
#endif

#include <math.h>
#include <node_api.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "fabric_wire_core.h"

#define FW_MAX_ARGS 4
#define FW_PATH_BUFFER 4096

static napi_value fw_int(napi_env env, int32_t value) {
  napi_value result;
  return napi_create_int32(env, value, &result) == napi_ok ? result : NULL;
}

static napi_value fw_bigint(napi_env env, int64_t value) {
  napi_value result;
  return napi_create_bigint_int64(env, value, &result) == napi_ok ? result : NULL;
}

/* Reads up to FW_MAX_ARGS arguments; missing ones are undefined. */
static void fw_args(napi_env env, napi_callback_info info, size_t count, napi_value *argv) {
  size_t argc = count;
  for (size_t i = 0; i < count; i++) argv[i] = NULL;
  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok) {
    for (size_t i = 0; i < count; i++) argv[i] = NULL;
  }
}

static int fw_is(napi_env env, napi_value value, napi_valuetype type) {
  napi_valuetype actual;
  return value != NULL && napi_typeof(env, value, &actual) == napi_ok && actual == type;
}

/* An integral JS number in [lo, hi]. Returns BAD_ARGUMENT for any other value, or
 * out_of_range for an integer outside the range. */
static int32_t fw_integer(napi_env env, napi_value value, double lo, double hi,
                          int32_t out_of_range, int64_t *out) {
  double number;
  if (!fw_is(env, value, napi_number) || napi_get_value_double(env, value, &number) != napi_ok) {
    return FABRIC_WIRE_BAD_ARGUMENT;
  }
  if (!isfinite(number) || floor(number) != number) return FABRIC_WIRE_BAD_ARGUMENT;
  if (number < lo || number > hi) return out_of_range;
  *out = (int64_t)number;
  return FABRIC_WIRE_OK;
}

/* A handle: an integral number; one outside the 32-bit handle space is BAD_HANDLE. */
static int32_t fw_handle(napi_env env, napi_value value, int32_t *out) {
  int64_t number;
  int32_t code = fw_integer(env, value, -2147483648.0, 2147483647.0, FABRIC_WIRE_BAD_HANDLE,
                            &number);
  if (code == FABRIC_WIRE_OK) *out = (int32_t)number;
  return code;
}

/* A non-negative bigint that fits int64. */
static int32_t fw_offset(napi_env env, napi_value value, int64_t *out) {
  bool lossless = false;
  if (!fw_is(env, value, napi_bigint) ||
      napi_get_value_bigint_int64(env, value, out, &lossless) != napi_ok || !lossless ||
      *out < 0) {
    return FABRIC_WIRE_BAD_ARGUMENT;
  }
  return FABRIC_WIRE_OK;
}

/* A UTF-8 copy of a JS string of at most max bytes into buffer (NUL-terminated). */
static int32_t fw_string(napi_env env, napi_value value, char *buffer, size_t max,
                         size_t *length) {
  size_t needed = 0;
  if (!fw_is(env, value, napi_string) ||
      napi_get_value_string_utf8(env, value, NULL, 0, &needed) != napi_ok || needed == 0 ||
      needed > max) {
    return FABRIC_WIRE_BAD_ARGUMENT;
  }
  if (napi_get_value_string_utf8(env, value, buffer, max + 1, length) != napi_ok ||
      *length != needed) {
    return FABRIC_WIRE_BAD_ARGUMENT;
  }
  return FABRIC_WIRE_OK;
}

static int32_t fw_typed(napi_env env, napi_value value, napi_typedarray_type want, void **data,
                        size_t *length) {
  bool is_typed = false;
  napi_typedarray_type type;
  napi_value buffer;
  size_t offset;
  if (value == NULL || napi_is_typedarray(env, value, &is_typed) != napi_ok || !is_typed ||
      napi_get_typedarray_info(env, value, &type, length, data, &buffer, &offset) != napi_ok ||
      type != want) {
    return FABRIC_WIRE_BAD_ARGUMENT;
  }
  return FABRIC_WIRE_OK;
}

#define FW_CHECK(expr)                     \
  do {                                     \
    int32_t code_ = (expr);                \
    if (code_ != FABRIC_WIRE_OK) return fw_int(env, code_); \
  } while (0)

static napi_value js_abiVersion(napi_env env, napi_callback_info info) {
  (void)info;
#ifdef FABRIC_WIRE_FAULTS
  return fw_int(env, fw_test_abi_version());
#else
  return fw_int(env, FABRIC_WIRE_ABI_VERSION);
#endif
}

static napi_value js_openDir(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  char path[FW_PATH_BUFFER + 1];
  size_t length = 0;
  fw_args(env, info, 1, argv);
  FW_CHECK(fw_string(env, argv[0], path, FW_PATH_BUFFER - 1, &length));
  return fw_int(env, fw_open_dir(path, length));
}

static napi_value js_openFile(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  int32_t dir;
  char name[FABRIC_WIRE_MAX_NAME_BYTES + 1];
  size_t length = 0;
  bool create = false;
  fw_args(env, info, 3, argv);
  FW_CHECK(fw_handle(env, argv[0], &dir));
  FW_CHECK(fw_string(env, argv[1], name, FABRIC_WIRE_MAX_NAME_BYTES, &length));
  if (!fw_is(env, argv[2], napi_boolean) || napi_get_value_bool(env, argv[2], &create) != napi_ok) {
    return fw_int(env, FABRIC_WIRE_BAD_ARGUMENT);
  }
  return fw_int(env, fw_open_file(dir, name, length, create ? 1 : 0));
}

static napi_value js_flock(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  int32_t h;
  int64_t op;
  fw_args(env, info, 2, argv);
  FW_CHECK(fw_handle(env, argv[0], &h));
  FW_CHECK(fw_integer(env, argv[1], 0, 2, FABRIC_WIRE_BAD_ARGUMENT, &op));
  return fw_int(env, fw_flock(h, (int32_t)op));
}

static napi_value js_recordLock(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  int32_t h;
  int64_t offset, length, op;
  fw_args(env, info, 4, argv);
  FW_CHECK(fw_handle(env, argv[0], &h));
  FW_CHECK(fw_offset(env, argv[1], &offset));
  FW_CHECK(fw_offset(env, argv[2], &length));
  FW_CHECK(fw_integer(env, argv[3], 0, 2, FABRIC_WIRE_BAD_ARGUMENT, &op));
  return fw_int(env, fw_record_lock(h, offset, length, (int32_t)op));
}

static napi_value js_pread(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  int32_t h;
  void *data = NULL;
  size_t length = 0;
  int64_t offset;
  fw_args(env, info, 3, argv);
  FW_CHECK(fw_handle(env, argv[0], &h));
  FW_CHECK(fw_typed(env, argv[1], napi_uint8_array, &data, &length));
  FW_CHECK(fw_offset(env, argv[2], &offset));
  return fw_int(env, fw_pread(h, data, length, offset));
}

static napi_value js_pwrite(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  int32_t h;
  void *data = NULL;
  size_t length = 0;
  int64_t offset;
  fw_args(env, info, 3, argv);
  FW_CHECK(fw_handle(env, argv[0], &h));
  FW_CHECK(fw_typed(env, argv[1], napi_uint8_array, &data, &length));
  FW_CHECK(fw_offset(env, argv[2], &offset));
  return fw_int(env, fw_pwrite(h, data, length, offset));
}

static napi_value js_fsync(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  int32_t h;
  fw_args(env, info, 1, argv);
  FW_CHECK(fw_handle(env, argv[0], &h));
  return fw_int(env, fw_fsync(h));
}

static napi_value js_allocate(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  int32_t h;
  int64_t length;
  fw_args(env, info, 2, argv);
  FW_CHECK(fw_handle(env, argv[0], &h));
  FW_CHECK(fw_offset(env, argv[1], &length));
  return fw_int(env, fw_allocate(h, length));
}

static napi_value js_mapShared(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  int32_t h;
  int64_t length;
  fw_args(env, info, 2, argv);
  FW_CHECK(fw_handle(env, argv[0], &h));
  FW_CHECK(fw_integer(env, argv[1], 1, FABRIC_WIRE_MAX_MAP_BYTES, FABRIC_WIRE_BAD_ARGUMENT,
                      &length));
  return fw_int(env, fw_map_shared(h, length));
}

static napi_value js_store64(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  int32_t m;
  int64_t offset, value;
  fw_args(env, info, 3, argv);
  FW_CHECK(fw_handle(env, argv[0], &m));
  FW_CHECK(fw_integer(env, argv[1], 0, FABRIC_WIRE_MAX_MAP_BYTES, FABRIC_WIRE_BAD_ARGUMENT,
                      &offset));
  FW_CHECK(fw_offset(env, argv[2], &value));
  return fw_int(env, fw_store64(m, offset, value));
}

static napi_value js_load64(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  int32_t m;
  int64_t offset;
  int32_t code;
  fw_args(env, info, 2, argv);
  code = fw_handle(env, argv[0], &m);
  if (code == FABRIC_WIRE_OK) {
    code = fw_integer(env, argv[1], 0, FABRIC_WIRE_MAX_MAP_BYTES, FABRIC_WIRE_BAD_ARGUMENT,
                      &offset);
  }
  if (code != FABRIC_WIRE_OK) return fw_bigint(env, code);
  return fw_bigint(env, fw_load64(m, offset));
}

static napi_value js_retire(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  int32_t m;
  fw_args(env, info, 1, argv);
  FW_CHECK(fw_handle(env, argv[0], &m));
  return fw_int(env, fw_retire(m));
}

static napi_value js_close(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  int32_t h;
  fw_args(env, info, 1, argv);
  FW_CHECK(fw_handle(env, argv[0], &h));
  return fw_int(env, fw_close(h));
}

/* The cleanup hook: append the id to the detached ring. No JS, no descriptor. */
static void fw_on_env_cleanup(void *arg) { fw_env_detached((uint32_t)(uintptr_t)arg); }

static napi_value js_envAttach(napi_env env, napi_callback_info info) {
  void *existing = NULL;
  (void)info;
  if (fw_forked()) return fw_int(env, FABRIC_WIRE_FORKED);
  /* One id per environment: a second call returns the first id. */
  if (napi_get_instance_data(env, &existing) == napi_ok && existing != NULL) {
    return fw_int(env, (int32_t)(uintptr_t)existing);
  }
  int32_t id = fw_env_attach_id();
  if (id < 0) return fw_int(env, id);
  void *tag = (void *)(uintptr_t)(uint32_t)id;
  if (napi_add_env_cleanup_hook(env, fw_on_env_cleanup, tag) != napi_ok) {
    fw_env_detached((uint32_t)id);
    return fw_int(env, FABRIC_WIRE_OTHER);
  }
  /* No finalizer: the instance data is the id itself, not memory to free. */
  if (napi_set_instance_data(env, tag, NULL, NULL) != napi_ok) return fw_int(env, FABRIC_WIRE_OTHER);
  return fw_int(env, id);
}

static napi_value js_takeDetachedEnvs(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  void *data = NULL;
  size_t length = 0;
  fw_args(env, info, 1, argv);
  FW_CHECK(fw_typed(env, argv[0], napi_uint32_array, &data, &length));
  return fw_int(env, fw_take_detached((uint32_t *)data, length));
}

#define FW_DESCRIPTOR(name, argc) \
  {#name, NULL, js_##name, NULL, NULL, NULL, napi_enumerable, NULL},

NAPI_MODULE_INIT() {
  static const napi_property_descriptor functions[] = {FABRIC_WIRE_FUNCTIONS(FW_DESCRIPTOR)};
  fw_init();
  if (napi_define_properties(env, exports, FABRIC_WIRE_FUNCTION_COUNT, functions) != napi_ok) {
    return NULL;
  }
  return exports;
}
