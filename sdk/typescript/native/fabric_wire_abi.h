/*
 * Copyright 2026 AI5Labs Research OPC Private Limited
 * SPDX-License-Identifier: Apache-2.0
 *
 * fabric_wire_abi.h: the frozen ABI of Fabric's Node-API addon (spec 055 §4.4, R12).
 *
 * The addon provides kernel lock, file-descriptor and mmap primitives plus one
 * isolate-teardown notification, and nothing else: no allocator, queue, byte arena,
 * threads, async work, thread-safe functions, callbacks into JavaScript, napi_ref,
 * finalizers on JavaScript objects, network, crypto, logging or customer code. The
 * allocator, queue and every other runtime structure are JavaScript (spec 055 §4.5).
 *
 * This header is the contract between the C addon (unit 055-t3) and its JavaScript
 * loader (wire/native.ts). It names the exported functions and their argument counts,
 * the fixed negative result codes, the operation constants and the bounds. Every
 * function is synchronous, returns in bounded time and never throws: a wrong argument
 * type returns FABRIC_WIRE_BAD_ARGUMENT. No message string, path or errno text crosses
 * the ABI. Changing a name, a value or a bound is a new ABI version.
 *
 * It includes nothing from Node-API, so the contract compiles on its own (the header
 * test in scripts/tests/test_fabric_wire_abi_header.py compiles it and checks every name
 * and value against spec 055 §4.4).
 */
#ifndef FABRIC_WIRE_ABI_H
#define FABRIC_WIRE_ABI_H

/* abiVersion() returns this; the loader refuses any other value. */
#define FABRIC_WIRE_ABI_VERSION 1
/* Built against Node-API version 8 (Node 24 provides 10); no node-addon-api. */
#define FABRIC_WIRE_NAPI_VERSION 8

/*
 * Result codes. A function returns a non-negative value (0, a byte count, a handle, an
 * environment id or a count) on success and one of these fixed negative codes otherwise.
 * load64 returns a negative bigint code; stored values are always >= 0.
 */
#define FABRIC_WIRE_OK 0
#define FABRIC_WIRE_WOULD_BLOCK (-1)  /* a non-blocking lock is held elsewhere */
#define FABRIC_WIRE_NOT_FOUND (-2)    /* ENOENT */
#define FABRIC_WIRE_EXISTS (-3)       /* EEXIST */
#define FABRIC_WIRE_PERMISSION (-4)   /* EACCES, EPERM */
#define FABRIC_WIRE_NO_SPACE (-5)     /* ENOSPC */
#define FABRIC_WIRE_QUOTA (-6)        /* EDQUOT */
#define FABRIC_WIRE_IO (-7)           /* EIO; an fsync failure never proves durability */
#define FABRIC_WIRE_UNSAFE_PATH (-8)  /* symlink, wrong type, owner, mode or link count */
#define FABRIC_WIRE_BAD_HANDLE (-9)   /* stale, closed or never issued */
#define FABRIC_WIRE_BAD_ARGUMENT (-10) /* wrong type, range or unsafe name */
#define FABRIC_WIRE_LIMIT (-11)       /* a table, length or environment bound is reached */
#define FABRIC_WIRE_FORKED (-12)      /* called in a child forked without exec */
#define FABRIC_WIRE_RETIRED (-13)     /* a store to a retired map */
#define FABRIC_WIRE_OVERFLOW (-14)    /* detached environment ids were dropped (once) */
#define FABRIC_WIRE_UNSUPPORTED (-15) /* the platform lacks the primitive */
#define FABRIC_WIRE_OTHER (-16)       /* any other failure */

/* flock(h, op): always LOCK_NB, never blocks. */
#define FABRIC_WIRE_FLOCK_SHARED 0
#define FABRIC_WIRE_FLOCK_EXCLUSIVE 1
#define FABRIC_WIRE_FLOCK_UNLOCK 2

/* recordLock(h, offset, length, op): fcntl(F_SETLK), never F_SETLKW; process-associated
 * POSIX record locks (as Python fcntl.lockf), never open-file-description locks. */
#define FABRIC_WIRE_RECORD_READ 0
#define FABRIC_WIRE_RECORD_WRITE 1
#define FABRIC_WIRE_RECORD_UNLOCK 2

/* Bounds. */
#define FABRIC_WIRE_FD_HANDLES 64                 /* process-global fd handle table */
#define FABRIC_WIRE_MAP_HANDLES 8                 /* process-global map handle table */
#define FABRIC_WIRE_MAX_MAP_BYTES 65536           /* mapShared length <= 64 KiB */
#define FABRIC_WIRE_MAX_IO_BYTES 1048576          /* pread dst / pwrite src <= 1 MiB */
#define FABRIC_WIRE_MAX_NAME_BYTES 255            /* openFile: one safe path component */
#define FABRIC_WIRE_MAX_LIVE_ENVS 1024            /* envAttach: live environments */
#define FABRIC_WIRE_DETACHED_RING 1024            /* takeDetachedEnvs ring entries */
#define FABRIC_WIRE_FILE_MODE 0600                /* openFile(create = true) */

/*
 * Handles are positive 32-bit values: the slot index in the low 8 bits and a generation
 * (1 to 2^23 - 1) above it, so a stale handle returns FABRIC_WIRE_BAD_HANDLE and never
 * reaches a reused slot. Fd and map handles live in separate tables, owned by the process,
 * never by an isolate.
 */
#define FABRIC_WIRE_HANDLE_SLOT_BITS 8
#define FABRIC_WIRE_HANDLE_SLOT_MASK 0xFF
#define FABRIC_WIRE_HANDLE_GENERATION_MAX 0x7FFFFF

/*
 * The exported functions, in spec 055 §4.4 order: X(name, argument count). The addon
 * registers exactly these properties on its exports object; the loader and the artifact
 * test refuse any other exported name.
 *
 *   abiVersion()                              -> 1
 *   openDir(path)                             -> handle | code
 *   openFile(dir, name, create)               -> handle | code
 *   flock(h, op)                              -> 0 | WOULD_BLOCK | code
 *   recordLock(h, offset, length, op)         -> 0 | WOULD_BLOCK | code (bigint offset, length)
 *   pread(h, dst, offset)                     -> bytes read | code (bigint offset)
 *   pwrite(h, src, offset)                    -> bytes written | code (short writes returned)
 *   fsync(h)                                  -> 0 | code
 *   allocate(h, length)                       -> 0 | code (bigint length)
 *   mapShared(h, length)                      -> map handle | code
 *   store64(m, offset, value)                 -> 0 | RETIRED | FORKED | code (bigint value)
 *   load64(m, offset)                         -> bigint value | negative bigint code
 *   retire(m)                                 -> 0 | code
 *   close(h)                                  -> 0 | BAD_HANDLE (idempotent)
 *   envAttach()                               -> environment id | code
 *   takeDetachedEnvs(dst)                     -> count | OVERFLOW (dst is a Uint32Array)
 */
#define FABRIC_WIRE_FUNCTIONS(X) \
  X(abiVersion, 0)               \
  X(openDir, 1)                  \
  X(openFile, 3)                 \
  X(flock, 2)                    \
  X(recordLock, 4)               \
  X(pread, 3)                    \
  X(pwrite, 3)                   \
  X(fsync, 1)                    \
  X(allocate, 2)                 \
  X(mapShared, 2)                \
  X(store64, 3)                  \
  X(load64, 2)                   \
  X(retire, 1)                   \
  X(close, 1)                    \
  X(envAttach, 0)                \
  X(takeDetachedEnvs, 1)

#define FABRIC_WIRE_FUNCTION_COUNT 16

/* The result codes as an X-macro list, for tables and tests: X(NAME, value). */
#define FABRIC_WIRE_CODES(X)                       \
  X(WOULD_BLOCK, FABRIC_WIRE_WOULD_BLOCK)          \
  X(NOT_FOUND, FABRIC_WIRE_NOT_FOUND)              \
  X(EXISTS, FABRIC_WIRE_EXISTS)                    \
  X(PERMISSION, FABRIC_WIRE_PERMISSION)            \
  X(NO_SPACE, FABRIC_WIRE_NO_SPACE)                \
  X(QUOTA, FABRIC_WIRE_QUOTA)                      \
  X(IO, FABRIC_WIRE_IO)                            \
  X(UNSAFE_PATH, FABRIC_WIRE_UNSAFE_PATH)          \
  X(BAD_HANDLE, FABRIC_WIRE_BAD_HANDLE)            \
  X(BAD_ARGUMENT, FABRIC_WIRE_BAD_ARGUMENT)        \
  X(LIMIT, FABRIC_WIRE_LIMIT)                      \
  X(FORKED, FABRIC_WIRE_FORKED)                    \
  X(RETIRED, FABRIC_WIRE_RETIRED)                  \
  X(OVERFLOW, FABRIC_WIRE_OVERFLOW)                \
  X(UNSUPPORTED, FABRIC_WIRE_UNSUPPORTED)          \
  X(OTHER, FABRIC_WIRE_OTHER)

#define FABRIC_WIRE_CODE_COUNT 16

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(FABRIC_WIRE_ABI_VERSION == 1, "ABI version 1");
_Static_assert(FABRIC_WIRE_OTHER == -FABRIC_WIRE_CODE_COUNT, "codes are -1 .. -16");
_Static_assert(FABRIC_WIRE_FD_HANDLES <= FABRIC_WIRE_HANDLE_SLOT_MASK + 1, "fd slots fit");
_Static_assert(FABRIC_WIRE_MAP_HANDLES <= FABRIC_WIRE_HANDLE_SLOT_MASK + 1, "map slots fit");
#endif

#endif /* FABRIC_WIRE_ABI_H */
