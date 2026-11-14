/*
 * Copyright 2026 AI5Labs Research OPC Private Limited
 * SPDX-License-Identifier: Apache-2.0
 *
 * fabric_wire_core.c: kernel lock, descriptor and shared-mapping primitives (spec 055 §4.4).
 *
 * Ownership. Every descriptor and mapping belongs to the process, in fixed process-global
 * tables (64 fd handles, 8 map handles), never to an isolate. A handle is the slot index
 * (low 8 bits) plus a generation (above), so a stale handle returns BAD_HANDLE and never
 * reaches a reused slot. The table mutex is held only to claim or release a slot, never
 * across open, close or I/O; lookups are a single atomic load.
 *
 * Maps are never unmapped while the process runs: retire() turns later stores into
 * no-ops and the kernel releases the mapping at exit, so a store can never race an unmap
 * made from another isolate. Map slots are therefore claimed once and never reused.
 *
 * fork() without exec: the pthread_atfork child handler marks the process FORKED and
 * closes every table descriptor with close(2), which is async-signal-safe and releases
 * nothing the parent holds (a flock belongs to the open file description, which the parent
 * still references; POSIX record locks are never inherited). Every later call returns
 * FORKED, so a forked child can never store into the parent's shared mapping. Every
 * descriptor is O_CLOEXEC, so fork-then-exec children (child_process, cluster) inherit
 * nothing at all.
 *
 * Nothing here allocates, starts threads, calls back into JavaScript, logs or reads the
 * environment (test builds compiled with FABRIC_WIRE_FAULTS read one variable, once).
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include "fabric_wire_core.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef FABRIC_WIRE_FAULTS
#include <stdlib.h>
#endif

#define FW_PATH_MAX 4096
#define FW_GEN_SHIFT 32
#define FW_MAP_LIVE 1u
#define FW_MAP_RETIRED 2u

typedef struct {
  /* 0 = free; else (generation << 32) | (uint32_t)fd. */
  _Atomic uint64_t word;
} fw_fd_slot;

typedef struct {
  /* 0 = free; else (generation << 32) | flags (FW_MAP_LIVE, FW_MAP_RETIRED). */
  _Atomic uint64_t word;
  unsigned char *addr; /* written before word is published with release order */
  size_t length;
} fw_map_slot;

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_table_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_env_lock = PTHREAD_MUTEX_INITIALIZER;
static fw_fd_slot g_fds[FABRIC_WIRE_FD_HANDLES];
static uint32_t g_fd_generation[FABRIC_WIRE_FD_HANDLES]; /* guarded by g_table_lock */
static fw_map_slot g_maps[FABRIC_WIRE_MAP_HANDLES];
static _Atomic int g_forked;

/* Detached-environment ring (guarded by g_env_lock). */
static uint32_t g_ring[FABRIC_WIRE_DETACHED_RING];
static size_t g_ring_head;
static size_t g_ring_count;
static int g_ring_overflow;
static uint32_t g_env_live;
static uint32_t g_env_next;

#ifdef FABRIC_WIRE_FAULTS
/* FABRIC_WIRE_TEST_FAULT=<op>=<ERRNO> | flock=ignore | forked=1 | abi=<n> | ring=overflow,
 * read once. */
static char g_fault_op[16];
static int g_fault_errno;
static int g_fault_ignore_flock;
static int32_t g_fault_abi = FABRIC_WIRE_ABI_VERSION;

static int fw_errno_named(const char *name) {
  static const struct {
    const char *name;
    int value;
  } names[] = {{"EEXIST", EEXIST}, {"EACCES", EACCES}, {"ENOSPC", ENOSPC},
               {"EDQUOT", EDQUOT}, {"EIO", EIO},       {"EOPNOTSUPP", EOPNOTSUPP},
               {"EXDEV", EXDEV},   {"EMFILE", EMFILE}, {"ENOENT", ENOENT}};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    if (strcmp(names[i].name, name) == 0) return names[i].value;
  }
  return 0;
}

static void fw_faults_init(void) {
  const char *spec = getenv("FABRIC_WIRE_TEST_FAULT");
  if (spec == NULL) return;
  const char *eq = strchr(spec, '=');
  if (eq == NULL || (size_t)(eq - spec) >= sizeof(g_fault_op)) return;
  memcpy(g_fault_op, spec, (size_t)(eq - spec));
  g_fault_op[eq - spec] = '\0';
  if (strcmp(g_fault_op, "forked") == 0) {
    atomic_store(&g_forked, 1);
  } else if (strcmp(g_fault_op, "abi") == 0) {
    g_fault_abi = (int32_t)atoi(eq + 1);
  } else if (strcmp(g_fault_op, "ring") == 0 && strcmp(eq + 1, "overflow") == 0) {
    g_ring_overflow = 1; /* as if 1,025 environments were torn down with no poll */
  } else if (strcmp(g_fault_op, "flock") == 0 && strcmp(eq + 1, "ignore") == 0) {
    g_fault_ignore_flock = 1;
  } else {
    g_fault_errno = fw_errno_named(eq + 1);
  }
}

int32_t fw_test_abi_version(void) {
  fw_init();
  return g_fault_abi;
}

/* The errno to inject for this operation, or 0. */
static int fw_fault(const char *op) {
  return (g_fault_errno != 0 && strcmp(g_fault_op, op) == 0) ? g_fault_errno : 0;
}
#define FW_FAULT(op)                          \
  do {                                        \
    int injected_ = fw_fault(op);             \
    if (injected_ != 0) return fw_errno_code(injected_); \
  } while (0)
#else
#define FW_FAULT(op) \
  do {               \
  } while (0)
#endif

static void fw_atfork_child(void) {
  atomic_store_explicit(&g_forked, 1, memory_order_relaxed);
  for (size_t i = 0; i < FABRIC_WIRE_FD_HANDLES; i++) {
    uint64_t word = atomic_exchange_explicit(&g_fds[i].word, 0, memory_order_relaxed);
    if (word != 0) (void)close((int)(uint32_t)word);
  }
}

static void fw_init_once(void) {
#ifdef FABRIC_WIRE_FAULTS
  fw_faults_init();
#endif
  (void)pthread_atfork(NULL, NULL, fw_atfork_child);
}

void fw_init(void) { (void)pthread_once(&g_once, fw_init_once); }

int fw_forked(void) { return atomic_load_explicit(&g_forked, memory_order_relaxed); }

int32_t fw_errno_code(int err) {
  switch (err) {
    case 0:
      return FABRIC_WIRE_OTHER;
    case EWOULDBLOCK:
#if EAGAIN != EWOULDBLOCK
    case EAGAIN:
#endif
      return FABRIC_WIRE_WOULD_BLOCK;
    case ENOENT:
      return FABRIC_WIRE_NOT_FOUND;
    case EEXIST:
      return FABRIC_WIRE_EXISTS;
    case EACCES:
    case EPERM:
    case EROFS:
      return FABRIC_WIRE_PERMISSION;
    case ENOSPC:
      return FABRIC_WIRE_NO_SPACE;
    case EDQUOT:
      return FABRIC_WIRE_QUOTA;
    case EIO:
      return FABRIC_WIRE_IO;
    case ELOOP:
    case ENOTDIR:
    case EISDIR:
    case EMLINK:
      return FABRIC_WIRE_UNSAFE_PATH;
    case EBADF:
      return FABRIC_WIRE_BAD_HANDLE;
    case EINVAL:
    case ENAMETOOLONG:
      return FABRIC_WIRE_BAD_ARGUMENT;
    case EMFILE:
    case ENFILE:
    case ENOMEM:
    case EFBIG:
      return FABRIC_WIRE_LIMIT;
    case ENOSYS:
    case EOPNOTSUPP:
#if defined(ENOTSUP) && ENOTSUP != EOPNOTSUPP
    case ENOTSUP:
#endif
      return FABRIC_WIRE_UNSUPPORTED;
    default:
      return FABRIC_WIRE_OTHER;
  }
}

/* ---- handle tables ------------------------------------------------------------------ */

static int fw_decode(int32_t handle, size_t slots, size_t *slot, uint32_t *generation) {
  if (handle <= 0) return 0;
  uint32_t value = (uint32_t)handle;
  *slot = value & FABRIC_WIRE_HANDLE_SLOT_MASK;
  *generation = value >> FABRIC_WIRE_HANDLE_SLOT_BITS;
  return *slot < slots && *generation >= 1 && *generation <= FABRIC_WIRE_HANDLE_GENERATION_MAX;
}

static int32_t fw_encode(size_t slot, uint32_t generation) {
  return (int32_t)((generation << FABRIC_WIRE_HANDLE_SLOT_BITS) | (uint32_t)slot);
}

/* Stores fd in a free slot and returns its handle; LIMIT (fd closed) when the table is full. */
static int32_t fw_fd_claim(int fd) {
  int32_t handle = FABRIC_WIRE_LIMIT;
  pthread_mutex_lock(&g_table_lock);
  for (size_t i = 0; i < FABRIC_WIRE_FD_HANDLES; i++) {
    if (atomic_load_explicit(&g_fds[i].word, memory_order_relaxed) != 0) continue;
    uint32_t generation = g_fd_generation[i] % FABRIC_WIRE_HANDLE_GENERATION_MAX + 1;
    g_fd_generation[i] = generation;
    uint64_t word = ((uint64_t)generation << FW_GEN_SHIFT) | (uint32_t)fd;
    atomic_store_explicit(&g_fds[i].word, word, memory_order_release);
    handle = fw_encode(i, generation);
    break;
  }
  pthread_mutex_unlock(&g_table_lock);
  if (handle < 0) (void)close(fd);
  return handle;
}

/* The descriptor of a live fd handle, or a negative code. */
static int fw_fd_of(int32_t handle) {
  size_t slot;
  uint32_t generation;
  if (fw_forked()) return FABRIC_WIRE_FORKED;
  if (!fw_decode(handle, FABRIC_WIRE_FD_HANDLES, &slot, &generation)) return FABRIC_WIRE_BAD_HANDLE;
  uint64_t word = atomic_load_explicit(&g_fds[slot].word, memory_order_acquire);
  if (word == 0 || (uint32_t)(word >> FW_GEN_SHIFT) != generation) return FABRIC_WIRE_BAD_HANDLE;
  return (int)(uint32_t)word;
}

/* The live map slot of a map handle, or NULL with *code set. */
static fw_map_slot *fw_map_of(int32_t handle, uint64_t *word_out, int32_t *code) {
  size_t slot;
  uint32_t generation;
  if (fw_forked()) {
    *code = FABRIC_WIRE_FORKED;
    return NULL;
  }
  if (!fw_decode(handle, FABRIC_WIRE_MAP_HANDLES, &slot, &generation)) {
    *code = FABRIC_WIRE_BAD_HANDLE;
    return NULL;
  }
  uint64_t word = atomic_load_explicit(&g_maps[slot].word, memory_order_acquire);
  if (word == 0 || (uint32_t)(word >> FW_GEN_SHIFT) != generation) {
    *code = FABRIC_WIRE_BAD_HANDLE;
    return NULL;
  }
  *word_out = word;
  return &g_maps[slot];
}

/* ---- functions of §4.4 -------------------------------------------------------------- */

static int fw_retry_open(int dirfd, const char *path, int flags, mode_t mode) {
  int fd;
  do {
    fd = dirfd < 0 ? open(path, flags, mode) : openat(dirfd, path, flags, mode);
  } while (fd < 0 && errno == EINTR);
  return fd;
}

int32_t fw_open_dir(const char *path, size_t path_len) {
  fw_init();
  if (fw_forked()) return FABRIC_WIRE_FORKED;
  if (path == NULL || path_len == 0 || path_len >= FW_PATH_MAX || strlen(path) != path_len) {
    return FABRIC_WIRE_BAD_ARGUMENT;
  }
  FW_FAULT("openDir");
  int fd = fw_retry_open(-1, path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0);
  if (fd < 0) return fw_errno_code(errno);
  struct stat st;
  if (fstat(fd, &st) != 0) {
    int32_t code = fw_errno_code(errno);
    (void)close(fd);
    return code;
  }
  if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077) != 0) {
    (void)close(fd);
    return FABRIC_WIRE_UNSAFE_PATH;
  }
  return fw_fd_claim(fd);
}

static int fw_safe_name(const char *name, size_t name_len) {
  if (name == NULL || name_len == 0 || name_len > FABRIC_WIRE_MAX_NAME_BYTES) return 0;
  if (strlen(name) != name_len || memchr(name, '/', name_len) != NULL) return 0;
  return strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

int32_t fw_open_file(int32_t dir, const char *name, size_t name_len, int create) {
  fw_init();
  int dirfd = fw_fd_of(dir);
  if (dirfd < 0) return dirfd;
  if (!fw_safe_name(name, name_len)) return FABRIC_WIRE_BAD_ARGUMENT;
  FW_FAULT("openFile");
  int flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (create ? O_CREAT : 0);
  int fd = fw_retry_open(dirfd, name, flags, FABRIC_WIRE_FILE_MODE);
  if (fd < 0) return fw_errno_code(errno);
  struct stat st;
  if (fstat(fd, &st) != 0) {
    int32_t code = fw_errno_code(errno);
    (void)close(fd);
    return code;
  }
  if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
      (st.st_mode & 077) != 0) {
    (void)close(fd);
    return FABRIC_WIRE_UNSAFE_PATH;
  }
  /* O_NONBLOCK only guarded the open itself (a FIFO); regular files do not need it. */
  int fl = fcntl(fd, F_GETFL);
  if (fl >= 0) (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
  return fw_fd_claim(fd);
}

int32_t fw_flock(int32_t h, int32_t op) {
  fw_init();
  int fd = fw_fd_of(h);
  if (fd < 0) return fd;
  int how;
  switch (op) {
    case FABRIC_WIRE_FLOCK_SHARED:
      how = LOCK_SH | LOCK_NB;
      break;
    case FABRIC_WIRE_FLOCK_EXCLUSIVE:
      how = LOCK_EX | LOCK_NB;
      break;
    case FABRIC_WIRE_FLOCK_UNLOCK:
      how = LOCK_UN;
      break;
    default:
      return FABRIC_WIRE_BAD_ARGUMENT;
  }
#ifdef FABRIC_WIRE_FAULTS
  if (g_fault_ignore_flock) return FABRIC_WIRE_OK;
#endif
  FW_FAULT("flock");
  int rc;
  do {
    rc = flock(fd, how);
  } while (rc != 0 && errno == EINTR);
  return rc == 0 ? FABRIC_WIRE_OK : fw_errno_code(errno);
}

int32_t fw_record_lock(int32_t h, int64_t offset, int64_t length, int32_t op) {
  fw_init();
  int fd = fw_fd_of(h);
  if (fd < 0) return fd;
  if (offset < 0 || length < 0) return FABRIC_WIRE_BAD_ARGUMENT;
  struct flock fl;
  memset(&fl, 0, sizeof fl);
  switch (op) {
    case FABRIC_WIRE_RECORD_READ:
      fl.l_type = F_RDLCK;
      break;
    case FABRIC_WIRE_RECORD_WRITE:
      fl.l_type = F_WRLCK;
      break;
    case FABRIC_WIRE_RECORD_UNLOCK:
      fl.l_type = F_UNLCK;
      break;
    default:
      return FABRIC_WIRE_BAD_ARGUMENT;
  }
  fl.l_whence = SEEK_SET;
  fl.l_start = (off_t)offset;
  fl.l_len = (off_t)length;
  FW_FAULT("recordLock");
  int rc;
  do {
    rc = fcntl(fd, F_SETLK, &fl); /* never F_SETLKW: a held lock is WOULD_BLOCK */
  } while (rc != 0 && errno == EINTR);
  if (rc == 0) return FABRIC_WIRE_OK;
  return (errno == EACCES || errno == EAGAIN) ? FABRIC_WIRE_WOULD_BLOCK : fw_errno_code(errno);
}

int32_t fw_pread(int32_t h, void *dst, size_t length, int64_t offset) {
  fw_init();
  int fd = fw_fd_of(h);
  if (fd < 0) return fd;
  if (length > FABRIC_WIRE_MAX_IO_BYTES || offset < 0 || (dst == NULL && length != 0)) {
    return FABRIC_WIRE_BAD_ARGUMENT;
  }
  FW_FAULT("pread");
  ssize_t n;
  do {
    n = pread(fd, dst, length, (off_t)offset);
  } while (n < 0 && errno == EINTR);
  return n < 0 ? fw_errno_code(errno) : (int32_t)n;
}

int32_t fw_pwrite(int32_t h, const void *src, size_t length, int64_t offset) {
  fw_init();
  int fd = fw_fd_of(h);
  if (fd < 0) return fd;
  if (length > FABRIC_WIRE_MAX_IO_BYTES || offset < 0 || (src == NULL && length != 0)) {
    return FABRIC_WIRE_BAD_ARGUMENT;
  }
  FW_FAULT("pwrite");
  ssize_t n;
  do {
    n = pwrite(fd, src, length, (off_t)offset);
  } while (n < 0 && errno == EINTR);
  return n < 0 ? fw_errno_code(errno) : (int32_t)n; /* a short write is returned as is */
}

int32_t fw_fsync(int32_t h) {
  fw_init();
  int fd = fw_fd_of(h);
  if (fd < 0) return fd;
  FW_FAULT("fsync");
  if (fsync(fd) == 0) return FABRIC_WIRE_OK;
  /* A failed fsync never proves durability; it is not retried. */
  int err = errno;
  if (err == ENOSPC || err == EDQUOT || err == EBADF) return fw_errno_code(err);
  return FABRIC_WIRE_IO;
}

int32_t fw_allocate(int32_t h, int64_t length) {
  fw_init();
  int fd = fw_fd_of(h);
  if (fd < 0) return fd;
  if (length <= 0) return FABRIC_WIRE_BAD_ARGUMENT;
  FW_FAULT("allocate");
#if defined(__APPLE__)
  struct stat st;
  if (fstat(fd, &st) != 0) return fw_errno_code(errno);
  if (st.st_size >= length) return FABRIC_WIRE_OK;
  fstore_t store;
  memset(&store, 0, sizeof store);
  store.fst_flags = F_ALLOCATECONTIG | F_ALLOCATEALL;
  store.fst_posmode = F_PEOFPOSMODE;
  store.fst_offset = 0;
  store.fst_length = (off_t)(length - st.st_size);
  if (fcntl(fd, F_PREALLOCATE, &store) == -1) {
    store.fst_flags = F_ALLOCATEALL; /* contiguous space is a preference, not a need */
    if (fcntl(fd, F_PREALLOCATE, &store) == -1) return fw_errno_code(errno);
  }
  if (ftruncate(fd, (off_t)length) != 0) return fw_errno_code(errno);
  return FABRIC_WIRE_OK;
#else
  int rc;
  do {
    rc = posix_fallocate(fd, 0, (off_t)length); /* returns the error; errno is untouched */
  } while (rc == EINTR);
  return rc == 0 ? FABRIC_WIRE_OK : fw_errno_code(rc);
#endif
}

int32_t fw_map_shared(int32_t h, int64_t length) {
  fw_init();
  int fd = fw_fd_of(h);
  if (fd < 0) return fd;
  if (length <= 0 || length > FABRIC_WIRE_MAX_MAP_BYTES) return FABRIC_WIRE_BAD_ARGUMENT;
  /* A mapping beyond the end of the file faults (SIGBUS) on access: refuse it. */
  struct stat st;
  if (fstat(fd, &st) != 0) return fw_errno_code(errno);
  if (st.st_size < length) return FABRIC_WIRE_BAD_ARGUMENT;
  FW_FAULT("mapShared");
  void *addr = mmap(NULL, (size_t)length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED) return fw_errno_code(errno);
  int32_t handle = FABRIC_WIRE_LIMIT;
  pthread_mutex_lock(&g_table_lock);
  for (size_t i = 0; i < FABRIC_WIRE_MAP_HANDLES; i++) {
    if (atomic_load_explicit(&g_maps[i].word, memory_order_relaxed) != 0) continue;
    g_maps[i].addr = (unsigned char *)addr;
    g_maps[i].length = (size_t)length;
    atomic_store_explicit(&g_maps[i].word, ((uint64_t)1 << FW_GEN_SHIFT) | FW_MAP_LIVE,
                          memory_order_release);
    handle = fw_encode(i, 1);
    break;
  }
  pthread_mutex_unlock(&g_table_lock);
  /* Never published, so no other isolate can be storing into it. */
  if (handle < 0) (void)munmap(addr, (size_t)length);
  return handle;
}

static int fw_map_offset_ok(const fw_map_slot *map, int64_t offset) {
  return offset >= 0 && (offset & 7) == 0 && (uint64_t)offset + 8 <= map->length;
}

int32_t fw_store64(int32_t m, int64_t offset, int64_t value) {
  uint64_t word;
  int32_t code;
  fw_map_slot *map = fw_map_of(m, &word, &code);
  if (map == NULL) return code;
  if (!fw_map_offset_ok(map, offset) || value < 0) return FABRIC_WIRE_BAD_ARGUMENT;
  if (word & FW_MAP_RETIRED) return FABRIC_WIRE_RETIRED;
  __atomic_store_n((uint64_t *)(void *)(map->addr + offset), (uint64_t)value, __ATOMIC_RELEASE);
  return FABRIC_WIRE_OK;
}

int64_t fw_load64(int32_t m, int64_t offset) {
  uint64_t word;
  int32_t code;
  fw_map_slot *map = fw_map_of(m, &word, &code);
  if (map == NULL) return code;
  if (!fw_map_offset_ok(map, offset)) return FABRIC_WIRE_BAD_ARGUMENT;
  uint64_t value = __atomic_load_n((const uint64_t *)(const void *)(map->addr + offset),
                                   __ATOMIC_ACQUIRE);
  /* Stored values are >= 0; a value with the top bit set was not written by store64. */
  return value > (uint64_t)INT64_MAX ? FABRIC_WIRE_OTHER : (int64_t)value;
}

int32_t fw_retire(int32_t m) {
  uint64_t word;
  int32_t code;
  fw_map_slot *map = fw_map_of(m, &word, &code);
  if (map == NULL) return code;
  atomic_fetch_or_explicit(&map->word, (uint64_t)FW_MAP_RETIRED, memory_order_acq_rel);
  return FABRIC_WIRE_OK;
}

int32_t fw_close(int32_t h) {
  fw_init();
  size_t slot;
  uint32_t generation;
  if (fw_forked()) return FABRIC_WIRE_FORKED;
  if (!fw_decode(h, FABRIC_WIRE_FD_HANDLES, &slot, &generation)) return FABRIC_WIRE_BAD_HANDLE;
  int fd = -1;
  pthread_mutex_lock(&g_table_lock);
  uint64_t word = atomic_load_explicit(&g_fds[slot].word, memory_order_relaxed);
  if (word != 0 && (uint32_t)(word >> FW_GEN_SHIFT) == generation) {
    fd = (int)(uint32_t)word;
    atomic_store_explicit(&g_fds[slot].word, 0, memory_order_release);
  }
  pthread_mutex_unlock(&g_table_lock);
  if (fd < 0) return FABRIC_WIRE_BAD_HANDLE;
  (void)close(fd); /* POSIX leaves the descriptor closed even when close reports EINTR/EIO */
  return FABRIC_WIRE_OK;
}

/* ---- environment teardown ring ------------------------------------------------------ */

int32_t fw_env_attach_id(void) {
  fw_init();
  if (fw_forked()) return FABRIC_WIRE_FORKED;
  int32_t id = FABRIC_WIRE_LIMIT;
  pthread_mutex_lock(&g_env_lock);
  if (g_env_live < FABRIC_WIRE_MAX_LIVE_ENVS) {
    g_env_next = g_env_next >= 0x7FFFFFFFu ? 1 : g_env_next + 1;
    g_env_live++;
    id = (int32_t)g_env_next;
  }
  pthread_mutex_unlock(&g_env_lock);
  return id;
}

void fw_env_detached(uint32_t id) {
  /* A forked child may have copied g_env_lock while another thread held it. */
  if (fw_forked()) return;
  pthread_mutex_lock(&g_env_lock);
  if (g_env_live > 0) g_env_live--;
  if (g_ring_count == FABRIC_WIRE_DETACHED_RING) {
    g_ring_overflow = 1;
  } else {
    g_ring[(g_ring_head + g_ring_count) % FABRIC_WIRE_DETACHED_RING] = id;
    g_ring_count++;
  }
  pthread_mutex_unlock(&g_env_lock);
}

int32_t fw_take_detached(uint32_t *dst, size_t n) {
  fw_init();
  if (fw_forked()) return FABRIC_WIRE_FORKED;
  if (dst == NULL && n != 0) return FABRIC_WIRE_BAD_ARGUMENT;
  int32_t moved;
  pthread_mutex_lock(&g_env_lock);
  if (g_ring_overflow) {
    g_ring_overflow = 0;
    moved = FABRIC_WIRE_OVERFLOW;
  } else {
    size_t count = n < g_ring_count ? n : g_ring_count;
    for (size_t i = 0; i < count; i++) {
      dst[i] = g_ring[(g_ring_head + i) % FABRIC_WIRE_DETACHED_RING];
    }
    g_ring_head = (g_ring_head + count) % FABRIC_WIRE_DETACHED_RING;
    g_ring_count -= count;
    moved = (int32_t)count;
  }
  pthread_mutex_unlock(&g_env_lock);
  return moved;
}
