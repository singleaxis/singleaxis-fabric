/*
 * Copyright 2026 AI5Labs Research OPC Private Limited
 * SPDX-License-Identifier: Apache-2.0
 *
 * C unit tests of fabric_wire_core.c (spec 055 §4.4), run without Node by
 * scripts/typescript/prebuild/compile.sh c-tests <work-dir>. Built twice: as shipped, and
 * with FABRIC_WIRE_FAULTS, where each injected errno must map to its fixed code.
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fabric_wire_core.h"

static int g_failed;
static char g_dir[3072];
/* Descriptors open before the tables opened anything (stdio, and whatever a CPU emulator
 * or test runner holds). */
static unsigned char g_baseline[256];

#define CHECK(cond)                                                    \
  do {                                                                 \
    if (!(cond)) {                                                     \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
      g_failed++;                                                      \
    }                                                                  \
  } while (0)
#define CHECK_EQ(actual, expected)                                               \
  do {                                                                           \
    long long a_ = (long long)(actual), e_ = (long long)(expected);              \
    if (a_ != e_) {                                                              \
      fprintf(stderr, "FAIL %s:%d: %s = %lld, expected %lld\n", __FILE__,        \
              __LINE__, #actual, a_, e_);                                        \
      g_failed++;                                                                \
    }                                                                            \
  } while (0)

/* The path of a name in the work directory; two calls may be live at once. */
static const char *path_of(const char *name) {
  static char buffers[2][4096];
  static int next;
  char *buffer = buffers[next++ & 1];
  snprintf(buffer, sizeof buffers[0], "%s/%s", g_dir, name);
  return buffer;
}

static int32_t open_named(int32_t dir, const char *name, int create) {
  return fw_open_file(dir, name, strlen(name), create);
}

/* Runs fn in a forked child and returns its exit status (255 when it did not exit). */
static int in_child(int (*fn)(void *), void *arg) {
  fflush(NULL);
  pid_t pid = fork();
  if (pid == 0) _exit(fn(arg));
  int status = 0;
  if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return 255;
  return WEXITSTATUS(status);
}

static void test_errno_codes(void) {
  CHECK_EQ(fw_errno_code(EWOULDBLOCK), FABRIC_WIRE_WOULD_BLOCK);
  CHECK_EQ(fw_errno_code(EAGAIN), FABRIC_WIRE_WOULD_BLOCK);
  CHECK_EQ(fw_errno_code(ENOENT), FABRIC_WIRE_NOT_FOUND);
  CHECK_EQ(fw_errno_code(EEXIST), FABRIC_WIRE_EXISTS);
  CHECK_EQ(fw_errno_code(EACCES), FABRIC_WIRE_PERMISSION);
  CHECK_EQ(fw_errno_code(EPERM), FABRIC_WIRE_PERMISSION);
  CHECK_EQ(fw_errno_code(ENOSPC), FABRIC_WIRE_NO_SPACE);
  CHECK_EQ(fw_errno_code(EDQUOT), FABRIC_WIRE_QUOTA);
  CHECK_EQ(fw_errno_code(EIO), FABRIC_WIRE_IO);
  CHECK_EQ(fw_errno_code(ELOOP), FABRIC_WIRE_UNSAFE_PATH);
  CHECK_EQ(fw_errno_code(EBADF), FABRIC_WIRE_BAD_HANDLE);
  CHECK_EQ(fw_errno_code(EINVAL), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_errno_code(EMFILE), FABRIC_WIRE_LIMIT);
  CHECK_EQ(fw_errno_code(EOPNOTSUPP), FABRIC_WIRE_UNSUPPORTED);
  CHECK_EQ(fw_errno_code(EXDEV), FABRIC_WIRE_OTHER);
  CHECK_EQ(fw_errno_code(0), FABRIC_WIRE_OTHER);
}

static void test_open_dir(void) {
  CHECK_EQ(fw_open_dir(NULL, 0), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_open_dir("", 0), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_open_dir(g_dir, strlen(g_dir) - 1), FABRIC_WIRE_BAD_ARGUMENT);
  const char *missing = path_of("missing");
  CHECK_EQ(fw_open_dir(missing, strlen(missing)), FABRIC_WIRE_NOT_FOUND);

  char open_dir[4096];
  snprintf(open_dir, sizeof open_dir, "%s", path_of("group-readable"));
  CHECK_EQ(mkdir(open_dir, 0700), 0);
  CHECK_EQ(chmod(open_dir, 0750), 0);
  CHECK_EQ(fw_open_dir(open_dir, strlen(open_dir)), FABRIC_WIRE_UNSAFE_PATH);

  char link_path[4096];
  snprintf(link_path, sizeof link_path, "%s", path_of("dir-link"));
  CHECK_EQ(symlink(g_dir, link_path), 0);
  CHECK_EQ(fw_open_dir(link_path, strlen(link_path)), FABRIC_WIRE_UNSAFE_PATH);

  const char *file = path_of("plain-file");
  int fd = open(file, O_CREAT | O_WRONLY, 0600);
  CHECK(fd >= 0);
  close(fd);
  CHECK_EQ(fw_open_dir(file, strlen(file)), FABRIC_WIRE_UNSAFE_PATH);
}

static void test_open_file(int32_t dir) {
  CHECK_EQ(open_named(dir, "absent", 0), FABRIC_WIRE_NOT_FOUND);
  CHECK_EQ(open_named(dir, ".", 1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(open_named(dir, "..", 1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(open_named(dir, "a/b", 1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_open_file(dir, "", 0, 1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_open_file(dir, "ab", 1, 1), FABRIC_WIRE_BAD_ARGUMENT);
  char long_name[300];
  memset(long_name, 'n', sizeof long_name);
  long_name[256] = '\0';
  CHECK_EQ(open_named(dir, long_name, 1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(open_named(12345, "x", 1), FABRIC_WIRE_BAD_HANDLE);
  CHECK_EQ(open_named(0, "x", 1), FABRIC_WIRE_BAD_HANDLE);
  CHECK_EQ(open_named(-3, "x", 1), FABRIC_WIRE_BAD_HANDLE);

  int32_t h = open_named(dir, "created", 1);
  CHECK(h > 0);
  struct stat st;
  CHECK_EQ(stat(path_of("created"), &st), 0);
  CHECK_EQ(st.st_mode & 0777, 0600);
  CHECK_EQ(fw_close(h), 0);

  CHECK_EQ(symlink(path_of("created"), path_of("file-link")), 0);
  CHECK_EQ(open_named(dir, "file-link", 0), FABRIC_WIRE_UNSAFE_PATH);
  CHECK_EQ(link(path_of("created"), path_of("hard-link")), 0);
  CHECK_EQ(open_named(dir, "created", 0), FABRIC_WIRE_UNSAFE_PATH); /* nlink == 2 */
  CHECK_EQ(unlink(path_of("hard-link")), 0);
  CHECK_EQ(chmod(path_of("created"), 0644), 0);
  CHECK_EQ(open_named(dir, "created", 0), FABRIC_WIRE_UNSAFE_PATH);
  CHECK_EQ(chmod(path_of("created"), 0600), 0);
  CHECK_EQ(mkdir(path_of("subdir"), 0700), 0);
  CHECK(open_named(dir, "subdir", 0) < 0);
  CHECK_EQ(mkfifo(path_of("fifo"), 0600), 0);
  CHECK_EQ(open_named(dir, "fifo", 0), FABRIC_WIRE_UNSAFE_PATH); /* and it did not block */
}

/* Every descriptor the tables opened carries FD_CLOEXEC. */
static void test_cloexec(int32_t dir) {
  int before[256], count = 0;
  for (int fd = 0; fd < 256; fd++) before[fd] = fcntl(fd, F_GETFD) >= 0;
  int32_t a = open_named(dir, "cloexec-a", 1);
  const char *d = g_dir;
  int32_t b = fw_open_dir(d, strlen(d));
  CHECK(a > 0 && b > 0);
  for (int fd = 0; fd < 256; fd++) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || before[fd]) continue;
    count++;
    CHECK(flags & FD_CLOEXEC);
  }
  CHECK_EQ(count, 2);
  CHECK_EQ(fw_close(a), 0);
  CHECK_EQ(fw_close(b), 0);
}

static int child_raw_flock(void *arg) {
  int fd = open((const char *)arg, O_RDWR);
  if (fd < 0) return 2;
  if (flock(fd, LOCK_EX | LOCK_NB) == 0) return 1;
  return errno == EWOULDBLOCK ? 0 : 3;
}

static int child_raw_record_lock(void *arg) {
  int fd = open((const char *)arg, O_RDWR);
  if (fd < 0) return 2;
  struct flock inside = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 4, .l_len = 2};
  if (fcntl(fd, F_SETLK, &inside) == 0) return 1;
  if (errno != EAGAIN && errno != EACCES) return 3;
  struct flock outside = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 100, .l_len = 1};
  return fcntl(fd, F_SETLK, &outside) == 0 ? 0 : 4;
}

static void test_locks(int32_t dir) {
  int32_t a = open_named(dir, "locked", 1);
  int32_t b = open_named(dir, "locked", 0);
  CHECK(a > 0 && b > 0 && a != b);
  char path[4096];
  snprintf(path, sizeof path, "%s", path_of("locked"));

  CHECK_EQ(fw_flock(a, 7), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_flock(a, FABRIC_WIRE_FLOCK_EXCLUSIVE), 0);
  CHECK_EQ(fw_flock(b, FABRIC_WIRE_FLOCK_EXCLUSIVE), FABRIC_WIRE_WOULD_BLOCK);
  CHECK_EQ(fw_flock(b, FABRIC_WIRE_FLOCK_SHARED), FABRIC_WIRE_WOULD_BLOCK);
  CHECK_EQ(in_child(child_raw_flock, path), 0);
  CHECK_EQ(fw_flock(a, FABRIC_WIRE_FLOCK_SHARED), 0);
  CHECK_EQ(fw_flock(b, FABRIC_WIRE_FLOCK_SHARED), 0);
  CHECK_EQ(fw_flock(a, FABRIC_WIRE_FLOCK_UNLOCK), 0);
  CHECK_EQ(fw_flock(b, FABRIC_WIRE_FLOCK_UNLOCK), 0);

  CHECK_EQ(fw_record_lock(a, -1, 1, FABRIC_WIRE_RECORD_WRITE), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_record_lock(a, 0, -1, FABRIC_WIRE_RECORD_WRITE), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_record_lock(a, 0, 1, 9), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_record_lock(a, 0, 10, FABRIC_WIRE_RECORD_WRITE), 0);
  CHECK_EQ(in_child(child_raw_record_lock, path), 0);
  CHECK_EQ(fw_record_lock(a, 0, 10, FABRIC_WIRE_RECORD_UNLOCK), 0);
  CHECK_EQ(fw_record_lock(a, 0, 10, FABRIC_WIRE_RECORD_READ), 0);
  CHECK_EQ(fw_record_lock(a, 0, 10, FABRIC_WIRE_RECORD_UNLOCK), 0);
  CHECK_EQ(fw_close(a), 0);
  CHECK_EQ(fw_close(b), 0);
}

static void test_io(int32_t dir) {
  static unsigned char big[FABRIC_WIRE_MAX_IO_BYTES + 1];
  unsigned char back[16];
  int32_t h = open_named(dir, "io", 1);
  CHECK(h > 0);
  CHECK_EQ(fw_pwrite(h, "fabric-wire", 11, 5), 11);
  CHECK_EQ(fw_pread(h, back, sizeof back, 0), 16);
  CHECK(memcmp(back + 5, "fabric-wire", 11) == 0 && back[0] == 0);
  CHECK_EQ(fw_pread(h, back, sizeof back, 1000), 0);
  CHECK_EQ(fw_pwrite(h, big, FABRIC_WIRE_MAX_IO_BYTES, 0), FABRIC_WIRE_MAX_IO_BYTES);
  CHECK_EQ(fw_pwrite(h, big, sizeof big, 0), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_pread(h, big, sizeof big, 0), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_pread(h, back, 1, -1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_pwrite(h, NULL, 1, 0), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_pwrite(h, NULL, 0, 0), 0);
  CHECK_EQ(fw_fsync(h), 0);
  CHECK_EQ(fw_close(h), 0);

  h = open_named(dir, "reserve", 1);
  CHECK_EQ(fw_allocate(h, 0), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_allocate(h, 256 * 1024), 0);
  struct stat st;
  CHECK_EQ(stat(path_of("reserve"), &st), 0);
  CHECK_EQ(st.st_size, 256 * 1024);
  CHECK((long long)st.st_blocks * 512 >= 256 * 1024); /* real blocks, not a hole */
  CHECK_EQ(fw_allocate(h, 4096), 0);                  /* never shrinks */
  CHECK_EQ(stat(path_of("reserve"), &st), 0);
  CHECK_EQ(st.st_size, 256 * 1024);
  CHECK_EQ(fw_close(h), 0);
}

static void test_handles(int32_t dir) {
  int32_t h = open_named(dir, "handles", 1);
  CHECK(h > 0);
  CHECK_EQ(fw_close(h), 0);
  CHECK_EQ(fw_close(h), FABRIC_WIRE_BAD_HANDLE);
  CHECK_EQ(fw_fsync(h), FABRIC_WIRE_BAD_HANDLE);
  int32_t again = open_named(dir, "handles", 0);
  CHECK(again > 0 && again != h); /* same slot, new generation */
  CHECK_EQ(again & FABRIC_WIRE_HANDLE_SLOT_MASK, h & FABRIC_WIRE_HANDLE_SLOT_MASK);
  CHECK_EQ(fw_fsync(h), FABRIC_WIRE_BAD_HANDLE);
  CHECK_EQ(fw_close(again), 0);

  int32_t held[FABRIC_WIRE_FD_HANDLES];
  int n = 0;
  for (;;) {
    int32_t next = open_named(dir, "handles", 0);
    if (next < 0) {
      CHECK_EQ(next, FABRIC_WIRE_LIMIT);
      break;
    }
    CHECK(n < FABRIC_WIRE_FD_HANDLES);
    held[n++] = next;
  }
  CHECK_EQ(n, FABRIC_WIRE_FD_HANDLES - 1); /* dir holds one slot */
  for (int i = 0; i < n; i++) CHECK_EQ(fw_close(held[i]), 0);
  h = open_named(dir, "handles", 0);
  CHECK(h > 0);
  CHECK_EQ(fw_close(h), 0);
}

static void *store_loop(void *arg) {
  int32_t m = *(int32_t *)arg;
  for (int64_t i = 0; i < 20000; i++) {
    if (fw_store64(m, 8, i) != 0 || fw_load64(m, 8) < 0) return (void *)1;
  }
  return NULL;
}

static void *claim_loop(void *arg) {
  int32_t dir = *(int32_t *)arg;
  for (int i = 0; i < 300; i++) {
    int32_t h = open_named(dir, "handles", 0);
    if (h <= 0 || fw_fsync(h) != 0 || fw_close(h) != 0) return (void *)1;
  }
  return NULL;
}

static int child_after_fork(void *arg) {
  int32_t *handles = arg; /* dir, file, map */
  if (!fw_forked()) return 1;
  if (fw_flock(handles[1], FABRIC_WIRE_FLOCK_UNLOCK) != FABRIC_WIRE_FORKED) return 2;
  if (fw_store64(handles[2], 0, 9) != FABRIC_WIRE_FORKED) return 3;
  if (fw_load64(handles[2], 0) != FABRIC_WIRE_FORKED) return 4;
  if (open_named(handles[0], "forked", 1) != FABRIC_WIRE_FORKED) return 5;
  if (fw_open_dir(g_dir, strlen(g_dir)) != FABRIC_WIRE_FORKED) return 6;
  if (fw_close(handles[1]) != FABRIC_WIRE_FORKED) return 7;
  if (fw_env_attach_id() != FABRIC_WIRE_FORKED) return 8;
  if (fw_take_detached(NULL, 0) != FABRIC_WIRE_FORKED) return 9;
  /* The handler closed every inherited table descriptor: only the baseline stays open. */
  for (int fd = 3; fd < 256; fd++) {
    if (!g_baseline[fd] && fcntl(fd, F_GETFD) >= 0) return 10;
  }
  return 0;
}

static void test_maps_and_fork(int32_t dir) {
  int32_t h = open_named(dir, "mirror", 1);
  CHECK(h > 0);
  CHECK_EQ(fw_map_shared(h, 4096), FABRIC_WIRE_BAD_ARGUMENT); /* longer than the file */
  CHECK_EQ(fw_allocate(h, 4096), 0);
  CHECK_EQ(fw_map_shared(h, 0), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_map_shared(h, FABRIC_WIRE_MAX_MAP_BYTES + 1), FABRIC_WIRE_BAD_ARGUMENT);
  int32_t m = fw_map_shared(h, 4096);
  CHECK(m > 0);
  CHECK_EQ(fw_store64(m, 16, 0x0123456789abcdefLL), 0);
  CHECK_EQ(fw_load64(m, 16), 0x0123456789abcdefLL);
  int64_t on_disk = 0;
  CHECK_EQ(fw_pread(h, &on_disk, 8, 16), 8);
  CHECK_EQ(on_disk, 0x0123456789abcdefLL); /* MAP_SHARED: the file sees the store */
  CHECK_EQ(fw_store64(m, 4, 1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_store64(m, 4096, 1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_store64(m, -8, 1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_store64(m, 0, -1), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_load64(m, 4090), FABRIC_WIRE_BAD_ARGUMENT);
  CHECK_EQ(fw_store64(h, 0, 1), FABRIC_WIRE_BAD_HANDLE); /* an fd handle is not a map */
  CHECK_EQ(fw_load64(0, 0), FABRIC_WIRE_BAD_HANDLE);
  CHECK_EQ(fw_retire(999999), FABRIC_WIRE_BAD_HANDLE);

  pthread_t threads[4];
  void *result = NULL;
  for (int i = 0; i < 4; i++) CHECK_EQ(pthread_create(&threads[i], NULL, store_loop, &m), 0);
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(pthread_join(threads[i], &result), 0);
    CHECK(result == NULL);
  }
  for (int i = 0; i < 4; i++) CHECK_EQ(pthread_create(&threads[i], NULL, claim_loop, &dir), 0);
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(pthread_join(threads[i], &result), 0);
    CHECK(result == NULL);
  }

  CHECK_EQ(fw_flock(h, FABRIC_WIRE_FLOCK_EXCLUSIVE), 0);
  int32_t handles[3] = {dir, h, m};
  CHECK_EQ(in_child(child_after_fork, handles), 0);
  /* The child's close released nothing: the parent still holds the flock. */
  char path[4096];
  snprintf(path, sizeof path, "%s", path_of("mirror"));
  CHECK_EQ(in_child(child_raw_flock, path), 0);
  CHECK_EQ(fw_forked(), 0);

  CHECK_EQ(fw_store64(m, 0, 7), 0);
  CHECK_EQ(fw_retire(m), 0);
  CHECK_EQ(fw_store64(m, 0, 8), FABRIC_WIRE_RETIRED);
  CHECK_EQ(fw_load64(m, 0), 7); /* the mapping stays until exit */
  CHECK_EQ(fw_retire(m), 0);

  int maps = 1;
  for (;;) {
    int32_t next = fw_map_shared(h, 4096);
    if (next < 0) {
      CHECK_EQ(next, FABRIC_WIRE_LIMIT);
      break;
    }
    CHECK(++maps <= FABRIC_WIRE_MAP_HANDLES);
  }
  CHECK_EQ(maps, FABRIC_WIRE_MAP_HANDLES);
  CHECK_EQ(fw_close(h), 0);
  CHECK_EQ(fw_load64(m, 0), 7); /* closing the descriptor does not unmap */
}

static void test_env_ring(void) {
  static uint32_t ids[FABRIC_WIRE_DETACHED_RING + 8];
  static int32_t live[FABRIC_WIRE_MAX_LIVE_ENVS];
  CHECK_EQ(fw_take_detached(ids, 8), 0);
  CHECK_EQ(fw_take_detached(NULL, 4), FABRIC_WIRE_BAD_ARGUMENT);
  for (int i = 0; i < FABRIC_WIRE_MAX_LIVE_ENVS; i++) {
    live[i] = fw_env_attach_id();
    CHECK(live[i] > 0 && (i == 0 || live[i] != live[i - 1]));
  }
  CHECK_EQ(fw_env_attach_id(), FABRIC_WIRE_LIMIT);
  fw_env_detached((uint32_t)live[0]);
  fw_env_detached((uint32_t)live[1]);
  fw_env_detached((uint32_t)live[2]);
  CHECK_EQ(fw_take_detached(ids, 2), 2);
  CHECK_EQ(ids[0], live[0]);
  CHECK_EQ(ids[1], live[1]);
  CHECK_EQ(fw_take_detached(ids, 8), 1);
  CHECK_EQ(ids[0], live[2]);
  CHECK(fw_env_attach_id() > 0); /* a slot is live again after a detach */

  /* 1,025 teardowns with no poll: one id is dropped and OVERFLOW is reported once. */
  for (int i = 0; i < FABRIC_WIRE_DETACHED_RING + 1; i++) fw_env_detached(5000u + (uint32_t)i);
  CHECK_EQ(fw_take_detached(ids, 8), FABRIC_WIRE_OVERFLOW);
  CHECK_EQ(fw_take_detached(ids, FABRIC_WIRE_DETACHED_RING + 8), FABRIC_WIRE_DETACHED_RING);
  CHECK_EQ(ids[0], 5000);
  CHECK_EQ(ids[FABRIC_WIRE_DETACHED_RING - 1], 5000 + FABRIC_WIRE_DETACHED_RING - 1);
  CHECK_EQ(fw_take_detached(ids, 8), 0);
}

#ifdef FABRIC_WIRE_FAULTS
/* argv: <work-dir> fault <op>. Exits with the negated code of the faulted operation. */
static int fault_child(const char *op) {
  int32_t dir = fw_open_dir(g_dir, strlen(g_dir));
  if (strcmp(op, "openDir") == 0 || strcmp(op, "forked") == 0) return -dir;
  if (strcmp(op, "abi") == 0) return fw_test_abi_version();
  if (strcmp(op, "ring") == 0) return -fw_take_detached(NULL, 0);
  int32_t h = open_named(dir, "fault", 1);
  if (strcmp(op, "openFile") == 0) return -h;
  int32_t other = open_named(dir, "fault", 0);
  unsigned char byte = 0;
  if (strcmp(op, "flock") == 0) {
    (void)fw_flock(h, FABRIC_WIRE_FLOCK_EXCLUSIVE);
    return -fw_flock(other, FABRIC_WIRE_FLOCK_EXCLUSIVE);
  }
  if (strcmp(op, "recordLock") == 0) return -fw_record_lock(h, 0, 1, FABRIC_WIRE_RECORD_WRITE);
  if (strcmp(op, "pread") == 0) return -fw_pread(h, &byte, 1, 0);
  if (strcmp(op, "pwrite") == 0) return -fw_pwrite(h, &byte, 1, 0);
  if (strcmp(op, "fsync") == 0) return -fw_fsync(h);
  if (strcmp(op, "allocate") == 0) return -fw_allocate(h, 4096);
  (void)fw_allocate(h, 4096);
  if (strcmp(op, "mapShared") == 0) return -fw_map_shared(h, 4096);
  return 99;
}

static void test_faults(const char *self) {
  static const struct {
    const char *fault, *op;
    int expected;
  } rows[] = {
      {"openDir=EACCES", "openDir", -FABRIC_WIRE_PERMISSION},
      {"openFile=EEXIST", "openFile", -FABRIC_WIRE_EXISTS},
      {"openFile=EMFILE", "openFile", -FABRIC_WIRE_LIMIT},
      {"flock=EOPNOTSUPP", "flock", -FABRIC_WIRE_UNSUPPORTED},
      {"flock=ignore", "flock", 0},
      {"recordLock=EOPNOTSUPP", "recordLock", -FABRIC_WIRE_UNSUPPORTED},
      {"pread=EIO", "pread", -FABRIC_WIRE_IO},
      {"pwrite=ENOSPC", "pwrite", -FABRIC_WIRE_NO_SPACE},
      {"pwrite=EDQUOT", "pwrite", -FABRIC_WIRE_QUOTA},
      {"fsync=EIO", "fsync", -FABRIC_WIRE_IO},
      {"allocate=ENOSPC", "allocate", -FABRIC_WIRE_NO_SPACE},
      {"mapShared=EXDEV", "mapShared", -FABRIC_WIRE_OTHER},
      {"forked=1", "forked", -FABRIC_WIRE_FORKED},
      {"abi=2", "abi", 2},
      {"ring=overflow", "ring", -FABRIC_WIRE_OVERFLOW},
  };
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
      setenv("FABRIC_WIRE_TEST_FAULT", rows[i].fault, 1);
      execl(self, self, g_dir, "fault", rows[i].op, (char *)NULL);
      _exit(120);
    }
    int status = 0;
    CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    if (WEXITSTATUS(status) != rows[i].expected) {
      fprintf(stderr, "FAIL fault %s: exit %d, expected %d\n", rows[i].fault,
              WEXITSTATUS(status), rows[i].expected);
      g_failed++;
    }
  }
}
#endif

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <work-dir> (an existing directory the test may write in)\n",
            argv[0]);
    return 2;
  }
#ifdef FABRIC_WIRE_FAULTS
  if (argc == 4 && strcmp(argv[2], "fault") == 0) {
    snprintf(g_dir, sizeof g_dir, "%s", argv[1]);
    return fault_child(argv[3]);
  }
#endif
  snprintf(g_dir, sizeof g_dir, "%s/core-XXXXXX", argv[1]);
  if (mkdtemp(g_dir) == NULL) {
    perror("mkdtemp");
    return 2;
  }
  for (int fd = 0; fd < 256; fd++) g_baseline[fd] = fcntl(fd, F_GETFD) >= 0;
  test_errno_codes();
  test_open_dir();
  int32_t dir = fw_open_dir(g_dir, strlen(g_dir));
  CHECK(dir > 0);
  test_open_file(dir);
  test_cloexec(dir);
  test_locks(dir);
  test_io(dir);
  test_handles(dir);
  test_maps_and_fork(dir);
  test_env_ring();
#ifdef FABRIC_WIRE_FAULTS
  test_faults(argv[0]);
#endif
  CHECK_EQ(fw_close(dir), 0);
  if (g_failed != 0) {
    fprintf(stderr, "fabric_wire_core_test: %d check(s) failed\n", g_failed);
    return 1;
  }
  printf("fabric_wire_core_test: ok\n");
  return 0;
}
