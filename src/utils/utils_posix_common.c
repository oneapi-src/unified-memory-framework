/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434 /* Syscall id */
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438 /* Syscall id */
#endif

// maximum value of the off_t type
#define OFF_T_MAX                                                              \
    (sizeof(off_t) == sizeof(long long)                                        \
         ? LLONG_MAX                                                           \
         : (sizeof(off_t) == sizeof(long) ? LONG_MAX : INT_MAX))

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

static void _utils_get_page_size(void) { Page_size = sysconf(_SC_PAGE_SIZE); }

size_t utils_get_page_size(void) {
    utils_init_once(&Page_size_is_initialized, _utils_get_page_size);
    return Page_size;
}

int utils_getpid(void) { return getpid(); }

int utils_gettid(void) {
#ifdef __APPLE__
    uint64_t tid64;
    pthread_threadid_np(NULL, &tid64);
    return (int)tid64;
#else
    // Some older OSes does not have
    // the gettid() function implemented,
    // so let's use the syscall instead:
    return syscall(SYS_gettid);
#endif
}

int utils_close_fd(int fd) { return close(fd); }

#ifndef __APPLE__
static umf_result_t errno_to_umf_result(int err) {
    switch (err) {
    case EBADF:
    case EINVAL:
    case ESRCH:
    case EPERM:
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    case EMFILE:
    case ENOMEM:
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    case ENODEV:
    case ENOSYS:
    case ENOTSUP:
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    default:
        return UMF_RESULT_ERROR_UNKNOWN;
    }
}
#endif

umf_result_t utils_duplicate_fd(int pid, int fd_in, int *fd_out) {
#ifdef __APPLE__
    (void)pid;    // unused
    (void)fd_in;  // unused
    (void)fd_out; // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
#else
    // pidfd_getfd(2) is used to obtain a duplicate of another process's file descriptor.
    // Permission to duplicate another process's file descriptor
    // is governed by a ptrace access mode PTRACE_MODE_ATTACH_REALCREDS check (see ptrace(2))
    // that can be changed using the /proc/sys/kernel/yama/ptrace_scope interface.
    // pidfd_getfd(2) is supported since Linux 5.6
    // pidfd_open(2) is supported since Linux 5.3
    errno = 0;
    int pid_fd = syscall(__NR_pidfd_open, pid, 0);
    if (pid_fd == -1) {
        LOG_PERR("__NR_pidfd_open");
        return errno_to_umf_result(errno);
    }

    int fd_dup = syscall(__NR_pidfd_getfd, pid_fd, fd_in, 0);
    close(pid_fd);
    if (fd_dup == -1) {
        LOG_PERR("__NR_pidfd_open");
        return errno_to_umf_result(errno);
    }

    *fd_out = fd_dup;

    return UMF_RESULT_SUCCESS;
#endif
}

umf_result_t utils_translate_mem_protection_one_flag(unsigned in_protection,
                                                     unsigned *out_protection) {
    switch (in_protection) {
    case UMF_PROTECTION_NONE:
        *out_protection = PROT_NONE;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_READ:
        *out_protection = PROT_READ;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_WRITE:
        *out_protection = PROT_WRITE;
        return UMF_RESULT_SUCCESS;
    case UMF_PROTECTION_EXEC:
        *out_protection = PROT_EXEC;
        return UMF_RESULT_SUCCESS;
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

size_t get_max_file_size(void) { return OFF_T_MAX; }

umf_result_t utils_translate_mem_protection_flags(unsigned in_protection,
                                                  unsigned *out_protection) {
    // translate protection - combination of 'umf_mem_protection_flags_t' flags
    return utils_translate_flags(in_protection, UMF_PROTECTION_MAX,
                                 utils_translate_mem_protection_one_flag,
                                 out_protection);
}

static int utils_translate_purge_advise(umf_purge_advise_t advise) {
    switch (advise) {
    case UMF_PURGE_LAZY:
        return MADV_FREE;
    case UMF_PURGE_FORCE:
        return MADV_DONTNEED;
    }
    return -1;
}

void *utils_mmap(void *hint_addr, size_t length, int prot, int flag, int fd,
                 size_t fd_offset) {
    fd = (fd == 0) ? -1 : fd;
    if (fd == -1) {
        // MAP_ANONYMOUS - the mapping is not backed by any file
        flag |= MAP_ANONYMOUS;
    }

    void *ptr = mmap(hint_addr, length, prot, flag, fd, fd_offset);
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    // this should be unnecessary but pairs of mmap/munmap do not reset
    // asan's user-poisoning flags, leading to invalid error reports
    // Bug 81619: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81619
    utils_annotate_memory_defined(ptr, length);
    return ptr;
}

int utils_munmap(void *addr, size_t length) {
    // this should be unnecessary but pairs of mmap/munmap do not reset
    // asan's user-poisoning flags, leading to invalid error reports
    // Bug 81619: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81619
    utils_annotate_memory_defined(addr, length);
    return munmap(addr, length);
}

int utils_purge(void *addr, size_t length, int advice) {
    return madvise(addr, length, utils_translate_purge_advise(advice));
}

void utils_strerror(int errnum, char *buf, size_t buflen) {
// 'strerror_r' implementation is XSI-compliant (returns 0 on success)
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE
    if (strerror_r(errnum, buf, buflen)) {
#else // 'strerror_r' implementation is GNU-specific (returns pointer on success)
    if (!strerror_r(errnum, buf, buflen)) {
#endif
        LOG_PERR("Retrieving error code description failed");
    }
}

// open a devdax
int utils_devdax_open(const char *path) {
    if (path == NULL) {
        LOG_ERR("empty path");
        return -1;
    }

    if (strstr(path, "/dev/dax") != path) {
        LOG_ERR("path of the file \"%s\" does not start with \"/dev/dax\"",
                path);
        return -1;
    }

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        LOG_PERR("cannot open the file: %s", path);
        return -1;
    }

    struct stat statbuf;
    int ret = stat(path, &statbuf);
    if (ret) {
        LOG_PERR("stat(%s) failed", path);
        close(fd);
        return -1;
    }

    if (!S_ISCHR(statbuf.st_mode)) {
        LOG_ERR("file %s is not a character device", path);
        close(fd);
        return -1;
    }

    return fd;
}

// open a file
int utils_file_open(const char *path) {
    if (!path) {
        LOG_ERR("empty path");
        return -1;
    }

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        LOG_PERR("cannot open the file: %s", path);
    }

    return fd;
}

// open a file or create
int utils_file_open_or_create(const char *path) {
    if (!path) {
        LOG_ERR("empty path");
        return -1;
    }

    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd == -1) {
        LOG_PERR("cannot open/create the file: %s", path);
        return -1;
    }

    LOG_DEBUG("opened/created the file: %s", path);

    return fd;
}
