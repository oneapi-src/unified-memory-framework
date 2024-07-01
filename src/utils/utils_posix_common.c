/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "utils_common.h"
#include "utils_concurrency.h"
#include "utils_log.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434 /* Syscall id */
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438 /* Syscall id */
#endif

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

static void _util_get_page_size(void) { Page_size = sysconf(_SC_PAGE_SIZE); }

size_t util_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _util_get_page_size);
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
