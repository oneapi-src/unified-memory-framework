/*
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <umf/providers/provider_os_memory.h>

#include "provider_os_memory_internal.h"
#include "utils_log.h"
#include "utils_sanitizers.h"

// maximum value of the off_t type
#define OFF_T_MAX                                                              \
    (sizeof(off_t) == sizeof(long long)                                        \
         ? LLONG_MAX                                                           \
         : (sizeof(off_t) == sizeof(long) ? LONG_MAX : INT_MAX))

umf_result_t os_translate_mem_protection_one_flag(unsigned in_protection,
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

umf_result_t os_translate_mem_protection_flags(unsigned in_protection,
                                               unsigned *out_protection) {
    // translate protection - combination of 'umf_mem_protection_flags_t' flags
    return os_translate_flags(in_protection, UMF_PROTECTION_MAX,
                              os_translate_mem_protection_one_flag,
                              out_protection);
}

static int os_translate_purge_advise(umf_purge_advise_t advise) {
    switch (advise) {
    case UMF_PURGE_LAZY:
        return MADV_FREE;
    case UMF_PURGE_FORCE:
        return MADV_DONTNEED;
    }
    return -1;
}

void *os_mmap(void *hint_addr, size_t length, int prot, int flag, int fd,
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

int os_munmap(void *addr, size_t length) {
    // this should be unnecessary but pairs of mmap/munmap do not reset
    // asan's user-poisoning flags, leading to invalid error reports
    // Bug 81619: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81619
    utils_annotate_memory_defined(addr, length);
    return munmap(addr, length);
}

size_t os_get_page_size(void) { return sysconf(_SC_PAGE_SIZE); }

int os_purge(void *addr, size_t length, int advice) {
    return madvise(addr, length, os_translate_purge_advise(advice));
}

void os_strerror(int errnum, char *buf, size_t buflen) {
// 'strerror_r' implementation is XSI-compliant (returns 0 on success)
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE
    if (strerror_r(errnum, buf, buflen)) {
#else // 'strerror_r' implementation is GNU-specific (returns pointer on success)
    if (!strerror_r(errnum, buf, buflen)) {
#endif
        LOG_PERR("Retrieving error code description failed");
    }
}
