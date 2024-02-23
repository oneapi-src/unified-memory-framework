/*
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "provider_os_memory_internal.h"
#include <umf/providers/provider_os_memory.h>

static int os_translate_mem_protection_one_flag(unsigned protection) {
    switch (protection) {
    case UMF_PROTECTION_NONE:
        return PROT_NONE;
    case UMF_PROTECTION_READ:
        return PROT_READ;
    case UMF_PROTECTION_WRITE:
        return PROT_WRITE;
    case UMF_PROTECTION_EXEC:
        return PROT_EXEC;
    }
    assert(0);
    return -1;
}

int os_translate_mem_protection_flags(unsigned protection_flags) {
    // translate protection - combination of 'umf_mem_protection_flags_t' flags
    return os_translate_flags(protection_flags, UMF_PROTECTION_MAX,
                              os_translate_mem_protection_one_flag);
}

static int os_translate_purge_advise(umf_purge_advise_t advise) {
    switch (advise) {
    case UMF_PURGE_LAZY:
        return MADV_FREE;
    case UMF_PURGE_FORCE:
        return MADV_DONTNEED;
    }
    assert(0);
    return -1;
}

void *os_mmap(void *hint_addr, size_t length, int prot) {
    // MAP_ANONYMOUS - the mapping is not backed by any file
    void *ptr =
        mmap(hint_addr, length, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    return ptr;
}

int os_munmap(void *addr, size_t length) { return munmap(addr, length); }

size_t os_get_page_size(void) { return sysconf(_SC_PAGE_SIZE); }

int os_purge(void *addr, size_t length, int advice) {
    return madvise(addr, length, os_translate_purge_advise(advice));
}

void os_strerror(int errnum, char *buf, size_t buflen) {
    strerror_r(errnum, buf, buflen);
}
