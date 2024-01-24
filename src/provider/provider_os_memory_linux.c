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

int os_translate_mem_visibility(umf_mem_visibility_t visibility) {
    switch (visibility) {
    case UMF_VISIBILITY_SHARED:
        return MAP_SHARED;
    case UMF_VISIBILITY_PRIVATE:
        return MAP_PRIVATE;
    }
    assert(0);
    return -1;
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

static inline void assert_is_page_aligned(uintptr_t ptr, size_t page_size) {
    assert((ptr & (page_size - 1)) == 0);
    (void)ptr;       // unused in Release build
    (void)page_size; // unused in Release build
}

int os_mmap_aligned(void *hint_addr, size_t length, size_t alignment,
                    size_t page_size, int prot, int flags, int fd, long offset,
                    void **out_addr) {
    assert(out_addr);

    size_t extended_length = length;

    if (alignment > page_size) {
        // We have to increase length by alignment to be able to "cut out"
        // the correctly aligned part of the memory from the mapped region
        // by unmapping the rest: unaligned beginning and unaligned end
        // of this region.
        extended_length += alignment;
    }

    // MAP_ANONYMOUS - the mapping is not backed by any file
    void *ptr = mmap(hint_addr, extended_length, prot, MAP_ANONYMOUS | flags,
                     fd, offset);
    if (ptr == MAP_FAILED) {
        return -1;
    }

    if (alignment > page_size) {
        uintptr_t addr = (uintptr_t)ptr;
        uintptr_t aligned_addr = addr;
        uintptr_t rest_of_div = aligned_addr % alignment;

        if (rest_of_div) {
            aligned_addr += alignment - rest_of_div;
        }

        assert_is_page_aligned(aligned_addr, page_size);

        size_t head_len = aligned_addr - addr;
        if (head_len > 0) {
            munmap(ptr, head_len);
        }

        // tail address has to page-aligned
        uintptr_t tail = aligned_addr + length;
        if (tail & (page_size - 1)) {
            tail = (tail + page_size) & ~(page_size - 1);
        }

        assert_is_page_aligned(tail, page_size);
        assert(tail >= aligned_addr + length);

        size_t tail_len = (addr + extended_length) - tail;
        if (tail_len > 0) {
            munmap((void *)tail, tail_len);
        }

        *out_addr = (void *)aligned_addr;
        return 0;
    }

    *out_addr = ptr;
    return 0;
}

int os_munmap(void *addr, size_t length) { return munmap(addr, length); }

size_t os_get_page_size(void) { return sysconf(_SC_PAGE_SIZE); }

int os_purge(void *addr, size_t length, int advice) {
    return madvise(addr, length, os_translate_purge_advise(advice));
}

void os_strerror(int errnum, char *buf, size_t buflen) {
    strerror_r(errnum, buf, buflen);
}
