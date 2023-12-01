/*
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <umf/providers/provider_os_memory.h>

#include <assert.h>
#include <numaif.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MPOL_LOCAL
#define MPOL_LOCAL 4
#endif

int os_translate_mem_protection_flags(unsigned protection) {
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

int os_translate_mem_visibility(enum umf_mem_visibility visibility) {
    switch (visibility) {
    case UMF_VISIBILITY_SHARED:
        return MAP_SHARED;
    case UMF_VISIBILITY_PRIVATE:
        return MAP_PRIVATE;
    }
    assert(0);
    return -1;
}

int os_translate_numa_mode(enum umf_numa_mode mode) {
    switch (mode) {
    case UMF_NUMA_MODE_DEFAULT:
        return MPOL_DEFAULT;
    case UMF_NUMA_MODE_BIND:
        return MPOL_BIND;
    case UMF_NUMA_MODE_INTERLEAVE:
        return MPOL_INTERLEAVE;
    case UMF_NUMA_MODE_PREFERRED:
        return MPOL_PREFERRED;
    case UMF_NUMA_MODE_LOCAL:
        return MPOL_LOCAL;
    case UMF_NUMA_MODE_STATIC_NODES: // unsupported
        // MPOL_F_STATIC_NODES is undefined
        assert(0);
        return -1;
    case UMF_NUMA_MODE_RELATIVE_NODES: // unsupported
        // MPOL_F_RELATIVE_NODES is undefined
        assert(0);
        return -1;
    }
    assert(0);
    return -1;
}

int os_translate_numa_flags(unsigned numa_flag) {
    switch (numa_flag) {
    case UMF_NUMA_FLAGS_STRICT:
        return MPOL_MF_STRICT;
    case UMF_NUMA_FLAGS_MOVE:
        return MPOL_MF_MOVE;
    case UMF_NUMA_FLAGS_MOVE_ALL:
        return MPOL_MF_MOVE_ALL;
    }
    assert(0);
    return -1;
}

static int os_translate_purge_advise(enum umf_purge_advise advise) {
    switch (advise) {
    case UMF_PURGE_LAZY:
        return MADV_FREE;
    case UMF_PURGE_FORCE:
        return MADV_DONTNEED;
    }
    assert(0);
    return -1;
}

long os_mbind(void *addr, unsigned long len, int mode,
              const unsigned long *nodemask, unsigned long maxnode,
              unsigned flags) {
    return mbind(addr, len, mode, nodemask, maxnode, flags);
}

long os_get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode,
                      void *addr) {
    return get_mempolicy(mode, nodemask, maxnode, addr,
                         MPOL_F_NODE | MPOL_F_ADDR);
}

int os_mmap(void *addr, size_t length, int prot, int flags, int fd, long offset,
            void **out_addr) {
    if (out_addr == NULL) {
        assert(0);
        return -1;
    }

    // MAP_ANONYMOUS - the mapping is not backed by any file
    void *mmap_addr =
        mmap(addr, length, prot, MAP_ANONYMOUS | flags, fd, offset);
    if (mmap_addr == MAP_FAILED) {
        return -1;
    }

    *out_addr = mmap_addr;

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
