/*
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>

#include "provider_os_memory_internal.h"
#include <umf/providers/provider_os_memory.h>

int os_translate_mem_protection_flags(unsigned protection_flags) {
    // TODO
    assert(0);
    return -1;
}

int os_translate_mem_visibility(umf_mem_visibility_t visibility) {
    // TODO
    assert(0);
    return -1;
}

int os_translate_numa_mode(umf_numa_mode_t mode) {
    // TODO
    assert(0);
    return -1;
}

int os_translate_numa_flags(unsigned numa_flags) {
    // TODO
    assert(0);
    return -1;
}

long os_mbind(void *addr, size_t len, int mode, const unsigned long *nodemask,
              unsigned long maxnode, unsigned flags) {
    // TODO
    assert(0);
    return -1;
}

long os_get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode,
                      void *addr) {
    // TODO
    assert(0);
    return -1;
}

int os_mmap_aligned(void *hint_addr, size_t length, size_t alignment,
                    size_t page_size, int prot, int flags, int fd, long offset,
                    void **out_addr) {
    // TODO
    assert(0);
    return -1;
}

int os_munmap(void *addr, size_t length) {
    // TODO
    assert(0);
    return -1;
}

size_t os_get_page_size(void) {
    // TODO
    assert(0);
    return -1;
}

int os_purge(void *addr, size_t length, int advice) {
    // TODO
    assert(0);
    return -1;
}

void os_strerror(int errnum, char *buf, size_t buflen) {
    // TODO
    assert(0);
}
