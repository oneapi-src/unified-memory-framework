/*
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_OS_MEMORY_PROVIDER_INTERNAL_H
#define UMF_OS_MEMORY_PROVIDER_INTERNAL_H

#include <umf/providers/provider_os_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define __TLS __declspec(thread)
#else
#define __TLS __thread
#endif

int os_translate_flags(unsigned in_flags, unsigned max,
                       int (*translate_flag)(unsigned));

int os_translate_mem_protection_flags(unsigned protection);

int os_translate_mem_visibility(enum umf_mem_visibility visibility);

int os_translate_numa_mode(enum umf_numa_mode mode);

int os_translate_numa_flags(unsigned numa_flag);

long os_mbind(void *addr, size_t len, int mode, const unsigned long *nodemask,
              unsigned long maxnode, unsigned flags);

long os_get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode,
                      void *addr);

int os_mmap(void *addr, size_t length, int prot, int flags, int fd, long offset,
            void **out_addr);

int os_munmap(void *addr, size_t length);

int os_purge(void *addr, size_t length, int advice);

size_t os_get_page_size(void);

void os_strerror(int errnum, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* UMF_OS_MEMORY_PROVIDER_INTERNAL_H */
