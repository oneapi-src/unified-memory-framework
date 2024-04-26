/*
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#ifndef UMF_OS_MEMORY_PROVIDER_INTERNAL_H
#define UMF_OS_MEMORY_PROVIDER_INTERNAL_H

#include "utils_common.h"
#include <umf/providers/provider_os_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum umf_purge_advise_t {
    UMF_PURGE_LAZY,
    UMF_PURGE_FORCE,
} umf_purge_advise_t;

umf_result_t os_translate_flags(unsigned in_flags, unsigned max,
                                umf_result_t (*translate_flag)(unsigned,
                                                               unsigned *),
                                unsigned *out_flags);

umf_result_t os_translate_mem_protection_flags(unsigned in_protection,
                                               unsigned *out_protection);

umf_result_t os_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                              unsigned *out_flag);

int os_create_anonymous_fd(unsigned translated_memory_flag);

size_t get_max_file_size(void);

int os_set_file_size(int fd, size_t size);

void *os_mmap(void *hint_addr, size_t length, int prot, int flag, int fd,
              size_t fd_offset);

int os_munmap(void *addr, size_t length);

int os_purge(void *addr, size_t length, int advice);

size_t os_get_page_size(void);

void os_strerror(int errnum, char *buf, size_t buflen);

int os_getpid(void);

umf_result_t os_duplicate_fd(int pid, int fd_in, int *fd_out);

umf_result_t os_close_fd(int fd);

#ifdef __cplusplus
}
#endif

#endif /* UMF_OS_MEMORY_PROVIDER_INTERNAL_H */
