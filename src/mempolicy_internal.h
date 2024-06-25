/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMPOLICY_INTERNAL_H
#define UMF_MEMPOLICY_INTERNAL_H 1

#include <umf/mempolicy.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_mempolicy_t {
    umf_mempolicy_membind_t type;
    union {
        struct {
            size_t part_size;
        } interleave;
        struct {
            umf_mempolicy_split_partition_t *part;
            size_t part_len;
        } split;
    } ops;
} umf_mempolicy_t;

typedef const umf_mempolicy_t umf_const_mempolicy_t;

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMPOLICY_INTERNAL_H */
