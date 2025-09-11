/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef UMF_CTL_DEFAULTS_H
#define UMF_CTL_DEFAULTS_H 1

#include <stddef.h>
#include <stdarg.h>

#include <umf/base.h>

#include "ctl_internal.h"
#include "utils_concurrency.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ctl_default_entry_t {
    char *name;
    void *value;
    size_t value_size;
    umf_ctl_query_source_t source;
    struct ctl_default_entry_t *next;
} ctl_default_entry_t;

umf_result_t ctl_default_subtree(ctl_default_entry_t **list, utils_mutex_t *mtx,
                                 umf_ctl_query_source_t source, void *arg,
                                 size_t size, const char *extra_name,
                                 umf_ctl_query_type_t queryType);

typedef umf_result_t (*ctl_ext_ctl_fn)(void *obj, umf_ctl_query_source_t source,
                                       const char *name, void *arg, size_t size,
                                       umf_ctl_query_type_t queryType,
                                       va_list args);

void ctl_default_apply(ctl_default_entry_t *list, const char *pname,
                       ctl_ext_ctl_fn ext_ctl, void *priv);

void ctl_default_destroy(ctl_default_entry_t **list, utils_mutex_t *mtx);

#ifdef __cplusplus
}
#endif

#endif /* UMF_CTL_DEFAULTS_H */
