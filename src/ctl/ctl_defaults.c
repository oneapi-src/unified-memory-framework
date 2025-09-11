/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "ctl_defaults.h"

#include <string.h>

#include "base_alloc_global.h"
#include "utils_concurrency.h"
#include "utils_log.h"
#include "utlist.h"

static umf_result_t default_ctl_helper(ctl_ext_ctl_fn fn, void *ctl,
                                       const char *name, void *arg, size_t size,
                                       ...) {
    va_list empty_args;
    va_start(empty_args, size);
    umf_result_t ret = fn(ctl, CTL_QUERY_PROGRAMMATIC, name, arg, size,
                          CTL_QUERY_WRITE, empty_args);
    va_end(empty_args);
    return ret;
}

umf_result_t ctl_default_subtree(ctl_default_entry_t **list, utils_mutex_t *mtx,
                                 umf_ctl_query_source_t source, void *arg,
                                 size_t size, const char *extra_name,
                                 umf_ctl_query_type_t queryType) {
    (void)source;
    if (strstr(extra_name, "{}") != NULL) {
        LOG_ERR("%s, default setting do not support wildcard parameters {}",
                extra_name);
        return UMF_RESULT_ERROR_NOT_SUPPORTED;
    }

    utils_mutex_lock(mtx);

    ctl_default_entry_t *entry = NULL;
    LL_FOREACH(*list, entry) {
        if (strcmp(entry->name, extra_name) == 0) {
            break;
        }
    }

    if (queryType == CTL_QUERY_WRITE) {
        bool is_new_entry = false;
        if (!entry) {
            entry = umf_ba_global_alloc(sizeof(*entry));
            if (!entry) {
                utils_mutex_unlock(mtx);
                return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
            }
            entry->name = NULL;
            entry->value = NULL;
            entry->next = NULL;
            is_new_entry = true;
        }

        char *new_name = umf_ba_global_strdup(extra_name);
        if (!new_name) {
            utils_mutex_unlock(mtx);
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }

        if (entry->name) {
            umf_ba_global_free(entry->name);
        }
        entry->name = new_name;

        void *new_value = NULL;
        if (size > 0) {
            new_value = umf_ba_global_alloc(size);
            if (!new_value) {
                utils_mutex_unlock(mtx);
                return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
            }
            memcpy(new_value, arg, size);
        }
        if (entry->value) {
            umf_ba_global_free(entry->value);
        }
        entry->value = new_value;
        entry->value_size = size;
        entry->source = source;

        if (is_new_entry) {
            LL_APPEND(*list, entry);
        }
    } else if (queryType == CTL_QUERY_READ) {
        if (!entry) {
            LOG_WARN("Wrong path name: %s", extra_name);
            utils_mutex_unlock(mtx);
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }

        if (entry->value_size > size) {
            LOG_ERR("Provided buffer size %zu is smaller than field size %zu",
                    size, entry->value_size);
            utils_mutex_unlock(mtx);
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        memcpy(arg, entry->value, entry->value_size);
    }

    utils_mutex_unlock(mtx);
    return UMF_RESULT_SUCCESS;
}

void ctl_default_apply(ctl_default_entry_t *list, const char *pname,
                       ctl_ext_ctl_fn ext_ctl, void *priv) {
    if (!pname || !ext_ctl) {
        return;
    }

    size_t pname_len = strlen(pname);
    ctl_default_entry_t *it = NULL;
    LL_FOREACH(list, it) {
        if (strlen(it->name) > pname_len + 1 &&
            strncmp(it->name, pname, pname_len) == 0 &&
            it->name[pname_len] == '.') {
            const char *ctl_name = it->name + pname_len + 1;
            default_ctl_helper(ext_ctl, priv, ctl_name, it->value,
                               it->value_size);
        }
    }
}

void ctl_default_destroy(ctl_default_entry_t **list, utils_mutex_t *mtx) {
    utils_mutex_lock(mtx);
    ctl_default_entry_t *entry = NULL, *tmp = NULL;
    LL_FOREACH_SAFE(*list, entry, tmp) {
        LL_DELETE(*list, entry);
        if (entry->name) {
            umf_ba_global_free(entry->name);
        }
        if (entry->value) {
            umf_ba_global_free(entry->value);
        }
        umf_ba_global_free(entry);
    }
    utils_mutex_unlock(mtx);
}
