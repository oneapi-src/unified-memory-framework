/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

/*
 * ctl_debug.c -- implementation of the debug CTL namespace
 */

#include <stdlib.h>
#include <string.h>

#include "ctl/ctl_internal.h"
#include "ctl_debug.h"

static struct ctl ctl_debug;

static int alloc_pattern = 0;
static int enable_logging = 0;
static int log_level = 0;

struct ctl *get_debug_ctl(void) { return &ctl_debug; }

/*
 * CTL_WRITE_HANDLER(alloc_pattern) -- sets the alloc_pattern field in heap
 */
static umf_result_t
CTL_WRITE_HANDLER(alloc_pattern)(void *ctx, umf_ctl_query_source_t source,
                                 void *arg, size_t size,
                                 umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx, (void)size;

    int arg_in = *(int *)arg;
    alloc_pattern = arg_in;
    return UMF_RESULT_SUCCESS;
}

/*
 * CTL_READ_HANDLER(alloc_pattern) -- returns alloc_pattern heap field
 */
static umf_result_t
CTL_READ_HANDLER(alloc_pattern)(void *ctx, umf_ctl_query_source_t source,
                                void *arg, size_t size,
                                umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx, (void)size;

    int *arg_out = arg;
    *arg_out = alloc_pattern;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_WRITE_HANDLER(enable_logging)(void *ctx, umf_ctl_query_source_t source,
                                  void *arg, size_t size,
                                  umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx, (void)size;

    int arg_in = *(int *)arg;
    enable_logging = arg_in;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_READ_HANDLER(enable_logging)(void *ctx, umf_ctl_query_source_t source,
                                 void *arg, size_t size,
                                 umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx, (void)size;

    int *arg_out = arg;
    *arg_out = enable_logging;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_WRITE_HANDLER(log_level)(void *ctx, umf_ctl_query_source_t source,
                             void *arg, size_t size,
                             umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx, (void)size;

    int arg_in = *(int *)arg;
    log_level = arg_in;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_READ_HANDLER(log_level)(void *ctx, umf_ctl_query_source_t source, void *arg,
                            size_t size, umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx, (void)size;

    int *arg_out = arg;
    *arg_out = log_level;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t
CTL_READ_HANDLER(arg_value)(void *ctx, umf_ctl_query_source_t source, void *arg,
                            size_t size, umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)ctx, (void)size;

    if (indexes == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (indexes->next != NULL) {
        // argument list should have exactly one argument
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (strcmp(indexes->name, "arg_test") != 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (indexes->arg_size != sizeof(int)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (indexes->arg == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    int *arg_out = arg;
    *arg_out = *(int *)indexes->arg;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t CTL_READ_HANDLER(CTL_NONAME, final_node)(
    void *ctx, umf_ctl_query_source_t source, void *arg, size_t size,
    umf_ctl_index_utlist_t *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)ctx, (void)size;

    if (indexes == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (indexes->next != NULL) {
        // argument list should have exactly one argument
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (strcmp(indexes->name, "arg_test_final") != 0) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (indexes->arg_size != sizeof(int)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    if (indexes->arg == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    int *arg_out = arg;
    *arg_out = *(int *)indexes->arg;
    return UMF_RESULT_SUCCESS;
}

static const struct ctl_argument CTL_ARG(alloc_pattern) = CTL_ARG_LONG_LONG;

static const struct ctl_argument CTL_ARG(enable_logging) = CTL_ARG_BOOLEAN;

static const struct ctl_argument CTL_ARG(log_level) = CTL_ARG_INT;
static const struct ctl_argument CTL_ARG(arg_test) = CTL_ARG_INT;
static const struct ctl_argument CTL_ARG(arg_test_final) = CTL_ARG_INT;

const umf_ctl_node_t CTL_NODE(arg_test)[] = {CTL_LEAF_RO(arg_value),
                                             CTL_NODE_END};
const umf_ctl_node_t CTL_NODE(arg_test_final)[] = {
    CTL_LEAF_RO(CTL_NONAME, final_node), CTL_NODE_END};

static const umf_ctl_node_t CTL_NODE(heap)[] = {
    CTL_LEAF_RW(alloc_pattern), CTL_LEAF_RW(enable_logging),
    CTL_LEAF_RW(log_level), CTL_NODE_END};

static const umf_ctl_node_t CTL_NODE(debug)[] = {
    CTL_CHILD(heap), CTL_CHILD_WITH_ARG(arg_test),
    CTL_CHILD_WITH_ARG(arg_test_final), CTL_NODE_END};

/*
 * debug_ctl_register -- registers ctl nodes for "debug" module
 */
void debug_ctl_register(struct ctl *ctl) { CTL_REGISTER_MODULE(ctl, debug); }

void initialize_debug_ctl(void) {
    debug_ctl_register(&ctl_debug);
    ctl_init(malloc, free);
}
