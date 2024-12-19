/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

/*
 * ctl_debug.c -- implementation of the debug CTL namespace
 */

#include "ctl_debug.h"

static struct ctl *ctl_debug;

static int alloc_pattern = 0;
static int enable_logging = 0;
static int log_level = 0;

struct ctl *get_debug_ctl(void) { return ctl_debug; }

/*
 * CTL_WRITE_HANDLER(alloc_pattern) -- sets the alloc_pattern field in heap
 */
static int CTL_WRITE_HANDLER(alloc_pattern)(void *ctx,
                                            enum ctl_query_source source,
                                            void *arg,
                                            struct ctl_index_utlist *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    int arg_in = *(int *)arg;
    alloc_pattern = arg_in;
    return 0;
}

/*
 * CTL_READ_HANDLER(alloc_pattern) -- returns alloc_pattern heap field
 */
static int CTL_READ_HANDLER(alloc_pattern)(void *ctx,
                                           enum ctl_query_source source,
                                           void *arg,
                                           struct ctl_index_utlist *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    int *arg_out = arg;
    *arg_out = alloc_pattern;
    return 0;
}

static int CTL_WRITE_HANDLER(enable_logging)(void *ctx,
                                             enum ctl_query_source source,
                                             void *arg,
                                             struct ctl_index_utlist *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    int arg_in = *(int *)arg;
    enable_logging = arg_in;
    return 0;
}

static int CTL_READ_HANDLER(enable_logging)(void *ctx,
                                            enum ctl_query_source source,
                                            void *arg,
                                            struct ctl_index_utlist *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    int *arg_out = arg;
    *arg_out = enable_logging;
    return 0;
}

static int CTL_WRITE_HANDLER(log_level)(void *ctx, enum ctl_query_source source,
                                        void *arg,
                                        struct ctl_index_utlist *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    int arg_in = *(int *)arg;
    log_level = arg_in;
    return 0;
}

static int CTL_READ_HANDLER(log_level)(void *ctx, enum ctl_query_source source,
                                       void *arg,
                                       struct ctl_index_utlist *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    int *arg_out = arg;
    *arg_out = log_level;
    return 0;
}

static const struct ctl_argument CTL_ARG(alloc_pattern) = CTL_ARG_LONG_LONG;

static const struct ctl_argument CTL_ARG(enable_logging) = CTL_ARG_BOOLEAN;

static const struct ctl_argument CTL_ARG(log_level) = CTL_ARG_INT;

static const struct ctl_node CTL_NODE(heap)[] = {CTL_LEAF_RW(alloc_pattern),
                                                 CTL_LEAF_RW(enable_logging),
                                                 CTL_LEAF_RW(log_level),

                                                 CTL_NODE_END};

static const struct ctl_node CTL_NODE(debug)[] = {CTL_CHILD(heap),

                                                  CTL_NODE_END};

/*
 * debug_ctl_register -- registers ctl nodes for "debug" module
 */
void debug_ctl_register(struct ctl *ctl) { CTL_REGISTER_MODULE(ctl, debug); }

void initialize_debug_ctl(void) {
    ctl_debug = ctl_new();
    debug_ctl_register(ctl_debug);
}

void deinitialize_debug_ctl(void) { ctl_delete(ctl_debug); }
