// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2018-2021, Intel Corporation */

/*
 * ctl_debug.c -- implementation of the debug CTL namespace
 */

#include "ctl_debug.h"
#include "ctl.h"

static struct ctl *ctl_debug;

static int alloc_pattern = 0;

struct ctl *get_debug_ctl(void) { return ctl_debug; }

/*
 * CTL_WRITE_HANDLER(alloc_pattern) -- sets the alloc_pattern field in heap
 */
static int CTL_WRITE_HANDLER(alloc_pattern, )(void *ctx,
                                              enum ctl_query_source source,
                                              void *arg,
                                              struct ctl_indexes *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    int arg_in = *(int *)arg;
    alloc_pattern = arg_in;
    return 0;
}

/*
 * CTL_READ_HANDLER(alloc_pattern) -- returns alloc_pattern heap field
 */
static int CTL_READ_HANDLER(alloc_pattern, )(void *ctx,
                                             enum ctl_query_source source,
                                             void *arg,
                                             struct ctl_indexes *indexes) {
    /* suppress unused-parameter errors */
    (void)source, (void)indexes, (void)ctx;

    int *arg_out = arg;
    *arg_out = alloc_pattern;
    return 0;
}

static const struct ctl_argument CTL_ARG(alloc_pattern) = CTL_ARG_LONG_LONG;

static const struct ctl_node CTL_NODE(heap, )[] = {CTL_LEAF_RW(alloc_pattern),

                                                   CTL_NODE_END};

static const struct ctl_node CTL_NODE(debug, )[] = {CTL_CHILD(heap, ),

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
