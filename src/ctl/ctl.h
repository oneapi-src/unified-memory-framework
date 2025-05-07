/*
 *
 * Copyright (C) 2016-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

// This file was originally under following license:
/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright 2016-2020, Intel Corporation */

/*
 * ctl.h -- internal declaration of statistics and control related structures
 */

#ifndef UMF_CTL_H
#define UMF_CTL_H 1

#include <errno.h>
#include <stddef.h>

#include <umf/memory_pool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CTL_MAX_ENTRIES 100

typedef struct ctl_index_utlist {
    const char *name;
    long value;
    struct ctl_index_utlist *next;
} umf_ctl_index_utlist_t;

typedef enum ctl_query_source {
    CTL_UNKNOWN_QUERY_SOURCE,
    /* query executed directly from the program */
    CTL_QUERY_PROGRAMMATIC,
    /* query executed from the config file */
    CTL_QUERY_CONFIG_INPUT,

    MAX_CTL_QUERY_SOURCE
} umf_ctl_query_source_t;

typedef int (*node_callback)(void *ctx, umf_ctl_query_source_t type, void *arg,
                             size_t size, umf_ctl_index_utlist_t *indexes,
                             const char *extra_name,
                             umf_ctl_query_type_t query_type);

enum ctl_node_type {
    CTL_NODE_UNKNOWN,
    CTL_NODE_NAMED,
    CTL_NODE_LEAF,
    CTL_NODE_INDEXED,
    CTL_NODE_SUBTREE,

    MAX_CTL_NODE
};

typedef int (*ctl_arg_parser)(const void *arg, void *dest, size_t dest_size);

struct ctl_argument_parser {
    size_t dest_offset; /* offset of the field inside of the argument */
    size_t dest_size;   /* size of the field inside of the argument */
    ctl_arg_parser parser;
};

struct ctl_argument {
    size_t dest_size;                     /* size of the entire argument */
    struct ctl_argument_parser parsers[]; /* array of 'fields' in arg */
};

#define sizeof_member(t, m) sizeof(((t *)0)->m)

#define CTL_ARG_PARSER(t, p)                                                   \
    { 0, sizeof(t), p }

#define CTL_ARG_PARSER_STRUCT(t, m, p)                                         \
    { offsetof(t, m), sizeof_member(t, m), p }

#define CTL_ARG_PARSER_END                                                     \
    { 0, 0, NULL }

/*
 * CTL Tree node structure, do not use directly. All the necessary functionality
 * is provided by the included macros.
 */
typedef struct ctl_node {
    const char *name;
    enum ctl_node_type type;

    node_callback cb[MAX_CTL_QUERY_TYPE];
    const struct ctl_argument *arg;

    const struct ctl_node *children;
} umf_ctl_node_t;

/*
 * This is the top level node of the ctl tree structure. Each node can contain
 * children and leaf nodes.
 *
 * Internal nodes simply create a new path in the tree whereas child nodes are
 * the ones providing the read/write functionality by the means of callbacks.
 *
 * Each tree node must be NULL-terminated, CTL_NODE_END macro is provided for
 * convenience.
 */
struct ctl {
    umf_ctl_node_t root[CTL_MAX_ENTRIES];
    int first_free;
};

struct ctl *ctl_new(void);
void ctl_delete(struct ctl *c);

void initialize_global_ctl(void);

int ctl_load_config_from_string(struct ctl *ctl, void *ctx,
                                const char *cfg_string);
int ctl_load_config_from_file(struct ctl *ctl, void *ctx, const char *cfg_file);

/* Use through CTL_REGISTER_MODULE, never directly */
void ctl_register_module_node(struct ctl *c, const char *name,
                              struct ctl_node *n);

int ctl_arg_boolean(const void *arg, void *dest, size_t dest_size);
#define CTL_ARG_BOOLEAN                                                        \
    {sizeof(int), {{0, sizeof(int), ctl_arg_boolean}, CTL_ARG_PARSER_END}};

int ctl_arg_integer(const void *arg, void *dest, size_t dest_size);
#define CTL_ARG_INT                                                            \
    {sizeof(int), {{0, sizeof(int), ctl_arg_integer}, CTL_ARG_PARSER_END}};

#define CTL_ARG_LONG_LONG                                                      \
    {                                                                          \
        sizeof(long long), {                                                   \
            {0, sizeof(long long), ctl_arg_integer}, CTL_ARG_PARSER_END        \
        }                                                                      \
    }

int ctl_arg_string(const void *arg, void *dest, size_t dest_size);
#define CTL_ARG_STRING(len)                                                    \
    {len, {{0, len, ctl_arg_string}, CTL_ARG_PARSER_END}};

#define CTL_STR(name) #name

#define CTL_NODE_END                                                           \
    { NULL, CTL_NODE_UNKNOWN, {NULL, NULL, NULL}, NULL, NULL }

#define CTL_NODE(name, ...) ctl_node_##__VA_ARGS__##_##name

int ctl_query(struct ctl *ctl, void *ctx, umf_ctl_query_source_t source,
              const char *name, umf_ctl_query_type_t type, void *arg,
              size_t size);

/* Declaration of a new child node */
#define CTL_CHILD(name, ...)                                                   \
    {                                                                          \
        CTL_STR(name), CTL_NODE_NAMED, {NULL, NULL, NULL}, NULL,               \
            (struct ctl_node *)CTL_NODE(name, __VA_ARGS__)                     \
    }

/* Declaration of a new indexed node */
#define CTL_INDEXED(name, ...)                                                 \
    {                                                                          \
        CTL_STR(name), CTL_NODE_INDEXED, {NULL, NULL, NULL}, NULL,             \
            (struct ctl_node *)CTL_NODE(name, __VA_ARGS__)                     \
    }

#define CTL_READ_HANDLER(name, ...) ctl_##__VA_ARGS__##_##name##_read

#define CTL_WRITE_HANDLER(name, ...) ctl_##__VA_ARGS__##_##name##_write

#define CTL_RUNNABLE_HANDLER(name, ...) ctl_##__VA_ARGS__##_##name##_runnable

#define CTL_SUBTREE_HANDLER(name, ...) ctl_##__VA_ARGS__##_##name##_subtree

#define CTL_ARG(name) ctl_arg_##name

/*
 * Declaration of a new read-only leaf. If used the corresponding read function
 * must be declared by CTL_READ_HANDLER macro.
 */
#define CTL_LEAF_RO(name, ...)                                                 \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF,                                          \
            {CTL_READ_HANDLER(name, __VA_ARGS__), NULL, NULL, NULL}, NULL,     \
            NULL                                                               \
    }

/*
 * Declaration of a new RW leaf. This type of RW leaf doesn't require parsing
 * of the argument. The argument is passed directly to the read/write callback.
 */
#define CTL_LEAF_RW_no_arg(name, ...)                                          \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF,                                          \
            {CTL_READ_HANDLER(name, __VA_ARGS__),                              \
             CTL_WRITE_HANDLER(name, __VA_ARGS__), NULL, NULL},                \
            NULL, NULL                                                         \
    }

/*
 * Declaration of a new write-only leaf. If used the corresponding write
 * function must be declared by CTL_WRITE_HANDLER macro.
 */
#define CTL_LEAF_WO(name, ...)                                                 \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF,                                          \
            {NULL, CTL_WRITE_HANDLER(name, __VA_ARGS__), NULL, NULL},          \
            &CTL_ARG(name), NULL                                               \
    }

/*
 * Declaration of a new runnable leaf. If used the corresponding run
 * function must be declared by CTL_RUNNABLE_HANDLER macro.
 */
#define CTL_LEAF_RUNNABLE(name, ...)                                           \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF,                                          \
            {NULL, NULL, CTL_RUNNABLE_HANDLER(name, __VA_ARGS__), NULL}, NULL, \
            NULL                                                               \
    }

#define CTL_LEAF_SUBTREE(name, ...)                                            \
    {                                                                          \
        CTL_STR(name), CTL_NODE_SUBTREE,                                       \
            {NULL, NULL, NULL, CTL_SUBTREE_HANDLER(name, __VA_ARGS__)}, NULL,  \
            NULL                                                               \
    }

#define CTL_LEAF_SUBTREE2(name, fun, ...)                                      \
    {                                                                          \
        CTL_STR(name), CTL_NODE_SUBTREE,                                       \
            {NULL, NULL, NULL, CTL_SUBTREE_HANDLER(fun, __VA_ARGS__)}, NULL,   \
            NULL                                                               \
    }

/*
 * Declaration of a new read-write leaf. If used both read and write function
 * must be declared by CTL_READ_HANDLER and CTL_WRITE_HANDLER macros.
 */
#define CTL_LEAF_RW(name)                                                      \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF,                                          \
            {CTL_READ_HANDLER(name), CTL_WRITE_HANDLER(name), NULL, NULL},     \
            &CTL_ARG(name), NULL                                               \
    }

#define CTL_REGISTER_MODULE(_ctl, name)                                        \
    ctl_register_module_node((_ctl), CTL_STR(name),                            \
                             (struct ctl_node *)CTL_NODE(name))

#ifdef __cplusplus
}
#endif

#endif
