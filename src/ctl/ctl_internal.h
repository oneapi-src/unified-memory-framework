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
 * ctl_internal.h -- internal declaration of statistics and control related structures
 */

#ifndef UMF_CTL_INTERNAL_H
#define UMF_CTL_INTERNAL_H 1

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>

#include <umf/memory_pool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CTL_MAX_ENTRIES 100

typedef struct ctl_index_utlist {
    const char *name;
    void *arg;
    size_t arg_size; /* size of the argument */
    struct ctl_index_utlist *next;
} umf_ctl_index_utlist_t;

typedef umf_result_t (*node_callback)(void *ctx, umf_ctl_query_source_t source,
                                      void *arg, size_t size,
                                      umf_ctl_index_utlist_t *indexes);

typedef umf_result_t (*node_callback_subtree)(
    void *ctx, umf_ctl_query_source_t source, void *arg, size_t size,
    umf_ctl_index_utlist_t *indexes, const char *extra_name,
    umf_ctl_query_type_t query_type, va_list args);

enum ctl_node_type {
    CTL_NODE_UNKNOWN,
    CTL_NODE_NAMED,
    CTL_NODE_LEAF,
    CTL_NODE_SUBTREE,
    MAX_CTL_NODE
};

typedef int (*ctl_arg_parser)(const void *arg, void *dest, size_t dest_size);

typedef enum ctl_arg_type {
    CTL_ARG_TYPE_UNKNOWN = 0,
    CTL_ARG_TYPE_BOOLEAN,
    CTL_ARG_TYPE_STRING,
    CTL_ARG_TYPE_INT,
    CTL_ARG_TYPE_LONG_LONG,
    CTL_ARG_TYPE_UNSIGNED_LONG_LONG,
    CTL_ARG_TYPE_PTR,
    MAX_CTL_ARG_TYPE
} ctl_arg_type_t;

struct ctl_argument_parser {
    size_t dest_offset;  /* offset of the field inside of the argument */
    size_t dest_size;    /* size of the field inside of the argument */
    ctl_arg_type_t type; /* type of the argument */
    ctl_arg_parser parser;
};

struct ctl_argument {
    size_t dest_size;                     /* size of the entire argument */
    struct ctl_argument_parser parsers[]; /* array of 'fields' in arg */
};

#define sizeof_member(type, member) sizeof(((type *)0)->member)

#define CTL_ARG_PARSER(type, vaarg_type, parser)                               \
    { 0, sizeof(type), vaarg_type, parser }

#define CTL_ARG_PARSER_STRUCT(type, member, vaarg_type, parser)                \
    { offsetof(type, member), sizeof_member(type, member), vaarg_type, parser }

#define CTL_ARG_PARSER_END                                                     \
    { 0, 0, 0, NULL }

/*
 * CTL Tree node structure, do not use directly. All the necessary functionality
 * is provided by the included macros.
 */
typedef struct ctl_node {
    const char *name;
    enum ctl_node_type type;

    node_callback read_cb;
    node_callback write_cb;
    node_callback runnable_cb;
    node_callback_subtree subtree_cb;

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

void ctl_init(void *(*Malloc)(size_t), void (*Free)(void *));

umf_result_t ctl_load_config_from_string(struct ctl *ctl, void *ctx,
                                         const char *cfg_string);
umf_result_t ctl_load_config_from_file(struct ctl *ctl, void *ctx,
                                       const char *cfg_file);

/* Use through CTL_REGISTER_MODULE, never directly */
void ctl_register_module_node(struct ctl *c, const char *name,
                              struct ctl_node *n);

int ctl_arg_boolean(const void *arg, void *dest, size_t dest_size);
int ctl_arg_integer(const void *arg, void *dest, size_t dest_size);
int ctl_arg_unsigned(const void *arg, void *dest, size_t dest_size);
int ctl_arg_string(const void *arg, void *dest, size_t dest_size);

#define CTL_ARG_BOOLEAN                                                        \
    {                                                                          \
        sizeof(int), {                                                         \
            {0, sizeof(int), CTL_ARG_TYPE_BOOLEAN, ctl_arg_boolean},           \
                CTL_ARG_PARSER_END                                             \
        }                                                                      \
    }

#define CTL_ARG_INT                                                            \
    {                                                                          \
        sizeof(int), {                                                         \
            {0, sizeof(int), CTL_ARG_TYPE_INT, ctl_arg_integer},               \
                CTL_ARG_PARSER_END                                             \
        }                                                                      \
    }

#define CTL_ARG_LONG_LONG                                                      \
    {                                                                          \
        sizeof(long long), {                                                   \
            {0, sizeof(long long), CTL_ARG_TYPE_LONG_LONG, ctl_arg_integer},   \
                CTL_ARG_PARSER_END                                             \
        }                                                                      \
    }

#define CTL_ARG_UNSIGNED_LONG_LONG                                             \
    {                                                                          \
        sizeof(unsigned long long), {                                          \
            {0, sizeof(unsigned long long), CTL_ARG_TYPE_UNSIGNED_LONG_LONG,   \
             ctl_arg_unsigned},                                                \
                CTL_ARG_PARSER_END                                             \
        }                                                                      \
    }

#define CTL_ARG_STRING(len)                                                    \
    {                                                                          \
        len, {                                                                 \
            {0, len, CTL_ARG_TYPE_STRING, ctl_arg_string}, CTL_ARG_PARSER_END  \
        }                                                                      \
    }

#define CTL_ARG_PTR                                                            \
    {                                                                          \
        sizeof(void *), {                                                      \
            {0, sizeof(void *), CTL_ARG_TYPE_PTR, NULL}, CTL_ARG_PARSER_END    \
        }                                                                      \
    }

#define _CTL_STR(name) #name
#define CTL_STR(name) _CTL_STR(name)

// this macro is only needed because Microsoft cannot implement C99 standard
#define CTL_NONAME CTL_NAMELESS_NODE_

#define CTL_NODE_END                                                           \
    { NULL, CTL_NODE_UNKNOWN, NULL, NULL, NULL, NULL, NULL, NULL }

#define CTL_NODE(name, ...) ctl_node_##__VA_ARGS__##_##name

umf_result_t ctl_query(struct ctl *ctl, void *ctx,
                       umf_ctl_query_source_t source, const char *name,
                       umf_ctl_query_type_t type, void *arg, size_t size,
                       va_list args);

/* Declaration of a new child node */
#define CTL_CHILD(name, ...)                                                   \
    {                                                                          \
        CTL_STR(name), CTL_NODE_NAMED, NULL, NULL, NULL, NULL, NULL,           \
            (struct ctl_node *)CTL_NODE(name, __VA_ARGS__)                     \
    }

/*
 * Declaration of a new child node with an argument
 * This is used to declare that the following node is an argument node, which
 * should be parsed and provided to the handler function in argument list.
 */
#define CTL_CHILD_WITH_ARG(name, ...)                                          \
    {                                                                          \
        CTL_STR(name), CTL_NODE_NAMED, NULL, NULL, NULL, NULL, &CTL_ARG(name), \
            (struct ctl_node *)CTL_NODE(name, __VA_ARGS__)                     \
    }

/* Declaration of a new indexed node */
#define CTL_INDEXED(name, ...)                                                 \
    {                                                                          \
        CTL_STR(name), CTL_NODE_INDEXED, NULL, NULL, NULL, NULL, NULL,         \
            (struct ctl_node *)CTL_NODE(name, __VA_ARGS__)                     \
    }

#define CTL_HANDLER_NAME(name, action, ...)                                    \
    ctl_##__VA_ARGS__##_##name##_##action

#define CTL_READ_HANDLER(name, ...) CTL_HANDLER_NAME(name, read, __VA_ARGS__)
#define CTL_WRITE_HANDLER(name, ...) CTL_HANDLER_NAME(name, write, __VA_ARGS__)

#define CTL_RUNNABLE_HANDLER(name, ...)                                        \
    CTL_HANDLER_NAME(name, runnable, __VA_ARGS__)

#define CTL_SUBTREE_HANDLER(name, ...)                                         \
    CTL_HANDLER_NAME(name, subtree, __VA_ARGS__)

#define CTL_ARG(name) ctl_arg_##name

/*
 * Declaration of a new read-only leaf. If used the corresponding read function
 * must be declared by CTL_READ_HANDLER macro.
 */
#define CTL_LEAF_RO(name, ...)                                                 \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF, CTL_READ_HANDLER(name, __VA_ARGS__),     \
            NULL, NULL, NULL, NULL, NULL                                       \
    }

/*
 * Declaration of a new write-only leaf. If used the corresponding write
 * function must be declared by CTL_WRITE_HANDLER macro.
 */
#define CTL_LEAF_WO(name, ...)                                                 \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF, NULL,                                    \
            CTL_WRITE_HANDLER(name, __VA_ARGS__), NULL, NULL, &CTL_ARG(name),  \
            NULL                                                               \
    }

/*
 * Declaration of a new runnable leaf. If used the corresponding run
 * function must be declared by CTL_RUNNABLE_HANDLER macro.
 */
#define CTL_LEAF_RUNNABLE(name, ...)                                           \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF, NULL, NULL,                              \
            CTL_RUNNABLE_HANDLER(name, __VA_ARGS__), NULL, NULL, NULL          \
    }

#define CTL_LEAF_SUBTREE(name, ...)                                            \
    {                                                                          \
        CTL_STR(name), CTL_NODE_SUBTREE, NULL, NULL, NULL,                     \
            CTL_SUBTREE_HANDLER(name, __VA_ARGS__), NULL, NULL                 \
    }

/*
 * Declaration of a new read-write leaf. If used both read and write function
 * must be declared by CTL_READ_HANDLER and CTL_WRITE_HANDLER macros.
 */
#define CTL_LEAF_RW(name)                                                      \
    {                                                                          \
        CTL_STR(name), CTL_NODE_LEAF, CTL_READ_HANDLER(name),                  \
            CTL_WRITE_HANDLER(name), NULL, NULL, &CTL_ARG(name), NULL          \
    }

#define CTL_REGISTER_MODULE(_ctl, name)                                        \
    ctl_register_module_node((_ctl), CTL_STR(name),                            \
                             (struct ctl_node *)CTL_NODE(name))

#ifdef __cplusplus
}
#endif

#endif /* UMF_CTL_INTERNAL_H */
