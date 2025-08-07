/*
 *
 * Copyright (C) 2016-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

// This file was originally under following license:
// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2024, Intel Corporation */

/*
 * ctl.c -- implementation of the interface for examination and modification of
 *    the library's internal state
 */

#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf/base.h>

#include "base_alloc/base_alloc_global.h"
#include "ctl_internal.h"
#include "uthash/utlist.h"
#include "utils/utils_common.h"
#include "utils_log.h"

#ifdef _WIN32
#define strtok_r strtok_s
#endif

#define MAX_CONFIG_FILE_LEN (1 << 20) /* 1 megabyte */

#define CTL_STRING_QUERY_SEPARATOR ";"
#define CTL_NAME_VALUE_SEPARATOR "="
#define CTL_QUERY_NODE_SEPARATOR "."
#define CTL_VALUE_ARG_SEPARATOR ","
#define CTL_WILDCARD "{}"

/* GLOBAL TREE */
static int ctl_global_first_free = 0;
static umf_ctl_node_t CTL_NODE(global)[CTL_MAX_ENTRIES];

static void *(*ctl_malloc_fn)(size_t) = NULL;
static void (*ctl_free_fn)(void *) = NULL;

void ctl_init(void *(*Malloc)(size_t), void (*Free)(void *)) {
    if (Malloc) {
        ctl_malloc_fn = Malloc;
    }
    if (Free) {
        ctl_free_fn = Free;
    }
}

typedef struct optional_umf_result_t {
    bool is_valid;
    umf_result_t value;
} optional_umf_result_t;

void *Zalloc(size_t sz) {
    void *ptr = ctl_malloc_fn(sz);
    if (ptr) {
        memset(ptr, 0, sz);
    }
    return ptr;
}

char *Strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = ctl_malloc_fn(len);
    if (p) {
        memcpy(p, s, len);
    }
    return p;
}

// this must be a macro as passing a va_list to a function makes the va_list
// in the original function indeterminate if the function invokes the va_arg macro.
// Ref 7.15/3 of C99 standard
#define pop_va_list(va, ctl_argument, output)                                  \
    do {                                                                       \
        switch (ctl_argument->type) {                                          \
        case CTL_ARG_TYPE_BOOLEAN: {                                           \
            int b = va_arg(va, int);                                           \
            *(bool *)output = b ? true : false;                                \
            break;                                                             \
        }                                                                      \
        case CTL_ARG_TYPE_STRING: {                                            \
            char *str = va_arg(va, char *);                                    \
            snprintf((char *)output, ctl_argument->dest_size, "%s", str);      \
            break;                                                             \
        }                                                                      \
        case CTL_ARG_TYPE_INT: {                                               \
            int i = va_arg(va, int);                                           \
            *(int *)output = i;                                                \
            break;                                                             \
        }                                                                      \
        case CTL_ARG_TYPE_LONG_LONG: {                                         \
            long long ll = va_arg(va, long long);                              \
            *(long long *)output = ll;                                         \
            break;                                                             \
        }                                                                      \
        case CTL_ARG_TYPE_UNSIGNED_LONG_LONG: {                                \
            unsigned long long ll = va_arg(va, unsigned long long);            \
            *(unsigned long long *)output = ll;                                \
            break;                                                             \
        }                                                                      \
        case CTL_ARG_TYPE_PTR: {                                               \
            void *ptr = va_arg(va, void *);                                    \
            *(uintptr_t *)output = (uintptr_t)ptr;                             \
            break;                                                             \
        }                                                                      \
        default:                                                               \
            LOG_FATAL("Unknown ctl argument type %d", ctl_argument->type);     \
            abort();                                                           \
        }                                                                      \
    } while (false)

/*
 * ctl_delete_indexes --
 *    (internal) removes and frees all entries on the index list
 */
static void ctl_delete_indexes(umf_ctl_index_utlist_t *indexes) {
    if (!indexes) {
        return;
    }
    umf_ctl_index_utlist_t *elem, *tmp;
    LL_FOREACH_SAFE(indexes, elem, tmp) {
        LL_DELETE(indexes, elem);
        if (elem) {
            if (elem->arg) {
                ctl_free_fn(elem->arg);
            }
            ctl_free_fn(elem);
        }
    }
}

/*
 * ctl_query_cleanup_real_args -- (internal) cleanups relevant argument
 *    structures allocated as a result of the get_real_args call
 */
static void ctl_query_cleanup_real_args(const umf_ctl_node_t *n, void *real_arg,
                                        umf_ctl_query_source_t source) {
    /* suppress unused-parameter errors */
    (void)n;

    switch (source) {
    case CTL_QUERY_CONFIG_INPUT:
        ctl_free_fn(real_arg);
        break;
    case CTL_QUERY_PROGRAMMATIC:
        break;
    default:
        break;
    }
}

/*
 * ctl_parse_args -- (internal) parses a string argument based on the node
 *    structure
 */
static void *ctl_parse_args(const struct ctl_argument *arg_proto, char *arg) {
    char *dest_arg = ctl_malloc_fn(arg_proto->dest_size);
    if (dest_arg == NULL) {
        return NULL;
    }

    char *sptr = NULL;
    char *arg_sep = strtok_r(arg, CTL_VALUE_ARG_SEPARATOR, &sptr);
    for (const struct ctl_argument_parser *p = arg_proto->parsers;
         p->parser != NULL; ++p) {

        if (p->parser(arg_sep, dest_arg + p->dest_offset, p->dest_size) != 0) {
            goto error_parsing;
        }

        arg_sep = strtok_r(NULL, CTL_VALUE_ARG_SEPARATOR, &sptr);
    }

    return dest_arg;

error_parsing:
    ctl_free_fn(dest_arg);
    return NULL;
}

/*
 * ctl_query_get_real_args -- (internal) returns a pointer with actual argument
 *    structure as required by the node callback
 */
static void *ctl_query_get_real_args(const umf_ctl_node_t *n, void *write_arg,
                                     umf_ctl_query_source_t source) {
    void *real_arg = NULL;
    switch (source) {
    case CTL_QUERY_CONFIG_INPUT:
        real_arg = ctl_parse_args(n->arg, write_arg);
        break;
    case CTL_QUERY_PROGRAMMATIC:
        real_arg = write_arg;
        break;
    default:
        break;
    }

    return real_arg;
}

/*
 * ctl_exec_query_read -- (internal) calls the read callback of a node
 */
static umf_result_t ctl_exec_query_read(void *ctx, const umf_ctl_node_t *n,
                                        umf_ctl_query_source_t source,
                                        void *arg, size_t size,
                                        umf_ctl_index_utlist_t *indexes) {
    assert(n != NULL);

    if (n->read_cb == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (arg == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return n->read_cb(ctx, source, arg, size, indexes);
}

/*
 * ctl_exec_query_write -- (internal) calls the write callback of a node
 */
static umf_result_t ctl_exec_query_write(void *ctx, const umf_ctl_node_t *n,
                                         umf_ctl_query_source_t source,
                                         void *arg, size_t size,
                                         umf_ctl_index_utlist_t *indexes) {
    assert(n != NULL);

    if (n->write_cb == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (arg == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    void *real_arg = ctl_query_get_real_args(n, arg, source);
    if (real_arg == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_result_t ret = n->write_cb(ctx, source, real_arg, size, indexes);
    ctl_query_cleanup_real_args(n, real_arg, source);

    return ret;
}

/*
 * ctl_exec_query_runnable -- (internal) calls the run callback of a node
 */
static umf_result_t ctl_exec_query_runnable(void *ctx, const umf_ctl_node_t *n,
                                            umf_ctl_query_source_t source,
                                            void *arg, size_t size,
                                            umf_ctl_index_utlist_t *indexes) {
    assert(n != NULL);

    if (n->runnable_cb == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    return n->runnable_cb(ctx, source, arg, size, indexes);
}

static umf_result_t
ctl_exec_query_subtree(void *ctx, const umf_ctl_node_t *n,
                       umf_ctl_query_source_t source, void *arg, size_t size,
                       umf_ctl_index_utlist_t *indexes, const char *extra_name,
                       umf_ctl_query_type_t query_type, va_list args) {
    assert(n != NULL);

    if (n->subtree_cb == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    return n->subtree_cb(ctx, source, arg, size, indexes, extra_name,
                         query_type, args);
}

/*
 * ctl_find_and_execulte_node -- (internal) searches for a matching entry point in the
 *    provided nodes
 *
 * Name offset is used to return the offset of the name in the query string.
 * The caller is responsible for freeing all of the allocated indexes,
 * regardless of the return value.
 */

static optional_umf_result_t
ctl_find_and_execute_node(const umf_ctl_node_t *nodes, void *ctx,
                          umf_ctl_query_source_t source, const char *name,
                          umf_ctl_query_type_t type, void *arg, size_t size,
                          va_list args) {
    assert(nodes != NULL);
    assert(name != NULL);

    const umf_ctl_node_t *n = NULL;
    optional_umf_result_t ret;
    size_t name_offset = 0;
    ret.is_valid = true;
    ret.value = UMF_RESULT_SUCCESS;
    char *sptr = NULL;
    char *parse_str = Strdup(name);
    if (parse_str == NULL) {
        ret.is_valid = false;
        return ret;
    }

    umf_ctl_index_utlist_t *indexes = Zalloc(sizeof(*indexes));
    if (!indexes) {
        ret.value = UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        return ret;
    }
    char *node_name = strtok_r(parse_str, CTL_QUERY_NODE_SEPARATOR, &sptr);

    /*
     * Go through the string and separate tokens that correspond to nodes
     * in the main ctl tree.
     */
    while (node_name != NULL) {
        char *next_node = strtok_r(NULL, CTL_QUERY_NODE_SEPARATOR, &sptr);
        name_offset = node_name - parse_str;
        if (n != NULL && n->type == CTL_NODE_SUBTREE) {
            // if a subtree occurs, the subtree handler should be called
            break;
        }

        if (strcmp(node_name, CTL_WILDCARD) == 0) {
            if (source == CTL_QUERY_CONFIG_INPUT) {
                LOG_ERR("ctl {} wildcard is not supported for config input");
                goto error;
            }
            // node is wildcard - we are expecting standard node name here, so lets
            // pop next node_name from the va_list
            node_name = va_arg(args, char *);
        }

        if (!nodes) {
            goto error;
        }

        for (n = &nodes[0]; n->type != CTL_NODE_UNKNOWN; ++n) {
            if (n->name && strcmp(n->name, node_name) == 0) {
                if (n->type == CTL_NODE_LEAF && next_node != NULL) {
                    // this is not the last node in the query, so it couldn't be leaf
                    continue;
                }
                if (n->type != CTL_NODE_LEAF && next_node == NULL) {
                    // this is the last node in the query, so it must be a leaf
                    continue;
                }
                break;
            }
        }

        if (n->type == CTL_NODE_UNKNOWN) {
            goto error;
        }

        if (n->arg != NULL && n->type == CTL_NODE_NAMED) {
            if (next_node == NULL) {
                // if the node has an argument, but no next node, then it is an error
                goto error;
            }

            char *node_arg = ctl_malloc_fn(n->arg->dest_size);
            if (node_arg == NULL) {
                goto error;
            }

            // Parse this argument. It might contain "struct" which is series of fields separated by comma.
            // each field contains separate parser in the parsers array.
            for (const struct ctl_argument_parser *p = n->arg->parsers;
                 p->dest_size != 0; ++p) {

                if (next_node && strcmp(next_node, CTL_WILDCARD) == 0) {
                    if (source == CTL_QUERY_CONFIG_INPUT) {
                        ctl_free_fn(node_arg);
                        LOG_ERR("ctl {} wildcard is not supported for config "
                                "input");
                        goto error;
                    }

                    if (p->type == CTL_ARG_TYPE_UNKNOWN) {
                        ctl_free_fn(node_arg);
                        LOG_ERR("ctl {} wildcard is not supported for node: %s",
                                node_name);
                        goto error;
                    }
                    char *output = node_arg + p->dest_offset;
                    pop_va_list(args, p, output);
                } else {
                    if (!p->parser) {
                        LOG_ERR(
                            "this node can be passed only as {} wildcard: %s",
                            next_node);
                        ctl_free_fn(node_arg);
                        goto error;
                    }
                    int r = p->parser(next_node, node_arg + p->dest_offset,
                                      p->dest_size);
                    if (r < 0) {
                        // Parsing failed — cleanup and propagate error
                        ctl_free_fn(node_arg);
                        goto error;
                    } else if (r > 0) {
                        // Parser did not consume next_node, which means this argument is optional
                        // and not present. Optional arguments are always at the end of the expected
                        // sequence, so we can safely stop parsing here.
                        //
                        // Example:
                        // Given two paths:
                        // "umf.pool.by_name.name.stats.allocs"
                        // "umf.pool.by_name.name.1.stats.allocs"
                        // The parser for 'by_name' expects the next node is string followed by optional
                        // integer index, if its sees "stats" instead of integer, like in second example
                        // it will return >0 to signal that the optional
                        // integer argument is not present.
                        // This allows the remaining nodes ("stats.allocs") to be parsed normally
                        // without treating "stats" as part of 'by_name'.
                        break;
                    }
                }
                // we parsed next_node as an argument so we next one
                next_node = strtok_r(NULL, CTL_QUERY_NODE_SEPARATOR, &sptr);
            }

            umf_ctl_index_utlist_t *entry = NULL;
            entry = ctl_malloc_fn(sizeof(*entry));
            if (entry == NULL) {
                ctl_free_fn(node_arg);
                goto error;
            }

            entry->arg = node_arg;
            entry->name = node_name;
            entry->arg_size = n->arg->dest_size;

            LL_APPEND(indexes, entry);

            if (next_node == NULL) {
                // last node was a node with arg, but there is no next mode.
                // check if there is nameless leaf on next level
                for (n = n->children; n->type != CTL_NODE_UNKNOWN; ++n) {
                    if (n->type == CTL_NODE_LEAF &&
                        strcmp(n->name, CTL_STR(CTL_NONAME)) == 0) {
                        // found a nameless leaf, so we can return it
                        break;
                    }
                }

                if (n->type == CTL_NODE_UNKNOWN) {
                    goto error;
                }
            } else if (n->children) {
                // if there is nameless subtree in the next node we should also stop here.
                // This is the HACK which forbids mixing subtree and normal nodes as a child of the
                // node with an argument. Probably no one will ever need to do so, so this is fine.
                for (const umf_ctl_node_t *m = n->children;
                     m->type != CTL_NODE_UNKNOWN; ++m) {
                    if (m->type == CTL_NODE_SUBTREE &&
                        strcmp(m->name, CTL_STR(CTL_NONAME)) == 0) {
                        // found a nameless subtree, so lets assign it as a current node
                        n = m;
                        break;
                    }
                }
            }
        }

        nodes = n->children;
        node_name = next_node;
    }

    // if the appropriate node (leaf or subtree) is not found, then return error
    if (n == NULL ||
        (n->type != CTL_NODE_LEAF && n->type != CTL_NODE_SUBTREE)) {
        ret.value = UMF_RESULT_ERROR_INVALID_ARGUMENT;
        goto out;
    }

    if (n->type == CTL_NODE_SUBTREE) {
        // if the node is a subtree, then we need to call the subtree handler
        ret.value =
            ctl_exec_query_subtree(ctx, n, source, arg, size, indexes->next,
                                   name + name_offset, type, args);
    } else {
        switch (type) {
        case CTL_QUERY_READ:
            ret.value =
                ctl_exec_query_read(ctx, n, source, arg, size, indexes->next);
            break;
        case CTL_QUERY_WRITE:
            ret.value =
                ctl_exec_query_write(ctx, n, source, arg, size, indexes->next);
            break;
        case CTL_QUERY_RUNNABLE:
            ret.value = ctl_exec_query_runnable(ctx, n, source, arg, size,
                                                indexes->next);
            break;
        }
    }
out:
    ctl_free_fn(parse_str);
    ctl_delete_indexes(indexes);
    return ret;

error:
    ctl_delete_indexes(indexes);
    ctl_free_fn(parse_str);
    ret.is_valid = false;
    return ret;
}

/*
 * ctl_query -- (internal) parses the name and calls the appropriate methods
 *    from the ctl tree
 */
umf_result_t ctl_query(struct ctl *ctl, void *ctx,
                       umf_ctl_query_source_t source, const char *name,
                       umf_ctl_query_type_t type, void *arg, size_t size,
                       va_list args) {
    if (name == NULL) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    va_list args_copy;
    va_copy(args_copy, args);

    optional_umf_result_t ret = ctl_find_and_execute_node(
        CTL_NODE(global), ctx, source, name, type, arg, size, args_copy);

    if (ret.is_valid == false && ctl) {
        ret = ctl_find_and_execute_node(ctl->root, ctx, source, name, type, arg,
                                        size, args);
    }

    va_end(args_copy);

    return ret.is_valid ? ret.value : UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

/*
 * ctl_register_module_node -- adds a new node to the CTL tree root.
 */
void ctl_register_module_node(struct ctl *c, const char *name,
                              umf_ctl_node_t *n) {
    umf_ctl_node_t *nnode = c == NULL
                                ? &CTL_NODE(global)[ctl_global_first_free++]
                                : &c->root[c->first_free++];

    nnode->children = n;
    nnode->type = CTL_NODE_NAMED;
    nnode->name = name;
}

/*
 * ctl_parse_query -- (internal) splits an entire query string
 *    into name and value
 */
static int ctl_parse_query(char *qbuf, char **name, char **value) {
    if (qbuf == NULL) {
        return -1;
    }

    char *sptr = NULL;
    *name = strtok_r(qbuf, CTL_NAME_VALUE_SEPARATOR, &sptr);
    if (*name == NULL) {
        return -1;
    }

    *value = strtok_r(NULL, CTL_NAME_VALUE_SEPARATOR, &sptr);
    if (*value == NULL) {
        return -1;
    }

    /* the value itself mustn't include CTL_NAME_VALUE_SEPARATOR */
    char *extra = strtok_r(NULL, CTL_NAME_VALUE_SEPARATOR, &sptr);
    if (extra != NULL) {
        return -1;
    }

    return 0;
}

/*
 * ctl_load_config_helper -- windows do not allow to use uninitialized va_list,
 * so this function allows us to initialize empty one
 */
static umf_result_t ctl_load_config_helper(struct ctl *ctl, void *ctx,
                                           char *buf, ...) {
    umf_result_t ret = UMF_RESULT_SUCCESS;
    char *sptr = NULL; /* for internal use of strtok */
    char *name;
    char *value;
    char *qbuf = strtok_r(buf, CTL_STRING_QUERY_SEPARATOR, &sptr);
    va_list empty_args;
    va_start(empty_args, buf);
    while (qbuf != NULL) {
        int parse_res = ctl_parse_query(qbuf, &name, &value);
        if (parse_res != 0) {
            ret = UMF_RESULT_ERROR_INVALID_ARGUMENT;
            goto end;
        }
        // we do not need to copy va_list before call as we know that for query_config_input
        // ctl_query will not call va_arg on it. Ref 7.15/3 of C99 standard
        ret = ctl_query(ctl, ctx, CTL_QUERY_CONFIG_INPUT, name, CTL_QUERY_WRITE,
                        value, strlen(value) + 1, empty_args);

        if (ret != UMF_RESULT_SUCCESS && ctx != NULL) {
            goto end;
        }

        qbuf = strtok_r(NULL, CTL_STRING_QUERY_SEPARATOR, &sptr);
    }

end:
    va_end(empty_args);
    return ret;
}

/*
 * ctl_load_config -- executes the entire query collection from a provider
 */
static umf_result_t ctl_load_config(struct ctl *ctl, void *ctx, char *buf) {
    return ctl_load_config_helper(ctl, ctx, buf);
}

/*
 * ctl_load_config_from_string -- loads obj configuration from string
 */
umf_result_t ctl_load_config_from_string(struct ctl *ctl, void *ctx,
                                         const char *cfg_string) {
    char *buf = Strdup(cfg_string);
    if (buf == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    umf_result_t ret = ctl_load_config(ctl, ctx, buf);

    ctl_free_fn(buf);
    return ret;
}

/*
 * ctl_load_config_from_file -- loads obj configuration from file
 *
 * This function opens up the config file, allocates a buffer of size equal to
 * the size of the file, reads its content and sanitizes it for ctl_load_config.
 */
umf_result_t ctl_load_config_from_file(struct ctl *ctl, void *ctx,
                                       const char *cfg_file) {
    umf_result_t ret = UMF_RESULT_ERROR_UNKNOWN;
    long fsize = 0;
    char *buf = NULL;

    FILE *fp = fopen(cfg_file, "r");
    if (fp == NULL) {
        return ret;
    }

    int err;
    if ((err = fseek(fp, 0, SEEK_END)) != 0) {
        goto error_file_parse;
    }

    fsize = ftell(fp);
    if (fsize == -1) {
        goto error_file_parse;
    }

    if (fsize > MAX_CONFIG_FILE_LEN) {
        goto error_file_parse;
    }

    if ((err = fseek(fp, 0, SEEK_SET)) != 0) {
        goto error_file_parse;
    }

    buf = Zalloc((size_t)fsize + 1); /* +1 for NULL-termination */
    if (buf == NULL) {
        goto error_file_parse;
    }

    {
        size_t bufpos = 0;
        int c;
        int is_comment_section = 0;
        while ((c = fgetc(fp)) != EOF) {
            if (c == '#') {
                is_comment_section = 1;
            } else if (c == '\n') {
                is_comment_section = 0;
            } else if (!is_comment_section && !isspace(c)) {
                buf[bufpos++] = (char)c;
            }
        }
    }

    ret = ctl_load_config(ctl, ctx, buf);

    ctl_free_fn(buf);

error_file_parse:
    (void)fclose(fp);
    return ret;
}

/*
 * ctl_parse_ull -- (internal) parses and returns an unsigned long long
 */
static unsigned long long ctl_parse_ull(const char *str) {
    char *endptr;
    int olderrno = errno;
    errno = 0;
    unsigned long long val = strtoull(str, &endptr, 0);
    if (endptr == str || errno != 0) {
        return ULLONG_MAX;
    }
    errno = olderrno;

    return val;
}

/*
 * ctl_parse_ll -- (internal) parses and returns a long long signed integer
 */
static long long ctl_parse_ll(const char *str) {
    char *endptr;
    int olderrno = errno;
    errno = 0;
    long long val = strtoll(str, &endptr, 0);
    if (endptr == str || errno != 0) {
        return LLONG_MIN;
    }
    errno = olderrno;

    return val;
}

/*
 * ctl_arg_boolean -- checks whether the provided argument contains
 *    either a 1 or y or Y.
 */
int ctl_arg_boolean(const void *arg, void *dest, size_t dest_size) {
    /* suppress unused-parameter errors */
    (void)dest_size;
    if (!arg) {
        return -1;
    }

    int *intp = dest;
    char in = ((const char *)arg)[0];

    if (tolower(in) == 'y' || in == '1') {
        *intp = 1;
        return 0;
    } else if (tolower(in) == 'n' || in == '0') {
        *intp = 0;
        return 0;
    }

    return -1;
}

/*
 * ctl_arg_unsigned -- parses unsigned integer argument
 */
int ctl_arg_unsigned(const void *arg, void *dest, size_t dest_size) {
    if (!arg) {
        return -1;
    }

    unsigned long long val = ctl_parse_ull(arg);
    if (val == ULLONG_MAX) {
        return -1;
    }

    switch (dest_size) {
    case sizeof(unsigned int):
        if (val > UINT_MAX) {
            return -1;
        }
        *(unsigned int *)dest = (unsigned int)val;
        break;
    case sizeof(unsigned long long):
        *(unsigned long long *)dest = val;
        break;
    case sizeof(uint8_t):
        if (val > UINT8_MAX) {
            return -1;
        }
        *(uint8_t *)dest = (uint8_t)val;
        break;
    default:
        return -1;
    }

    return 0;
}

/*
 * ctl_arg_integer -- parses signed integer argument
 */
int ctl_arg_integer(const void *arg, void *dest, size_t dest_size) {
    if (!arg) {
        return -1;
    }
    long long val = ctl_parse_ll(arg);
    if (val == LLONG_MIN) {
        return -1;
    }

    switch (dest_size) {
    case sizeof(int):
        if (val > INT_MAX || val < INT_MIN) {
            return -1;
        }
        *(int *)dest = (int)val;
        break;
    case sizeof(long long):
        *(long long *)dest = val;
        break;
    default:
        return -1;
    }

    return 0;
}

/*
 * ctl_arg_string -- verifies length and copies a string argument into a zeroed
 *    buffer
 */
int ctl_arg_string(const void *arg, void *dest, size_t dest_size) {
    if (!arg) {
        return -1;
    }

    /* check if the incoming string is longer or equal to dest_size */
    if (strnlen(arg, dest_size) == dest_size) {
        return -1;
    }

    strncpy(dest, arg, dest_size);

    return 0;
}
