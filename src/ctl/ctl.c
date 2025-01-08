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

#include "ctl.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base_alloc/base_alloc_global.h"
#include "utils/utils_common.h"
#include "utlist.h"

#ifdef _WIN32
#define strtok_r strtok_s
#else
#include <stdio.h>
#endif

#define CTL_MAX_ENTRIES 100

#define MAX_CONFIG_FILE_LEN (1 << 20) /* 1 megabyte */

#define CTL_STRING_QUERY_SEPARATOR ";"
#define CTL_NAME_VALUE_SEPARATOR "="
#define CTL_QUERY_NODE_SEPARATOR "."
#define CTL_VALUE_ARG_SEPARATOR ","

static int ctl_global_first_free = 0;
static struct ctl_node CTL_NODE(global)[CTL_MAX_ENTRIES];

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
    struct ctl_node root[CTL_MAX_ENTRIES];
    int first_free;
};

void *Zalloc(size_t sz) {
    void *ptr = umf_ba_global_alloc(sz);
    if (ptr) {
        memset(ptr, 0, sz);
    }
    return ptr;
}

char *Strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = umf_ba_global_alloc(len);
    if (p) {
        memcpy(p, s, len);
    }
    return p;
}

/*
 * ctl_find_node -- (internal) searches for a matching entry point in the
 *    provided nodes
 *
 * The caller is responsible for freeing all of the allocated indexes,
 * regardless of the return value.
 */
static const struct ctl_node *ctl_find_node(const struct ctl_node *nodes,
                                            const char *name,
                                            struct ctl_index_utlist *indexes) {
    const struct ctl_node *n = NULL;
    char *sptr = NULL;
    char *parse_str = Strdup(name);
    if (parse_str == NULL) {
        return NULL;
    }

    char *node_name = strtok_r(parse_str, CTL_QUERY_NODE_SEPARATOR, &sptr);

    /*
     * Go through the string and separate tokens that correspond to nodes
     * in the main ctl tree.
     */
    while (node_name != NULL) {
        char *endptr;
        /*
         * Ignore errno from strtol: FreeBSD returns EINVAL if no
         * conversion is performed. Linux does not, but endptr
         * check is valid in both cases.
         */
        int tmp_errno = errno;
        long index_value = strtol(node_name, &endptr, 0);
        errno = tmp_errno;
        struct ctl_index_utlist *index_entry = NULL;
        if (endptr != node_name) { /* a valid index */
            index_entry = umf_ba_global_alloc(sizeof(*index_entry));
            if (index_entry == NULL) {
                goto error;
            }
            index_entry->value = index_value;
            LL_PREPEND(indexes, index_entry);
        }

        for (n = &nodes[0]; n->name != NULL; ++n) {
            if (index_entry && n->type == CTL_NODE_INDEXED) {
                break;
            } else if (strcmp(n->name, node_name) == 0) {
                break;
            }
        }
        if (n->name == NULL) {
            goto error;
        }

        if (index_entry) {
            index_entry->name = n->name;
        }

        nodes = n->children;
        node_name = strtok_r(NULL, CTL_QUERY_NODE_SEPARATOR, &sptr);
    }

    umf_ba_global_free(parse_str);
    return n;

error:
    umf_ba_global_free(parse_str);
    return NULL;
}

/*
 * ctl_delete_indexes --
 *    (internal) removes and frees all entries on the index list
 */
static void ctl_delete_indexes(struct ctl_index_utlist *indexes) {
    if (!indexes) {
        return;
    }
    struct ctl_index_utlist *elem, *tmp;
    LL_FOREACH_SAFE(indexes, elem, tmp) {
        LL_DELETE(indexes, elem);
        if (elem) {
            umf_ba_global_free(elem);
        }
    }
}

/*
 * ctl_parse_args -- (internal) parses a string argument based on the node
 *    structure
 */
static void *ctl_parse_args(const struct ctl_argument *arg_proto, char *arg) {
    char *dest_arg = umf_ba_global_alloc(arg_proto->dest_size);
    if (dest_arg == NULL) {
        return NULL;
    }

    char *sptr = NULL;
    char *arg_sep = strtok_r(arg, CTL_VALUE_ARG_SEPARATOR, &sptr);
    for (const struct ctl_argument_parser *p = arg_proto->parsers;
         p->parser != NULL; ++p) {
        if (arg_sep == NULL) {
            goto error_parsing;
        }

        if (p->parser(arg_sep, dest_arg + p->dest_offset, p->dest_size) != 0) {
            goto error_parsing;
        }

        arg_sep = strtok_r(NULL, CTL_VALUE_ARG_SEPARATOR, &sptr);
    }

    return dest_arg;

error_parsing:
    umf_ba_global_free(dest_arg);
    return NULL;
}

/*
 * ctl_query_get_real_args -- (internal) returns a pointer with actual argument
 *    structure as required by the node callback
 */
static void *ctl_query_get_real_args(const struct ctl_node *n, void *write_arg,
                                     enum ctl_query_source source) {
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
 * ctl_query_cleanup_real_args -- (internal) cleanups relevant argument
 *    structures allocated as a result of the get_real_args call
 */
static void ctl_query_cleanup_real_args(const struct ctl_node *n,
                                        void *real_arg,
                                        enum ctl_query_source source) {
    /* suppress unused-parameter errors */
    (void)n;

    switch (source) {
    case CTL_QUERY_CONFIG_INPUT:
        umf_ba_global_free(real_arg);
        break;
    case CTL_QUERY_PROGRAMMATIC:
        break;
    default:
        break;
    }
}

/*
 * ctl_exec_query_read -- (internal) calls the read callback of a node
 */
static int ctl_exec_query_read(void *ctx, const struct ctl_node *n,
                               enum ctl_query_source source, void *arg,
                               struct ctl_index_utlist *indexes) {
    if (arg == NULL) {
        errno = EINVAL;
        return -1;
    }

    return n->cb[CTL_QUERY_READ](ctx, source, arg, indexes);
}

/*
 * ctl_exec_query_write -- (internal) calls the write callback of a node
 */
static int ctl_exec_query_write(void *ctx, const struct ctl_node *n,
                                enum ctl_query_source source, void *arg,
                                struct ctl_index_utlist *indexes) {
    if (arg == NULL) {
        errno = EINVAL;
        return -1;
    }

    void *real_arg = ctl_query_get_real_args(n, arg, source);
    if (real_arg == NULL) {
        return -1;
    }

    int ret = n->cb[CTL_QUERY_WRITE](ctx, source, real_arg, indexes);
    ctl_query_cleanup_real_args(n, real_arg, source);

    return ret;
}

/*
 * ctl_exec_query_runnable -- (internal) calls the run callback of a node
 */
static int ctl_exec_query_runnable(void *ctx, const struct ctl_node *n,
                                   enum ctl_query_source source, void *arg,
                                   struct ctl_index_utlist *indexes) {
    return n->cb[CTL_QUERY_RUNNABLE](ctx, source, arg, indexes);
}

static int (*ctl_exec_query[MAX_CTL_QUERY_TYPE])(
    void *ctx, const struct ctl_node *n, enum ctl_query_source source,
    void *arg, struct ctl_index_utlist *indexes) = {
    ctl_exec_query_read,
    ctl_exec_query_write,
    ctl_exec_query_runnable,
};

/*
 * ctl_query -- (internal) parses the name and calls the appropriate methods
 *    from the ctl tree
 */
int ctl_query(struct ctl *ctl, void *ctx, enum ctl_query_source source,
              const char *name, enum ctl_query_type type, void *arg) {
    if (name == NULL) {
        errno = EINVAL;
        return -1;
    }

    /*
     * All of the indexes are put on this list so that the handlers can
     * easily retrieve the index values. The list is cleared once the ctl
     * query has been handled.
     */
    struct ctl_index_utlist *indexes = NULL;
    indexes = Zalloc(sizeof(*indexes));
    if (!indexes) {
        return -1;
    }

    int ret = -1;

    const struct ctl_node *n = ctl_find_node(CTL_NODE(global), name, indexes);

    if (n == NULL && ctl) {
        ctl_delete_indexes(indexes);
        indexes = NULL;
        n = ctl_find_node(ctl->root, name, indexes);
    }

    if (n == NULL || n->type != CTL_NODE_LEAF || n->cb[type] == NULL) {
        errno = EINVAL;
        goto out;
    }

    ret = ctl_exec_query[type](ctx, n, source, arg, indexes);

out:
    ctl_delete_indexes(indexes);

    return ret;
}

/*
 * ctl_register_module_node -- adds a new node to the CTL tree root.
 */
void ctl_register_module_node(struct ctl *c, const char *name,
                              struct ctl_node *n) {
    struct ctl_node *nnode = c == NULL
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
 * ctl_load_config -- executes the entire query collection from a provider
 */
static int ctl_load_config(struct ctl *ctl, void *ctx, char *buf) {
    int r = 0;
    char *sptr = NULL; /* for internal use of strtok */
    char *name;
    char *value;
    char *qbuf = strtok_r(buf, CTL_STRING_QUERY_SEPARATOR, &sptr);

    while (qbuf != NULL) {
        r = ctl_parse_query(qbuf, &name, &value);
        if (r != 0) {
            return -1;
        }

        r = ctl_query(ctl, ctx, CTL_QUERY_CONFIG_INPUT, name, CTL_QUERY_WRITE,
                      value);

        if (r < 0 && ctx != NULL) {
            return -1;
        }

        qbuf = strtok_r(NULL, CTL_STRING_QUERY_SEPARATOR, &sptr);
    }

    return 0;
}

/*
 * ctl_load_config_from_string -- loads obj configuration from string
 */
int ctl_load_config_from_string(struct ctl *ctl, void *ctx,
                                const char *cfg_string) {
    char *buf = Strdup(cfg_string);
    if (buf == NULL) {
        return -1;
    }

    int ret = ctl_load_config(ctl, ctx, buf);

    umf_ba_global_free(buf);
    return ret;
}

/*
 * ctl_load_config_from_file -- loads obj configuration from file
 *
 * This function opens up the config file, allocates a buffer of size equal to
 * the size of the file, reads its content and sanitizes it for ctl_load_config.
 */
#ifndef _WIN32 // TODO: implement for Windows
int ctl_load_config_from_file(struct ctl *ctl, void *ctx,
                              const char *cfg_file) {
    int ret = -1;
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

    umf_ba_global_free(buf);

error_file_parse:
    (void)fclose(fp);
    return ret;
}
#endif

/*
 * ctl_new -- allocates and initializes ctl data structures
 */
struct ctl *ctl_new(void) {
    struct ctl *c = Zalloc(sizeof(struct ctl));
    if (c == NULL) {
        return NULL;
    }

    c->first_free = 0;
    return c;
}

/*
 * ctl_delete -- deletes ctl
 */
void ctl_delete(struct ctl *c) { umf_ba_global_free(c); }

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
 * ctl_arg_integer -- parses signed integer argument
 */
int ctl_arg_integer(const void *arg, void *dest, size_t dest_size) {
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
    case sizeof(uint8_t):
        if (val > UINT8_MAX || val < 0) {
            return -1;
        }
        *(uint8_t *)dest = (uint8_t)val;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/*
 * ctl_arg_string -- verifies length and copies a string argument into a zeroed
 *    buffer
 */
int ctl_arg_string(const void *arg, void *dest, size_t dest_size) {
    /* check if the incoming string is longer or equal to dest_size */
    if (strnlen(arg, dest_size) == dest_size) {
        return -1;
    }

    strncpy(dest, arg, dest_size);

    return 0;
}
