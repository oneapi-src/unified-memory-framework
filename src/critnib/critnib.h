/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_CRITNIB_H
#define UMF_CRITNIB_H 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct critnib;
typedef struct critnib critnib;
typedef void (*free_leaf_t)(void *leaf_allocator, void *ptr);

enum find_dir_t {
    FIND_L = -2,
    FIND_LE = -1,
    FIND_EQ = 0,
    FIND_GE = +1,
    FIND_G = +2,
};

critnib *critnib_new(free_leaf_t cb_free_leaf, void *leaf_allocator);
void critnib_delete(critnib *c);

int critnib_insert(critnib *c, uintptr_t key, void *value, int update);
void critnib_iter(critnib *c, uintptr_t min, uintptr_t max,
                  int (*func)(uintptr_t key, void *value, void *privdata),
                  void *privdata);

// The following 4 functions:
void *critnib_remove(critnib *c, uintptr_t key, void **ref);
void *critnib_get(critnib *c, uintptr_t key, void **ref);
void *critnib_find_le(critnib *c, uintptr_t key, void **ref);
int critnib_find(critnib *c, uintptr_t key, enum find_dir_t dir,
                 uintptr_t *rkey, void **rvalue, void **ref);
// ... returns a reference (void *ref) to the key,
// that MUST be released by calling critnib_release():
int critnib_release(struct critnib *c, void *ref);
// when the returned value is no longer used and can be freed using the cb_free_leaf callback.

#ifdef __cplusplus
}
#endif

#endif // UMF_CRITNIB_H
