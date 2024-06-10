/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SIZE_ALLOC 4096

typedef int (*umfMemoryProviderCreateFromMemspace_t)(void *hMemspace,
                                                     void *hPolicy,
                                                     void **hPool);
typedef int (*umfPoolCreate_t)(void *ops, void *provider, void *params,
                               uint32_t flags, void **hPool);
typedef void (*umfDestroy_t)(void *handle);
typedef void (*umfVoidVoid_t)(void);
typedef void *(*umfGetPtr_t)(void);

static umfVoidVoid_t umfTearDown;
static umfDestroy_t umfMemoryProviderDestroy;
static umfDestroy_t umfPoolDestroy;
static const char *umf_lib_name;
static void *h_umf;
static void *umf_provider_default;
static void *umf_pool_default;
static void *umf_default;

// UMF alloc
static void *(*umf_alloc)(void *pool, size_t size);

// UMF free
static void (*umf_free)(void *pool, void *ptr);

static void load_symbol(void *handle, const char *name, void **dest) {
    void *symbol = dlsym(handle, name);
    if (symbol == NULL) {
        fprintf(stderr, "umf_load: symbol %s NOT found\n", name);
        *dest = NULL;
        return;
    }

    fprintf(stderr, "umf_load: symbol found: %s\n", name);

    *dest = symbol;
}

static int umf_load(int n_init_teardown) {
    umfMemoryProviderCreateFromMemspace_t umfMemoryProviderCreateFromMemspace;
    umfGetPtr_t umfMemspaceHostAllGet; // the default memspace
    umfGetPtr_t umfScalablePoolOps;
    umfPoolCreate_t umfPoolCreate;
    umfVoidVoid_t umfInit;
    void *memspaceHostAll;
    int ret;

    umf_lib_name = "libumf.so";
    h_umf = dlopen(umf_lib_name, RTLD_LAZY);
    if (h_umf == NULL) {
        fprintf(stderr, "umf_load: UMF library not found (%s)\n", umf_lib_name);
        return -1;
    }

    load_symbol(h_umf, "umfInit", (void **)&umfInit);
    if (umfInit == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfTearDown", (void **)&umfTearDown);
    if (umfTearDown == NULL) {
        goto err_dlclose;
    }

    // Initialize libumf (increment the reference counter of users).
    // Normally this should be done exactly once.
    for (int i = 0; i < n_init_teardown; i++) {
        (*umfInit)();
    }

    load_symbol(h_umf, "umfMemoryProviderCreateFromMemspace",
                (void **)&umfMemoryProviderCreateFromMemspace);
    if (umfMemoryProviderCreateFromMemspace == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfMemoryProviderDestroy",
                (void **)&umfMemoryProviderDestroy);
    if (umfMemoryProviderDestroy == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfPoolCreate", (void **)&umfPoolCreate);
    if (umfPoolCreate == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfPoolDestroy", (void **)&umfPoolDestroy);
    if (umfPoolDestroy == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfPoolMalloc", (void **)&umf_alloc);
    if (umf_alloc == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfPoolFree", (void **)&umf_free);
    if (umf_free == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfScalablePoolOps", (void **)&umfScalablePoolOps);
    if (umfScalablePoolOps == NULL) {
        goto err_dlclose;
    }

    load_symbol(h_umf, "umfMemspaceHostAllGet",
                (void **)&umfMemspaceHostAllGet);
    if (umfMemspaceHostAllGet == NULL) {
        goto err_dlclose;
    }

    memspaceHostAll = (*umfMemspaceHostAllGet)();
    if (memspaceHostAll == NULL) {
        fprintf(stderr, "umf_load: cannot get the memspaceHostAll memspace\n");
        goto err_dlclose;
    }
    fprintf(stderr, "umf_load: got memspace: memspaceHostAll\n");

    ret = (*umfMemoryProviderCreateFromMemspace)(memspaceHostAll, NULL,
                                                 &umf_provider_default);
    if (ret || umf_provider_default == NULL) {
        fprintf(stderr, "umf_load: error creating the default provider: %i\n",
                ret);
        goto err_dlclose;
    }
    fprintf(stderr, "umf_load: the default provider created from memspace\n");

    umf_default = NULL;
    ret = (*umfPoolCreate)((*umfScalablePoolOps)(), umf_provider_default, NULL,
                           0, &umf_pool_default);
    if (ret || umf_pool_default == NULL) {
        fprintf(stderr, "umf_load: error creating the default pool: %i\n", ret);
        goto err_destroy_provider;
    }
    fprintf(stderr,
            "umf_load: the default pool created from the All Nodes provider\n");

    umf_default = umf_pool_default; // umf pool using the default memspace

    fprintf(stderr, "umf_load: umf initialized\n");

    return 0;

err_destroy_provider:
    (*umfMemoryProviderDestroy)(umf_provider_default);
err_dlclose:
    dlclose(h_umf);

    return -1;
}

static void umf_unload(int n_init_teardown) {
    umf_default = NULL;

    fprintf(stderr, "umf_unload: finalizing UMF ...\n");

    (*umfPoolDestroy)(umf_pool_default);
    fprintf(stderr, "umf_unload: the default umf memory pool destroyed\n");

    (*umfMemoryProviderDestroy)(umf_provider_default);
    fprintf(stderr, "umf_unload: the default umf memory provider destroyed\n");

    // Deinitialize libumf (decrement the reference counter of users).
    // Normally this should be done exactly once.
    for (int i = 0; i < n_init_teardown; i++) {
        fprintf(stderr, "umf_unload: calling umfTearDown() ...\n");
        (*umfTearDown)();
    }

    fprintf(stderr, "umf_unload: closing umf library ...\n");
    dlclose(h_umf);
    fprintf(stderr, "umf_unload: umf library closed\n");
}

static int run_test(int n_init_teardown, int wrong_dtor_order) {

    if (wrong_dtor_order) {
        fprintf(stderr, "\n\n*** Running test with INCORRECT order of "
                        "destructors ***\n\n\n");
    } else {
        fprintf(
            stderr,
            "\n\n*** Running test with CORRECT order of destructors ***\n\n\n");
    }

    if (umf_load(n_init_teardown)) {
        return -1;
    }

    assert(umf_default);
    void *ptr = (*umf_alloc)(umf_default, SIZE_ALLOC);
    (*umf_free)(umf_default, ptr);

    // simulate incorrect order of destructors (an additional, unwanted destructor call)
    if (wrong_dtor_order) {
        fprintf(stderr,
                "*** Simulating incorrect order of destructors !!! ***\n");
        (*umfTearDown)();
    }

    umf_unload(n_init_teardown);

    return 0;
}

#define CORRECT_ORDER_OF_DESTRUCTORS 0
#define INCORRECT_ORDER_OF_DESTRUCTORS 1

int main(void) {
    if (run_test(1, CORRECT_ORDER_OF_DESTRUCTORS)) {
        return -1;
    }

    if (run_test(1, INCORRECT_ORDER_OF_DESTRUCTORS)) {
        return -1;
    }

    if (run_test(10, CORRECT_ORDER_OF_DESTRUCTORS)) {
        return -1;
    }

    if (run_test(10, INCORRECT_ORDER_OF_DESTRUCTORS)) {
        return -1;
    }

    return 0;
}
