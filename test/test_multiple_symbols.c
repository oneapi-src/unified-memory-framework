/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <umf/memory_provider_ops.h>

typedef void *(*umfGetPtr_t)(void);

// UMF so handle
static void *h_umf;

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

static int umf_load() {
    umfGetPtr_t umfFileMemoryProviderOps;
    umfGetPtr_t umfFileMemoryProviderOps_0_11;
    umfGetPtr_t umfDevDaxMemoryProviderOps;
    umfGetPtr_t umfDevDaxMemoryProviderOps_0_11;

    char *umf_lib_name = "libumf.so";
    h_umf = dlopen(umf_lib_name, RTLD_LAZY);
    if (h_umf == NULL) {
        fprintf(stderr, "umf_load: UMF library not found (%s)\n", umf_lib_name);
        return -1;
    }

    load_symbol(h_umf, "umfFileMemoryProviderOps",
                (void **)&umfFileMemoryProviderOps);
    if (umfFileMemoryProviderOps == NULL) {
        goto err_dlclose;
    } else {
        umf_memory_provider_ops_t *ops = umfFileMemoryProviderOps();
        if (ops == NULL) {
            fprintf(stderr, "umfFileMemoryProviderOps: NULL ops\n");
            goto err_dlclose;
        }

        // default version of umfFileMemoryProviderOps should return ops_0_10
        if (ops->version != UMF_MAKE_VERSION(0, 10)) {
            fprintf(stderr, "umfFileMemoryProviderOps: bad ops version\n");
            goto err_dlclose;
        }
    }

    load_symbol(h_umf, "umfFileMemoryProviderOps_0_11",
                (void **)&umfFileMemoryProviderOps_0_11);
    if (umfFileMemoryProviderOps_0_11 == NULL) {
        goto err_dlclose;
    } else {
        umf_memory_provider_ops_0_11_t *ops = umfFileMemoryProviderOps_0_11();
        if (ops == NULL) {
            fprintf(stderr, "umfFileMemoryProviderOps_0_11: NULL ops\n");
            goto err_dlclose;
        }

        if (ops->version != UMF_MAKE_VERSION(0, 11)) {
            fprintf(stderr, "umfFileMemoryProviderOps_0_11: bad ops version\n");
            goto err_dlclose;
        }
    }

    load_symbol(h_umf, "umfDevDaxMemoryProviderOps",
                (void **)&umfDevDaxMemoryProviderOps);
    if (umfDevDaxMemoryProviderOps == NULL) {
        goto err_dlclose;
    } else {
        umf_memory_provider_ops_t *ops = umfDevDaxMemoryProviderOps();
        if (ops == NULL) {
            fprintf(stderr, "umfDevDaxMemoryProviderOps: NULL ops\n");
            goto err_dlclose;
        }

        // default version of umfDevDaxMemoryProviderOps should return ops_0_10
        if (ops->version != UMF_MAKE_VERSION(0, 10)) {
            fprintf(stderr, "umfDevDaxMemoryProviderOps: bad ops version\n");
            goto err_dlclose;
        }
    }

    load_symbol(h_umf, "umfDevDaxMemoryProviderOps_0_11",
                (void **)&umfDevDaxMemoryProviderOps_0_11);
    if (umfDevDaxMemoryProviderOps_0_11 == NULL) {
        goto err_dlclose;
    } else {
        umf_memory_provider_ops_0_11_t *ops = umfDevDaxMemoryProviderOps_0_11();
        if (ops == NULL) {
            fprintf(stderr, "umfDevDaxMemoryProviderOps_0_11: NULL ops\n");
            goto err_dlclose;
        }

        if (ops->version != UMF_MAKE_VERSION(0, 11)) {
            fprintf(stderr,
                    "umfDevDaxMemoryProviderOps_0_11: bad ops version\n");
            goto err_dlclose;
        }
    }

    return 0;

err_dlclose:
    dlclose(h_umf);

    return -1;
}

static void umf_unload() {
    fprintf(stderr, "umf_unload: closing umf library ...\n");
    dlclose(h_umf);
    fprintf(stderr, "umf_unload: umf library closed\n");
}

int main(void) {

    if (umf_load()) {
        return -1;
    }

    umf_unload();
    return 0;
}
