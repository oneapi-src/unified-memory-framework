/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <umf/ipc.h>

#include "utils_load_library.h"

umf_result_t (*pfnGetIPCHandle)(const void *ptr, umf_ipc_handle_t *umfIPCHandle,
                                size_t *size);

// This is a test for a scenario where a user process is started using the
// LD_PRELOAD with the UMF Proxy Lib and this process uses UMF by loading
// libumf.so at runtime.
// In this test, we expect that all allocations made by the process will be
// handled by UMF in the Proxy Lib and added to the UMF tracker so that they
// can be used later in the UMF IPC API.
int main(void) {
    int ret = 0;

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    // read the "/proc/self/maps" file until the "libumf_proxy.so" of the maps
    // is found or EOF is reached.
    const size_t size_buf = 8192;
    char buf[size_buf];
    size_t nbytes = 1;
    char *found = NULL;
    while (nbytes > 0 && found == NULL) {
        memset(buf, 0, nbytes); // erase previous data
        nbytes = read(fd, buf, size_buf);
        found = strstr(buf, "libumf_proxy.so");
    }
    (void)close(fd);

    if (found == NULL) {
        fprintf(
            stderr,
            "test binary not run under LD_PRELOAD with \"libumf_proxy.so\"\n");
        return -1;
    }

    // open the UMF library and get umfGetIPCHandle() function
    const char *umf_lib_name = "libumf.so";
    void *umf_lib_handle = utils_open_library(umf_lib_name, 0);
    if (umf_lib_handle == NULL) {
        fprintf(stderr, "utils_open_library: UMF library not found (%s)\n",
                umf_lib_name);
        return -1;
    }

    *(void **)&pfnGetIPCHandle =
        utils_get_symbol_addr(umf_lib_handle, "umfGetIPCHandle", umf_lib_name);
    if (pfnGetIPCHandle == NULL) {
        ret = -1;
        goto err_close_lib;
    }

    // create simple allocation - it should be added to the UMF tracker if the
    // process was launched under UMF Proxy Lib
    size_t size = 2137;
    void *ptr = malloc(size);
    if (ptr == NULL) {
        ret = -1;
        goto err_close_lib;
    }

    fprintf(stderr, "Allocated memory - %zu\n", size);
    *(int *)ptr = 0x23;

    // get IPC handle of the allocation
    umf_ipc_handle_t ipc_handle = NULL;
    size_t ipc_handle_size = 0;
    umf_result_t res = pfnGetIPCHandle(ptr, &ipc_handle, &ipc_handle_size);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "pfnGetIPCHandle() failed!\n");
        ret = -1;
        goto err_free_mem;
    }

    // check if we got valid data
    if (ipc_handle == NULL || ipc_handle_size == 0) {
        fprintf(stderr, "pfnGetIPCHandle() couldn't find the handle data!\n");
        ret = -1;
        goto err_free_mem;
    }

    fprintf(stderr, "Got IPCHandle for memory - %p | size - %zu\n",
            (void *)ipc_handle, ipc_handle_size);

err_free_mem:
    free(ptr);

err_close_lib:
    utils_close_library(umf_lib_handle);

    return ret;
}
