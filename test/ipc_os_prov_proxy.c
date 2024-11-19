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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <umf/ipc.h>

#include "ipc_common.h"
#include "utils_load_library.h"

umf_result_t (*pfnGetIPCHandle)(const void *ptr, umf_ipc_handle_t *umfIPCHandle,
                                size_t *size);
umf_result_t (*pfnPutIPCHandle)(umf_ipc_handle_t umfIPCHandle);

// This is a test for a scenario where a user process is started using the
// LD_PRELOAD with the UMF Proxy Lib and this process uses UMF by loading
// libumf.so at runtime.
// In this test, we expect that all allocations made by the process will be
// handled by UMF in the Proxy Lib and added to the UMF tracker so that they
// can be used later in the UMF IPC API.
int main(int argc, char *argv[]) {
    int ret = 0;
    umf_result_t umf_result = UMF_RESULT_ERROR_UNKNOWN;
    int producer_socket = -1;
    const size_t MSG_SIZE = 2048;
    char consumer_message[MSG_SIZE];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <port> [shm_name]\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    // read the "/proc/self/maps" file until the "libumf_proxy.so" of the maps
    // is found or EOF is reached.
    const size_t SIZE_BUF = 8192;
    char buf[SIZE_BUF];
    ssize_t nbytes = 1;
    char *found = NULL;
    while (nbytes > 0 && found == NULL) {
        memset(buf, 0, SIZE_BUF); // erase previous data
        nbytes = read(fd, buf, SIZE_BUF);
        if (nbytes <= 0) {
            break;
        }
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

    *(void **)&pfnPutIPCHandle =
        utils_get_symbol_addr(umf_lib_handle, "umfPutIPCHandle", umf_lib_name);
    if (pfnPutIPCHandle == NULL) {
        ret = -1;
        goto err_close_lib;
    }

    // create simple allocation - it should be added to the UMF tracker if the
    // process was launched under UMF Proxy Lib
    size_t size = 2137;
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "malloc() failed!\n");
        ret = -1;
        goto err_close_lib;
    }

    fprintf(stderr, "Allocated memory - %zu\n", size);
    size_t val = 144;
    size_t expected_val = val / 2;
    *(size_t *)ptr = val;

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

    producer_socket = producer_connect(port);
    if (producer_socket < 0) {
        goto err_PutIPCHandle;
    }

    // send the ipc_handle_size to the consumer
    ssize_t len =
        send(producer_socket, &ipc_handle_size, sizeof(ipc_handle_size), 0);
    if (len < 0) {
        fprintf(stderr, "[producer] ERROR: unable to send the ipc_handle_size "
                        "to the consumer\n");
        goto err_close_producer_socket;
    }

    fprintf(stderr,
            "[producer] Sent the size of the IPC handle (%zu) to the consumer "
            "(sent %zu bytes)\n",
            ipc_handle_size, len);

    // zero the consumer_message buffer
    memset(consumer_message, 0, sizeof(consumer_message));

    // receive the consumer's confirmation - IPC handle size
    len = recv(producer_socket, consumer_message, sizeof(consumer_message), 0);
    if (len < 0) {
        fprintf(stderr, "[producer] ERROR: error while receiving the "
                        "confirmation from the consumer\n");
        goto err_close_producer_socket;
    }

    size_t conf_IPC_handle_size = *(size_t *)consumer_message;
    if (conf_IPC_handle_size == ipc_handle_size) {
        fprintf(stderr,
                "[producer] Received the correct confirmation (%zu) from the "
                "consumer (%zu bytes)\n",
                conf_IPC_handle_size, len);
    } else {
        fprintf(stderr,
                "[producer] Received an INCORRECT confirmation (%zu) from the "
                "consumer (%zu bytes)\n",
                conf_IPC_handle_size, len);
        goto err_close_producer_socket;
    }

    // send the ipc_handle of ipc_handle_size to the consumer
    if (send(producer_socket, ipc_handle, ipc_handle_size, 0) < 0) {
        fprintf(stderr, "[producer] ERROR: unable to send the ipc_handle to "
                        "the consumer\n");
        goto err_close_producer_socket;
    }

    fprintf(stderr,
            "[producer] Sent the IPC handle to the consumer (%zu bytes)\n",
            ipc_handle_size);

    // zero the consumer_message buffer
    memset(consumer_message, 0, sizeof(consumer_message));

    // receive the consumer's response
    if (recv(producer_socket, consumer_message, sizeof(consumer_message) - 1,
             0) < 0) {
        fprintf(
            stderr,
            "[producer] ERROR: error while receiving the consumer's message\n");
        goto err_close_producer_socket;
    }

    fprintf(stderr, "[producer] Received the consumer's response: \"%s\"\n",
            consumer_message);

    if (strncmp(consumer_message, "SKIP", 5 /* length of "SKIP" + 1 */) == 0) {
        fprintf(stderr, "[producer] SKIP: received the 'SKIP' response from "
                        "consumer, skipping ...\n");
        ret = 1;
        goto err_close_producer_socket;
    }

    // read a new value - the expected correct value val / 2
    volatile unsigned long long new_val = *(unsigned long long *)ptr;
    if (new_val == expected_val) {
        ret = 0; // got the correct value - success!
        fprintf(
            stderr,
            "[producer] The consumer wrote the correct value (the old one / 2) "
            "to my shared memory: %llu\n",
            new_val);
    } else {
        fprintf(
            stderr,
            "[producer] ERROR: The consumer did NOT write the correct value "
            "(the old one / 2 = %zu) to my shared memory: %llu\n",
            expected_val, new_val);
    }

err_close_producer_socket:
    close(producer_socket);

err_PutIPCHandle:
    umf_result = pfnPutIPCHandle(ipc_handle);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[producer] ERROR: putting the IPC handle failed\n");
    }

    fprintf(stderr, "[producer] Put the IPC handle\n");

    if (ret == 0) {
        fprintf(stderr, "[producer] Shutting down (status OK) ...\n");
    } else if (ret == 1) {
        fprintf(stderr, "[producer] Shutting down (status SKIP) ...\n");
        ret = 0;
    } else {
        fprintf(stderr, "[producer] Shutting down (status ERROR) ...\n");
    }

    return ret;

err_free_mem:
    free(ptr);

err_close_lib:
    utils_close_library(umf_lib_handle);

    return ret;
}
