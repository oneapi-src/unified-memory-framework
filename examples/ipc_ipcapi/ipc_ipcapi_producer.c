/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <umf/ipc.h>
#include <umf/memory_pool.h>
#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_os_memory.h>

#define INET_ADDR "127.0.0.1"
#define MSG_SIZE 1024
#define SIZE_SHM 1024

int producer_connect_to_consumer(int port) {
    struct sockaddr_in consumer_addr;
    int producer_socket = -1;

    // create a producer socket
    producer_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (producer_socket < 0) {
        fprintf(stderr, "[producer] ERROR: Unable to create socket\n");
        return -1;
    }

    fprintf(stderr, "[producer] Socket created\n");

    // set IP address and port the same as for the consumer
    consumer_addr.sin_family = AF_INET;
    consumer_addr.sin_port = htons(port);
    consumer_addr.sin_addr.s_addr = inet_addr(INET_ADDR);

    // send connection request to the consumer
    if (connect(producer_socket, (struct sockaddr *)&consumer_addr,
                sizeof(consumer_addr)) < 0) {
        fprintf(stderr,
                "[producer] ERROR: unable to connect to the consumer\n");
        goto err_close_producer_socket_connect;
    }

    fprintf(stderr, "[producer] Connected to the consumer\n");

    return producer_socket; // success

err_close_producer_socket_connect:
    close(producer_socket);

    return -1;
}

int main(int argc, char *argv[]) {
    char recv_buffer[MSG_SIZE];
    int producer_socket;
    int ret = -1;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <port> [shm_name]\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    // The prctl() function with PR_SET_PTRACER is used here to allow parent process and its children
    // to ptrace the current process. This is necessary because UMF's memory providers on Linux (except CUDA)
    // use the pidfd_getfd(2) system call to duplicate another process's file descriptor, which is
    // governed by ptrace permissions. By default on Ubuntu /proc/sys/kernel/yama/ptrace_scope is
    // set to 1 ("restricted ptrace"), which prevents pidfd_getfd from working unless ptrace_scope
    // is set to 0.
    // To overcome this limitation without requiring users to change the ptrace_scope
    // setting (which requires root privileges), we use prctl() to allow the consumer process
    // to copy producer's file descriptor, even when ptrace_scope is set to 1.
    ret = prctl(PR_SET_PTRACER, getppid());
    if (ret == -1) {
        perror("PR_SET_PTRACER may be not supported. prctl() call failed");
        goto err_end;
    }

    umf_memory_provider_handle_t OS_memory_provider = NULL;
    umf_os_memory_provider_params_handle_t os_params = NULL;
    enum umf_result_t umf_result;

    umf_result = umfOsMemoryProviderParamsCreate(&os_params);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(
            stderr,
            "[producer] ERROR: creating OS memory provider params failed\n");
        return -1;
    }
    umf_result =
        umfOsMemoryProviderParamsSetVisibility(os_params, UMF_MEM_MAP_SHARED);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[producer] ERROR: setting visibility mode failed\n");
        goto err_destroy_OS_params;
    }
    if (argc >= 3) {
        umf_result = umfOsMemoryProviderParamsSetShmName(os_params, argv[2]);
        if (umf_result != UMF_RESULT_SUCCESS) {
            fprintf(stderr,
                    "[producer] ERROR: setting shared memory name failed\n");
            goto err_destroy_OS_params;
        }
    }

    // create OS memory provider
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), os_params,
                                         &OS_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[producer] ERROR: creating OS memory provider failed\n");
        return -1;
    }

    umf_memory_pool_handle_t scalable_pool;
    umf_result = umfPoolCreate(umfScalablePoolOps(), OS_memory_provider, NULL,
                               0, &scalable_pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[producer] ERROR: creating the UMF jemalloc pool failed\n");
        goto err_destroy_OS_memory_provider;
    }

    void *IPC_shared_memory;
    size_t size_IPC_shared_memory = SIZE_SHM;
    IPC_shared_memory = umfPoolCalloc(scalable_pool, 1, size_IPC_shared_memory);
    if (IPC_shared_memory == NULL) {
        fprintf(stderr, "[producer] ERROR: allocating memory failed\n");
        goto err_destroy_scalable_pool;
    }

    // save a random number (&OS_memory_provider) in the shared memory
    unsigned long long SHM_number_1 = (unsigned long long)&OS_memory_provider;
    *(unsigned long long *)IPC_shared_memory = SHM_number_1;

    fprintf(stderr, "[producer] My shared memory contains a number: %llu\n",
            *(unsigned long long *)IPC_shared_memory);

    // get the IPC handle
    size_t IPC_handle_size;
    umf_ipc_handle_t IPC_handle;
    umf_result =
        umfGetIPCHandle(IPC_shared_memory, &IPC_handle, &IPC_handle_size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[producer] ERROR: getting the IPC handle failed\n");
        goto err_free_IPC_shared_memory;
    }

    fprintf(stderr, "[producer] Got the IPC handle\n");

    // connect to the consumer
    producer_socket = producer_connect_to_consumer(port);
    if (producer_socket < 0) {
        goto err_PutIPCHandle;
    }

    // send a size of the IPC_handle to the consumer
    ssize_t len =
        send(producer_socket, &IPC_handle_size, sizeof(IPC_handle_size), 0);
    if (len < 0) {
        fprintf(stderr, "[producer] ERROR: unable to send the message\n");
        goto err_close_producer_socket;
    }

    fprintf(stderr,
            "[producer] Sent the size of the IPC handle (%zu) to the consumer "
            "(sent %zu bytes)\n",
            IPC_handle_size, len);

    // zero the recv_buffer buffer
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // receive the consumer's confirmation
    len = recv(producer_socket, recv_buffer, sizeof(recv_buffer), 0);
    if (len < 0) {
        fprintf(stderr, "[producer] ERROR: error while receiving the "
                        "confirmation from the consumer\n");
        goto err_close_producer_socket;
    }

    size_t conf_IPC_handle_size = *(size_t *)recv_buffer;
    if (conf_IPC_handle_size == IPC_handle_size) {
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

    // send the IPC_handle of IPC_handle_size to the consumer
    len = send(producer_socket, IPC_handle, IPC_handle_size, 0);
    if (len < 0) {
        fprintf(stderr, "[producer] ERROR: unable to send the message\n");
        goto err_close_producer_socket;
    }

    fprintf(stderr,
            "[producer] Sent the IPC handle to the consumer (%zu bytes)\n",
            IPC_handle_size);

    // zero the recv_buffer buffer
    memset(recv_buffer, 0, sizeof(recv_buffer));

    // receive the consumer's response
    len = recv(producer_socket, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (len < 0) {
        fprintf(
            stderr,
            "[producer] ERROR: error while receiving the consumer's message\n");
        goto err_close_producer_socket;
    }

    fprintf(stderr, "[producer] Received the consumer's response: \"%s\"\n",
            recv_buffer);

    if (strncmp(recv_buffer, "SKIP", 5 /* length of "SKIP" + 1 */) == 0) {
        fprintf(stderr, "[producer] Received the \"SKIP\" response from the "
                        "consumer, skipping ...\n");
        ret = 1;
        goto err_close_producer_socket;
    }

    // read a new value from the shared memory
    unsigned long long SHM_number_2 = *(unsigned long long *)IPC_shared_memory;

    // the expected correct value is: SHM_number_2 == (SHM_number_1 / 2)
    if (SHM_number_2 == (SHM_number_1 / 2)) {
        ret = 0; // got the correct value - success!
        fprintf(
            stderr,
            "[producer] The consumer wrote the correct value (the old one / 2) "
            "to my shared memory: %llu\n",
            SHM_number_2);
    } else {
        fprintf(
            stderr,
            "[producer] ERROR: The consumer did NOT write the correct value "
            "(the old one / 2 = %llu) to my shared memory: %llu\n",
            (SHM_number_1 / 2), SHM_number_2);
    }

err_close_producer_socket:
    close(producer_socket);

err_PutIPCHandle:
    umf_result = umfPutIPCHandle(IPC_handle);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[producer] ERROR: putting the IPC handle failed\n");
    }

    fprintf(stderr, "[producer] Put the IPC handle\n");

err_free_IPC_shared_memory:
    (void)umfPoolFree(scalable_pool, IPC_shared_memory);

err_destroy_scalable_pool:
    umfPoolDestroy(scalable_pool);

err_destroy_OS_memory_provider:
    umfMemoryProviderDestroy(OS_memory_provider);

err_destroy_OS_params:
    umfOsMemoryProviderParamsDestroy(os_params);

err_end:
    if (ret == 0) {
        fprintf(stderr, "[producer] Shutting down (status OK) ...\n");
    } else if (ret == 1) {
        fprintf(stderr, "[producer] Shutting down (status SKIP) ...\n");
        ret = 0;
    } else {
        fprintf(stderr, "[producer] Shutting down (status ERROR) ...\n");
    }

    return ret;
}
