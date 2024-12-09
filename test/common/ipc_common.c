/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ipc_common.h"

#define INET_ADDR "127.0.0.1"
#define MSG_SIZE 1024 * 8

// consumer's response message
#define CONSUMER_MSG                                                           \
    "This is the consumer. I just wrote a new number directly into your "      \
    "shared memory!"

/*
Generally communication between the producer and the consumer looks like:
- Consumer starts
- Consumer creates a socket
- Consumer listens for incoming connections
- Producer starts
- Producer's shared memory contains a number: N
- Producer gets the IPC handle
- Producer creates a socket
- Producer connects to the consumer
- Consumer connects at IP 127.0.0.1 and a port to the producer
- Producer sends the IPC handle size to the consumer
- Consumer receives the IPC handle size from the producer
- Consumer sends the confirmation (IPC handle size) to the producer
- Producer receives the confirmation (IPC handle size) from the consumer
- Producer sends the IPC handle to the consumer
- Consumer receives the IPC handle from the producer
- Consumer opens the IPC handle received from the producer
- Consumer reads the number from the producer's shared memory: N
- Consumer writes a new number directly to the producer's shared memory: N/2
- Consumer sends a response message to the producer
- Consumer closes the IPC handle received from the producer
- Producer receives the response from the consumer: "This is the consumer. I just wrote a new number directly into your shared memory!"
- Producer verifies the consumer wrote the correct value (the old one / 2) to the producer's shared memory: N/2
- Producer puts the IPC handle
- Consumer shuts down
- Producer shuts down
*/

int consumer_connect(int port) {
    struct sockaddr_in consumer_addr;
    struct sockaddr_in producer_addr;
    int producer_addr_len;
    int producer_socket = -1;
    int consumer_socket = -1;
    int ret = -1;

    // create a socket
    consumer_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (consumer_socket < 0) {
        fprintf(stderr, "[consumer] ERROR: creating socket failed\n");
        return -1;
    }

    fprintf(stderr, "[consumer] Socket created\n");

    // set the IP address and the port
    consumer_addr.sin_family = AF_INET;
    consumer_addr.sin_port = htons(port);
    consumer_addr.sin_addr.s_addr = inet_addr(INET_ADDR);

    // bind to the IP address and the port
    if (bind(consumer_socket, (struct sockaddr *)&consumer_addr,
             sizeof(consumer_addr)) < 0) {
        fprintf(stderr, "[consumer] ERROR: cannot bind to the port\n");
        goto err_close_consumer_socket;
    }

    fprintf(stderr, "[consumer] Binding done\n");

    // listen for the producer
    if (listen(consumer_socket, 1) < 0) {
        fprintf(stderr, "[consumer] ERROR: listen() failed\n");
        goto err_close_consumer_socket;
    }

    fprintf(stderr, "[consumer] Listening for incoming connections ...\n");

    // accept an incoming connection
    producer_addr_len = sizeof(producer_addr);
    producer_socket = accept(consumer_socket, (struct sockaddr *)&producer_addr,
                             (socklen_t *)&producer_addr_len);
    if (producer_socket < 0) {
        fprintf(stderr, "[consumer] ERROR: accept() failed\n");
        goto err_close_consumer_socket;
    }

    fprintf(stderr, "[consumer] Producer connected at IP %s and port %i\n",
            inet_ntoa(producer_addr.sin_addr), ntohs(producer_addr.sin_port));

    ret = producer_socket; // success

err_close_consumer_socket:
    close(consumer_socket);

    return ret;
}

int run_consumer(int port, umf_memory_pool_ops_t *pool_ops, void *pool_params,
                 umf_memory_provider_ops_t *provider_ops, void *provider_params,
                 memcopy_callback_t memcopy_callback, void *memcopy_ctx) {
    char consumer_message[MSG_SIZE];
    int producer_socket = -1;
    int ret = -1;
    umf_memory_provider_handle_t provider = NULL;
    umf_result_t umf_result = UMF_RESULT_ERROR_UNKNOWN;

    // zero the consumer_message buffer
    memset(consumer_message, 0, sizeof(consumer_message));

    // create OS memory provider
    umf_result =
        umfMemoryProviderCreate(provider_ops, provider_params, &provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[consumer] ERROR: creating OS memory provider failed\n");
        return -1;
    }

    umf_memory_pool_handle_t pool;
    umf_result = umfPoolCreate(pool_ops, provider, pool_params, 0, &pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: creating memory pool failed\n");
        goto err_umfMemoryProviderDestroy;
    }

    umf_ipc_handler_handle_t ipc_handler;
    umf_result = umfPoolGetIPCHandler(pool, &ipc_handler);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: get IPC handler failed\n");
        goto err_umfMemoryPoolDestroy;
    }

    producer_socket = consumer_connect(port);
    if (producer_socket < 0) {
        goto err_umfMemoryPoolDestroy;
    }

    // allocate the zeroed receive buffer
    char *recv_buffer = calloc(1, MSG_SIZE);
    if (!recv_buffer) {
        fprintf(stderr, "[consumer] ERROR: out of memory\n");
        goto err_close_producer_socket;
    }

    // get the size of the IPC handle from the producer
    size_t IPC_handle_size;
    ssize_t recv_len = recv(producer_socket, recv_buffer, MSG_SIZE, 0);
    if (recv_len < 0) {
        fprintf(stderr, "[consumer] ERROR: recv() failed\n");
        goto err_free_recv_buffer;
    }
    IPC_handle_size = *(size_t *)recv_buffer;
    fprintf(stderr, "[consumer] Got the size of the IPC handle: %zu\n",
            IPC_handle_size);

    // send confirmation to the producer (IPC handle size)
    recv_len =
        send(producer_socket, &IPC_handle_size, sizeof(IPC_handle_size), 0);
    if (recv_len < 0) {
        fprintf(stderr, "[consumer] ERROR: sending confirmation failed\n");
        goto err_free_recv_buffer;
    }
    fprintf(stderr,
            "[consumer] Send the confirmation (IPC handle size) to producer\n");

    // receive IPC handle from the producer
    recv_len = recv(producer_socket, recv_buffer, MSG_SIZE, 0);
    if (recv_len < 0) {
        fprintf(stderr, "[consumer] ERROR: recv() failed\n");
        goto err_free_recv_buffer;
    }

    size_t len = (size_t)recv_len;
    if (len != IPC_handle_size) {
        fprintf(stderr,
                "[consumer] ERROR: recv() received a wrong number of bytes "
                "(%zi != %zu expected)\n",
                len, IPC_handle_size);
        goto err_free_recv_buffer;
    }

    void *IPC_handle = recv_buffer;

    fprintf(
        stderr,
        "[consumer] Received the IPC handle from the producer (%zi bytes)\n",
        len);

    void *SHM_ptr;
    umf_result = umfOpenIPCHandle(ipc_handler, IPC_handle, &SHM_ptr);
    if (umf_result == UMF_RESULT_ERROR_NOT_SUPPORTED) {
        fprintf(stderr,
                "[consumer] SKIP: opening the IPC handle is not supported\n");
        ret = 1; // SKIP

        // write the SKIP response to the consumer_message buffer
        strcpy(consumer_message, "SKIP");

        // send the SKIP response to the producer
        send(producer_socket, consumer_message, strlen(consumer_message) + 1,
             0);

        goto err_free_recv_buffer;
    }
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: opening the IPC handle failed\n");
        goto err_free_recv_buffer;
    }

    fprintf(stderr,
            "[consumer] Opened the IPC handle received from the producer\n");

    // read the current value from the shared memory
    unsigned long long SHM_number_1 = 0;
    memcopy_callback(&SHM_number_1, SHM_ptr, sizeof(SHM_number_1), memcopy_ctx);
    fprintf(
        stderr,
        "[consumer] Read the number from the producer's shared memory: %llu\n",
        SHM_number_1);

    // calculate the new value
    unsigned long long SHM_number_2 = SHM_number_1 / 2;

    // write the new number directly to the producer's shared memory
    memcopy_callback(SHM_ptr, &SHM_number_2, sizeof(SHM_number_2), memcopy_ctx);
    fprintf(stderr,
            "[consumer] Wrote a new number directly to the producer's shared "
            "memory: %llu\n",
            SHM_number_2);

    // write the response to the consumer_message buffer
    strcpy(consumer_message, CONSUMER_MSG);

    // send response to the producer
    if (send(producer_socket, consumer_message, strlen(consumer_message) + 1,
             0) < 0) {
        fprintf(stderr, "[consumer] ERROR: send() failed\n");
        goto err_closeIPCHandle;
    }

    fprintf(stderr, "[consumer] Sent a response message to the producer\n");

    ret = 0; // SUCCESS

err_closeIPCHandle:
    // we do not know the exact size of the remote shared memory
    umf_result = umfCloseIPCHandle(SHM_ptr);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: closing the IPC handle failed\n");
    }

    fprintf(stderr,
            "[consumer] Closed the IPC handle received from the producer\n");

err_free_recv_buffer:
    free(recv_buffer);

err_close_producer_socket:
    close(producer_socket);

err_umfMemoryPoolDestroy:
    umfPoolDestroy(pool);

err_umfMemoryProviderDestroy:
    umfMemoryProviderDestroy(provider);

    if (ret == 0) {
        fprintf(stderr, "[consumer] Shutting down (status OK) ...\n");
    } else if (ret == 1) {
        fprintf(stderr, "[consumer] Shutting down (status SKIP) ...\n");
        ret = 0;
    } else {
        fprintf(stderr, "[consumer] Shutting down (status ERROR) ...\n");
    }

    return ret;
}

int producer_connect(int port) {
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

int run_producer(int port, umf_memory_pool_ops_t *pool_ops, void *pool_params,
                 umf_memory_provider_ops_t *provider_ops, void *provider_params,
                 memcopy_callback_t memcopy_callback, void *memcopy_ctx) {
    int ret = -1;
    umf_memory_provider_handle_t provider = NULL;
    umf_result_t umf_result = UMF_RESULT_ERROR_UNKNOWN;
    int producer_socket = -1;
    char consumer_message[MSG_SIZE];

    // create OS memory provider
    umf_result =
        umfMemoryProviderCreate(provider_ops, provider_params, &provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[producer] ERROR: creating OS memory provider failed\n");
        return -1;
    }

    umf_memory_pool_handle_t pool;
    umf_result = umfPoolCreate(pool_ops, provider, pool_params, 0, &pool);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[producer] ERROR: creating memory pool failed\n");
        goto err_umfMemoryProviderDestroy;
    }

    size_t page_size;
    umf_result = umfMemoryProviderGetMinPageSize(provider, NULL, &page_size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[producer] ERROR: getting the minimum page size failed\n");
        goto err_umfMemoryPoolDestroy;
    }

    // Make 3 allocations of size: 1 page, 2 pages and 3 pages
    void *ptr1, *ptr2, *IPC_shared_memory;
    size_t ptr1_size = 1 * page_size;
    size_t ptr2_size = 2 * page_size;
    size_t size_IPC_shared_memory = 3 * page_size;

    ptr1 = umfPoolMalloc(pool, ptr1_size);
    if (ptr1 == NULL) {
        fprintf(stderr, "[producer] ERROR: allocating 1 page failed\n");
        goto err_umfMemoryPoolDestroy;
    }

    ptr2 = umfPoolMalloc(pool, ptr2_size);
    if (ptr2 == NULL) {
        fprintf(stderr, "[producer] ERROR: allocating 2 pages failed\n");
        goto err_free_ptr1;
    }

    IPC_shared_memory = umfPoolMalloc(pool, size_IPC_shared_memory);
    if (IPC_shared_memory == NULL) {
        fprintf(stderr, "[producer] ERROR: allocating 3 pages failed\n");
        goto err_free_ptr2;
    }

    // get size of the IPC handle
    size_t IPC_handle_size;
    umf_ipc_handle_t IPC_handle = NULL;

    // get the IPC handle
    umf_result =
        umfGetIPCHandle(IPC_shared_memory, &IPC_handle, &IPC_handle_size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[producer] ERROR: getting the IPC handle failed\n");
        goto err_free_IPC_shared_memory;
    }

    // save a random number (&provider) in the shared memory
    unsigned long long SHM_number_1 = (unsigned long long)&provider;
    memcopy_callback(IPC_shared_memory, &SHM_number_1, sizeof(SHM_number_1),
                     memcopy_ctx);

    fprintf(stderr, "[producer] My shared memory contains a number: %llu\n",
            SHM_number_1);

    fprintf(stderr, "[producer] Got the IPC handle\n");

    producer_socket = producer_connect(port);
    if (producer_socket < 0) {
        goto err_PutIPCHandle;
    }

    // send the IPC_handle_size to the consumer
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
    if (send(producer_socket, IPC_handle, IPC_handle_size, 0) < 0) {
        fprintf(stderr, "[producer] ERROR: unable to send the message\n");
        goto err_close_producer_socket;
    }

    fprintf(stderr,
            "[producer] Sent the IPC handle to the consumer (%zu bytes)\n",
            IPC_handle_size);

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

    // read a new value from the shared memory
    unsigned long long SHM_number_2;
    memcopy_callback(&SHM_number_2, IPC_shared_memory, sizeof(SHM_number_2),
                     memcopy_ctx);

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
    (void)umfFree(IPC_shared_memory);

err_free_ptr2:
    (void)umfFree(ptr2);

err_free_ptr1:
    (void)umfFree(ptr1);

err_umfMemoryPoolDestroy:
    umfPoolDestroy(pool);

err_umfMemoryProviderDestroy:
    umfMemoryProviderDestroy(provider);

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
