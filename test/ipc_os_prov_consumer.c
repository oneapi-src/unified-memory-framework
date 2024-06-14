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

#include <umf/providers/provider_os_memory.h>

#define INET_ADDR "127.0.0.1"
#define MSG_SIZE 256
#define RECV_BUFF_SIZE 1024

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

int main(int argc, char *argv[]) {
    char consumer_message[MSG_SIZE];
    char recv_buffer[RECV_BUFF_SIZE];
    int producer_socket = -1;
    int ret = -1;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <port> [shm_name]\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    // zero the consumer_message buffer
    memset(consumer_message, 0, sizeof(consumer_message));

    umf_memory_provider_handle_t OS_memory_provider = NULL;
    umf_os_memory_provider_params_t os_params;
    enum umf_result_t umf_result;

    os_params = umfOsMemoryProviderParamsDefault();
    os_params.visibility = UMF_MEM_MAP_SHARED;
    if (argc >= 3) {
        os_params.shm_name = argv[2];
    }

    // create OS memory provider
    umf_result = umfMemoryProviderCreate(umfOsMemoryProviderOps(), &os_params,
                                         &OS_memory_provider);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[consumer] ERROR: creating OS memory provider failed\n");
        return -1;
    }

    // get the size of the IPC handle
    size_t IPC_handle_size;
    umf_result =
        umfMemoryProviderGetIPCHandleSize(OS_memory_provider, &IPC_handle_size);
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr,
                "[consumer] ERROR: getting size of the IPC handle failed\n");
        goto err_umfMemoryProviderDestroy;
    }

    producer_socket = consumer_connect(port);
    if (producer_socket < 0) {
        goto err_umfMemoryProviderDestroy;
    }

    // zero the receive buffer
    memset(recv_buffer, 0, RECV_BUFF_SIZE);

    // receive a producer's message
    ssize_t len = recv(producer_socket, recv_buffer, RECV_BUFF_SIZE, 0);
    if (len < 0) {
        fprintf(stderr, "[consumer] ERROR: recv() failed\n");
        goto err_close_producer_socket;
    }
    if (len != IPC_handle_size) {
        fprintf(stderr,
                "[consumer] ERROR: recv() received a wrong number of bytes "
                "(%zi != %zu expected)\n",
                len, IPC_handle_size);
        goto err_close_producer_socket;
    }

    void *IPC_handle = recv_buffer;

    fprintf(
        stderr,
        "[consumer] Received the IPC handle from the producer (%zi bytes)\n",
        len);

    void *SHM_ptr;
    umf_result = umfMemoryProviderOpenIPCHandle(OS_memory_provider, IPC_handle,
                                                &SHM_ptr);
    if (umf_result == UMF_RESULT_ERROR_NOT_SUPPORTED) {
        fprintf(stderr,
                "[consumer] SKIP: opening the IPC handle is not supported\n");
        ret = 1; // SKIP

        // write the SKIP response to the consumer_message buffer
        strcpy(consumer_message, "SKIP");

        // send the SKIP response to the producer
        send(producer_socket, consumer_message, strlen(consumer_message) + 1,
             0);

        goto err_close_producer_socket;
    }
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: opening the IPC handle failed\n");
        goto err_close_producer_socket;
    }

    fprintf(stderr,
            "[consumer] Opened the IPC handle received from the producer\n");

    // read the current value from the shared memory
    unsigned long long SHM_number_1 = *(unsigned long long *)SHM_ptr;
    fprintf(
        stderr,
        "[consumer] Read the number from the producer's shared memory: %llu\n",
        SHM_number_1);

    // calculate the new value
    unsigned long long SHM_number_2 = SHM_number_1 / 2;

    // write the new number directly to the producer's shared memory
    *(unsigned long long *)SHM_ptr = SHM_number_2;
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
    umf_result = umfMemoryProviderCloseIPCHandle(OS_memory_provider, SHM_ptr,
                                                 sizeof(unsigned long long));
    if (umf_result != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "[consumer] ERROR: closing the IPC handle failed\n");
    }

    fprintf(stderr,
            "[consumer] Closed the IPC handle received from the producer\n");

err_close_producer_socket:
    close(producer_socket);

err_umfMemoryProviderDestroy:
    umfMemoryProviderDestroy(OS_memory_provider);

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
