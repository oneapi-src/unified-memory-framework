# Examples

This directory contains examples of UMF usage. Each example has a brief
description below.

## Basic

This example covers the basics of UMF API. It walks you through a basic usage
of a memory provider and a pool allocator. OS memory provider and Scalable pool
are used for this purpose.

### Requirements
* libtbb-dev (libtbbmalloc.so.2) on Linux or tbb (tbbmalloc.dll) on Windows

## GPU shared memory

This example demonstrates the usage of Intel's Level Zero API for accessing GPU
memory. It initializes the Level Zero driver, discovers all the driver
instances, and creates GPU context for the first found GPU device. Next, it
sets up a combination of UMF Level Zero memory provider and a Disjoint Pool
memory pool to allocate from shared memory. If any step fails, the program
cleans up and exits with an error status.

### Requirements
* Level Zero headers and libraries
* compatible GPU with installed driver
* set UMF_BUILD_GPU_EXAMPLES, UMF_BUILD_LIBUMF_POOL_DISJOINT and UMF_BUILD_LEVEL_ZERO_PROVIDER CMake configuration flags to ON

## IPC example with Level Zero memory provider
This example demonstrates how to use UMF IPC API. The example creates two
memory pools of Level Zero device memory: the producer pool (where the buffer
is allocated) and the consumer pool (where the IPC handle is mapped). To run
and build this example Level Zero development package should be installed.

### Requirements
* Level Zero headers and libraries
* compatible GPU with installed driver
* set UMF_BUILD_GPU_EXAMPLES, UMF_BUILD_LIBUMF_POOL_DISJOINT and UMF_BUILD_LEVEL_ZERO_PROVIDER CMake configuration flags to ON

## IPC example with shared memory
This example also demonstrates how to use UMF IPC API. The example creates two
processes: a producer and a consumer that communicate in the following way
(the initial value N in the shared memory is quasi-random):
- Consumer starts
- Consumer creates a socket
- Consumer listens for incoming connections
- Producer starts
- Producer's shared memory contains a number: N
- Producer gets the IPC handle
- Producer creates a socket
- Producer connects to the consumer
- Consumer connects at IP 127.0.0.1 and a port to the producer
- Producer sends the size of the IPC handle to the consumer
- Consumer receives the size of the IPC handle
- Consumer sends the received size of the IPC handle as a confirmation back to the producer
- Producer receives the confirmation from the consumer and verifies if it is correct
- Producer sends the IPC handle to the consumer
- Consumer receives the IPC handle from the producer
- Consumer opens the IPC handle received from the producer
- Consumer reads the number from the producer's shared memory: N
- Consumer writes a new number directly to the producer's shared memory: N/2
- Consumer sends a response message to the producer
- Producer receives the response message from the consumer: "This is the consumer. I just wrote a new number directly into your shared memory!"
- Producer verifies if the consumer wrote the correct value (the old one / 2) to the producer's shared memory: N/2
- Consumer closes the IPC handle received from the producer
- Producer puts the IPC handle
- Consumer shuts down
- Producer shuts down
