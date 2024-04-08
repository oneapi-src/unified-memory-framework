# Examples

This directory contains examples of UMF usage. Each example has a brief
description below.

## Basic

This example covers the basics of UMF API. It walks you through a basic usage
of a memory provider and a pool allocator. OS memory provider and Scalable pool
are used for this purpose.

### Requirements
* libtbb-dev needed for Scalable Pool
* set UMF_BUILD_LIBUMF_POOL_SCALABLE and UMF_ENABLE_POOL_TRACKING CMake
configuration flags to ON

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
* set UMF_BUILD_GPU_EXAMPLES, UMF_BUILD_LIBUMF_POOL_DISJOINT, UMF_BUILD_LEVEL_ZERO_PROVIDER and UMF_ENABLE_POOL_TRACKING CMake configuration flags to ON
