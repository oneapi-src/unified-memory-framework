# Examples

This directory contains examples of UMF usage. Each example has a brief description below.

## Basic

This example covers the basics of UMF API. It walks you through a basic usage of a memory provider and a pool allocator. OS memory provider and Scalable pool are used for this purpose.

### Required CMake configuration flags
* UMF_BUILD_OS_MEMORY_PROVIDER=ON
* UMF_BUILD_LIBUMF_POOL_SCALABLE=ON
* UMF_ENABLE_POOL_TRACKING=ON
