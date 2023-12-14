# Unified Memory Framework

[![GHA build status](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/basic.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/basic.yml)

The Unified Memory Framework (UMF) is a library for constructing allocators and memory pools. It also contains broadly useful abstractions and utilities for memory management. UMF allows users to manage multiple memory pools characterized by different attributes, allowing certain allocation types to be isolated from others and allocated using different hardware resources as required.

# Architecture: memory pools and providers

A UMF memory pool is a combination of a pool allocator and a memory provider. A memory provider is responsible for coarse-grained memory allocations and management of memory pages, while the pool allocator controls memory pooling and handles fine-grained memory allocations.

Pool allocator can leverage existing allocators (e.g. jemalloc or tbbmalloc) or be written from scratch. 

UMF comes with predefined pool allocators (see include/pool) and providers (see include/provider). UMF can also work with user-defined pools and providers that implement a specific interface (see include/umf/memory_pool_ops.h and include/umf/memory_provider_ops.h)

## Memory providers

### OS memory provider (Linux-only yet)

A memory provider that provides memory from an operating system.

## Memory pool managers

### libumf_pool_jemalloc (Linux-only)

libumf_pool_jemalloc is a [jemalloc](https://github.com/jemalloc/jemalloc)-based memory pool manager built as a separate static library.
The `UMF_BUILD_LIBUMF_POOL_JEMALLOC` option has to be turned `ON` to build this library.

#### Requirements

1) The `UMF_BUILD_LIBUMF_POOL_JEMALLOC` option turned `ON`
2) Required packages:
- libjemalloc-dev

## Building

### Requirements

Required packages:
- C++ compiler with C++17 support
- [CMake](https://cmake.org/) >= 3.14.0
- Linux only: libnuma-dev

For development and contributions:
- clang-format-15.0 (can be installed with `python -m pip install clang-format==15.0.7`)

### Windows

Generating Visual Studio Project. EXE and binaries will be in **build/bin/{build_config}**

```bash
$ mkdir build
$ cd build
$ cmake {path_to_source_dir} -G "Visual Studio 15 2017 Win64"
```

### Linux

Executable and binaries will be in **build/bin**

```bash
$ mkdir build
$ cd build
$ cmake {path_to_source_dir}
$ make
```
## Contributions

All code has to be formatted using clang-format. To check the formatting do:

```bash
$ mkdir build
$ cd build
$ cmake {path_to_source_dir} -DUMF_FORMAT_CODE_STYLE=ON
$ make clang-format-check
```

Additionally, to apply code formatting do:

```bash
$ make clang-format-apply
```

### CMake standard options

List of options provided by CMake:

| Name | Description | Values | Default |
| - | - | - | - |
| UMF_BUILD_SHARED_LIBRARY | Build UMF as shared library | ON/OFF | OFF |
| UMF_BUILD_LIBUMF_POOL_JEMALLOC | Build the libumf_pool_jemalloc static library | ON/OFF | OFF |
| UMF_BUILD_TESTS | Build UMF tests | ON/OFF | ON |
| UMF_ENABLE_POOL_TRACKING | Build UMF with pool tracking | ON/OFF | ON |
| UMF_DEVELOPER_MODE | Treat warnings as errors and enables additional checks | ON/OFF | OFF |
| UMF_FORMAT_CODE_STYLE | Add clang-format-check and clang-format-apply targets to make | ON/OFF | OFF |
