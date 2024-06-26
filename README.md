# Unified Memory Framework

[![Basic builds](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/basic.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/basic.yml)
[![CodeQL](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/codeql.yml)
[![SpellCheck](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/spellcheck.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/spellcheck.yml)
[![GitHubPages](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/docs.yml)
[![Benchmarks](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/benchmarks.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/benchmarks.yml)
[![Nightly](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/nightly.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/oneapi-src/unified-memory-framework/badge)](https://securityscorecards.dev/viewer/?uri=github.com/oneapi-src/unified-memory-framework)
[![Coverity build](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/coverity.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/coverity.yml)
[![Coverity report](https://scan.coverity.com/projects/29761/badge.svg?flat=0)](https://scan.coverity.com/projects/oneapi-src-unified-memory-framework)
[![Bandit](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/bandit.yml/badge.svg?branch=main)](https://github.com/oneapi-src/unified-memory-framework/actions/workflows/bandit.yml)

## Introduction

The Unified Memory Framework (UMF) is a library for constructing allocators and memory pools. It also contains broadly useful abstractions and utilities for memory management. UMF allows users to manage multiple memory pools characterized by different attributes, allowing certain allocation types to be isolated from others and allocated using different hardware resources as required.

**⚠️ Work-In-Progress disclaimer:**
> Please note that this project is **pre-production software**, it should not be considered complete or fully functional.
> It has not been fully tested yet (including security testing). It is not recommended to be used in production
> as part of a larger system. Note that this warning is temporary - we plan to release a stable version within six months.
> This project is not eligible for Intel® Bug Bounty Program.
>
> The API is not yet stable, may change without notice, and will not maintain backward compatibility.

## Usage

For a quick introduction to UMF usage, please see
[examples](https://oneapi-src.github.io/unified-memory-framework/examples.html)
documentation, which includes the code of the
[basic example](https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/basic/basic.c)
and the more advanced one that allocates
[USM memory from the GPU device](https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/basic/gpu_shared_memory.c)
using the Level Zero API and UMF Level Zero memory provider.

## Build

### Requirements

Required packages:
- libhwloc-dev >= 2.3.0 (Linux) / hwloc >= 2.3.0 (Windows)
- C compiler
- [CMake](https://cmake.org/) >= 3.14.0

For development and contributions:
- clang-format-15.0 (can be installed with `python -m pip install clang-format==15.0.7`)
- cmake-format-0.6 (can be installed with `python -m pip install cmake-format==0.6.13`)
- black (can be installed with `python -m pip install black==24.3.0`)

For building tests, multithreaded benchmarks and Disjoint Pool:
- C++ compiler with C++17 support

For Level Zero memory provider tests:
- Level Zero headers and libraries
- compatible GPU with installed driver

### Linux

Executable and binaries will be in **build/bin**

```bash
$ mkdir build
$ cd build
$ cmake {path_to_source_dir}
$ make
```

### Windows

Generating Visual Studio Project. EXE and binaries will be in **build/bin/{build_config}**

```bash
$ mkdir build
$ cd build
$ cmake {path_to_source_dir} -G "Visual Studio 15 2017 Win64"
```

### Benchmark

UMF comes with a single-threaded micro benchmark based on [ubench](https://github.com/sheredom/ubench.h).
In order to build the benchmark, the `UMF_BUILD_BENCHMARKS` CMake configuration flag has to be turned `ON`.

UMF also provides multithreaded benchmarks that can be enabled by setting both
`UMF_BUILD_BENCHMARKS` and `UMF_BUILD_BENCHMARKS_MT` CMake
configuration flags to `ON`. Multithreaded benchmarks require a C++ support.

The Scalable Pool requirements can be found in the relevant 'Memory Pool 
managers' section below.

### Sanitizers

List of sanitizers available on Linux:
- AddressSanitizer
- UndefinedBehaviorSanitizer
- ThreadSanitizer
   - Is mutually exclusive with other sanitizers.
- MemorySanitizer
   - Requires linking against MSan-instrumented libraries to prevent false positive reports. More information [here](https://github.com/google/sanitizers/wiki/MemorySanitizerLibcxxHowTo).

List of sanitizers available on Windows:
- AddressSanitizer

Listed sanitizers can be enabled with appropriate [CMake options](#cmake-standard-options).

### CMake standard options

List of options provided by CMake:

| Name | Description | Values | Default |
| - | - | - | - |
| UMF_BUILD_SHARED_LIBRARY | Build UMF as shared library | ON/OFF | OFF |
| UMF_BUILD_LEVEL_ZERO_PROVIDER | Build Level Zero memory provider | ON/OFF | ON |
| UMF_BUILD_LIBUMF_POOL_DISJOINT | Build the libumf_pool_disjoint static library | ON/OFF | OFF |
| UMF_BUILD_LIBUMF_POOL_JEMALLOC | Build the libumf_pool_jemalloc static library | ON/OFF | OFF |
| UMF_BUILD_TESTS | Build UMF tests | ON/OFF | ON |
| UMF_BUILD_GPU_TESTS | Build UMF GPU tests | ON/OFF | OFF |
| UMF_BUILD_BENCHMARKS | Build UMF benchmarks | ON/OFF | OFF |
| UMF_BUILD_EXAMPLES | Build UMF examples | ON/OFF | ON |
| UMF_BUILD_FUZZTESTS | Build UMF fuzz tests | ON/OFF | OFF |
| UMF_BUILD_GPU_EXAMPLES | Build UMF GPU examples | ON/OFF | OFF |
| UMF_DEVELOPER_MODE | Treat warnings as errors and enables additional checks | ON/OFF | OFF |
| UMF_FORMAT_CODE_STYLE | Add clang, cmake, and black -format-check and -format-apply targets to make | ON/OFF | OFF |
| UMF_TESTS_FAIL_ON_SKIP | Treat skips in tests as fail | ON/OFF | OFF |
| USE_ASAN | Enable AddressSanitizer checks | ON/OFF | OFF |
| USE_UBSAN | Enable UndefinedBehaviorSanitizer checks | ON/OFF | OFF |
| USE_TSAN | Enable ThreadSanitizer checks | ON/OFF | OFF |
| USE_MSAN | Enable MemorySanitizer checks | ON/OFF | OFF |
| USE_VALGRIND | Enable Valgrind instrumentation | ON/OFF | OFF |
| USE_GCOV | Enable gcov support (Linux only) | ON/OFF | OFF |

## Architecture: memory pools and providers

A UMF memory pool is a combination of a pool allocator and a memory provider. A memory provider is responsible for coarse-grained memory allocations and management of memory pages, while the pool allocator controls memory pooling and handles fine-grained memory allocations.

Pool allocator can leverage existing allocators (e.g. jemalloc or tbbmalloc) or be written from scratch.

UMF comes with predefined pool allocators (see include/pool) and providers (see include/provider). UMF can also work with user-defined pools and providers that implement a specific interface (see include/umf/memory_pool_ops.h and include/umf/memory_provider_ops.h).

More detailed documentation is available here: https://oneapi-src.github.io/unified-memory-framework/

### Memory providers

#### OS memory provider

A memory provider that provides memory from an operating system.

OS memory provider supports two types of memory mappings (set by the `visibility` parameter):
1) private memory mapping (`UMF_MEM_MAP_PRIVATE`)
2) shared memory mapping (`UMF_MEM_MAP_SHARED` - supported on Linux only yet)

There are available two mechanisms for the shared memory mapping:
1) a named shared memory object (used if the `shm_name` parameter is not NULL) or
2) an anonymous file descriptor (used if the `shm_name` parameter is NULL)

The `shm_name` parameter should be a null-terminated string of up to NAME_MAX (i.e., 255) characters none of which are slashes.

An anonymous file descriptor for the shared memory mapping will be created using:
1) `memfd_secret()` syscall - (if it is implemented and) if the `UMF_MEM_FD_FUNC` environment variable does not contain the "memfd_create" string or
2) `memfd_create()` syscall - otherwise (and if it is implemented).

##### Requirements

Required packages for tests (Linux-only yet):
   - libnuma-dev

#### Level Zero memory provider

A memory provider that provides memory from L0 device.

##### Requirements

1) Linux or Windows OS
2) The `UMF_BUILD_LEVEL_ZERO_PROVIDER` option turned `ON` (by default)

Additionally, required for tests:

3) The `UMF_BUILD_GPU_TESTS` option turned `ON`
4) System with Level Zero compatible GPU
5) Required packages:
   - liblevel-zero-dev (Linux) or level-zero-sdk (Windows)

### Memory pool managers

#### Proxy pool (part of libumf)

This memory pool is distributed as part of libumf. It forwards all requests to the underlying
memory provider. Currently umfPoolRealloc, umfPoolCalloc and umfPoolMallocUsableSize functions
are not supported by the proxy pool.

#### Disjoint pool

TODO: Add a description

##### Requirements

To enable this feature, the `UMF_BUILD_LIBUMF_POOL_DISJOINT` option needs to be turned `ON`.

#### Jemalloc pool

Jemalloc pool is a [jemalloc](https://github.com/jemalloc/jemalloc)-based memory 
pool manager built as a separate static library: libjemalloc_pool.a on Linux and
jemalloc_pool.lib on Windows.
The `UMF_BUILD_LIBUMF_POOL_JEMALLOC` option has to be turned `ON` to build this library.

##### Requirements

1) The `UMF_BUILD_LIBUMF_POOL_JEMALLOC` option turned `ON`
2) Required packages:
   - libjemalloc-dev (Linux) or jemalloc (Windows)

#### Scalable Pool (part of libumf)

Scalable Pool is a [oneTBB](https://github.com/oneapi-src/oneTBB)-based memory pool manager.
It is distributed as part of libumf. To use this pool, TBB must be installed in the system.

##### Requirements

Required packages:
   - libtbb-dev (libtbbmalloc.so.2) on Linux or tbb (tbbmalloc.dll) on Windows

### Memspaces (Linux-only)

TODO: Add general information about memspaces.

#### Host all memspace

Memspace backed by all available NUMA nodes discovered on the platform. Can be retrieved
using umfMemspaceHostAllGet.

#### Highest capacity memspace

Memspace backed by all available NUMA nodes discovered on the platform sorted by capacity.
Can be retrieved using umfMemspaceHighestCapacityGet.

#### Highest bandwidth memspace

Memspace backed by an aggregated list of NUMA nodes identified as highest bandwidth after selecting each available NUMA node as the initiator.
Querying the bandwidth value requires HMAT support on the platform. Calling `umfMemspaceHighestBandwidthGet()` will return NULL if it's not supported.

#### Lowest latency memspace

Memspace backed by an aggregated list of NUMA nodes identified as lowest latency after selecting each available NUMA node as the initiator.
Querying the latency value requires HMAT support on the platform. Calling `umfMemspaceLowestLatencyGet()` will return NULL if it's not supported.

### Proxy library

UMF provides the UMF proxy library (`umf_proxy`) that makes it possible
to override the default allocator in other programs in both Linux and Windows.

#### Linux

In case of Linux it can be done without any code changes using the `LD_PRELOAD` environment variable:

```sh
$ LD_PRELOAD=/usr/lib/libumf_proxy.so myprogram
```

The memory used by the proxy memory allocator is mmap'ed:
1) with the `MAP_PRIVATE` flag by default or
2) with the `MAP_SHARED` flag if the `UMF_PROXY` environment variable contains one of two following strings: `page.disposition=shared-shm` or `page.disposition=shared-fd`. These two options differ in a mechanism used during IPC:
   - `page.disposition=shared-shm` - IPC uses the named shared memory. An SHM name is generated using the `umf_proxy_lib_shm_pid_$PID` pattern, where `$PID` is the PID of the process. It creates the `/dev/shm/umf_proxy_lib_shm_pid_$PID` file.
   - `page.disposition=shared-fd` - IPC uses the file descriptor duplication. It requires using `pidfd_getfd(2)` to obtain a duplicate of another process's file descriptor. Permission to duplicate another process's file descriptor is governed by a ptrace access mode `PTRACE_MODE_ATTACH_REALCREDS` check (see `ptrace(2)`) that can be changed using the `/proc/sys/kernel/yama/ptrace_scope` interface. `pidfd_getfd(2)` is supported since Linux 5.6.

#### Windows

In case of Windows it requires:
1) explicitly linking your program dynamically with the `umf_proxy.dll` library
2) (C++ code only) including `proxy_lib_new_delete.h` in a single(!) source file in your project
   to override also the `new`/`delete` operations.

## Contributions

All contributions to the UMF project are most welcome! Before submitting
an issue or a Pull Request, please read [Contribution Guide](./CONTRIBUTING.md).

## Logging

To enable logging in UMF source files please follow the guide in the
[web documentation](https://oneapi-src.github.io/unified-memory-framework/introduction.html#logging).
