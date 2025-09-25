# UMF (Unified Memory Framework) - AI Coding Guide

## Project Architecture

UMF is a C library for constructing memory allocators and pools, built around a two-layer architecture:

- **Memory Providers** (`src/provider/`): Handle coarse-grained OS-level memory allocation (mmap, CUDA, Level Zero, etc.)
- **Memory Pools** (`src/pool/`): Handle fine-grained allocation using providers as backing store (jemalloc, scalable, disjoint)

Key architectural patterns:
- Provider/pool separation enables mixing any provider with any pool allocator
- Operations structures (`*_ops_t`) define plugin interfaces for extensibility
- Handle-based API (`*_handle_t`) abstracts implementation details
- Result codes (`umf_result_t`) for consistent error handling

## Development Workflows

### Build System
```bash
# Standard build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j $(nproc)

# Enable all features for development
# GPU tests will work only in an environment with proper hardware and drivers
cmake -B build -DCMAKE_BUILD_TYPE=Debug \
  -DUMF_BUILD_TESTS=ON -DUMF_BUILD_GPU_TESTS=OFF \
  -DUMF_BUILD_EXAMPLES=ON -DUMF_DEVELOPER_MODE=ON \
  -DUMF_FORMAT_CODE_STYLE=ON
```

### Version Management
- Version determined by:
  1. `git describe` (preferred)
  2. `VERSION` file fallback
  3. "0.0.0" default
- `set_version_variables()` in `cmake/helpers.cmake` handles version detection
- For releases: create `VERSION` file with semver format (e.g., "1.0.3")

### Code Formatting
- **Always format code before committing**: `make format-apply`
- Requires build with `-DUMF_FORMAT_CODE_STYLE=ON`
- Uses clang-format-15.0, cmake-format-0.6, and black for Python

### Testing Patterns
- Use `build_umf_test()` CMake function in `test/CMakeLists.txt`
- GPU tests require `UMF_BUILD_GPU_TESTS=ON` and hardware/drivers
- IPC tests use producer/consumer pattern with shell scripts
- Platform-specific tests: `.c` files for portability, `.cpp` for C++ features, utils, and selected tests

### CI/CD Structure
- `pr_push.yml`: Main workflow calling reusable workflows. It's called for each PR change or push to main/stable branches
- Separate workflows for different configurations: `reusable_gpu.yml`, `reusable_sanitizers.yml`, etc.
- Provider-specific testing: Level Zero, CUDA runners with actual hardware

## Coding Conventions

### Naming Patterns
- Public API: `umf*` prefix (e.g., `umfMemoryProviderCreate`)
- Internal functions: `snake_case` without prefix
- Structures: `*_t` suffix for types, `*_handle_t` for opaque handles
- Constants: `UMF_*` uppercase with underscores

### Memory Management Patterns
- Always pair create/destroy functions (e.g., `umfMemoryProviderCreate`/`umfMemoryProviderDestroy`)
- Use `umf_result_t` return codes, never throw exceptions
- Provider params have separate create/destroy lifecycle
- Thread-local storage (`__TLS`) for error state in providers

### Provider Implementation Pattern
```c
// Standard provider structure
typedef struct my_provider_t {
    // Provider-specific state
} my_provider_t;

static umf_result_t my_initialize(const void *params, void **provider);
static umf_result_t my_finalize(void *provider);
static umf_result_t my_alloc(void *provider, size_t size, size_t alignment, void **ptr);
static umf_result_t my_free(void *provider, void *ptr, size_t size);

static const umf_memory_provider_ops_t MY_PROVIDER_OPS = {
    .version = UMF_PROVIDER_OPS_VERSION_CURRENT,
    .initialize = my_initialize,
    .finalize = my_finalize,
    .alloc = my_alloc,
    .free = my_free,
    // ... other required ops
};
```

## Key Files and Patterns

### Core APIs
- `include/umf.h`: Main header, include this for basic usage
- `include/umf/memory_provider_ops.h`: Provider plugin interface
- `include/umf/memory_pool_ops.h`: Pool plugin interface

### Common Utilities
- `src/utils/`: Logging (`utils_log.h`), concurrency (`utils_concurrency.h`), assertions
- `src/critnib/`: Concurrent radix tree for address tracking
- `src/base_alloc/`: Base allocation utilities

### Platform Abstractions
- `libumf_linux.c`/`libumf_windows.c`: OS-specific implementations
- `topology.c`: HWLOC integration for NUMA topology discovery
- Provider files handle platform-specific allocation (CUDA, Level Zero, OS memory)

## Integration Points

### NUMA Support
- Uses HWLOC for topology discovery (`topology.c`, `umf_hwloc.h`)
- NUMA policies in `mempolicy.c`: bind, interleave, split modes
- Memory spaces (`memspace.c`) and targets (`memtarget.c`) for NUMA abstraction

### GPU Integration
- Level Zero provider: `provider_level_zero.c` for Intel GPUs
- CUDA provider: `provider_cuda.c` for NVIDIA GPUs
- Examples in `examples/level_zero_shared_memory/` and `examples/cuda_shared_memory/`

### IPC (Inter-Process Communication)
- Linux-specific implementation using file descriptor passing
- Requires `PTRACE_MODE_ATTACH_REALCREDS` permission
- Uses `memfd_create()` or `memfd_secret()` for anonymous shared memory

When implementing new providers or pools, follow the existing patterns in
`src/provider/provider_os_memory.c` and `src/pool/pool_scalable.c` as reference implementations.
