/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "benchmark.hpp"

#define UMF_BENCHMARK_TEMPLATE_DEFINE(BaseClass, Method, ...)                  \
    BENCHMARK_TEMPLATE_DEFINE_F(BaseClass, Method, __VA_ARGS__)                \
    (benchmark::State & state) {                                               \
        for (auto _ : state) {                                                 \
            bench(state);                                                      \
        }                                                                      \
    }

#define UMF_BENCHMARK_REGISTER_F(BaseClass, Method)                            \
    BENCHMARK_REGISTER_F(BaseClass, Method)                                    \
        ->ArgNames(                                                            \
            BENCHMARK_PRIVATE_CONCAT_NAME(BaseClass, Method)::argsName())      \
        ->Name(BENCHMARK_PRIVATE_CONCAT_NAME(BaseClass, Method)::name())       \
        ->Iterations(                                                          \
            BENCHMARK_PRIVATE_CONCAT_NAME(BaseClass, Method)::iterations())

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, glibc_fix, fixed_alloc_size,
                              glibc_malloc);

// Benchmarks scenarios:

// The benchmark arguments specified in Args() are, in order:
// benchmark arguments, allocator arguments, size generator arguments.
// The exact meaning of each argument depends on the benchmark, allocator, and size components used.
// Refer to the 'argsName()' function in each component to find detailed descriptions of these arguments.
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, glibc_fix)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, glibc_uniform,
                              uniform_alloc_size, glibc_malloc);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, glibc_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, os_provider, fixed_alloc_size,
                              provider_allocator<os_provider>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, os_provider)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, proxy_pool, fixed_alloc_size,
                              pool_allocator<proxy_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(alloc_benchmark, proxy_pool)
    ->Args({1000, 0, 4096})
    ->Args({1000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

#ifdef UMF_POOL_DISJOINT_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, disjoint_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, disjoint_pool_fix)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

// TODO: debug why this crashes
/*UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, disjoint_pool_uniform,
                              uniform_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, disjoint_pool_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    //    ->Threads(4)
    ->Threads(1);
*/
#endif

#ifdef UMF_POOL_JEMALLOC_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, jemalloc_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, jemalloc_pool_fix)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, jemalloc_pool_uniform,
                              uniform_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, jemalloc_pool_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, scalable_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(alloc_benchmark, scalable_pool_fix)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, scalable_pool_uniform,
                              uniform_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(alloc_benchmark, scalable_pool_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);
#endif
// Multiple allocs/free

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, glibc_fix,
                              fixed_alloc_size, glibc_malloc);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, glibc_fix)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, glibc_uniform,
                              uniform_alloc_size, glibc_malloc);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, glibc_uniform)
    ->Args({10000, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, proxy_pool,
                              fixed_alloc_size,
                              pool_allocator<proxy_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, proxy_pool)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, os_provider,
                              fixed_alloc_size,
                              provider_allocator<os_provider>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, os_provider)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

#ifdef UMF_POOL_DISJOINT_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, disjoint_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, disjoint_pool_fix)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

// TODO: debug why this crashes
/*UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              disjoint_pool_uniform, uniform_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, disjoint_pool_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);
*/
#endif

#ifdef UMF_POOL_JEMALLOC_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, jemalloc_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, jemalloc_pool_fix)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              jemalloc_pool_uniform, uniform_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, jemalloc_pool_uniform)
    ->Args({1000, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

#endif

#ifdef UMF_POOL_SCALABLE_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, scalable_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, scalable_pool_fix)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              scalable_pool_uniform, uniform_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, scalable_pool_uniform)
    ->Args({10000, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

#endif
BENCHMARK_MAIN();
